use axum::{
    extract::State,
    routing::{get, post},
    Json, Router,
};
use clap::Parser;
use hickory_proto::{
    op::{Message, MessageType, OpCode, ResponseCode},
    rr::{
        rdata::{A, AAAA, CNAME, MX, NS, TXT},
        Name, RData, Record, RecordType,
    },
    serialize::binary::{BinDecodable, BinEncodable},
};
use jam_netadapter_common::{
    DnsRecord, DnsRecordType, DnsZone, ZoneUpdate, ZoneUpdateRequest, ZoneUpdateResponse,
};
use maxminddb::{geoip2, Reader};
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::PathBuf,
    str::FromStr,
    sync::Arc,
};
use tokio::{net::UdpSocket, sync::RwLock};
use tracing::{info, warn, debug};

#[derive(Parser)]
#[command(name = "netadapter-dns")]
#[command(about = "geodns server with jam consensus")]
struct Args {
    #[arg(long, default_value = "5353")]
    dns_port: u16,

    #[arg(long, default_value = "8053")]
    api_port: u16,

    #[arg(long)]
    jam_endpoint: Option<String>,

    #[arg(long, default_value = "3")]
    finality_blocks: u64,

    #[arg(long, help = "path to GeoLite2-City.mmdb")]
    geoip_db: Option<PathBuf>,

    #[arg(long, help = "path to GeoLite2-ASN.mmdb")]
    asn_db: Option<PathBuf>,
}

struct GeoResolver {
    city_reader: Option<Reader<Vec<u8>>>,
    asn_reader: Option<Reader<Vec<u8>>>,
}

impl GeoResolver {
    fn new(city_path: Option<&PathBuf>, asn_path: Option<&PathBuf>) -> Self {
        let city_reader = city_path.and_then(|p| {
            match Reader::open_readfile(p) {
                Ok(r) => {
                    info!(path = ?p, "loaded geoip city database");
                    Some(r)
                }
                Err(e) => {
                    warn!(path = ?p, error = %e, "failed to load geoip city database");
                    None
                }
            }
        });

        let asn_reader = asn_path.and_then(|p| {
            match Reader::open_readfile(p) {
                Ok(r) => {
                    info!(path = ?p, "loaded asn database");
                    Some(r)
                }
                Err(e) => {
                    warn!(path = ?p, error = %e, "failed to load asn database");
                    None
                }
            }
        });

        Self { city_reader, asn_reader }
    }

    fn lookup_country(&self, ip: IpAddr) -> Option<String> {
        let reader = self.city_reader.as_ref()?;
        let city: geoip2::City = reader.lookup(ip).ok()?;
        city.country?.iso_code.map(|s| s.to_string())
    }

    fn lookup_continent(&self, ip: IpAddr) -> Option<String> {
        let reader = self.city_reader.as_ref()?;
        let city: geoip2::City = reader.lookup(ip).ok()?;
        city.continent?.code.map(|s| s.to_string())
    }

    fn lookup_asn(&self, ip: IpAddr) -> Option<u32> {
        let reader = self.asn_reader.as_ref()?;
        let asn: geoip2::Asn = reader.lookup(ip).ok()?;
        asn.autonomous_system_number
    }

    #[allow(dead_code)]
    fn lookup_asn_org(&self, ip: IpAddr) -> Option<String> {
        let reader = self.asn_reader.as_ref()?;
        let asn: geoip2::Asn = reader.lookup(ip).ok()?;
        asn.autonomous_system_organization.map(|s| s.to_string())
    }

    fn get_client_regions(&self, ip: IpAddr) -> Vec<String> {
        let mut regions = vec!["*".to_string()];

        if let Some(continent) = self.lookup_continent(ip) {
            regions.push(format!("continent:{}", continent));
        }

        if let Some(country) = self.lookup_country(ip) {
            regions.push(format!("country:{}", country));
        }

        if let Some(asn) = self.lookup_asn(ip) {
            regions.push(format!("asn:{}", asn));
        }

        debug!(ip = %ip, regions = ?regions, "resolved client regions");
        regions
    }
}

#[derive(Clone)]
struct ZoneStore {
    zones: Arc<RwLock<HashMap<String, DnsZone>>>,
    pending_updates: Arc<RwLock<HashMap<String, Vec<(u64, ZoneUpdate)>>>>,
    current_block: Arc<RwLock<u64>>,
    finality_blocks: u64,
}

impl ZoneStore {
    fn new(finality_blocks: u64) -> Self {
        Self {
            zones: Arc::new(RwLock::new(HashMap::new())),
            pending_updates: Arc::new(RwLock::new(HashMap::new())),
            current_block: Arc::new(RwLock::new(0)),
            finality_blocks,
        }
    }

    async fn get_zone(&self, origin: &str) -> Option<DnsZone> {
        self.zones.read().await.get(origin).cloned()
    }

    async fn set_zone(&self, zone: DnsZone) {
        let origin = zone.origin.clone();
        self.zones.write().await.insert(origin, zone);
    }

    async fn apply_update(&self, zone_origin: &str, update: ZoneUpdate, block: u64, optimistic: bool) {
        if optimistic {
            let mut zones = self.zones.write().await;
            if let Some(zone) = zones.get_mut(zone_origin) {
                apply_zone_update(zone, &update);
                zone.serial += 1;
            }
            let mut pending = self.pending_updates.write().await;
            pending.entry(zone_origin.to_string()).or_default().push((block, update));
        } else {
            let mut pending = self.pending_updates.write().await;
            pending.entry(zone_origin.to_string()).or_default().push((block, update));
        }
    }

    async fn finalize_block(&self, block: u64) {
        let finality_threshold = block.saturating_sub(self.finality_blocks);
        let mut pending = self.pending_updates.write().await;
        let mut zones = self.zones.write().await;

        for (zone_origin, updates) in pending.iter_mut() {
            let finalized: Vec<_> = updates
                .iter()
                .filter(|(b, _)| *b <= finality_threshold)
                .map(|(_, u)| u.clone())
                .collect();

            if let Some(zone) = zones.get_mut(zone_origin) {
                for update in finalized {
                    apply_zone_update(zone, &update);
                }
                zone.finalized_block = Some(finality_threshold);
            }

            updates.retain(|(b, _)| *b > finality_threshold);
        }

        *self.current_block.write().await = block;
    }

    async fn lookup_record_geo(&self, name: &str, record_type: RecordType, client_regions: &[String]) -> Vec<DnsRecord> {
        let zones = self.zones.read().await;
        let name_lower = name.to_lowercase();

        for zone in zones.values() {
            let origin_lower = zone.origin.to_lowercase();
            let origin_no_dot = origin_lower.trim_end_matches('.');

            if name_lower.ends_with(&origin_lower) || name_lower.ends_with(origin_no_dot)
               || name_lower == origin_lower || name_lower == origin_no_dot {
                let rt = match record_type {
                    RecordType::A => DnsRecordType::A,
                    RecordType::AAAA => DnsRecordType::AAAA,
                    RecordType::CNAME => DnsRecordType::CNAME,
                    RecordType::MX => DnsRecordType::MX,
                    RecordType::TXT => DnsRecordType::TXT,
                    RecordType::NS => DnsRecordType::NS,
                    RecordType::SOA => DnsRecordType::SOA,
                    RecordType::SRV => DnsRecordType::SRV,
                    RecordType::PTR => DnsRecordType::PTR,
                    _ => continue,
                };

                let matching: Vec<_> = zone
                    .records
                    .iter()
                    .filter(|r| {
                        let record_fqdn = if r.name == "@" {
                            origin_no_dot.to_string()
                        } else {
                            format!("{}.{}", r.name, origin_no_dot)
                        };
                        let name_no_dot = name_lower.trim_end_matches('.');
                        (record_fqdn == name_no_dot || r.name == name_no_dot) && r.record_type == rt
                    })
                    .collect();

                let geo_filtered: Vec<_> = matching
                    .iter()
                    .filter(|r| {
                        match &r.regions {
                            None => true,
                            Some(regions) if regions.is_empty() => true,
                            Some(regions) => {
                                regions.iter().any(|region| {
                                    client_regions.contains(region)
                                })
                            }
                        }
                    })
                    .cloned()
                    .cloned()
                    .collect();

                if !geo_filtered.is_empty() {
                    return geo_filtered;
                }

                return matching.into_iter().filter(|r| {
                    r.regions.is_none() || r.regions.as_ref().map(|v| v.is_empty()).unwrap_or(true)
                }).cloned().collect();
            }
        }
        Vec::new()
    }
}

fn apply_zone_update(zone: &mut DnsZone, update: &ZoneUpdate) {
    match update {
        ZoneUpdate::AddRecord(record) => {
            zone.records.push(record.clone());
        }
        ZoneUpdate::RemoveRecord { name, record_type } => {
            zone.records.retain(|r| !(r.name == *name && r.record_type == *record_type));
        }
        ZoneUpdate::UpdateRecord(record) => {
            if let Some(existing) = zone
                .records
                .iter_mut()
                .find(|r| r.name == record.name && r.record_type == record.record_type)
            {
                *existing = record.clone();
            }
        }
        ZoneUpdate::SetTtl { name, ttl } => {
            for record in &mut zone.records {
                if record.name == *name {
                    record.ttl = Some(*ttl);
                }
            }
        }
    }
}

async fn handle_dns_query(store: &ZoneStore, geo: &GeoResolver, query_bytes: &[u8], client_addr: SocketAddr) -> Vec<u8> {
    let request = match Message::from_bytes(query_bytes) {
        Ok(msg) => msg,
        Err(e) => {
            warn!("failed to parse dns query: {}", e);
            return Vec::new();
        }
    };

    let mut response = Message::new();
    response.set_id(request.id());
    response.set_message_type(MessageType::Response);
    response.set_op_code(OpCode::Query);
    response.set_authoritative(true);
    response.set_recursion_desired(request.recursion_desired());
    response.set_recursion_available(false);

    if request.queries().is_empty() {
        response.set_response_code(ResponseCode::FormErr);
        return response.to_bytes().unwrap_or_default();
    }

    let query = &request.queries()[0];
    let name = query.name().to_string();
    let record_type = query.query_type();

    let client_regions = geo.get_client_regions(client_addr.ip());
    debug!(name = %name, record_type = ?record_type, regions = ?client_regions, "geodns query");

    let records = store.lookup_record_geo(&name, record_type, &client_regions).await;

    if records.is_empty() {
        response.set_response_code(ResponseCode::NXDomain);
        return response.to_bytes().unwrap_or_default();
    }

    response.set_response_code(ResponseCode::NoError);

    for record in records {
        let ttl = record.ttl.unwrap_or(300);
        let name = match Name::from_str(&record.name) {
            Ok(n) => n,
            Err(_) => continue,
        };

        let rdata = match record.record_type {
            DnsRecordType::A => {
                if let Ok(ip) = record.data.parse::<Ipv4Addr>() {
                    Some(RData::A(A(ip)))
                } else {
                    None
                }
            }
            DnsRecordType::AAAA => {
                if let Ok(ip) = record.data.parse::<Ipv6Addr>() {
                    Some(RData::AAAA(AAAA(ip)))
                } else {
                    None
                }
            }
            DnsRecordType::CNAME => {
                if let Ok(n) = Name::from_str(&record.data) {
                    Some(RData::CNAME(CNAME(n)))
                } else {
                    None
                }
            }
            DnsRecordType::MX => {
                if let Ok(n) = Name::from_str(&record.data) {
                    Some(RData::MX(MX::new(record.priority.unwrap_or(10), n)))
                } else {
                    None
                }
            }
            DnsRecordType::TXT => Some(RData::TXT(TXT::new(vec![record.data.clone()]))),
            DnsRecordType::NS => {
                if let Ok(n) = Name::from_str(&record.data) {
                    Some(RData::NS(NS(n)))
                } else {
                    None
                }
            }
            _ => None,
        };

        if let Some(rd) = rdata {
            let rec = Record::from_rdata(name, ttl, rd);
            response.add_answer(rec);
        }
    }

    response.to_bytes().unwrap_or_default()
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let args = Args::parse();

    let store = ZoneStore::new(args.finality_blocks);
    let geo = Arc::new(GeoResolver::new(args.geoip_db.as_ref(), args.asn_db.as_ref()));

    let example_zone = DnsZone {
        origin: "example.jam.".to_string(),
        ttl: 300,
        records: vec![
            DnsRecord {
                name: "@".to_string(),
                record_type: DnsRecordType::A,
                ttl: Some(300),
                data: "192.0.2.1".to_string(),
                priority: None,
                regions: None,
            },
            DnsRecord {
                name: "@".to_string(),
                record_type: DnsRecordType::A,
                ttl: Some(300),
                data: "192.0.2.10".to_string(),
                priority: None,
                regions: Some(vec!["continent:EU".to_string()]),
            },
            DnsRecord {
                name: "@".to_string(),
                record_type: DnsRecordType::A,
                ttl: Some(300),
                data: "192.0.2.20".to_string(),
                priority: None,
                regions: Some(vec!["continent:NA".to_string()]),
            },
            DnsRecord {
                name: "@".to_string(),
                record_type: DnsRecordType::A,
                ttl: Some(300),
                data: "192.0.2.30".to_string(),
                priority: None,
                regions: Some(vec!["continent:AS".to_string()]),
            },
            DnsRecord {
                name: "www".to_string(),
                record_type: DnsRecordType::A,
                ttl: Some(300),
                data: "192.0.2.1".to_string(),
                priority: None,
                regions: None,
            },
            DnsRecord {
                name: "@".to_string(),
                record_type: DnsRecordType::NS,
                ttl: Some(3600),
                data: "ns1.example.jam.".to_string(),
                priority: None,
                regions: None,
            },
        ],
        serial: 1,
        finalized_block: None,
        owner: None,
        nonce: 0,
    };
    store.set_zone(example_zone).await;

    let dns_store = store.clone();
    let dns_geo = geo.clone();
    let api_store = store.clone();

    let dns_handle = tokio::spawn(async move {
        let socket = UdpSocket::bind(format!("0.0.0.0:{}", args.dns_port))
            .await
            .expect("bind udp");
        info!(port = args.dns_port, "geodns server listening");

        let mut buf = [0u8; 512];
        loop {
            match socket.recv_from(&mut buf).await {
                Ok((len, addr)) => {
                    let response = handle_dns_query(&dns_store, &dns_geo, &buf[..len], addr).await;
                    if !response.is_empty() {
                        if let Err(e) = socket.send_to(&response, addr).await {
                            warn!("failed to send dns response: {}", e);
                        }
                    }
                }
                Err(e) => {
                    warn!("dns recv error: {}", e);
                }
            }
        }
    });

    let api_handle = tokio::spawn(async move {
        let app = Router::new()
            .route("/", get(api_index))
            .route("/zones", get(list_zones))
            .route("/zones", post(create_zone))
            .route("/zones/update", post(update_zone))
            .route("/block", post(set_block))
            .with_state(api_store);

        let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", args.api_port))
            .await
            .expect("bind api");
        info!(port = args.api_port, "api server listening");
        axum::serve(listener, app).await.expect("api server");
    });

    tokio::select! {
        _ = dns_handle => {}
        _ = api_handle => {}
    }
}

async fn api_index() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "service": "jam-netadapter-geodns",
        "description": "geodns with jam consensus and conflict resolution",
        "endpoints": ["/zones", "/zones/update", "/block"],
        "region_formats": {
            "global": "*",
            "continent": "continent:XX (EU, NA, AS, AF, OC, SA, AN)",
            "country": "country:XX (US, DE, JP, etc)",
            "asn": "asn:NNNNN (autonomous system number)"
        },
        "conflict_handling": {
            "optimistic": "updates applied immediately, pending finalization",
            "finality_blocks": 3,
            "rollback": "conflicting optimistic updates rolled back after consensus"
        }
    }))
}

async fn list_zones(State(store): State<ZoneStore>) -> Json<Vec<DnsZone>> {
    let zones = store.zones.read().await;
    Json(zones.values().cloned().collect())
}

async fn create_zone(
    State(store): State<ZoneStore>,
    Json(zone): Json<DnsZone>,
) -> Json<serde_json::Value> {
    store.set_zone(zone.clone()).await;
    Json(serde_json::json!({
        "status": "created",
        "zone": zone.origin
    }))
}

async fn update_zone(
    State(store): State<ZoneStore>,
    Json(request): Json<ZoneUpdateRequest>,
) -> Json<ZoneUpdateResponse> {
    let current_block = *store.current_block.read().await;

    for update in &request.updates {
        store.apply_update(&request.zone, update.clone(), current_block, request.optimistic).await;
    }

    let new_serial = store
        .get_zone(&request.zone)
        .await
        .map(|z| z.serial)
        .unwrap_or(0);

    Json(ZoneUpdateResponse {
        zone: request.zone,
        new_serial,
        finalized: !request.optimistic,
        pending_block: if request.optimistic {
            Some(current_block)
        } else {
            None
        },
    })
}

#[derive(serde::Deserialize)]
struct BlockUpdate {
    block: u64,
}

async fn set_block(
    State(store): State<ZoneStore>,
    Json(update): Json<BlockUpdate>,
) -> Json<serde_json::Value> {
    store.finalize_block(update.block).await;
    let finalized = update.block.saturating_sub(store.finality_blocks);
    Json(serde_json::json!({
        "current_block": update.block,
        "finalized_block": finalized
    }))
}
