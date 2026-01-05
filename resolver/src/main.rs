use axum::{
    extract::{Path, State},
    routing::get,
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
use hickory_resolver::{
    config::{NameServerConfigGroup, ResolverConfig, ResolverOpts},
    name_server::TokioConnectionProvider,
    TokioResolver,
};
use jam_netadapter_common::{AltDomain, AltNamespace, DnsRecord, DnsRecordType, RegistrationPolicy};
use serde::Serialize;
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    str::FromStr,
    sync::Arc,
    time::Duration,
};
use tokio::{net::UdpSocket, sync::RwLock};
use tracing::{debug, info, warn};

#[derive(Parser)]
#[command(name = "netadapter-resolver")]
#[command(about = "recursive dns resolver with .alt gateway support")]
struct Args {
    #[arg(long, default_value = "5354")]
    dns_port: u16,

    #[arg(long, default_value = "8054")]
    api_port: u16,

    #[arg(long, default_value = "9.9.9.9")]
    upstream: String,

    #[arg(long, value_delimiter = ',', default_value = "dot,eth,jam,hs")]
    alt_namespaces: Vec<String>,
}

#[derive(Clone)]
struct AppState {
    inner: Arc<RwLock<ResolverState>>,
}

struct ResolverState {
    upstream_resolver: TokioResolver,
    alt_namespaces: HashMap<String, AltNamespace>,
    stats: ResolverStats,
}

#[derive(Default, Clone, Serialize)]
struct ResolverStats {
    queries_total: u64,
    queries_recursive: u64,
    queries_alt: u64,
}

#[derive(Serialize)]
struct ResolverInfo {
    name: &'static str,
    version: &'static str,
    upstream: String,
    alt_namespaces: Vec<String>,
    stats: ResolverStats,
}

#[derive(Serialize)]
struct NamespaceInfo {
    name: String,
    domain_count: usize,
    policy: String,
}

#[derive(Serialize)]
struct DomainInfo {
    name: String,
    namespace: String,
    records: Vec<DnsRecord>,
}

async fn resolve_alt(state: &ResolverState, name: &str) -> Option<Vec<DnsRecord>> {
    // parse name.namespace.alt
    let parts: Vec<&str> = name.trim_end_matches('.').split('.').collect();
    if parts.len() < 3 || parts.last() != Some(&"alt") {
        return None;
    }

    let namespace = parts[parts.len() - 2];
    let domain_name = parts[..parts.len() - 2].join(".");

    if let Some(ns) = state.alt_namespaces.get(namespace) {
        for domain in &ns.domains {
            if domain.name == domain_name {
                return Some(domain.records.clone());
            }
        }
    }

    None
}

async fn handle_dns_query(state: &AppState, query_bytes: &[u8], _client_addr: SocketAddr) -> Vec<u8> {
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
    response.set_recursion_desired(request.recursion_desired());
    response.set_recursion_available(true);

    if request.queries().is_empty() {
        response.set_response_code(ResponseCode::FormErr);
        return response.to_bytes().unwrap_or_default();
    }

    let query = &request.queries()[0];
    let name = query.name().to_string();
    let record_type = query.query_type();

    debug!(name = %name, record_type = ?record_type, "dns query");

    let mut inner = state.inner.write().await;
    inner.stats.queries_total += 1;

    // check if .alt domain
    if name.ends_with(".alt.") || name.ends_with(".alt") {
        inner.stats.queries_alt += 1;

        if let Some(records) = resolve_alt(&inner, &name).await {
            response.set_authoritative(true);
            response.set_response_code(ResponseCode::NoError);

            for record in records {
                let ttl = record.ttl.unwrap_or(300);
                let record_name = Name::from_str(&name).unwrap_or_default();

                let rdata = match record.record_type {
                    DnsRecordType::A => {
                        record.data.parse::<Ipv4Addr>().ok().map(|ip| RData::A(A(ip)))
                    }
                    DnsRecordType::AAAA => {
                        record.data.parse::<Ipv6Addr>().ok().map(|ip| RData::AAAA(AAAA(ip)))
                    }
                    DnsRecordType::CNAME => {
                        Name::from_str(&record.data).ok().map(|n| RData::CNAME(CNAME(n)))
                    }
                    DnsRecordType::TXT => {
                        Some(RData::TXT(TXT::new(vec![record.data.clone()])))
                    }
                    DnsRecordType::NS => {
                        Name::from_str(&record.data).ok().map(|n| RData::NS(NS(n)))
                    }
                    DnsRecordType::MX => {
                        Name::from_str(&record.data).ok().map(|n| {
                            RData::MX(MX::new(record.priority.unwrap_or(10), n))
                        })
                    }
                    _ => None,
                };

                if let Some(rd) = rdata {
                    let rec = Record::from_rdata(record_name.clone(), ttl, rd);
                    response.add_answer(rec);
                }
            }

            return response.to_bytes().unwrap_or_default();
        }

        // .alt domain not found
        response.set_response_code(ResponseCode::NXDomain);
        return response.to_bytes().unwrap_or_default();
    }

    // recursive resolution for normal domains
    inner.stats.queries_recursive += 1;
    let resolver = inner.upstream_resolver.clone();
    drop(inner);

    let lookup_name = name.trim_end_matches('.');

    match record_type {
        RecordType::A => {
            match resolver.ipv4_lookup(lookup_name).await {
                Ok(lookup) => {
                    response.set_response_code(ResponseCode::NoError);
                    let name_parsed = Name::from_str(&name).unwrap_or_default();
                    for ip in lookup.iter() {
                        let rec = Record::from_rdata(name_parsed.clone(), 300, RData::A(A(ip.0)));
                        response.add_answer(rec);
                    }
                }
                Err(e) => {
                    debug!(error = %e, name = %name, "ipv4 lookup failed");
                    response.set_response_code(ResponseCode::NXDomain);
                }
            }
        }
        RecordType::AAAA => {
            match resolver.ipv6_lookup(lookup_name).await {
                Ok(lookup) => {
                    response.set_response_code(ResponseCode::NoError);
                    let name_parsed = Name::from_str(&name).unwrap_or_default();
                    for ip in lookup.iter() {
                        let rec = Record::from_rdata(name_parsed.clone(), 300, RData::AAAA(AAAA(ip.0)));
                        response.add_answer(rec);
                    }
                }
                Err(e) => {
                    debug!(error = %e, name = %name, "ipv6 lookup failed");
                    response.set_response_code(ResponseCode::NXDomain);
                }
            }
        }
        RecordType::MX => {
            match resolver.mx_lookup(lookup_name).await {
                Ok(lookup) => {
                    response.set_response_code(ResponseCode::NoError);
                    let name_parsed = Name::from_str(&name).unwrap_or_default();
                    for mx in lookup.iter() {
                        let rec = Record::from_rdata(
                            name_parsed.clone(),
                            300,
                            RData::MX(MX::new(mx.preference(), mx.exchange().clone())),
                        );
                        response.add_answer(rec);
                    }
                }
                Err(e) => {
                    debug!(error = %e, name = %name, "mx lookup failed");
                    response.set_response_code(ResponseCode::NXDomain);
                }
            }
        }
        RecordType::TXT => {
            match resolver.txt_lookup(lookup_name).await {
                Ok(lookup) => {
                    response.set_response_code(ResponseCode::NoError);
                    let name_parsed = Name::from_str(&name).unwrap_or_default();
                    for txt in lookup.iter() {
                        let rec = Record::from_rdata(name_parsed.clone(), 300, RData::TXT(txt.clone()));
                        response.add_answer(rec);
                    }
                }
                Err(e) => {
                    debug!(error = %e, name = %name, "txt lookup failed");
                    response.set_response_code(ResponseCode::NXDomain);
                }
            }
        }
        _ => {
            response.set_response_code(ResponseCode::NotImp);
        }
    }

    response.to_bytes().unwrap_or_default()
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let args = Args::parse();

    // setup upstream resolver
    let upstream_ip: IpAddr = args.upstream.parse().expect("valid upstream ip");
    let resolver_config = ResolverConfig::from_parts(
        None,
        vec![],
        NameServerConfigGroup::from_ips_clear(&[upstream_ip], 53, true),
    );
    let mut opts = ResolverOpts::default();
    opts.cache_size = 1000;
    opts.timeout = Duration::from_secs(5);

    let mut builder = TokioResolver::builder_with_config(resolver_config, TokioConnectionProvider::default());
    *builder.options_mut() = opts;
    let upstream_resolver = builder.build();

    // initialize alt namespaces (would be synced from external sources)
    let mut alt_namespaces = HashMap::new();
    for ns in &args.alt_namespaces {
        alt_namespaces.insert(
            ns.clone(),
            AltNamespace {
                name: ns.clone(),
                admin: None,
                policy: RegistrationPolicy::Open,
                domains: Vec::new(),
            },
        );
    }

    // add some test domains for development
    if let Some(jam_ns) = alt_namespaces.get_mut("jam") {
        jam_ns.domains.push(AltDomain {
            name: "test".to_string(),
            namespace: "jam".to_string(),
            owner: [0u8; 32],
            records: vec![DnsRecord {
                name: "test".to_string(),
                record_type: DnsRecordType::A,
                ttl: Some(300),
                data: "127.0.0.1".to_string(),
                priority: None,
                regions: None,
            }],
            registered_block: 0,
            expires_block: None,
            nonce: 0,
        });
    }

    let state = AppState {
        inner: Arc::new(RwLock::new(ResolverState {
            upstream_resolver,
            alt_namespaces,
            stats: ResolverStats::default(),
        })),
    };

    info!(
        dns_port = args.dns_port,
        api_port = args.api_port,
        upstream = %args.upstream,
        namespaces = ?args.alt_namespaces,
        "resolver starting"
    );

    // start dns server
    let dns_state = state.clone();
    let dns_port = args.dns_port;
    tokio::spawn(async move {
        let socket = UdpSocket::bind(format!("0.0.0.0:{}", dns_port))
            .await
            .expect("bind dns socket");
        info!(port = dns_port, "dns server listening");

        let mut buf = [0u8; 512];
        loop {
            match socket.recv_from(&mut buf).await {
                Ok((len, addr)) => {
                    let response = handle_dns_query(&dns_state, &buf[..len], addr).await;
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

    // start api server
    let app = Router::new()
        .route("/", get(handle_info))
        .route("/alt", get(handle_list_namespaces))
        .route("/alt/{namespace}", get(handle_list_domains))
        .route("/alt/{namespace}/{domain}", get(handle_get_domain))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", args.api_port))
        .await
        .expect("bind api");
    info!(port = args.api_port, "api server listening");
    axum::serve(listener, app).await.expect("serve");
}

async fn handle_info(State(state): State<AppState>) -> Json<ResolverInfo> {
    let s = state.inner.read().await;
    Json(ResolverInfo {
        name: "netadapter-resolver",
        version: env!("CARGO_PKG_VERSION"),
        upstream: "configured".to_string(),
        alt_namespaces: s.alt_namespaces.keys().cloned().collect(),
        stats: s.stats.clone(),
    })
}

async fn handle_list_namespaces(State(state): State<AppState>) -> Json<Vec<NamespaceInfo>> {
    let s = state.inner.read().await;
    let namespaces: Vec<NamespaceInfo> = s
        .alt_namespaces
        .values()
        .map(|ns| NamespaceInfo {
            name: ns.name.clone(),
            domain_count: ns.domains.len(),
            policy: format!("{:?}", ns.policy),
        })
        .collect();
    Json(namespaces)
}

async fn handle_list_domains(
    State(state): State<AppState>,
    Path(namespace): Path<String>,
) -> Json<Vec<DomainInfo>> {
    let s = state.inner.read().await;
    if let Some(ns) = s.alt_namespaces.get(&namespace) {
        let domains: Vec<DomainInfo> = ns
            .domains
            .iter()
            .map(|d| DomainInfo {
                name: d.name.clone(),
                namespace: d.namespace.clone(),
                records: d.records.clone(),
            })
            .collect();
        Json(domains)
    } else {
        Json(vec![])
    }
}

async fn handle_get_domain(
    State(state): State<AppState>,
    Path((namespace, domain)): Path<(String, String)>,
) -> Json<Option<DomainInfo>> {
    let s = state.inner.read().await;
    if let Some(ns) = s.alt_namespaces.get(&namespace) {
        for d in &ns.domains {
            if d.name == domain {
                return Json(Some(DomainInfo {
                    name: d.name.clone(),
                    namespace: d.namespace.clone(),
                    records: d.records.clone(),
                }));
            }
        }
    }
    Json(None)
}
