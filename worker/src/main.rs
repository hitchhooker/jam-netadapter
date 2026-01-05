use axum::{
    extract::State,
    routing::{get, post},
    Json, Router,
};
use clap::Parser;
use ed25519_dalek::{Signer, SigningKey};
use hickory_resolver::Resolver;
use jam_netadapter_common::{DnsRecordType, OracleRequest, WorkerResponse};
use rand::rngs::OsRng;
use std::{
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::sync::RwLock;
use tracing::{info, warn};

#[derive(Parser)]
#[command(name = "netadapter-worker")]
#[command(about = "jam network adapter oracle worker")]
struct Args {
    #[arg(short, long, default_value = "3000")]
    port: u16,

    #[arg(short, long)]
    key_file: Option<String>,
}

type TokioResolver = Resolver<hickory_resolver::name_server::TokioConnectionProvider>;

struct AppState {
    signing_key: SigningKey,
    resolver: TokioResolver,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let args = Args::parse();

    let signing_key = if let Some(key_path) = &args.key_file {
        let key_bytes = std::fs::read(key_path).expect("read key file");
        let key_array: [u8; 32] = key_bytes.try_into().expect("key must be 32 bytes");
        SigningKey::from_bytes(&key_array)
    } else {
        info!("generating ephemeral signing key");
        SigningKey::generate(&mut OsRng)
    };

    let worker_id = hex::encode(signing_key.verifying_key().to_bytes());
    info!(worker_id = %worker_id, "worker starting");

    let resolver = TokioResolver::builder_tokio().expect("create dns resolver").build();

    let state = Arc::new(RwLock::new(AppState {
        signing_key,
        resolver,
    }));

    let app = Router::new()
        .route("/", get(index))
        .route("/oracle", post(handle_oracle))
        .route("/oracle/http", post(handle_http))
        .route("/oracle/dns", post(handle_dns))
        .route("/oracle/timestamp", get(handle_timestamp))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", args.port))
        .await
        .expect("bind");
    info!(port = args.port, "listening");
    axum::serve(listener, app).await.expect("serve");
}

async fn index(State(state): State<Arc<RwLock<AppState>>>) -> Json<serde_json::Value> {
    let state = state.read().await;
    let worker_id = hex::encode(state.signing_key.verifying_key().to_bytes());
    Json(serde_json::json!({
        "service": "jam-netadapter-worker",
        "worker_id": worker_id,
        "endpoints": ["/oracle", "/oracle/http", "/oracle/dns", "/oracle/timestamp"]
    }))
}

async fn handle_oracle(
    State(state): State<Arc<RwLock<AppState>>>,
    Json(request): Json<OracleRequest>,
) -> Json<WorkerResponse> {
    let data = match &request {
        OracleRequest::Http { url, method } => fetch_http(url, method).await,
        OracleRequest::Dns { name, record_type } => {
            let state = state.read().await;
            resolve_dns(&state.resolver, name, *record_type).await
        }
        OracleRequest::Timestamp => get_timestamp(),
        OracleRequest::Feed { feed_id } => fetch_feed(feed_id).await,
    };

    let state = state.read().await;
    let request_id = request.request_id();
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let msg = WorkerResponse::signing_message(&request_id, &data, timestamp);
    let signature = state.signing_key.sign(&msg);

    Json(WorkerResponse {
        request_id,
        worker_id: state.signing_key.verifying_key().to_bytes(),
        data,
        timestamp,
        signature: signature.to_bytes(),
    })
}

#[derive(serde::Deserialize)]
struct HttpRequest {
    url: String,
    method: Option<String>,
}

async fn handle_http(
    State(state): State<Arc<RwLock<AppState>>>,
    Json(req): Json<HttpRequest>,
) -> Json<WorkerResponse> {
    let method = req.method.unwrap_or_else(|| "GET".to_string());
    let request = OracleRequest::Http {
        url: req.url.clone(),
        method: method.clone(),
    };
    let data = fetch_http(&req.url, &method).await;

    let state = state.read().await;
    let request_id = request.request_id();
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let msg = WorkerResponse::signing_message(&request_id, &data, timestamp);
    let signature = state.signing_key.sign(&msg);

    Json(WorkerResponse {
        request_id,
        worker_id: state.signing_key.verifying_key().to_bytes(),
        data,
        timestamp,
        signature: signature.to_bytes(),
    })
}

#[derive(serde::Deserialize)]
struct DnsRequest {
    name: String,
    record_type: DnsRecordType,
}

async fn handle_dns(
    State(state): State<Arc<RwLock<AppState>>>,
    Json(req): Json<DnsRequest>,
) -> Json<WorkerResponse> {
    let request = OracleRequest::Dns {
        name: req.name.clone(),
        record_type: req.record_type,
    };

    let data = {
        let state = state.read().await;
        resolve_dns(&state.resolver, &req.name, req.record_type).await
    };

    let state = state.read().await;
    let request_id = request.request_id();
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let msg = WorkerResponse::signing_message(&request_id, &data, timestamp);
    let signature = state.signing_key.sign(&msg);

    Json(WorkerResponse {
        request_id,
        worker_id: state.signing_key.verifying_key().to_bytes(),
        data,
        timestamp,
        signature: signature.to_bytes(),
    })
}

async fn handle_timestamp(State(state): State<Arc<RwLock<AppState>>>) -> Json<WorkerResponse> {
    let request = OracleRequest::Timestamp;
    let data = get_timestamp();

    let state = state.read().await;
    let request_id = request.request_id();
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let msg = WorkerResponse::signing_message(&request_id, &data, timestamp);
    let signature = state.signing_key.sign(&msg);

    Json(WorkerResponse {
        request_id,
        worker_id: state.signing_key.verifying_key().to_bytes(),
        data,
        timestamp,
        signature: signature.to_bytes(),
    })
}

async fn fetch_http(url: &str, method: &str) -> Vec<u8> {
    let client = reqwest::Client::new();
    let result = match method.to_uppercase().as_str() {
        "GET" => client.get(url).send().await,
        "HEAD" => client.head(url).send().await,
        "POST" => client.post(url).send().await,
        _ => {
            warn!(method = method, "unsupported http method");
            return b"error: unsupported method".to_vec();
        }
    };

    match result {
        Ok(resp) => resp.bytes().await.unwrap_or_default().to_vec(),
        Err(e) => format!("error: {}", e).into_bytes(),
    }
}

async fn resolve_dns(resolver: &TokioResolver, name: &str, record_type: DnsRecordType) -> Vec<u8> {
    let result = match record_type {
        DnsRecordType::A => resolver
            .lookup_ip(name)
            .await
            .map(|r| {
                r.iter()
                    .filter_map(|ip| match ip {
                        std::net::IpAddr::V4(v4) => Some(v4.to_string()),
                        _ => None,
                    })
                    .collect::<Vec<_>>()
                    .join(",")
            }),
        DnsRecordType::AAAA => resolver
            .lookup_ip(name)
            .await
            .map(|r| {
                r.iter()
                    .filter_map(|ip| match ip {
                        std::net::IpAddr::V6(v6) => Some(v6.to_string()),
                        _ => None,
                    })
                    .collect::<Vec<_>>()
                    .join(",")
            }),
        DnsRecordType::TXT => resolver
            .txt_lookup(name)
            .await
            .map(|r| {
                r.iter()
                    .map(|txt| txt.to_string())
                    .collect::<Vec<_>>()
                    .join("\n")
            }),
        DnsRecordType::MX => resolver
            .mx_lookup(name)
            .await
            .map(|r| {
                r.iter()
                    .map(|mx| format!("{} {}", mx.preference(), mx.exchange()))
                    .collect::<Vec<_>>()
                    .join("\n")
            }),
        DnsRecordType::NS => resolver
            .ns_lookup(name)
            .await
            .map(|r| {
                r.iter()
                    .map(|ns| ns.to_string())
                    .collect::<Vec<_>>()
                    .join("\n")
            }),
        DnsRecordType::SOA => resolver
            .soa_lookup(name)
            .await
            .map(|r| {
                r.iter()
                    .map(|soa| {
                        format!(
                            "{} {} {} {} {} {} {}",
                            soa.mname(),
                            soa.rname(),
                            soa.serial(),
                            soa.refresh(),
                            soa.retry(),
                            soa.expire(),
                            soa.minimum()
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("\n")
            }),
        DnsRecordType::SRV => resolver
            .srv_lookup(name)
            .await
            .map(|r| {
                r.iter()
                    .map(|srv| {
                        format!(
                            "{} {} {} {}",
                            srv.priority(),
                            srv.weight(),
                            srv.port(),
                            srv.target()
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("\n")
            }),
        _ => Ok("unsupported record type".to_string()),
    };

    match result {
        Ok(data) => data.into_bytes(),
        Err(e) => format!("error: {}", e).into_bytes(),
    }
}

fn get_timestamp() -> Vec<u8> {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    ts.to_string().into_bytes()
}

async fn fetch_feed(feed_id: &str) -> Vec<u8> {
    format!("feed:{} not implemented", feed_id).into_bytes()
}
