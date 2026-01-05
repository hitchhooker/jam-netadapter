use axum::{
    extract::State,
    routing::post,
    Json, Router,
};
use clap::Parser;
use ed25519_dalek::VerifyingKey;
use jam_netadapter_common::{OracleRequest, ThresholdResponse, WorkerResponse, WorkerSignature};
use sha2::{Digest, Sha256};
use std::{collections::HashMap, sync::Arc};
use tokio::sync::RwLock;
use tracing::info;

#[derive(Parser)]
#[command(name = "netadapter-aggregator")]
#[command(about = "aggregates oracle worker responses")]
struct Args {
    #[arg(short, long, default_value = "3001")]
    port: u16,

    #[arg(short, long, default_value = "2")]
    threshold: usize,

    #[arg(long, value_delimiter = ',')]
    workers: Vec<String>,

    #[arg(long, value_delimiter = ',')]
    worker_keys: Vec<String>,
}

#[allow(dead_code)]
struct AppState {
    workers: Vec<String>,
    worker_keys: HashMap<[u8; 32], VerifyingKey>,
    threshold: usize,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let args = Args::parse();

    let mut worker_keys = HashMap::new();
    for key_hex in &args.worker_keys {
        let key_bytes: [u8; 32] = hex::decode(key_hex)
            .expect("decode worker key hex")
            .try_into()
            .expect("worker key must be 32 bytes");
        let verifying_key = VerifyingKey::from_bytes(&key_bytes).expect("valid verifying key");
        worker_keys.insert(key_bytes, verifying_key);
    }

    info!(
        workers = ?args.workers,
        threshold = args.threshold,
        "aggregator starting"
    );

    let state = Arc::new(RwLock::new(AppState {
        workers: args.workers,
        worker_keys,
        threshold: args.threshold,
    }));

    let app = Router::new()
        .route("/aggregate", post(handle_aggregate))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", args.port))
        .await
        .expect("bind");
    info!(port = args.port, "listening");
    axum::serve(listener, app).await.expect("serve");
}

async fn handle_aggregate(
    State(state): State<Arc<RwLock<AppState>>>,
    Json(request): Json<OracleRequest>,
) -> Json<ThresholdResponse> {
    let state = state.read().await;
    let client = reqwest::Client::new();

    let mut handles = Vec::new();
    for worker_url in &state.workers {
        let url = format!("{}/oracle", worker_url);
        let req = request.clone();
        let client = client.clone();
        handles.push(tokio::spawn(async move {
            client.post(&url).json(&req).send().await?.json::<WorkerResponse>().await
        }));
    }

    let mut responses = Vec::new();
    for handle in handles {
        if let Ok(Ok(resp)) = handle.await {
            responses.push(resp);
        }
    }

    let verified: Vec<_> = responses
        .iter()
        .filter(|r| {
            if let Some(pk) = state.worker_keys.get(&r.worker_id) {
                r.verify(pk)
            } else {
                false
            }
        })
        .collect();

    let mut data_groups: HashMap<[u8; 32], Vec<&WorkerResponse>> = HashMap::new();
    for resp in &verified {
        let mut hasher = Sha256::new();
        hasher.update(&resp.data);
        let hash: [u8; 32] = hasher.finalize().into();
        data_groups.entry(hash).or_default().push(resp);
    }

    let consensus_group = data_groups
        .values()
        .max_by_key(|g| g.len())
        .cloned()
        .unwrap_or_default();

    let request_id = request.request_id();
    let data = consensus_group.first().map(|r| r.data.clone()).unwrap_or_default();

    let timestamps: Vec<u64> = consensus_group.iter().map(|r| r.timestamp).collect();
    let median_timestamp = if timestamps.is_empty() {
        0
    } else {
        let mut sorted = timestamps.clone();
        sorted.sort();
        sorted[sorted.len() / 2]
    };

    let signatures: Vec<WorkerSignature> = consensus_group
        .iter()
        .map(|r| WorkerSignature {
            worker_id: r.worker_id,
            timestamp: r.timestamp,
            signature: r.signature,
        })
        .collect();

    Json(ThresholdResponse {
        request_id,
        data,
        timestamp: median_timestamp,
        signatures,
    })
}
