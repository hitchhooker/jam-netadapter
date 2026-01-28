//! jam ibc executor
//!
//! off-chain relay executor for ibc packets between jam and cosmos chains

mod config;
mod cosmos;
mod jam;
mod relay;
mod tx;
mod types;

use clap::Parser;
use tracing::{info, warn};
use std::time::Duration;

#[derive(Parser, Debug)]
#[command(name = "jam-ibc-executor")]
#[command(about = "relay ibc packets between jam and cosmos chains")]
struct Args {
    /// path to config file
    #[arg(short, long, default_value = "executor.toml")]
    config: String,

    /// jam rpc endpoint
    #[arg(long, default_value = "http://localhost:9933")]
    jam_rpc: String,

    /// cosmos rpc endpoint (tendermint)
    #[arg(long, default_value = "http://localhost:26657")]
    cosmos_rpc: String,

    /// path to executor keypair
    #[arg(long)]
    keypair: Option<String>,

    /// minimum bounty to claim tasks (in base units)
    #[arg(long, default_value = "500")]
    min_bounty: u64,

    /// poll interval in seconds
    #[arg(long, default_value = "6")]
    poll_interval: u64,

    /// dry run (don't submit transactions)
    #[arg(long)]
    dry_run: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // init logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("jam_ibc_executor=info".parse()?)
        )
        .init();

    let args = Args::parse();

    info!("starting jam ibc executor");
    info!("jam rpc: {}", args.jam_rpc);
    info!("cosmos rpc: {}", args.cosmos_rpc);

    // load or generate keypair
    let keypair = match &args.keypair {
        Some(path) => {
            info!("loading keypair from {}", path);
            load_keypair(path)?
        }
        None => {
            warn!("no keypair specified, generating ephemeral keypair");
            generate_keypair()
        }
    };

    let pub_key = keypair.verifying_key().to_bytes();
    info!("executor public key: {}", hex::encode(&pub_key));

    // create clients
    let jam_client = jam::JamClient::new(&args.jam_rpc)?;
    let cosmos_client = cosmos::CosmosClient::new(&args.cosmos_rpc).await?;

    // create executor
    let mut executor = relay::Executor::new(
        jam_client,
        cosmos_client,
        keypair,
        args.min_bounty,
        args.dry_run,
    );

    // run main loop
    let poll_interval = Duration::from_secs(args.poll_interval);
    executor.run(poll_interval).await
}

fn load_keypair(path: &str) -> anyhow::Result<ed25519_dalek::SigningKey> {
    let bytes = std::fs::read(path)?;
    if bytes.len() != 32 {
        anyhow::bail!("keypair file must be 32 bytes (ed25519 seed)");
    }
    let seed: [u8; 32] = bytes.try_into().unwrap();
    Ok(ed25519_dalek::SigningKey::from_bytes(&seed))
}

fn generate_keypair() -> ed25519_dalek::SigningKey {
    use rand::rngs::OsRng;
    ed25519_dalek::SigningKey::generate(&mut OsRng)
}
