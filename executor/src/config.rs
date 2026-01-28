//! executor configuration

use serde::{Deserialize, Serialize};

/// executor configuration
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    /// jam chain configuration
    pub jam: JamConfig,

    /// cosmos chains to relay
    pub cosmos_chains: Vec<CosmosChainConfig>,

    /// executor settings
    pub executor: ExecutorConfig,
}

/// jam chain config
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JamConfig {
    /// rpc endpoint
    pub rpc_url: String,

    /// service id of ibc module
    pub service_id: u32,
}

/// cosmos chain config
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CosmosChainConfig {
    /// chain id (e.g., "osmosis-1")
    pub chain_id: String,

    /// tendermint rpc endpoint
    pub rpc_url: String,

    /// grpc endpoint (for proofs)
    pub grpc_url: Option<String>,

    /// ibc client id on jam
    pub client_id: String,

    /// ports to monitor
    pub ports: Vec<String>,

    /// channels to monitor
    pub channels: Vec<String>,
}

/// executor settings
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExecutorConfig {
    /// minimum bounty to claim (filter low-value tasks)
    pub min_bounty: u64,

    /// maximum gas to spend per tx
    pub max_gas: u64,

    /// poll interval in seconds
    pub poll_interval_secs: u64,

    /// number of retries on failure
    pub max_retries: u32,

    /// timeout for rpc calls in seconds
    pub rpc_timeout_secs: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            jam: JamConfig {
                rpc_url: "http://localhost:9933".into(),
                service_id: 0,
            },
            cosmos_chains: vec![
                CosmosChainConfig {
                    chain_id: "osmosis-1".into(),
                    rpc_url: "https://rpc.osmosis.zone".into(),
                    grpc_url: Some("https://grpc.osmosis.zone".into()),
                    client_id: "07-tendermint-0".into(),
                    ports: vec!["transfer".into()],
                    channels: vec!["channel-0".into()],
                }
            ],
            executor: ExecutorConfig {
                min_bounty: 500,
                max_gas: 1000000,
                poll_interval_secs: 6,
                max_retries: 3,
                rpc_timeout_secs: 30,
            },
        }
    }
}

impl Config {
    /// load config from toml file
    pub fn load(path: &str) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let config: Config = toml::from_str(&content)?;
        Ok(config)
    }

    /// save config to toml file
    pub fn save(&self, path: &str) -> anyhow::Result<()> {
        let content = toml::to_string_pretty(self)?;
        std::fs::write(path, content)?;
        Ok(())
    }
}
