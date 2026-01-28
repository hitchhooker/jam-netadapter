//! cosmos chain client
//!
//! interfaces with tendermint rpc to monitor ibc events and fetch proofs

use tendermint_rpc::{Client, HttpClient};
use tendermint::block::Height as TmHeight;
use tracing::{info, debug, warn};

use crate::types::*;

/// cosmos chain client
pub struct CosmosClient {
    client: HttpClient,
    chain_id: String,
}

impl CosmosClient {
    /// create new cosmos client
    pub async fn new(rpc_url: &str) -> anyhow::Result<Self> {
        let client = HttpClient::new(rpc_url)?;

        // get chain id from status
        let status = client.status().await?;
        let chain_id = status.node_info.network.to_string();

        info!("connected to cosmos chain: {}", chain_id);

        Ok(Self { client, chain_id })
    }

    /// get current block height
    pub async fn get_height(&self) -> anyhow::Result<u64> {
        let status = self.client.status().await?;
        Ok(status.sync_info.latest_block_height.value())
    }

    /// get block at height
    pub async fn get_block(&self, height: u64) -> anyhow::Result<tendermint::Block> {
        let height = TmHeight::try_from(height)?;
        let block = self.client.block(height).await?;
        Ok(block.block)
    }

    /// get block results (for tx events)
    pub async fn get_block_results(&self, height: u64) -> anyhow::Result<tendermint_rpc::endpoint::block_results::Response> {
        let height = TmHeight::try_from(height)?;
        let results = self.client.block_results(height).await?;
        Ok(results)
    }

    /// subscribe to ibc send_packet events
    pub async fn query_send_packets(
        &self,
        start_height: u64,
        end_height: u64,
    ) -> anyhow::Result<Vec<PacketEvent>> {
        let mut packets = Vec::new();

        for height in start_height..=end_height {
            let results = match self.get_block_results(height).await {
                Ok(r) => r,
                Err(e) => {
                    warn!("failed to get block results at {}: {}", height, e);
                    continue;
                }
            };

            // parse tx results for send_packet events
            if let Some(txs) = results.txs_results {
                for (tx_idx, tx_result) in txs.iter().enumerate() {
                    for event in &tx_result.events {
                        if event.kind == "send_packet" {
                            if let Some(packet) = self.parse_packet_event(event, height) {
                                debug!("found send_packet at height {}, tx {}", height, tx_idx);
                                packets.push(packet);
                            }
                        }
                    }
                }
            }
        }

        Ok(packets)
    }

    /// parse packet from event attributes
    fn parse_packet_event(
        &self,
        event: &tendermint::abci::Event,
        height: u64,
    ) -> Option<PacketEvent> {
        let mut packet = Packet {
            sequence: 0,
            source_port: String::new(),
            source_channel: String::new(),
            destination_port: String::new(),
            destination_channel: String::new(),
            data: Vec::new(),
            timeout_height: Height::default(),
            timeout_timestamp: 0,
        };

        for attr in &event.attributes {
            let key = attr.key_str().unwrap_or("");
            let value = attr.value_str().unwrap_or("");

            match key {
                "packet_sequence" => {
                    packet.sequence = value.parse().unwrap_or(0);
                }
                "packet_src_port" => {
                    packet.source_port = value.to_string();
                }
                "packet_src_channel" => {
                    packet.source_channel = value.to_string();
                }
                "packet_dst_port" => {
                    packet.destination_port = value.to_string();
                }
                "packet_dst_channel" => {
                    packet.destination_channel = value.to_string();
                }
                "packet_data" => {
                    // packet data is usually base64 or hex encoded
                    packet.data = value.as_bytes().to_vec();
                }
                "packet_timeout_height" => {
                    // format: "revision-height"
                    if let Some((rev, h)) = value.split_once('-') {
                        packet.timeout_height = Height::new(
                            rev.parse::<u64>().unwrap_or(0),
                            h.parse::<u64>().unwrap_or(0),
                        );
                    }
                }
                "packet_timeout_timestamp" => {
                    packet.timeout_timestamp = value.parse().unwrap_or(0);
                }
                _ => {}
            }
        }

        if packet.sequence == 0 || packet.source_port.is_empty() {
            return None;
        }

        Some(PacketEvent {
            packet,
            proof: Vec::new(), // proof fetched separately
            proof_height: Height::new(0, height),
            tx_hash: [0u8; 32], // TODO: get from tx
        })
    }

    /// fetch merkle proof for packet commitment
    pub async fn get_packet_commitment_proof(
        &self,
        port_id: &str,
        channel_id: &str,
        sequence: u64,
        height: u64,
    ) -> anyhow::Result<(Vec<u8>, Height)> {
        // construct ibc path
        let path = format!(
            "commitments/ports/{}/channels/{}/sequences/{}",
            port_id, channel_id, sequence
        );

        // query with proof
        let query_height = TmHeight::try_from(height)?;
        let response = self.client
            .abci_query(
                Some("store/ibc/key".to_string()),
                path.as_bytes().to_vec(),
                Some(query_height),
                true, // prove
            )
            .await?;

        let proof = response.proof
            .map(|p| {
                // serialize proof ops
                let mut proof_bytes = Vec::new();
                for op in p.ops {
                    proof_bytes.extend_from_slice(&(op.data.len() as u32).to_le_bytes());
                    proof_bytes.extend_from_slice(&op.data);
                }
                proof_bytes
            })
            .unwrap_or_default();

        let proof_height = Height::new(0, response.height.value());

        Ok((proof, proof_height))
    }

    /// fetch inclusion proof for tx
    pub async fn get_tx_inclusion_proof(
        &self,
        tx_hash: &Hash32,
    ) -> anyhow::Result<Vec<u8>> {
        // query tx by hash
        let hash = tendermint::Hash::from_bytes(tendermint::hash::Algorithm::Sha256, tx_hash)?;
        let response = self.client.tx(hash, false).await?;

        // the proof would come from the block's tx merkle tree
        // for now, return the tx result as proof (simplified)
        let proof = response.tx_result.data.to_vec();

        Ok(proof)
    }

    /// broadcast transaction to cosmos
    pub async fn broadcast_tx(&self, tx_bytes: &[u8]) -> anyhow::Result<Hash32> {
        let response = self.client
            .broadcast_tx_sync(tx_bytes.to_vec())
            .await?;

        if response.code.is_err() {
            anyhow::bail!("tx failed: {:?}", response.log);
        }

        let mut hash = [0u8; 32];
        hash.copy_from_slice(response.hash.as_bytes());
        Ok(hash)
    }

    /// wait for tx inclusion
    pub async fn wait_for_tx(&self, tx_hash: &Hash32, timeout_secs: u64) -> anyhow::Result<u64> {
        use std::time::{Duration, Instant};

        let start = Instant::now();
        let timeout = Duration::from_secs(timeout_secs);
        let hash = tendermint::Hash::from_bytes(tendermint::hash::Algorithm::Sha256, tx_hash)?;

        loop {
            if start.elapsed() > timeout {
                anyhow::bail!("timeout waiting for tx inclusion");
            }

            match self.client.tx(hash, false).await {
                Ok(response) => {
                    return Ok(response.height.value());
                }
                Err(_) => {
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            }
        }
    }

    /// get chain id
    pub fn chain_id(&self) -> &str {
        &self.chain_id
    }
}
