//! jam chain client
//!
//! interfaces with jam rpc to query state and submit work items

use reqwest::Client;
use serde::{Deserialize, Serialize};
use tracing::{info, debug};

use crate::types::*;

/// jam rpc client
pub struct JamClient {
    client: Client,
    rpc_url: String,
}

impl JamClient {
    /// create new jam client
    pub fn new(rpc_url: &str) -> anyhow::Result<Self> {
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()?;

        info!("jam client configured for {}", rpc_url);

        Ok(Self {
            client,
            rpc_url: rpc_url.to_string(),
        })
    }

    /// get current timeslot
    pub async fn get_timeslot(&self) -> anyhow::Result<u32> {
        let response: RpcResponse<u32> = self.rpc_call("jam_getTimeslot", ()).await?;
        Ok(response.result)
    }

    /// query pending relay tasks
    pub async fn get_pending_tasks(&self) -> anyhow::Result<Vec<RelayTask>> {
        // query storage for pending task index
        let response: RpcResponse<Vec<RelayTask>> = self
            .rpc_call("jam_queryIbcPendingTasks", ())
            .await
            .unwrap_or_else(|_| RpcResponse { result: Vec::new() });

        debug!("found {} pending tasks", response.result.len());
        Ok(response.result)
    }

    /// get relay task by id
    pub async fn get_task(&self, task_id: &Hash32) -> anyhow::Result<Option<RelayTask>> {
        let params = GetTaskParams {
            task_id: hex::encode(task_id),
        };
        let response: RpcResponse<Option<RelayTask>> = self
            .rpc_call("jam_queryIbcTask", params)
            .await?;
        Ok(response.result)
    }

    /// submit work item
    pub async fn submit_work_item(&self, work_item: &IbcWorkItem) -> anyhow::Result<Hash32> {
        let encoded = encode_work_item(work_item);
        let params = SubmitWorkItemParams {
            payload: hex::encode(&encoded),
        };

        let response: RpcResponse<String> = self.rpc_call("jam_submitWorkItem", params).await?;

        let hash_bytes = hex::decode(&response.result)?;
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&hash_bytes);
        Ok(hash)
    }

    /// query ibc client state
    pub async fn get_client_state(&self, client_id: &str) -> anyhow::Result<Option<ClientState>> {
        let params = GetClientParams {
            client_id: client_id.to_string(),
        };
        let response: RpcResponse<Option<ClientState>> = self
            .rpc_call("jam_queryIbcClientState", params)
            .await?;
        Ok(response.result)
    }

    /// query consensus state at height
    pub async fn get_consensus_state(
        &self,
        client_id: &str,
        height: Height,
    ) -> anyhow::Result<Option<ConsensusState>> {
        let params = GetConsensusParams {
            client_id: client_id.to_string(),
            height,
        };
        let response: RpcResponse<Option<ConsensusState>> = self
            .rpc_call("jam_queryIbcConsensusState", params)
            .await?;
        Ok(response.result)
    }

    /// make rpc call
    async fn rpc_call<P: Serialize, R: for<'de> Deserialize<'de>>(
        &self,
        method: &str,
        params: P,
    ) -> anyhow::Result<RpcResponse<R>> {
        let request = RpcRequest {
            jsonrpc: "2.0",
            id: 1,
            method,
            params,
        };

        let response = self.client
            .post(&self.rpc_url)
            .json(&request)
            .send()
            .await?
            .json::<RpcResponse<R>>()
            .await?;

        Ok(response)
    }
}

// ============================================================================
// rpc types
// ============================================================================

#[derive(Serialize)]
struct RpcRequest<'a, P> {
    jsonrpc: &'a str,
    id: u32,
    method: &'a str,
    params: P,
}

#[derive(Deserialize)]
struct RpcResponse<R> {
    result: R,
}

#[derive(Serialize)]
struct GetTaskParams {
    task_id: String,
}

#[derive(Serialize)]
struct SubmitWorkItemParams {
    payload: String,
}

#[derive(Serialize)]
struct GetClientParams {
    client_id: String,
}

#[derive(Serialize)]
struct GetConsensusParams {
    client_id: String,
    height: Height,
}

/// client state info
#[derive(Clone, Debug, Deserialize)]
pub struct ClientState {
    pub chain_id: String,
    pub latest_height: Height,
    pub frozen_height: Option<Height>,
    pub status: String,
}

/// consensus state info
#[derive(Clone, Debug, Deserialize)]
pub struct ConsensusState {
    pub timestamp: u64,
    pub root: String, // hex encoded
}

// ============================================================================
// encoding
// ============================================================================

/// encode work item for submission
fn encode_work_item(item: &IbcWorkItem) -> Vec<u8> {
    let mut buf = Vec::new();

    // work item type prefix (IbcOp = 5)
    buf.push(5);

    match item {
        IbcWorkItem::RecvPacket { packet, proof_commitment, proof_height } => {
            buf.push(30); // RecvPacket discriminator
            encode_packet(&mut buf, packet);
            encode_bytes(&mut buf, proof_commitment);
            encode_height(&mut buf, proof_height);
        }

        IbcWorkItem::AcknowledgePacket { packet, acknowledgement, proof_acked, proof_height } => {
            buf.push(31); // AcknowledgePacket discriminator
            encode_packet(&mut buf, packet);
            encode_bytes(&mut buf, acknowledgement);
            encode_bytes(&mut buf, proof_acked);
            encode_height(&mut buf, proof_height);
        }

        IbcWorkItem::ClaimRelayTask { task_id, executor, signature } => {
            buf.push(40); // ClaimRelayTask discriminator
            buf.extend_from_slice(task_id);
            buf.extend_from_slice(executor);
            buf.extend_from_slice(signature);
        }

        IbcWorkItem::ConfirmExecution { task_id, dest_tx_hash, inclusion_proof } => {
            buf.push(41); // ConfirmExecution discriminator
            buf.extend_from_slice(task_id);
            buf.extend_from_slice(dest_tx_hash);
            encode_bytes(&mut buf, inclusion_proof);
        }
    }

    buf
}

fn encode_packet(buf: &mut Vec<u8>, packet: &Packet) {
    buf.extend_from_slice(&packet.sequence.to_le_bytes());
    encode_string(buf, &packet.source_port);
    encode_string(buf, &packet.source_channel);
    encode_string(buf, &packet.destination_port);
    encode_string(buf, &packet.destination_channel);
    encode_bytes(buf, &packet.data);
    encode_height(buf, &packet.timeout_height);
    buf.extend_from_slice(&packet.timeout_timestamp.to_le_bytes());
}

fn encode_string(buf: &mut Vec<u8>, s: &str) {
    buf.extend_from_slice(&(s.len() as u32).to_le_bytes());
    buf.extend_from_slice(s.as_bytes());
}

fn encode_bytes(buf: &mut Vec<u8>, data: &[u8]) {
    buf.extend_from_slice(&(data.len() as u32).to_le_bytes());
    buf.extend_from_slice(data);
}

fn encode_height(buf: &mut Vec<u8>, height: &Height) {
    buf.extend_from_slice(&height.revision_number.to_le_bytes());
    buf.extend_from_slice(&height.revision_height.to_le_bytes());
}
