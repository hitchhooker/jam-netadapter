//! jam chain client (romio compatible)
//!
//! interfaces with romio rpc (jip-2) to query state and submit work items

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use blake2::{Blake2b, Digest};
use blake2::digest::consts::U32;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use tracing::{info, debug};

use crate::types::*;

/// jam rpc client for romio
pub struct JamClient {
    client: Client,
    rpc_url: String,
    service_id: u32,
    /// cached service code hash
    service_code_hash: Option<Hash32>,
}

impl JamClient {
    /// create new jam client
    pub fn new(rpc_url: &str) -> anyhow::Result<Self> {
        Self::with_service_id(rpc_url, 0)
    }

    /// create jam client for specific service
    pub fn with_service_id(rpc_url: &str, service_id: u32) -> anyhow::Result<Self> {
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()?;

        info!("jam client configured for {} (service {})", rpc_url, service_id);

        Ok(Self {
            client,
            rpc_url: rpc_url.to_string(),
            service_id,
            service_code_hash: None,
        })
    }

    /// get current timeslot via jam_getInfo
    pub async fn get_timeslot(&self) -> anyhow::Result<u32> {
        let response: RpcResponse<JamInfo> = self.rpc_call("jam_getInfo", serde_json::Value::Null).await?;
        Ok(response.result.slot)
    }

    /// get finalized block
    pub async fn get_finalized_block(&self) -> anyhow::Result<BlockDescriptor> {
        let response: RpcResponse<BlockDescriptor> = self.rpc_call("finalizedBlock", serde_json::Value::Null).await?;
        Ok(response.result)
    }

    /// get best block
    pub async fn get_best_block(&self) -> anyhow::Result<BlockDescriptor> {
        let response: RpcResponse<BlockDescriptor> = self.rpc_call("bestBlock", serde_json::Value::Null).await?;
        Ok(response.result)
    }

    /// get block header by hash
    pub async fn get_header(&self, hash: &str) -> anyhow::Result<JamHeader> {
        let params = serde_json::json!([hash]);
        let response: RpcResponse<JamHeader> = self.rpc_call("jam_getHeader", params).await?;
        Ok(response.result)
    }

    /// get service account info (includes code hash)
    pub async fn get_service_account(&self, service_id: u32) -> anyhow::Result<Option<ServiceAccount>> {
        let best = self.get_best_block().await?;
        let params = serde_json::json!([best.header_hash, service_id]);
        let response: RpcResponse<Option<ServiceAccount>> = self.rpc_call("serviceAccount", params).await?;
        Ok(response.result)
    }

    /// get service code hash, caching the result
    pub async fn get_service_code_hash(&mut self) -> anyhow::Result<Hash32> {
        if let Some(hash) = self.service_code_hash {
            return Ok(hash);
        }

        let account = self.get_service_account(self.service_id).await?
            .ok_or_else(|| anyhow::anyhow!("service {} not found", self.service_id))?;

        let hash = account.code_hash;
        self.service_code_hash = Some(hash);
        Ok(hash)
    }

    /// query service storage value
    pub async fn get_storage(&self, key: &[u8]) -> anyhow::Result<Option<Vec<u8>>> {
        let best = self.get_best_block().await?;

        let params = serde_json::json!([
            best.header_hash,
            self.service_id,
            BASE64.encode(key)
        ]);

        let response: RpcResponse<Option<String>> = self.rpc_call("serviceValue", params).await?;

        match response.result {
            Some(b64) => {
                let bytes = BASE64.decode(&b64)?;
                Ok(Some(bytes))
            }
            None => Ok(None),
        }
    }

    /// query pending relay tasks from ibc service storage
    pub async fn get_pending_tasks(&self) -> anyhow::Result<Vec<RelayTask>> {
        // storage key for pending task index: prefix 0x3F
        let key = vec![0x3F];

        match self.get_storage(&key).await? {
            Some(data) => {
                let task_ids = decode_task_ids(&data)?;
                let mut tasks = Vec::new();

                for task_id in task_ids {
                    if let Some(task) = self.get_task(&task_id).await? {
                        if task.status == TaskStatus::Pending {
                            tasks.push(task);
                        }
                    }
                }

                debug!("found {} pending tasks", tasks.len());
                Ok(tasks)
            }
            None => {
                debug!("no pending tasks found");
                Ok(Vec::new())
            }
        }
    }

    /// get relay task by id
    pub async fn get_task(&self, task_id: &Hash32) -> anyhow::Result<Option<RelayTask>> {
        // storage key: prefix 0x3A + task_id
        let mut key = vec![0x3A];
        key.extend_from_slice(task_id);

        match self.get_storage(&key).await? {
            Some(data) => {
                let task = decode_relay_task(&data)?;
                Ok(Some(task))
            }
            None => Ok(None),
        }
    }

    /// get client state
    pub async fn get_client_state(&self, client_id: &str) -> anyhow::Result<Option<IbcClientState>> {
        // storage key: prefix 0x30 + client_id bytes
        let mut key = vec![0x30];
        key.extend_from_slice(client_id.as_bytes());

        match self.get_storage(&key).await? {
            Some(data) => {
                let state = decode_client_state(&data)?;
                Ok(Some(state))
            }
            None => Ok(None),
        }
    }

    /// get consensus state
    pub async fn get_consensus_state(
        &self,
        client_id: &str,
        height: &Height,
    ) -> anyhow::Result<Option<IbcConsensusState>> {
        // storage key: prefix 0x31 + client_id + "/" + height
        let mut key = vec![0x31];
        key.extend_from_slice(client_id.as_bytes());
        key.push(b'/');
        key.extend_from_slice(&height.revision_number.to_be_bytes());
        key.push(b'-');
        key.extend_from_slice(&height.revision_height.to_be_bytes());

        match self.get_storage(&key).await? {
            Some(data) => {
                let state = decode_consensus_state(&data)?;
                Ok(Some(state))
            }
            None => Ok(None),
        }
    }

    /// submit ibc work item as work package
    pub async fn submit_work_item(&mut self, work_item: &IbcWorkItem) -> anyhow::Result<Hash32> {
        let payload = encode_ibc_work_item(work_item);
        let code_hash = self.get_service_code_hash().await?;
        let best = self.get_best_block().await?;
        let header = self.get_header(&best.header_hash).await?;

        let wp = WorkPackage {
            authorization: Authorization {
                service_id: self.service_id,
                code_hash,
            },
            context: WorkContext {
                anchor: decode_hex_hash(&best.header_hash)?,
                state_root: header.state_root,
            },
            items: vec![WorkItem {
                service_id: self.service_id,
                code_hash,
                gas: 1_000_000_000,
                payload,
            }],
        };

        let wp_encoded = encode_work_package(&wp);
        let wp_hash = blake2b_256(&wp_encoded);

        let params = serde_json::json!([
            0u8,
            BASE64.encode(&wp_encoded),
            []
        ]);

        let response: RpcResponse<WorkPackageResult> = self.rpc_call("submitWorkPackage", params).await?;

        if response.result.success {
            info!("submitted work package: {}", hex::encode(&wp_hash[..8]));
            Ok(wp_hash)
        } else {
            anyhow::bail!("work package submission failed: {:?}", response.result.error);
        }
    }

    /// generic rpc call
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

        let response = self
            .client
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
    id: u64,
    method: &'a str,
    params: P,
}

#[derive(Deserialize)]
pub struct RpcResponse<R> {
    pub result: R,
}

#[derive(Deserialize)]
pub struct JamInfo {
    pub slot: u32,
    pub epoch: u32,
    pub cores: u32,
}

#[derive(Deserialize)]
pub struct BlockDescriptor {
    pub header_hash: String,
    pub slot: u32,
}

#[derive(Deserialize)]
pub struct JamHeader {
    pub parent: String,
    pub parent_state_root: Hash32,
    pub state_root: Hash32,
    pub extrinsic_hash: Hash32,
    pub timeslot: u32,
    pub epoch_marker: Option<EpochMarker>,
}

#[derive(Deserialize)]
pub struct EpochMarker {
    pub entropy: Hash32,
    pub validators: Vec<ValidatorKey>,
}

#[derive(Deserialize)]
pub struct ValidatorKey {
    pub bandersnatch: [u8; 32],
    pub ed25519: [u8; 32],
    #[serde(with = "base64_bytes")]
    pub bls: Vec<u8>,
    #[serde(with = "base64_bytes")]
    pub metadata: Vec<u8>,
}

mod base64_bytes {
    use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
    use serde::{Deserialize, Deserializer};

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        BASE64.decode(&s).map_err(serde::de::Error::custom)
    }
}

#[derive(Deserialize)]
pub struct ServiceAccount {
    pub storage_root: Hash32,
    pub code_hash: Hash32,
    pub balance: u64,
    pub min_accum_gas: u64,
    pub min_on_transfer_gas: u64,
    pub items: u32,
    pub item_total_bytes: u32,
}

#[derive(Deserialize)]
pub struct WorkPackageResult {
    pub success: bool,
    pub error: Option<String>,
}

/// ibc client state stored in jam service
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IbcClientState {
    pub chain_id: Vec<u8>,
    pub trust_level_numerator: u64,
    pub trust_level_denominator: u64,
    pub trusting_period_ns: u64,
    pub unbonding_period_ns: u64,
    pub max_clock_drift_ns: u64,
    pub latest_height: Height,
    pub frozen_height: Option<Height>,
}

/// ibc consensus state stored in jam service
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IbcConsensusState {
    pub timestamp_ns: u64,
    pub root: Hash32,
    pub next_validators_hash: Hash32,
}

// ============================================================================
// encoding helpers
// ============================================================================

/// encode ibc work item for jam service payload
fn encode_ibc_work_item(item: &IbcWorkItem) -> Vec<u8> {
    let mut buf = Vec::new();

    match item {
        IbcWorkItem::RecvPacket { packet, proof_commitment, proof_height } => {
            buf.push(0x03);
            buf.extend_from_slice(&encode_packet(packet));
            buf.extend_from_slice(&encode_length_prefixed(proof_commitment));
            buf.extend_from_slice(&encode_height(proof_height));
        }
        IbcWorkItem::AcknowledgePacket { packet, acknowledgement, proof_acked, proof_height } => {
            buf.push(0x04);
            buf.extend_from_slice(&encode_packet(packet));
            buf.extend_from_slice(&encode_length_prefixed(acknowledgement));
            buf.extend_from_slice(&encode_length_prefixed(proof_acked));
            buf.extend_from_slice(&encode_height(proof_height));
        }
        IbcWorkItem::ClaimRelayTask { task_id, executor, signature } => {
            buf.push(0x06);
            buf.extend_from_slice(task_id);
            buf.extend_from_slice(executor);
            buf.extend_from_slice(&encode_length_prefixed(signature));
        }
        IbcWorkItem::ConfirmExecution { task_id, dest_tx_hash, inclusion_proof } => {
            buf.push(0x07);
            buf.extend_from_slice(task_id);
            buf.extend_from_slice(dest_tx_hash);
            buf.extend_from_slice(&encode_length_prefixed(inclusion_proof));
        }
    }

    buf
}

fn encode_packet(packet: &Packet) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&packet.sequence.to_le_bytes());
    buf.extend_from_slice(&encode_length_prefixed(packet.source_port.as_bytes()));
    buf.extend_from_slice(&encode_length_prefixed(packet.source_channel.as_bytes()));
    buf.extend_from_slice(&encode_length_prefixed(packet.destination_port.as_bytes()));
    buf.extend_from_slice(&encode_length_prefixed(packet.destination_channel.as_bytes()));
    buf.extend_from_slice(&encode_length_prefixed(&packet.data));
    buf.extend_from_slice(&encode_height(&packet.timeout_height));
    buf.extend_from_slice(&packet.timeout_timestamp.to_le_bytes());
    buf
}

fn encode_height(height: &Height) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&height.revision_number.to_le_bytes());
    buf.extend_from_slice(&height.revision_height.to_le_bytes());
    buf
}

fn encode_length_prefixed(data: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(4 + data.len());
    buf.extend_from_slice(&(data.len() as u32).to_le_bytes());
    buf.extend_from_slice(data);
    buf
}

// ============================================================================
// work package building
// ============================================================================

struct WorkPackage {
    authorization: Authorization,
    context: WorkContext,
    items: Vec<WorkItem>,
}

struct Authorization {
    service_id: u32,
    code_hash: Hash32,
}

struct WorkContext {
    anchor: Hash32,
    state_root: Hash32,
}

struct WorkItem {
    service_id: u32,
    code_hash: Hash32,
    gas: u64,
    payload: Vec<u8>,
}

fn encode_work_package(wp: &WorkPackage) -> Vec<u8> {
    let mut buf = Vec::new();

    buf.extend_from_slice(&wp.authorization.service_id.to_le_bytes());
    buf.extend_from_slice(&wp.authorization.code_hash);

    buf.extend_from_slice(&wp.context.anchor);
    buf.extend_from_slice(&wp.context.state_root);

    buf.extend_from_slice(&(wp.items.len() as u32).to_le_bytes());

    for item in &wp.items {
        buf.extend_from_slice(&item.service_id.to_le_bytes());
        buf.extend_from_slice(&item.code_hash);
        buf.extend_from_slice(&item.gas.to_le_bytes());
        buf.extend_from_slice(&encode_length_prefixed(&item.payload));
    }

    buf
}

// ============================================================================
// decoding helpers
// ============================================================================

fn decode_hex_hash(hex_str: &str) -> anyhow::Result<Hash32> {
    let stripped = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    let bytes = hex::decode(stripped)?;
    if bytes.len() != 32 {
        anyhow::bail!("invalid hash length: expected 32, got {}", bytes.len());
    }
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&bytes);
    Ok(hash)
}

fn decode_task_ids(data: &[u8]) -> anyhow::Result<Vec<Hash32>> {
    let mut ids = Vec::new();
    let mut offset = 0;

    if data.len() < 4 {
        return Ok(ids);
    }

    let count = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;
    offset += 4;

    for _ in 0..count {
        if offset + 32 > data.len() {
            break;
        }
        let mut id = [0u8; 32];
        id.copy_from_slice(&data[offset..offset + 32]);
        ids.push(id);
        offset += 32;
    }

    Ok(ids)
}

/// decode relay task from storage format
/// format: id (32) | task_type (1) | status (1) | bounty (8) | deadline (4) |
///         created_at (4) | claimed_at (4, optional) | claimed_by (32, optional) |
///         source_chain_len (4) | source_chain | dest_chain_len (4) | dest_chain |
///         proof_height (16) | proof_len (4) | proof | packet
fn decode_relay_task(data: &[u8]) -> anyhow::Result<RelayTask> {
    if data.len() < 54 {
        anyhow::bail!("relay task data too short: {} bytes", data.len());
    }

    let mut offset = 0;

    let mut id = [0u8; 32];
    id.copy_from_slice(&data[offset..offset + 32]);
    offset += 32;

    let task_type = match data[offset] {
        0 => RelayTaskType::RecvPacket,
        1 => RelayTaskType::AckPacket,
        2 => RelayTaskType::TimeoutPacket,
        t => anyhow::bail!("unknown task type: {}", t),
    };
    offset += 1;

    let status = match data[offset] {
        0 => TaskStatus::Pending,
        1 => TaskStatus::Claimed,
        2 => TaskStatus::Executed,
        3 => TaskStatus::Failed,
        4 => TaskStatus::Expired,
        s => anyhow::bail!("unknown task status: {}", s),
    };
    offset += 1;

    let bounty = u64::from_le_bytes([
        data[offset], data[offset + 1], data[offset + 2], data[offset + 3],
        data[offset + 4], data[offset + 5], data[offset + 6], data[offset + 7],
    ]);
    offset += 8;

    let deadline = u32::from_le_bytes([
        data[offset], data[offset + 1], data[offset + 2], data[offset + 3],
    ]);
    offset += 4;

    let created_at = u32::from_le_bytes([
        data[offset], data[offset + 1], data[offset + 2], data[offset + 3],
    ]);
    offset += 4;

    let (claimed_at, claimed_by) = if status == TaskStatus::Claimed {
        let claimed_at = u32::from_le_bytes([
            data[offset], data[offset + 1], data[offset + 2], data[offset + 3],
        ]);
        offset += 4;
        let mut claimed_by = [0u8; 32];
        claimed_by.copy_from_slice(&data[offset..offset + 32]);
        offset += 32;
        (Some(claimed_at), Some(claimed_by))
    } else {
        (None, None)
    };

    let source_chain_len = u32::from_le_bytes([
        data[offset], data[offset + 1], data[offset + 2], data[offset + 3],
    ]) as usize;
    offset += 4;
    let source_chain = String::from_utf8(data[offset..offset + source_chain_len].to_vec())?;
    offset += source_chain_len;

    let dest_chain_len = u32::from_le_bytes([
        data[offset], data[offset + 1], data[offset + 2], data[offset + 3],
    ]) as usize;
    offset += 4;
    let dest_chain = String::from_utf8(data[offset..offset + dest_chain_len].to_vec())?;
    offset += dest_chain_len;

    let proof_height = Height {
        revision_number: u64::from_le_bytes([
            data[offset], data[offset + 1], data[offset + 2], data[offset + 3],
            data[offset + 4], data[offset + 5], data[offset + 6], data[offset + 7],
        ]),
        revision_height: u64::from_le_bytes([
            data[offset + 8], data[offset + 9], data[offset + 10], data[offset + 11],
            data[offset + 12], data[offset + 13], data[offset + 14], data[offset + 15],
        ]),
    };
    offset += 16;

    let proof_len = u32::from_le_bytes([
        data[offset], data[offset + 1], data[offset + 2], data[offset + 3],
    ]) as usize;
    offset += 4;
    let proof = data[offset..offset + proof_len].to_vec();
    offset += proof_len;

    let packet = decode_packet(&data[offset..])?;

    Ok(RelayTask {
        id,
        task_type,
        source_chain,
        dest_chain,
        packet,
        proof,
        proof_height,
        deadline,
        bounty,
        claimed_by,
        claimed_at,
        status,
        created_at,
    })
}

/// decode ibc packet from binary format
fn decode_packet(data: &[u8]) -> anyhow::Result<Packet> {
    let mut offset = 0;

    let sequence = u64::from_le_bytes([
        data[offset], data[offset + 1], data[offset + 2], data[offset + 3],
        data[offset + 4], data[offset + 5], data[offset + 6], data[offset + 7],
    ]);
    offset += 8;

    let source_port_len = u32::from_le_bytes([
        data[offset], data[offset + 1], data[offset + 2], data[offset + 3],
    ]) as usize;
    offset += 4;
    let source_port = String::from_utf8(data[offset..offset + source_port_len].to_vec())?;
    offset += source_port_len;

    let source_channel_len = u32::from_le_bytes([
        data[offset], data[offset + 1], data[offset + 2], data[offset + 3],
    ]) as usize;
    offset += 4;
    let source_channel = String::from_utf8(data[offset..offset + source_channel_len].to_vec())?;
    offset += source_channel_len;

    let dest_port_len = u32::from_le_bytes([
        data[offset], data[offset + 1], data[offset + 2], data[offset + 3],
    ]) as usize;
    offset += 4;
    let destination_port = String::from_utf8(data[offset..offset + dest_port_len].to_vec())?;
    offset += dest_port_len;

    let dest_channel_len = u32::from_le_bytes([
        data[offset], data[offset + 1], data[offset + 2], data[offset + 3],
    ]) as usize;
    offset += 4;
    let destination_channel = String::from_utf8(data[offset..offset + dest_channel_len].to_vec())?;
    offset += dest_channel_len;

    let data_len = u32::from_le_bytes([
        data[offset], data[offset + 1], data[offset + 2], data[offset + 3],
    ]) as usize;
    offset += 4;
    let packet_data = data[offset..offset + data_len].to_vec();
    offset += data_len;

    let timeout_height = Height {
        revision_number: u64::from_le_bytes([
            data[offset], data[offset + 1], data[offset + 2], data[offset + 3],
            data[offset + 4], data[offset + 5], data[offset + 6], data[offset + 7],
        ]),
        revision_height: u64::from_le_bytes([
            data[offset + 8], data[offset + 9], data[offset + 10], data[offset + 11],
            data[offset + 12], data[offset + 13], data[offset + 14], data[offset + 15],
        ]),
    };
    offset += 16;

    let timeout_timestamp = u64::from_le_bytes([
        data[offset], data[offset + 1], data[offset + 2], data[offset + 3],
        data[offset + 4], data[offset + 5], data[offset + 6], data[offset + 7],
    ]);

    Ok(Packet {
        sequence,
        source_port,
        source_channel,
        destination_port,
        destination_channel,
        data: packet_data,
        timeout_height,
        timeout_timestamp,
    })
}

/// decode ibc client state from storage
fn decode_client_state(data: &[u8]) -> anyhow::Result<IbcClientState> {
    let mut offset = 0;

    let chain_id_len = u32::from_le_bytes([
        data[offset], data[offset + 1], data[offset + 2], data[offset + 3],
    ]) as usize;
    offset += 4;
    let chain_id = data[offset..offset + chain_id_len].to_vec();
    offset += chain_id_len;

    let trust_level_numerator = u64::from_le_bytes([
        data[offset], data[offset + 1], data[offset + 2], data[offset + 3],
        data[offset + 4], data[offset + 5], data[offset + 6], data[offset + 7],
    ]);
    offset += 8;

    let trust_level_denominator = u64::from_le_bytes([
        data[offset], data[offset + 1], data[offset + 2], data[offset + 3],
        data[offset + 4], data[offset + 5], data[offset + 6], data[offset + 7],
    ]);
    offset += 8;

    let trusting_period_ns = u64::from_le_bytes([
        data[offset], data[offset + 1], data[offset + 2], data[offset + 3],
        data[offset + 4], data[offset + 5], data[offset + 6], data[offset + 7],
    ]);
    offset += 8;

    let unbonding_period_ns = u64::from_le_bytes([
        data[offset], data[offset + 1], data[offset + 2], data[offset + 3],
        data[offset + 4], data[offset + 5], data[offset + 6], data[offset + 7],
    ]);
    offset += 8;

    let max_clock_drift_ns = u64::from_le_bytes([
        data[offset], data[offset + 1], data[offset + 2], data[offset + 3],
        data[offset + 4], data[offset + 5], data[offset + 6], data[offset + 7],
    ]);
    offset += 8;

    let latest_height = Height {
        revision_number: u64::from_le_bytes([
            data[offset], data[offset + 1], data[offset + 2], data[offset + 3],
            data[offset + 4], data[offset + 5], data[offset + 6], data[offset + 7],
        ]),
        revision_height: u64::from_le_bytes([
            data[offset + 8], data[offset + 9], data[offset + 10], data[offset + 11],
            data[offset + 12], data[offset + 13], data[offset + 14], data[offset + 15],
        ]),
    };
    offset += 16;

    let has_frozen = data[offset] != 0;
    offset += 1;

    let frozen_height = if has_frozen {
        Some(Height {
            revision_number: u64::from_le_bytes([
                data[offset], data[offset + 1], data[offset + 2], data[offset + 3],
                data[offset + 4], data[offset + 5], data[offset + 6], data[offset + 7],
            ]),
            revision_height: u64::from_le_bytes([
                data[offset + 8], data[offset + 9], data[offset + 10], data[offset + 11],
                data[offset + 12], data[offset + 13], data[offset + 14], data[offset + 15],
            ]),
        })
    } else {
        None
    };

    Ok(IbcClientState {
        chain_id,
        trust_level_numerator,
        trust_level_denominator,
        trusting_period_ns,
        unbonding_period_ns,
        max_clock_drift_ns,
        latest_height,
        frozen_height,
    })
}

/// decode ibc consensus state from storage
fn decode_consensus_state(data: &[u8]) -> anyhow::Result<IbcConsensusState> {
    if data.len() < 72 {
        anyhow::bail!("consensus state data too short: {} bytes", data.len());
    }

    let timestamp_ns = u64::from_le_bytes([
        data[0], data[1], data[2], data[3],
        data[4], data[5], data[6], data[7],
    ]);

    let mut root = [0u8; 32];
    root.copy_from_slice(&data[8..40]);

    let mut next_validators_hash = [0u8; 32];
    next_validators_hash.copy_from_slice(&data[40..72]);

    Ok(IbcConsensusState {
        timestamp_ns,
        root,
        next_validators_hash,
    })
}

/// blake2b-256 hash
fn blake2b_256(data: &[u8]) -> Hash32 {
    let mut hasher = Blake2b::<U32>::new();
    hasher.update(data);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_height() {
        let height = Height::new(1, 1000);
        let encoded = encode_height(&height);
        assert_eq!(encoded.len(), 16);
        assert_eq!(u64::from_le_bytes(encoded[0..8].try_into().unwrap()), 1);
        assert_eq!(u64::from_le_bytes(encoded[8..16].try_into().unwrap()), 1000);
    }

    #[test]
    fn test_encode_length_prefixed() {
        let data = b"hello";
        let encoded = encode_length_prefixed(data);
        assert_eq!(encoded.len(), 9);
        assert_eq!(u32::from_le_bytes(encoded[0..4].try_into().unwrap()), 5);
        assert_eq!(&encoded[4..], b"hello");
    }

    #[test]
    fn test_blake2b_256() {
        let hash = blake2b_256(b"test");
        assert_eq!(hash.len(), 32);
        assert_eq!(
            hex::encode(&hash),
            "928b20366943e2afd11ebc0eae2e53a93bf177a4fcf35bcc64d503704e65e202"
        );
    }

    #[test]
    fn test_decode_task_ids() {
        let mut data = vec![0u8; 68];
        data[0..4].copy_from_slice(&2u32.to_le_bytes());
        data[4..36].copy_from_slice(&[1u8; 32]);
        data[36..68].copy_from_slice(&[2u8; 32]);

        let ids = decode_task_ids(&data).unwrap();
        assert_eq!(ids.len(), 2);
        assert_eq!(ids[0], [1u8; 32]);
        assert_eq!(ids[1], [2u8; 32]);
    }

    #[test]
    fn test_decode_hex_hash() {
        let hash = decode_hex_hash("0x0000000000000000000000000000000000000000000000000000000000000001").unwrap();
        assert_eq!(hash[31], 1);
        assert_eq!(hash[0], 0);

        let hash2 = decode_hex_hash("0000000000000000000000000000000000000000000000000000000000000002").unwrap();
        assert_eq!(hash2[31], 2);
    }

    #[test]
    fn test_decode_consensus_state() {
        let mut data = vec![0u8; 72];
        data[0..8].copy_from_slice(&1234567890u64.to_le_bytes());
        data[8..40].copy_from_slice(&[0xAA; 32]);
        data[40..72].copy_from_slice(&[0xBB; 32]);

        let cs = decode_consensus_state(&data).unwrap();
        assert_eq!(cs.timestamp_ns, 1234567890);
        assert_eq!(cs.root, [0xAA; 32]);
        assert_eq!(cs.next_validators_hash, [0xBB; 32]);
    }
}
