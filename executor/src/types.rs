//! shared types for executor

use serde::{Deserialize, Serialize};

/// 32-byte hash
pub type Hash32 = [u8; 32];

/// ibc height
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize)]
pub struct Height {
    pub revision_number: u64,
    pub revision_height: u64,
}

impl Height {
    pub fn new(revision_number: u64, revision_height: u64) -> Self {
        Self { revision_number, revision_height }
    }
}

/// relay task from jam service
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RelayTask {
    pub id: Hash32,
    pub task_type: RelayTaskType,
    pub source_chain: String,
    pub dest_chain: String,
    pub packet: Packet,
    pub proof: Vec<u8>,
    pub proof_height: Height,
    pub deadline: u32,
    pub bounty: u64,
    pub claimed_by: Option<Hash32>,
    pub claimed_at: Option<u32>,
    pub status: TaskStatus,
    pub created_at: u32,
}

/// relay task type
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RelayTaskType {
    RecvPacket,
    AckPacket,
    TimeoutPacket,
}

/// task status
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum TaskStatus {
    Pending,
    Claimed,
    Executed,
    Failed,
    Expired,
}

/// ibc packet
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Packet {
    pub sequence: u64,
    pub source_port: String,
    pub source_channel: String,
    pub destination_port: String,
    pub destination_channel: String,
    pub data: Vec<u8>,
    pub timeout_height: Height,
    pub timeout_timestamp: u64,
}

/// cosmos ibc packet event
#[derive(Clone, Debug)]
pub struct PacketEvent {
    pub packet: Packet,
    pub proof: Vec<u8>,
    pub proof_height: Height,
    pub tx_hash: Hash32,
}

/// work item to submit to jam
#[derive(Clone, Debug, Serialize)]
pub enum IbcWorkItem {
    RecvPacket {
        packet: Packet,
        proof_commitment: Vec<u8>,
        proof_height: Height,
    },
    AcknowledgePacket {
        packet: Packet,
        acknowledgement: Vec<u8>,
        proof_acked: Vec<u8>,
        proof_height: Height,
    },
    ClaimRelayTask {
        task_id: Hash32,
        executor: Hash32,
        #[serde(with = "hex::serde")]
        signature: Vec<u8>,
    },
    ConfirmExecution {
        task_id: Hash32,
        dest_tx_hash: Hash32,
        inclusion_proof: Vec<u8>,
    },
}
