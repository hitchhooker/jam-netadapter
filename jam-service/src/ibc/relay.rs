//! ibc relay task queue
//!
//! coordinates off-chain executors for packet relay

use alloc::vec::Vec;
use crate::ibc::types::*;
use crate::ibc::packet::Packet;

/// relay task type
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum RelayTaskType {
    /// relay packet to destination chain
    RecvPacket = 0,
    /// relay acknowledgement to source chain
    AckPacket = 1,
    /// relay timeout to source chain
    TimeoutPacket = 2,
}

impl RelayTaskType {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::RecvPacket),
            1 => Some(Self::AckPacket),
            2 => Some(Self::TimeoutPacket),
            _ => None,
        }
    }
}

/// relay task status
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum TaskStatus {
    /// waiting for executor to claim
    Pending = 0,
    /// claimed by executor, awaiting execution
    Claimed = 1,
    /// successfully executed and confirmed
    Executed = 2,
    /// execution failed
    Failed = 3,
    /// deadline passed without execution
    Expired = 4,
}

impl TaskStatus {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Pending),
            1 => Some(Self::Claimed),
            2 => Some(Self::Executed),
            3 => Some(Self::Failed),
            4 => Some(Self::Expired),
            _ => None,
        }
    }
}

/// relay task
#[derive(Clone, Debug)]
pub struct RelayTask {
    /// unique task identifier
    pub id: Hash32,
    /// task type
    pub task_type: RelayTaskType,
    /// source chain (where packet originated)
    pub source_chain: ChainId,
    /// destination chain (where packet goes)
    pub dest_chain: ChainId,
    /// the packet to relay
    pub packet: Packet,
    /// proof data (commitment proof for recv, ack proof for ack)
    pub proof: Vec<u8>,
    /// height at which proof was generated
    pub proof_height: Height,
    /// deadline slot for execution
    pub deadline: u32,
    /// bounty amount in native tokens
    pub bounty: u64,
    /// executor who claimed the task
    pub claimed_by: Option<[u8; 32]>,
    /// slot when claimed
    pub claimed_at: Option<u32>,
    /// current status
    pub status: TaskStatus,
    /// creation slot
    pub created_at: u32,
}

impl RelayTask {
    /// create new pending task
    pub fn new(
        task_type: RelayTaskType,
        source_chain: ChainId,
        dest_chain: ChainId,
        packet: Packet,
        proof: Vec<u8>,
        proof_height: Height,
        deadline: u32,
        bounty: u64,
        created_at: u32,
    ) -> Self {
        use sha2::{Sha256, Digest};

        // compute task id from packet details
        let mut hasher = Sha256::new();
        hasher.update(&[task_type as u8]);
        hasher.update(&source_chain.0);
        hasher.update(&dest_chain.0);
        hasher.update(&packet.sequence.0.to_le_bytes());
        hasher.update(&packet.source_port.0);
        hasher.update(&packet.source_channel.0);
        let result = hasher.finalize();
        let mut id = [0u8; 32];
        id.copy_from_slice(&result);

        Self {
            id,
            task_type,
            source_chain,
            dest_chain,
            packet,
            proof,
            proof_height,
            deadline,
            bounty,
            claimed_by: None,
            claimed_at: None,
            status: TaskStatus::Pending,
            created_at,
        }
    }

    /// check if task can be claimed
    pub fn can_claim(&self, current_slot: u32) -> bool {
        self.status == TaskStatus::Pending && current_slot < self.deadline
    }

    /// check if task is expired
    pub fn is_expired(&self, current_slot: u32) -> bool {
        current_slot >= self.deadline && self.status != TaskStatus::Executed
    }

    /// claim task by executor
    pub fn claim(&mut self, executor: [u8; 32], slot: u32) -> bool {
        if !self.can_claim(slot) {
            return false;
        }
        self.claimed_by = Some(executor);
        self.claimed_at = Some(slot);
        self.status = TaskStatus::Claimed;
        true
    }

    /// mark task as executed
    pub fn mark_executed(&mut self) {
        self.status = TaskStatus::Executed;
    }

    /// mark task as failed
    pub fn mark_failed(&mut self) {
        self.status = TaskStatus::Failed;
    }

    /// mark task as expired and reset for re-claim
    pub fn expire(&mut self) {
        self.status = TaskStatus::Expired;
        self.claimed_by = None;
        self.claimed_at = None;
    }

    pub fn encode(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.id);
        buf.push(self.task_type as u8);
        self.source_chain.encode(buf);
        self.dest_chain.encode(buf);
        self.packet.encode(buf);

        buf.extend_from_slice(&(self.proof.len() as u32).to_le_bytes());
        buf.extend_from_slice(&self.proof);

        self.proof_height.encode(buf);
        buf.extend_from_slice(&self.deadline.to_le_bytes());
        buf.extend_from_slice(&self.bounty.to_le_bytes());

        match &self.claimed_by {
            Some(pk) => {
                buf.push(1);
                buf.extend_from_slice(pk);
            }
            None => buf.push(0),
        }

        match self.claimed_at {
            Some(slot) => {
                buf.push(1);
                buf.extend_from_slice(&slot.to_le_bytes());
            }
            None => buf.push(0),
        }

        buf.push(self.status as u8);
        buf.extend_from_slice(&self.created_at.to_le_bytes());
    }

    pub fn decode(data: &[u8]) -> Option<Self> {
        if data.len() < 32 + 1 {
            return None;
        }
        let mut offset = 0;

        let mut id = [0u8; 32];
        id.copy_from_slice(&data[offset..offset + 32]);
        offset += 32;

        let task_type = RelayTaskType::from_u8(data[offset])?;
        offset += 1;

        let (source_chain, len) = ChainId::decode(&data[offset..])?;
        offset += len;

        let (dest_chain, len) = ChainId::decode(&data[offset..])?;
        offset += len;

        let packet = Packet::decode(&data[offset..])?;
        offset += packet_encoded_len(&packet);

        if data.len() < offset + 4 {
            return None;
        }
        let proof_len = u32::from_le_bytes(data[offset..offset + 4].try_into().ok()?) as usize;
        offset += 4;

        if data.len() < offset + proof_len {
            return None;
        }
        let proof = data[offset..offset + proof_len].to_vec();
        offset += proof_len;

        let proof_height = Height::decode(&data[offset..])?;
        offset += 16;

        if data.len() < offset + 4 + 8 {
            return None;
        }
        let deadline = u32::from_le_bytes(data[offset..offset + 4].try_into().ok()?);
        offset += 4;

        let bounty = u64::from_le_bytes(data[offset..offset + 8].try_into().ok()?);
        offset += 8;

        let claimed_by = if data.get(offset)? == &1 {
            offset += 1;
            if data.len() < offset + 32 {
                return None;
            }
            let mut pk = [0u8; 32];
            pk.copy_from_slice(&data[offset..offset + 32]);
            offset += 32;
            Some(pk)
        } else {
            offset += 1;
            None
        };

        let claimed_at = if data.get(offset)? == &1 {
            offset += 1;
            if data.len() < offset + 4 {
                return None;
            }
            let slot = u32::from_le_bytes(data[offset..offset + 4].try_into().ok()?);
            offset += 4;
            Some(slot)
        } else {
            offset += 1;
            None
        };

        let status = TaskStatus::from_u8(*data.get(offset)?)?;
        offset += 1;

        if data.len() < offset + 4 {
            return None;
        }
        let created_at = u32::from_le_bytes(data[offset..offset + 4].try_into().ok()?);

        Some(Self {
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
}

/// helper to compute encoded packet length
fn packet_encoded_len(packet: &Packet) -> usize {
    8 // sequence
    + 4 + packet.source_port.0.len()
    + 4 + packet.source_channel.0.len()
    + 4 + packet.destination_port.0.len()
    + 4 + packet.destination_channel.0.len()
    + 4 + packet.data.len()
    + 16 // timeout_height
    + 8 // timeout_timestamp
}

/// bounty calculator
pub struct BountyCalculator;

impl BountyCalculator {
    /// base bounty for relay tasks
    pub const BASE_BOUNTY: u64 = 1000;

    /// bonus per kb of proof data
    pub const PROOF_BONUS_PER_KB: u64 = 100;

    /// urgency multiplier (higher for closer deadlines)
    pub const URGENCY_MULTIPLIER: u64 = 2;

    /// calculate bounty for a relay task
    pub fn calculate(
        proof_size: usize,
        slots_until_deadline: u32,
        packet_value: u64,
    ) -> u64 {
        let mut bounty = Self::BASE_BOUNTY;

        // add proof size bonus
        let kb = (proof_size / 1024) as u64;
        bounty += kb * Self::PROOF_BONUS_PER_KB;

        // add urgency bonus (more bounty if deadline is close)
        if slots_until_deadline < 100 {
            bounty *= Self::URGENCY_MULTIPLIER;
        }

        // add value-based bonus (1% of packet value, capped)
        let value_bonus = core::cmp::min(packet_value / 100, 10000);
        bounty += value_bonus;

        bounty
    }
}

/// task queue metrics
#[derive(Clone, Debug, Default)]
pub struct TaskQueueMetrics {
    pub total_created: u64,
    pub total_claimed: u64,
    pub total_executed: u64,
    pub total_failed: u64,
    pub total_expired: u64,
    pub total_bounties_paid: u64,
}

impl TaskQueueMetrics {
    pub fn encode(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.total_created.to_le_bytes());
        buf.extend_from_slice(&self.total_claimed.to_le_bytes());
        buf.extend_from_slice(&self.total_executed.to_le_bytes());
        buf.extend_from_slice(&self.total_failed.to_le_bytes());
        buf.extend_from_slice(&self.total_expired.to_le_bytes());
        buf.extend_from_slice(&self.total_bounties_paid.to_le_bytes());
    }

    pub fn decode(data: &[u8]) -> Option<Self> {
        if data.len() < 48 {
            return None;
        }
        Some(Self {
            total_created: u64::from_le_bytes(data[0..8].try_into().ok()?),
            total_claimed: u64::from_le_bytes(data[8..16].try_into().ok()?),
            total_executed: u64::from_le_bytes(data[16..24].try_into().ok()?),
            total_failed: u64::from_le_bytes(data[24..32].try_into().ok()?),
            total_expired: u64::from_le_bytes(data[32..40].try_into().ok()?),
            total_bounties_paid: u64::from_le_bytes(data[40..48].try_into().ok()?),
        })
    }
}
