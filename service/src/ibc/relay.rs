//! relay task queue
//!
//! manages pending relay tasks with bounty incentives

use serde::{Deserialize, Serialize};

use super::types::*;

/// relay task
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RelayTask {
    /// unique task id (hash of packet)
    pub id: Hash32,
    /// task type
    pub task_type: RelayTaskType,
    /// source chain
    pub source_chain: ChainId,
    /// destination chain
    pub dest_chain: ChainId,
    /// packet to relay
    pub packet: Packet,
    /// proof bytes
    pub proof: Vec<u8>,
    /// proof height
    pub proof_height: Height,
    /// deadline timeslot
    pub deadline: u32,
    /// bounty amount
    pub bounty: u64,
    /// executor who claimed (if any)
    pub claimed_by: Option<Hash32>,
    /// timeslot when claimed
    pub claimed_at: Option<u32>,
    /// task status
    pub status: TaskStatus,
    /// timeslot when created
    pub created_at: u32,
}

/// relay task type
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RelayTaskType {
    /// relay RecvPacket to destination
    RecvPacket,
    /// relay Acknowledgement back to source
    AckPacket,
    /// relay Timeout back to source
    TimeoutPacket,
}

/// task status
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum TaskStatus {
    /// waiting to be claimed
    Pending,
    /// claimed by executor
    Claimed,
    /// successfully executed
    Executed,
    /// execution failed
    Failed,
    /// deadline passed without execution
    Expired,
}

impl RelayTask {
    /// create new relay task
    pub fn new(
        packet: Packet,
        task_type: RelayTaskType,
        source_chain: ChainId,
        dest_chain: ChainId,
        proof: Vec<u8>,
        proof_height: Height,
        bounty: u64,
        deadline: u32,
        created_at: u32,
    ) -> Self {
        // compute task id from packet
        let id = packet.commitment();

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

    /// check if task is claimable
    pub fn is_claimable(&self, current_timeslot: u32) -> bool {
        self.status == TaskStatus::Pending && current_timeslot < self.deadline
    }

    /// check if task is expired
    pub fn is_expired(&self, current_timeslot: u32) -> bool {
        current_timeslot >= self.deadline && self.status != TaskStatus::Executed
    }

    /// claim task
    pub fn claim(&mut self, executor: Hash32, timeslot: u32) -> Result<(), IbcError> {
        if self.status != TaskStatus::Pending {
            return Err(IbcError::TaskAlreadyClaimed);
        }

        if timeslot >= self.deadline {
            return Err(IbcError::TaskExpired);
        }

        self.claimed_by = Some(executor);
        self.claimed_at = Some(timeslot);
        self.status = TaskStatus::Claimed;
        Ok(())
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
    pub fn expire_and_reset(&mut self) {
        self.status = TaskStatus::Pending;
        self.claimed_by = None;
        self.claimed_at = None;
    }
}

/// bounty calculator
pub struct BountyCalculator {
    /// base bounty for any relay
    pub base_bounty: u64,
    /// bonus per kb of proof data
    pub proof_size_bonus: u64,
    /// urgency multiplier (percentage increase per timeslot closer to deadline)
    pub urgency_multiplier: u64,
}

impl Default for BountyCalculator {
    fn default() -> Self {
        Self {
            base_bounty: 100,
            proof_size_bonus: 10,
            urgency_multiplier: 5,
        }
    }
}

impl BountyCalculator {
    /// calculate bounty for a relay task
    pub fn calculate(
        &self,
        proof_size: usize,
        timeslots_until_deadline: u32,
    ) -> u64 {
        let mut bounty = self.base_bounty;

        // add proof size bonus
        let kb = (proof_size / 1024) as u64;
        bounty += kb * self.proof_size_bonus;

        // add urgency bonus (higher as deadline approaches)
        if timeslots_until_deadline < 10 {
            let urgency = (10 - timeslots_until_deadline) as u64;
            bounty += (bounty * self.urgency_multiplier * urgency) / 100;
        }

        bounty
    }
}

/// task queue metrics
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct TaskQueueMetrics {
    /// total tasks created
    pub total_created: u64,
    /// total tasks executed successfully
    pub total_executed: u64,
    /// total tasks failed
    pub total_failed: u64,
    /// total tasks expired
    pub total_expired: u64,
    /// total bounties paid out
    pub total_bounties_paid: u64,
    /// current pending tasks
    pub pending_count: u64,
}

impl TaskQueueMetrics {
    pub fn task_created(&mut self) {
        self.total_created += 1;
        self.pending_count += 1;
    }

    pub fn task_executed(&mut self, bounty: u64) {
        self.total_executed += 1;
        self.total_bounties_paid += bounty;
        if self.pending_count > 0 {
            self.pending_count -= 1;
        }
    }

    pub fn task_failed(&mut self) {
        self.total_failed += 1;
    }

    pub fn task_expired(&mut self) {
        self.total_expired += 1;
        if self.pending_count > 0 {
            self.pending_count -= 1;
        }
    }
}
