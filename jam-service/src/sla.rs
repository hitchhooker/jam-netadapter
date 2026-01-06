//! sla monitoring for decentralized service level tracking
//!
//! monitors endpoints across geographic zones using distributed probes.
//! uses commit-reveal to prevent collusion, reputation for long-term honesty.

use alloc::vec::Vec;
use crate::codec;
use crate::types::{Hash, PublicKey, Signature};

// ============================================================================
// sla types
// ============================================================================

pub type NodeId = Hash;
pub type ProbeId = PublicKey;
pub type Epoch = u64;
pub type ContractId = Hash;

/// measurement result from a probe
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum MeasurementResult {
    Up = 0,        // node responded successfully
    Down = 1,      // node did not respond
    Timeout = 2,   // request timed out
    Degraded = 3,  // responded but degraded performance
}

impl MeasurementResult {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Up),
            1 => Some(Self::Down),
            2 => Some(Self::Timeout),
            3 => Some(Self::Degraded),
            _ => None,
        }
    }
}

/// geographic zone for probe diversity
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum GeographicZone {
    NorthAmerica = 0,
    SouthAmerica = 1,
    Europe = 2,
    AsiaPacific = 3,
    Africa = 4,
    Oceania = 5,
}

impl GeographicZone {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::NorthAmerica),
            1 => Some(Self::SouthAmerica),
            2 => Some(Self::Europe),
            3 => Some(Self::AsiaPacific),
            4 => Some(Self::Africa),
            5 => Some(Self::Oceania),
            _ => None,
        }
    }
}

/// registered probe info
#[derive(Clone, Debug)]
pub struct ProbeInfo {
    pub probe_id: ProbeId,
    pub stake: u64,
    pub zone: GeographicZone,
    pub endpoint: Vec<u8>,
    pub registered_slot: u32,
    pub last_active_slot: u32,
    pub total_reports: u64,
    pub accurate_reports: u64,
    pub reputation: u64,  // 0-100
}

impl ProbeInfo {
    pub fn accuracy_percent(&self) -> u8 {
        if self.total_reports == 0 {
            return 0;
        }
        ((self.accurate_reports * 100) / self.total_reports) as u8
    }

    pub fn can_direct_submit(&self) -> bool {
        self.reputation >= 80
    }
}

/// monitored node info
#[derive(Clone, Debug)]
pub struct MonitoredNode {
    pub node_id: NodeId,
    pub owner: PublicKey,
    pub endpoint: Vec<u8>,
    pub stake: u64,
    pub total_epochs: u64,
    pub successful_epochs: u64,
    pub registered_slot: u32,
}

impl MonitoredNode {
    pub fn uptime_percent(&self) -> u8 {
        if self.total_epochs == 0 {
            return 0;
        }
        ((self.successful_epochs * 100) / self.total_epochs) as u8
    }
}

/// sla contract between customer and node operator
#[derive(Clone, Debug)]
pub struct SlaContract {
    pub contract_id: ContractId,
    pub node_id: NodeId,
    pub customer: PublicKey,
    pub required_uptime_percent: u8,  // 0-100
    pub max_latency_ms: u32,
    pub payment_per_epoch: u64,
    pub start_epoch: Epoch,
    pub end_epoch: Epoch,
    pub total_paid: u64,
    pub active: bool,
}

/// probe report for a single measurement
#[derive(Clone, Debug)]
pub struct ProbeReport {
    pub probe_id: ProbeId,
    pub node_id: NodeId,
    pub epoch: Epoch,
    pub result: MeasurementResult,
    pub latency_ms: u32,
    pub timestamp: u32,  // slot
    pub signature: Signature,
}

/// commitment for commit-reveal scheme
#[derive(Clone, Debug)]
pub struct Commitment {
    pub probe_id: ProbeId,
    pub node_id: NodeId,
    pub epoch: Epoch,
    pub hash: Hash,  // sha256(result || latency || blinding_factor)
    pub submitted_slot: u32,
}

/// revealed report with blinding factor
#[derive(Clone, Debug)]
pub struct RevealedReport {
    pub probe_id: ProbeId,
    pub node_id: NodeId,
    pub epoch: Epoch,
    pub result: MeasurementResult,
    pub latency_ms: u32,
    pub blinding_factor: Hash,
    pub signature: Signature,
}

/// epoch result after consensus
#[derive(Clone, Debug)]
pub struct EpochResult {
    pub node_id: NodeId,
    pub epoch: Epoch,
    pub up_votes: u32,
    pub down_votes: u32,
    pub timeout_votes: u32,
    pub degraded_votes: u32,
    pub avg_latency_ms: u32,
    pub consensus_reached: bool,
    pub node_up: bool,
    pub finalized_slot: u32,
}

impl EpochResult {
    pub fn total_votes(&self) -> u32 {
        self.up_votes + self.down_votes + self.timeout_votes + self.degraded_votes
    }

    pub fn up_percent(&self) -> u8 {
        let total = self.total_votes();
        if total == 0 {
            return 0;
        }
        ((self.up_votes as u64 * 100) / total as u64) as u8
    }

    pub fn meets_sla(&self, required_uptime: u8, max_latency: u32) -> bool {
        self.consensus_reached
            && self.node_up
            && self.up_percent() >= required_uptime
            && self.avg_latency_ms <= max_latency
    }
}

// ============================================================================
// sla operations (work items)
// ============================================================================

#[derive(Clone, Debug)]
pub enum SlaOp {
    /// register a new probe
    RegisterProbe {
        probe_id: ProbeId,
        zone: GeographicZone,
        endpoint: Vec<u8>,
        stake: u64,
        signature: Signature,
    },

    /// register a node for monitoring
    RegisterNode {
        node_id: NodeId,
        owner: PublicKey,
        endpoint: Vec<u8>,
        stake: u64,
        signature: Signature,
    },

    /// create sla contract
    CreateContract {
        node_id: NodeId,
        customer: PublicKey,
        required_uptime_percent: u8,
        max_latency_ms: u32,
        payment_per_epoch: u64,
        duration_epochs: u64,
        signature: Signature,
    },

    /// submit commitment (phase 1)
    SubmitCommitment {
        probe_id: ProbeId,
        node_id: NodeId,
        epoch: Epoch,
        hash: Hash,
        signature: Signature,
    },

    /// reveal measurement (phase 2)
    RevealMeasurement {
        probe_id: ProbeId,
        node_id: NodeId,
        epoch: Epoch,
        result: MeasurementResult,
        latency_ms: u32,
        blinding_factor: Hash,
        signature: Signature,
    },

    /// direct submit for high-reputation probes
    DirectSubmit {
        probe_id: ProbeId,
        node_id: NodeId,
        epoch: Epoch,
        result: MeasurementResult,
        latency_ms: u32,
        signature: Signature,
    },

    /// finalize epoch (triggers consensus)
    FinalizeEpoch {
        node_id: NodeId,
        epoch: Epoch,
    },

    /// slash a misbehaving probe
    SlashProbe {
        probe_id: ProbeId,
        reason: SlashReason,
        evidence: Vec<u8>,
        signature: Signature,  // signed by quorum
    },

    /// unregister probe
    UnregisterProbe {
        probe_id: ProbeId,
        signature: Signature,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum SlashReason {
    ConsistentDisagreement = 0,  // regularly contradicts consensus
    MissingReports = 1,          // failed to submit measurements
    InvalidProof = 2,            // proof verification failed
    Collusion = 3,               // coordinated false reporting
}

impl SlashReason {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::ConsistentDisagreement),
            1 => Some(Self::MissingReports),
            2 => Some(Self::InvalidProof),
            3 => Some(Self::Collusion),
            _ => None,
        }
    }

    pub fn slash_percent(&self) -> u8 {
        match self {
            Self::ConsistentDisagreement => 10,
            Self::MissingReports => 5,
            Self::InvalidProof => 50,
            Self::Collusion => 100,
        }
    }
}

// ============================================================================
// constants
// ============================================================================

pub const MIN_PROBE_STAKE: u64 = 100_000_000_000;  // 100 units
pub const MIN_NODE_STAKE: u64 = 1_000_000_000_000; // 1000 units
pub const MIN_REPORTS_FOR_CONSENSUS: u32 = 3;
pub const CONSENSUS_THRESHOLD_PERCENT: u8 = 67;
pub const COMMIT_REVEAL_DELAY_SLOTS: u32 = 50;
pub const EPOCH_DURATION_SLOTS: u32 = 100;
pub const MAX_PROBES_PER_NODE: u32 = 10;
pub const HIGH_REPUTATION_THRESHOLD: u64 = 80;

// ============================================================================
// encoding/decoding
// ============================================================================

impl ProbeInfo {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.probe_id);
        out.extend_from_slice(&self.stake.to_le_bytes());
        out.push(self.zone as u8);
        out.extend_from_slice(&codec::encode_bytes(&self.endpoint));
        out.extend_from_slice(&self.registered_slot.to_le_bytes());
        out.extend_from_slice(&self.last_active_slot.to_le_bytes());
        out.extend_from_slice(&self.total_reports.to_le_bytes());
        out.extend_from_slice(&self.accurate_reports.to_le_bytes());
        out.extend_from_slice(&self.reputation.to_le_bytes());
        out
    }

    pub fn decode(data: &[u8]) -> Option<(Self, usize)> {
        if data.len() < 32 + 8 + 1 {
            return None;
        }

        let mut offset = 0;

        let mut probe_id = [0u8; 32];
        probe_id.copy_from_slice(&data[0..32]);
        offset += 32;

        let stake = u64::from_le_bytes(data[offset..offset + 8].try_into().ok()?);
        offset += 8;

        let zone = GeographicZone::from_u8(data[offset])?;
        offset += 1;

        let (endpoint, consumed) = codec::decode_bytes(&data[offset..])?;
        offset += consumed;

        if data.len() < offset + 4 + 4 + 8 + 8 + 8 {
            return None;
        }

        let registered_slot = u32::from_le_bytes(data[offset..offset + 4].try_into().ok()?);
        offset += 4;

        let last_active_slot = u32::from_le_bytes(data[offset..offset + 4].try_into().ok()?);
        offset += 4;

        let total_reports = u64::from_le_bytes(data[offset..offset + 8].try_into().ok()?);
        offset += 8;

        let accurate_reports = u64::from_le_bytes(data[offset..offset + 8].try_into().ok()?);
        offset += 8;

        let reputation = u64::from_le_bytes(data[offset..offset + 8].try_into().ok()?);
        offset += 8;

        Some((
            Self {
                probe_id,
                stake,
                zone,
                endpoint: endpoint.to_vec(),
                registered_slot,
                last_active_slot,
                total_reports,
                accurate_reports,
                reputation,
            },
            offset,
        ))
    }
}

impl EpochResult {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.node_id);
        out.extend_from_slice(&self.epoch.to_le_bytes());
        out.extend_from_slice(&self.up_votes.to_le_bytes());
        out.extend_from_slice(&self.down_votes.to_le_bytes());
        out.extend_from_slice(&self.timeout_votes.to_le_bytes());
        out.extend_from_slice(&self.degraded_votes.to_le_bytes());
        out.extend_from_slice(&self.avg_latency_ms.to_le_bytes());
        out.push(if self.consensus_reached { 1 } else { 0 });
        out.push(if self.node_up { 1 } else { 0 });
        out.extend_from_slice(&self.finalized_slot.to_le_bytes());
        out
    }

    pub fn decode(data: &[u8]) -> Option<(Self, usize)> {
        if data.len() < 32 + 8 + 4 * 5 + 2 + 4 {
            return None;
        }

        let mut offset = 0;

        let mut node_id = [0u8; 32];
        node_id.copy_from_slice(&data[0..32]);
        offset += 32;

        let epoch = u64::from_le_bytes(data[offset..offset + 8].try_into().ok()?);
        offset += 8;

        let up_votes = u32::from_le_bytes(data[offset..offset + 4].try_into().ok()?);
        offset += 4;

        let down_votes = u32::from_le_bytes(data[offset..offset + 4].try_into().ok()?);
        offset += 4;

        let timeout_votes = u32::from_le_bytes(data[offset..offset + 4].try_into().ok()?);
        offset += 4;

        let degraded_votes = u32::from_le_bytes(data[offset..offset + 4].try_into().ok()?);
        offset += 4;

        let avg_latency_ms = u32::from_le_bytes(data[offset..offset + 4].try_into().ok()?);
        offset += 4;

        let consensus_reached = data[offset] != 0;
        offset += 1;

        let node_up = data[offset] != 0;
        offset += 1;

        let finalized_slot = u32::from_le_bytes(data[offset..offset + 4].try_into().ok()?);
        offset += 4;

        Some((
            Self {
                node_id,
                epoch,
                up_votes,
                down_votes,
                timeout_votes,
                degraded_votes,
                avg_latency_ms,
                consensus_reached,
                node_up,
                finalized_slot,
            },
            offset,
        ))
    }
}

/// compute consensus from revealed reports
pub fn compute_consensus(reports: &[RevealedReport]) -> EpochResult {
    let mut up = 0u32;
    let mut down = 0u32;
    let mut timeout = 0u32;
    let mut degraded = 0u32;
    let mut total_latency = 0u64;

    for report in reports {
        match report.result {
            MeasurementResult::Up => up += 1,
            MeasurementResult::Down => down += 1,
            MeasurementResult::Timeout => timeout += 1,
            MeasurementResult::Degraded => degraded += 1,
        }
        total_latency += report.latency_ms as u64;
    }

    let total = up + down + timeout + degraded;
    let avg_latency = if total > 0 {
        (total_latency / total as u64) as u32
    } else {
        0
    };

    let consensus_reached = total >= MIN_REPORTS_FOR_CONSENSUS;
    let up_percent = if total > 0 {
        (up as u64 * 100 / total as u64) as u8
    } else {
        0
    };
    let node_up = up_percent >= CONSENSUS_THRESHOLD_PERCENT;

    EpochResult {
        node_id: if reports.is_empty() { [0u8; 32] } else { reports[0].node_id },
        epoch: if reports.is_empty() { 0 } else { reports[0].epoch },
        up_votes: up,
        down_votes: down,
        timeout_votes: timeout,
        degraded_votes: degraded,
        avg_latency_ms: avg_latency,
        consensus_reached,
        node_up,
        finalized_slot: 0,
    }
}

/// compute payment based on epoch result
pub fn compute_payment(result: &EpochResult, contract: &SlaContract) -> u64 {
    if !contract.active {
        return 0;
    }

    if result.meets_sla(contract.required_uptime_percent, contract.max_latency_ms) {
        // full payment
        contract.payment_per_epoch
    } else if result.consensus_reached {
        // partial payment (10%)
        contract.payment_per_epoch / 10
    } else {
        // no consensus (50%)
        contract.payment_per_epoch / 2
    }
}

/// update probe reputation based on consensus match
pub fn update_reputation(probe: &mut ProbeInfo, matched_consensus: bool) {
    probe.total_reports += 1;
    if matched_consensus {
        probe.accurate_reports += 1;
        // increase reputation (max 100)
        probe.reputation = (probe.reputation + 1).min(100);
    } else {
        // decrease reputation
        probe.reputation = probe.reputation.saturating_sub(5);
    }
}
