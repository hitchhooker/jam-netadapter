//! sla storage schema
//!
//! key prefixes:
//! - 0x10: probes
//! - 0x11: monitored nodes
//! - 0x12: sla contracts
//! - 0x13: commitments
//! - 0x14: revealed reports
//! - 0x15: epoch results

use alloc::vec::Vec;
use crate::host;
use crate::codec;
use crate::sla::*;
use crate::types::Hash;

// storage key prefixes
pub const PREFIX_PROBE: u8 = 0x10;
pub const PREFIX_NODE: u8 = 0x11;
pub const PREFIX_CONTRACT: u8 = 0x12;
pub const PREFIX_COMMITMENT: u8 = 0x13;
pub const PREFIX_REVEALED: u8 = 0x14;
pub const PREFIX_EPOCH_RESULT: u8 = 0x15;
pub const PREFIX_PROBE_ASSIGNMENT: u8 = 0x16;

// ============================================================================
// probe storage
// ============================================================================

fn probe_key(probe_id: &ProbeId) -> Vec<u8> {
    let mut key = Vec::with_capacity(33);
    key.push(PREFIX_PROBE);
    key.extend_from_slice(probe_id);
    key
}

pub fn get_probe(probe_id: &ProbeId) -> Option<ProbeInfo> {
    let key = probe_key(probe_id);
    host::storage_read(&key).and_then(|data| ProbeInfo::decode(&data).map(|(p, _)| p))
}

pub fn set_probe(probe: &ProbeInfo) {
    let key = probe_key(&probe.probe_id);
    let data = probe.encode();
    let _ = host::storage_write(&key, &data);
}

pub fn delete_probe(probe_id: &ProbeId) {
    let key = probe_key(probe_id);
    let _ = host::storage_delete(&key);
}

// ============================================================================
// monitored node storage
// ============================================================================

fn node_key(node_id: &NodeId) -> Vec<u8> {
    let mut key = Vec::with_capacity(33);
    key.push(PREFIX_NODE);
    key.extend_from_slice(node_id);
    key
}

pub fn get_node(node_id: &NodeId) -> Option<MonitoredNode> {
    let key = node_key(node_id);
    host::storage_read(&key).and_then(|data| decode_monitored_node(&data).map(|(n, _)| n))
}

pub fn set_node(node: &MonitoredNode) {
    let key = node_key(&node.node_id);
    let data = encode_monitored_node(node);
    let _ = host::storage_write(&key, &data);
}

fn encode_monitored_node(node: &MonitoredNode) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&node.node_id);
    out.extend_from_slice(&node.owner);
    out.extend_from_slice(&codec::encode_bytes(&node.endpoint));
    out.extend_from_slice(&node.stake.to_le_bytes());
    out.extend_from_slice(&node.total_epochs.to_le_bytes());
    out.extend_from_slice(&node.successful_epochs.to_le_bytes());
    out.extend_from_slice(&node.registered_slot.to_le_bytes());
    out
}

fn decode_monitored_node(data: &[u8]) -> Option<(MonitoredNode, usize)> {
    if data.len() < 32 + 32 {
        return None;
    }

    let mut offset = 0;

    let mut node_id = [0u8; 32];
    node_id.copy_from_slice(&data[0..32]);
    offset += 32;

    let mut owner = [0u8; 32];
    owner.copy_from_slice(&data[offset..offset + 32]);
    offset += 32;

    let (endpoint, consumed) = codec::decode_bytes(&data[offset..])?;
    offset += consumed;

    if data.len() < offset + 8 + 8 + 8 + 4 {
        return None;
    }

    let stake = u64::from_le_bytes(data[offset..offset + 8].try_into().ok()?);
    offset += 8;

    let total_epochs = u64::from_le_bytes(data[offset..offset + 8].try_into().ok()?);
    offset += 8;

    let successful_epochs = u64::from_le_bytes(data[offset..offset + 8].try_into().ok()?);
    offset += 8;

    let registered_slot = u32::from_le_bytes(data[offset..offset + 4].try_into().ok()?);
    offset += 4;

    Some((
        MonitoredNode {
            node_id,
            owner,
            endpoint: endpoint.to_vec(),
            stake,
            total_epochs,
            successful_epochs,
            registered_slot,
        },
        offset,
    ))
}

// ============================================================================
// sla contract storage
// ============================================================================

fn contract_key(contract_id: &ContractId) -> Vec<u8> {
    let mut key = Vec::with_capacity(33);
    key.push(PREFIX_CONTRACT);
    key.extend_from_slice(contract_id);
    key
}

pub fn get_contract(contract_id: &ContractId) -> Option<SlaContract> {
    let key = contract_key(contract_id);
    host::storage_read(&key).and_then(|data| decode_sla_contract(&data).map(|(c, _)| c))
}

pub fn set_contract(contract: &SlaContract) {
    let key = contract_key(&contract.contract_id);
    let data = encode_sla_contract(contract);
    let _ = host::storage_write(&key, &data);
}

fn encode_sla_contract(c: &SlaContract) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&c.contract_id);
    out.extend_from_slice(&c.node_id);
    out.extend_from_slice(&c.customer);
    out.push(c.required_uptime_percent);
    out.extend_from_slice(&c.max_latency_ms.to_le_bytes());
    out.extend_from_slice(&c.payment_per_epoch.to_le_bytes());
    out.extend_from_slice(&c.start_epoch.to_le_bytes());
    out.extend_from_slice(&c.end_epoch.to_le_bytes());
    out.extend_from_slice(&c.total_paid.to_le_bytes());
    out.push(if c.active { 1 } else { 0 });
    out
}

fn decode_sla_contract(data: &[u8]) -> Option<(SlaContract, usize)> {
    if data.len() < 32 + 32 + 32 + 1 + 4 + 8 + 8 + 8 + 8 + 1 {
        return None;
    }

    let mut offset = 0;

    let mut contract_id = [0u8; 32];
    contract_id.copy_from_slice(&data[0..32]);
    offset += 32;

    let mut node_id = [0u8; 32];
    node_id.copy_from_slice(&data[offset..offset + 32]);
    offset += 32;

    let mut customer = [0u8; 32];
    customer.copy_from_slice(&data[offset..offset + 32]);
    offset += 32;

    let required_uptime_percent = data[offset];
    offset += 1;

    let max_latency_ms = u32::from_le_bytes(data[offset..offset + 4].try_into().ok()?);
    offset += 4;

    let payment_per_epoch = u64::from_le_bytes(data[offset..offset + 8].try_into().ok()?);
    offset += 8;

    let start_epoch = u64::from_le_bytes(data[offset..offset + 8].try_into().ok()?);
    offset += 8;

    let end_epoch = u64::from_le_bytes(data[offset..offset + 8].try_into().ok()?);
    offset += 8;

    let total_paid = u64::from_le_bytes(data[offset..offset + 8].try_into().ok()?);
    offset += 8;

    let active = data[offset] != 0;
    offset += 1;

    Some((
        SlaContract {
            contract_id,
            node_id,
            customer,
            required_uptime_percent,
            max_latency_ms,
            payment_per_epoch,
            start_epoch,
            end_epoch,
            total_paid,
            active,
        },
        offset,
    ))
}

// ============================================================================
// commitment storage (commit-reveal phase 1)
// ============================================================================

fn commitment_key(epoch: Epoch, node_id: &NodeId, probe_id: &ProbeId) -> Vec<u8> {
    let mut key = Vec::with_capacity(1 + 8 + 32 + 32);
    key.push(PREFIX_COMMITMENT);
    key.extend_from_slice(&epoch.to_le_bytes());
    key.extend_from_slice(node_id);
    key.extend_from_slice(probe_id);
    key
}

pub fn get_commitment(epoch: Epoch, node_id: &NodeId, probe_id: &ProbeId) -> Option<Commitment> {
    let key = commitment_key(epoch, node_id, probe_id);
    host::storage_read(&key).and_then(|data| decode_commitment(&data).map(|(c, _)| c))
}

pub fn set_commitment(commitment: &Commitment) {
    let key = commitment_key(commitment.epoch, &commitment.node_id, &commitment.probe_id);
    let data = encode_commitment(commitment);
    let _ = host::storage_write(&key, &data);
}

fn encode_commitment(c: &Commitment) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&c.probe_id);
    out.extend_from_slice(&c.node_id);
    out.extend_from_slice(&c.epoch.to_le_bytes());
    out.extend_from_slice(&c.hash);
    out.extend_from_slice(&c.submitted_slot.to_le_bytes());
    out
}

fn decode_commitment(data: &[u8]) -> Option<(Commitment, usize)> {
    if data.len() < 32 + 32 + 8 + 32 + 4 {
        return None;
    }

    let mut offset = 0;

    let mut probe_id = [0u8; 32];
    probe_id.copy_from_slice(&data[0..32]);
    offset += 32;

    let mut node_id = [0u8; 32];
    node_id.copy_from_slice(&data[offset..offset + 32]);
    offset += 32;

    let epoch = u64::from_le_bytes(data[offset..offset + 8].try_into().ok()?);
    offset += 8;

    let mut hash = [0u8; 32];
    hash.copy_from_slice(&data[offset..offset + 32]);
    offset += 32;

    let submitted_slot = u32::from_le_bytes(data[offset..offset + 4].try_into().ok()?);
    offset += 4;

    Some((
        Commitment {
            probe_id,
            node_id,
            epoch,
            hash,
            submitted_slot,
        },
        offset,
    ))
}

// ============================================================================
// revealed report storage (commit-reveal phase 2)
// ============================================================================

fn revealed_key(epoch: Epoch, node_id: &NodeId, probe_id: &ProbeId) -> Vec<u8> {
    let mut key = Vec::with_capacity(1 + 8 + 32 + 32);
    key.push(PREFIX_REVEALED);
    key.extend_from_slice(&epoch.to_le_bytes());
    key.extend_from_slice(node_id);
    key.extend_from_slice(probe_id);
    key
}

pub fn get_revealed(epoch: Epoch, node_id: &NodeId, probe_id: &ProbeId) -> Option<RevealedReport> {
    let key = revealed_key(epoch, node_id, probe_id);
    host::storage_read(&key).and_then(|data| decode_revealed(&data).map(|(r, _)| r))
}

pub fn set_revealed(report: &RevealedReport) {
    let key = revealed_key(report.epoch, &report.node_id, &report.probe_id);
    let data = encode_revealed(report);
    let _ = host::storage_write(&key, &data);
}

fn encode_revealed(r: &RevealedReport) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&r.probe_id);
    out.extend_from_slice(&r.node_id);
    out.extend_from_slice(&r.epoch.to_le_bytes());
    out.push(r.result as u8);
    out.extend_from_slice(&r.latency_ms.to_le_bytes());
    out.extend_from_slice(&r.blinding_factor);
    out.extend_from_slice(&r.signature);
    out
}

fn decode_revealed(data: &[u8]) -> Option<(RevealedReport, usize)> {
    if data.len() < 32 + 32 + 8 + 1 + 4 + 32 + 64 {
        return None;
    }

    let mut offset = 0;

    let mut probe_id = [0u8; 32];
    probe_id.copy_from_slice(&data[0..32]);
    offset += 32;

    let mut node_id = [0u8; 32];
    node_id.copy_from_slice(&data[offset..offset + 32]);
    offset += 32;

    let epoch = u64::from_le_bytes(data[offset..offset + 8].try_into().ok()?);
    offset += 8;

    let result = MeasurementResult::from_u8(data[offset])?;
    offset += 1;

    let latency_ms = u32::from_le_bytes(data[offset..offset + 4].try_into().ok()?);
    offset += 4;

    let mut blinding_factor = [0u8; 32];
    blinding_factor.copy_from_slice(&data[offset..offset + 32]);
    offset += 32;

    let mut signature = [0u8; 64];
    signature.copy_from_slice(&data[offset..offset + 64]);
    offset += 64;

    Some((
        RevealedReport {
            probe_id,
            node_id,
            epoch,
            result,
            latency_ms,
            blinding_factor,
            signature,
        },
        offset,
    ))
}

// ============================================================================
// epoch result storage
// ============================================================================

fn epoch_result_key(epoch: Epoch, node_id: &NodeId) -> Vec<u8> {
    let mut key = Vec::with_capacity(1 + 8 + 32);
    key.push(PREFIX_EPOCH_RESULT);
    key.extend_from_slice(&epoch.to_le_bytes());
    key.extend_from_slice(node_id);
    key
}

pub fn get_epoch_result(epoch: Epoch, node_id: &NodeId) -> Option<EpochResult> {
    let key = epoch_result_key(epoch, node_id);
    host::storage_read(&key).and_then(|data| EpochResult::decode(&data).map(|(r, _)| r))
}

pub fn set_epoch_result(result: &EpochResult) {
    let key = epoch_result_key(result.epoch, &result.node_id);
    let data = result.encode();
    let _ = host::storage_write(&key, &data);
}
