//! accumulate phase - apply validated work to state
//!
//! accumulate processes refined outputs and:
//! - stores oracle data
//! - applies state updates
//! - registers/updates namespace domains
//! - handles transfers

use alloc::vec::Vec;
use sha2::{Sha256, Digest};

use crate::host;
use crate::codec;
use crate::types::*;
use crate::storage::{self, OracleEntry};
use crate::refine::RefineOutput;

/// main accumulate handler
pub fn handle_accumulate(args: &AccumulateArgs) {
    // fetch all inputs
    let inputs_data = host::fetch_inputs();
    if inputs_data.is_empty() {
        return;
    }

    let mut offset = 0;

    // decode number of inputs
    let (num_inputs, consumed) = match codec::decode_list_len(&inputs_data) {
        Some(v) => v,
        None => return,
    };
    offset += consumed;

    // process each input
    for _ in 0..num_inputs {
        let (input, consumed) = match AccumulateInput::decode(&inputs_data[offset..]) {
            Some(i) => i,
            None => break,
        };
        offset += consumed;

        if input.is_transfer {
            if let Some(transfer) = input.transfer {
                handle_transfer(&transfer, args.timeslot);
            }
        } else if let Some(operand) = input.operand {
            handle_operand(&operand, args.timeslot);
        }
    }
}

/// handle a refined work operand
fn handle_operand(operand: &Operand, timeslot: u32) {
    // decode the refine output from digest
    let (refined, _) = match RefineOutput::decode(&operand.digest_output) {
        Some(r) => r,
        None => return,
    };

    if !refined.valid {
        return;
    }

    // decode original work payload from report output
    let payload = &operand.report_output;
    if payload.is_empty() {
        return;
    }

    let item_type = match WorkItemType::from_u8(refined.item_type) {
        Some(t) => t,
        None => return,
    };

    match item_type {
        WorkItemType::OracleData => {
            accumulate_oracle(payload, &refined, timeslot);
        }
        WorkItemType::StateUpdate => {
            accumulate_state(payload, &refined, timeslot);
        }
        WorkItemType::NamespaceOp => {
            accumulate_namespace(payload, &refined, timeslot);
        }
        WorkItemType::SlaOp => {
            crate::sla_accumulate::accumulate_sla(payload, &refined, timeslot);
        }
        WorkItemType::PrivateOp => {
            crate::privacy_accumulate::accumulate_private(payload, &refined, timeslot);
        }
    }
}

/// store validated oracle data
fn accumulate_oracle(payload: &[u8], refined: &RefineOutput, timeslot: u32) {
    let request_id = match refined.request_id {
        Some(id) => id,
        None => return,
    };

    // decode oracle response to get data
    let (response, _) = match OracleResponse::decode(&payload[1..]) {
        Some(r) => r,
        None => return,
    };

    let entry = OracleEntry {
        data: response.data,
        data_hash: refined.data_hash,
        timestamp: response.timestamp,
        slot: timeslot,
    };

    storage::set_oracle_data(&request_id, &entry);
}

/// apply validated state update
fn accumulate_state(payload: &[u8], refined: &RefineOutput, _timeslot: u32) {
    let key = match &refined.key {
        Some(k) => k,
        None => return,
    };

    // decode state operation
    let (op, _) = match decode_state_op(&payload[1..]) {
        Some(o) => o,
        None => return,
    };

    match op {
        StateOp::Set { key, value, signature: _ } => {
            let existing = storage::get_state(&key);
            let nonce = existing.as_ref().map(|e| e.nonce + 1).unwrap_or(1);
            let owner = existing.and_then(|e| e.owner);

            let entry = StateEntry {
                key: key.clone(),
                value,
                owner,
                nonce,
            };
            storage::set_state(&entry);
        }
        StateOp::Delete { key, signature: _ } => {
            storage::delete_state(&key);
        }
        StateOp::Transfer { key, new_owner, signature: _ } => {
            if let Some(mut entry) = storage::get_state(&key) {
                entry.owner = Some(new_owner);
                entry.nonce += 1;
                storage::set_state(&entry);
            }
        }
    }
}

/// apply validated namespace operation
fn accumulate_namespace(payload: &[u8], refined: &RefineOutput, timeslot: u32) {
    let (op, _) = match decode_namespace_op(&payload[1..]) {
        Some(o) => o,
        None => return,
    };

    match op {
        NamespaceOp::Register { name, namespace, owner, records, signature: _ } => {
            let domain = NamespaceDomain {
                name,
                namespace,
                owner,
                records,
                registered_slot: timeslot,
                expires_slot: None,  // no expiry by default
                nonce: 1,
            };
            storage::set_domain(&domain);
        }
        NamespaceOp::Update { name, namespace, records, nonce, signature: _ } => {
            if let Some(mut domain) = storage::get_domain(&namespace, &name) {
                domain.records = records;
                domain.nonce = nonce;
                storage::set_domain(&domain);
            }
        }
        NamespaceOp::Transfer { name, namespace, new_owner, signature: _ } => {
            if let Some(mut domain) = storage::get_domain(&namespace, &name) {
                domain.owner = new_owner;
                domain.nonce += 1;
                storage::set_domain(&domain);
            }
        }
        NamespaceOp::Renew { name, namespace, signature: _ } => {
            if let Some(mut domain) = storage::get_domain(&namespace, &name) {
                // extend expiry by 1 year worth of slots (assuming 6s slots)
                let slots_per_year = 365 * 24 * 60 * 10;  // ~5.26M slots
                domain.expires_slot = Some(timeslot + slots_per_year);
                domain.nonce += 1;
                storage::set_domain(&domain);
            }
        }
    }
}

/// handle inter-service transfer
fn handle_transfer(transfer: &Transfer, _timeslot: u32) {
    // transfers can carry memo with instructions
    if transfer.memo.is_empty() {
        return;
    }

    // memo format: first byte is command
    let cmd = transfer.memo[0];
    let data = &transfer.memo[1..];

    match cmd {
        // 0x01: set config (admin only - check sender)
        0x01 => {
            // TODO: verify sender is admin
            // for now, accept threshold updates
            if data.len() >= 4 {
                let threshold = u32::from_le_bytes(data[0..4].try_into().unwrap_or([0; 4]));
                if threshold > 0 && threshold <= 100 {
                    storage::set_threshold(threshold);
                }
            }
        }
        // 0x02: add worker key
        0x02 => {
            if data.len() >= 32 {
                let mut keys = storage::get_worker_keys();
                let mut new_key = [0u8; 32];
                new_key.copy_from_slice(&data[0..32]);
                if !keys.contains(&new_key) {
                    keys.push(new_key);
                    // re-encode and store
                    let mut encoded = codec::encode_u64(keys.len() as u64);
                    for k in &keys {
                        encoded.extend_from_slice(k);
                    }
                    let _ = host::storage_write(storage::CONFIG_WORKER_KEYS, &encoded);
                }
            }
        }
        _ => {}
    }
}

// ============================================================================
// helpers - re-use decode functions from refine
// ============================================================================

fn decode_state_op(data: &[u8]) -> Option<(StateOp, usize)> {
    if data.is_empty() {
        return None;
    }

    let op_type = data[0];
    let mut offset = 1;

    match op_type {
        0 => {
            let (key, consumed) = codec::decode_bytes(&data[offset..])?;
            offset += consumed;
            let (value, consumed) = codec::decode_bytes(&data[offset..])?;
            offset += consumed;
            if data.len() < offset + 64 {
                return None;
            }
            let mut signature = [0u8; 64];
            signature.copy_from_slice(&data[offset..offset + 64]);
            offset += 64;
            Some((StateOp::Set { key: key.to_vec(), value: value.to_vec(), signature }, offset))
        }
        1 => {
            let (key, consumed) = codec::decode_bytes(&data[offset..])?;
            offset += consumed;
            if data.len() < offset + 64 {
                return None;
            }
            let mut signature = [0u8; 64];
            signature.copy_from_slice(&data[offset..offset + 64]);
            offset += 64;
            Some((StateOp::Delete { key: key.to_vec(), signature }, offset))
        }
        2 => {
            let (key, consumed) = codec::decode_bytes(&data[offset..])?;
            offset += consumed;
            if data.len() < offset + 32 + 64 {
                return None;
            }
            let mut new_owner = [0u8; 32];
            new_owner.copy_from_slice(&data[offset..offset + 32]);
            offset += 32;
            let mut signature = [0u8; 64];
            signature.copy_from_slice(&data[offset..offset + 64]);
            offset += 64;
            Some((StateOp::Transfer { key: key.to_vec(), new_owner, signature }, offset))
        }
        _ => None,
    }
}

fn decode_namespace_op(data: &[u8]) -> Option<(NamespaceOp, usize)> {
    if data.is_empty() {
        return None;
    }

    let op_type = data[0];
    let mut offset = 1;

    match op_type {
        0 => {
            let (name, consumed) = codec::decode_bytes(&data[offset..])?;
            offset += consumed;
            let (namespace, consumed) = codec::decode_bytes(&data[offset..])?;
            offset += consumed;
            if data.len() < offset + 32 {
                return None;
            }
            let mut owner = [0u8; 32];
            owner.copy_from_slice(&data[offset..offset + 32]);
            offset += 32;

            let (num_records, consumed) = codec::decode_list_len(&data[offset..])?;
            offset += consumed;
            let mut records = Vec::with_capacity(num_records);
            for _ in 0..num_records {
                let (record, consumed) = DnsRecord::decode(&data[offset..])?;
                offset += consumed;
                records.push(record);
            }

            if data.len() < offset + 64 {
                return None;
            }
            let mut signature = [0u8; 64];
            signature.copy_from_slice(&data[offset..offset + 64]);
            offset += 64;

            Some((
                NamespaceOp::Register {
                    name: name.to_vec(),
                    namespace: namespace.to_vec(),
                    owner,
                    records,
                    signature,
                },
                offset,
            ))
        }
        1 => {
            let (name, consumed) = codec::decode_bytes(&data[offset..])?;
            offset += consumed;
            let (namespace, consumed) = codec::decode_bytes(&data[offset..])?;
            offset += consumed;

            let (num_records, consumed) = codec::decode_list_len(&data[offset..])?;
            offset += consumed;
            let mut records = Vec::with_capacity(num_records);
            for _ in 0..num_records {
                let (record, consumed) = DnsRecord::decode(&data[offset..])?;
                offset += consumed;
                records.push(record);
            }

            let (nonce, consumed) = codec::decode_u64(&data[offset..])?;
            offset += consumed;

            if data.len() < offset + 64 {
                return None;
            }
            let mut signature = [0u8; 64];
            signature.copy_from_slice(&data[offset..offset + 64]);
            offset += 64;

            Some((
                NamespaceOp::Update {
                    name: name.to_vec(),
                    namespace: namespace.to_vec(),
                    records,
                    nonce,
                    signature,
                },
                offset,
            ))
        }
        2 => {
            let (name, consumed) = codec::decode_bytes(&data[offset..])?;
            offset += consumed;
            let (namespace, consumed) = codec::decode_bytes(&data[offset..])?;
            offset += consumed;
            if data.len() < offset + 32 + 64 {
                return None;
            }
            let mut new_owner = [0u8; 32];
            new_owner.copy_from_slice(&data[offset..offset + 32]);
            offset += 32;
            let mut signature = [0u8; 64];
            signature.copy_from_slice(&data[offset..offset + 64]);
            offset += 64;

            Some((
                NamespaceOp::Transfer {
                    name: name.to_vec(),
                    namespace: namespace.to_vec(),
                    new_owner,
                    signature,
                },
                offset,
            ))
        }
        3 => {
            let (name, consumed) = codec::decode_bytes(&data[offset..])?;
            offset += consumed;
            let (namespace, consumed) = codec::decode_bytes(&data[offset..])?;
            offset += consumed;
            if data.len() < offset + 64 {
                return None;
            }
            let mut signature = [0u8; 64];
            signature.copy_from_slice(&data[offset..offset + 64]);
            offset += 64;

            Some((
                NamespaceOp::Renew {
                    name: name.to_vec(),
                    namespace: namespace.to_vec(),
                    signature,
                },
                offset,
            ))
        }
        _ => None,
    }
}
