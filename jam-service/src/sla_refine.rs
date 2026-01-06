//! sla refine logic - validate sla operations

use alloc::vec::Vec;
use sha2::{Sha256, Digest};

use crate::codec;
use crate::sla::*;
use crate::sla_storage;
use crate::refine::RefineOutput;
use crate::types::{WorkItemType, Hash, Signature, PublicKey};

/// refine sla operation
pub fn refine_sla(payload: &[u8]) -> RefineOutput {
    let (op, _) = match decode_sla_op(payload) {
        Some(o) => o,
        None => {
            return RefineOutput {
                valid: false,
                item_type: WorkItemType::SlaOp as u8,
                data_hash: [0u8; 32],
                request_id: None,
                key: None,
            };
        }
    };

    let (valid, data_hash, key) = match &op {
        SlaOp::RegisterProbe { probe_id, zone: _, endpoint: _, stake, signature } => {
            // verify stake meets minimum
            if *stake < MIN_PROBE_STAKE {
                (false, [0u8; 32], None)
            } else {
                // verify probe doesn't exist
                let exists = sla_storage::get_probe(probe_id).is_some();
                if exists {
                    (false, [0u8; 32], None)
                } else {
                    // verify signature
                    let msg = make_register_probe_msg(probe_id, *stake);
                    let valid = verify_ed25519(probe_id, &msg, signature);
                    (valid, sha256(probe_id), Some(probe_id.to_vec()))
                }
            }
        }

        SlaOp::RegisterNode { node_id, owner, endpoint: _, stake, signature } => {
            if *stake < MIN_NODE_STAKE {
                (false, [0u8; 32], None)
            } else {
                let exists = sla_storage::get_node(node_id).is_some();
                if exists {
                    (false, [0u8; 32], None)
                } else {
                    let msg = make_register_node_msg(node_id, owner, *stake);
                    let valid = verify_ed25519(owner, &msg, signature);
                    (valid, sha256(node_id), Some(node_id.to_vec()))
                }
            }
        }

        SlaOp::CreateContract { node_id, customer, required_uptime_percent, max_latency_ms: _, payment_per_epoch: _, duration_epochs: _, signature } => {
            // verify node exists
            let node = sla_storage::get_node(node_id);
            if node.is_none() {
                (false, [0u8; 32], None)
            } else if *required_uptime_percent > 100 {
                (false, [0u8; 32], None)
            } else {
                let msg = make_create_contract_msg(node_id, customer, *required_uptime_percent);
                let valid = verify_ed25519(customer, &msg, signature);
                let contract_id = sha256(&[node_id.as_slice(), customer.as_slice()].concat());
                (valid, contract_id, Some(contract_id.to_vec()))
            }
        }

        SlaOp::SubmitCommitment { probe_id, node_id, epoch, hash, signature } => {
            // verify probe exists
            let probe = sla_storage::get_probe(probe_id);
            if probe.is_none() {
                (false, [0u8; 32], None)
            } else {
                // verify node exists
                let node = sla_storage::get_node(node_id);
                if node.is_none() {
                    (false, [0u8; 32], None)
                } else {
                    // verify no commitment exists yet
                    let existing = sla_storage::get_commitment(*epoch, node_id, probe_id);
                    if existing.is_some() {
                        (false, [0u8; 32], None)
                    } else {
                        let msg = make_commitment_msg(probe_id, node_id, *epoch, hash);
                        let valid = verify_ed25519(probe_id, &msg, signature);
                        (valid, *hash, Some([probe_id.as_slice(), node_id.as_slice()].concat()))
                    }
                }
            }
        }

        SlaOp::RevealMeasurement { probe_id, node_id, epoch, result, latency_ms, blinding_factor, signature } => {
            // verify commitment exists
            let commitment = sla_storage::get_commitment(*epoch, node_id, probe_id);
            match commitment {
                None => (false, [0u8; 32], None),
                Some(c) => {
                    // verify hash matches
                    let expected_hash = compute_commitment_hash(*result as u8, *latency_ms, blinding_factor);
                    if c.hash != expected_hash {
                        (false, [0u8; 32], None)
                    } else {
                        let msg = make_reveal_msg(probe_id, node_id, *epoch, *result as u8, *latency_ms);
                        let valid = verify_ed25519(probe_id, &msg, signature);
                        (valid, expected_hash, Some([probe_id.as_slice(), node_id.as_slice()].concat()))
                    }
                }
            }
        }

        SlaOp::DirectSubmit { probe_id, node_id, epoch, result, latency_ms, signature } => {
            // verify probe exists and has high reputation
            let probe = sla_storage::get_probe(probe_id);
            match probe {
                None => (false, [0u8; 32], None),
                Some(p) => {
                    if !p.can_direct_submit() {
                        (false, [0u8; 32], None)
                    } else {
                        // verify node exists
                        let node = sla_storage::get_node(node_id);
                        if node.is_none() {
                            (false, [0u8; 32], None)
                        } else {
                            let msg = make_direct_submit_msg(probe_id, node_id, *epoch, *result as u8, *latency_ms);
                            let valid = verify_ed25519(probe_id, &msg, signature);
                            let data_hash = sha256(&msg);
                            (valid, data_hash, Some([probe_id.as_slice(), node_id.as_slice()].concat()))
                        }
                    }
                }
            }
        }

        SlaOp::FinalizeEpoch { node_id, epoch } => {
            // anyone can finalize, just check node exists
            let node = sla_storage::get_node(node_id);
            if node.is_none() {
                (false, [0u8; 32], None)
            } else {
                // check epoch result doesn't exist
                let existing = sla_storage::get_epoch_result(*epoch, node_id);
                if existing.is_some() {
                    (false, [0u8; 32], None)
                } else {
                    let data_hash = sha256(&[&epoch.to_le_bytes(), node_id.as_slice()].concat());
                    (true, data_hash, Some(node_id.to_vec()))
                }
            }
        }

        SlaOp::SlashProbe { probe_id, reason: _, evidence, signature } => {
            // verify probe exists
            let probe = sla_storage::get_probe(probe_id);
            if probe.is_none() {
                (false, [0u8; 32], None)
            } else {
                // TODO: verify quorum signature on slash
                // for now just verify evidence hash
                let data_hash = sha256(evidence);
                let valid = verify_ed25519(probe_id, evidence, signature);
                (valid, data_hash, Some(probe_id.to_vec()))
            }
        }

        SlaOp::UnregisterProbe { probe_id, signature } => {
            let probe = sla_storage::get_probe(probe_id);
            if probe.is_none() {
                (false, [0u8; 32], None)
            } else {
                let msg = b"unregister";
                let valid = verify_ed25519(probe_id, msg, signature);
                (valid, sha256(probe_id), Some(probe_id.to_vec()))
            }
        }
    };

    RefineOutput {
        valid,
        item_type: WorkItemType::SlaOp as u8,
        data_hash,
        request_id: None,
        key,
    }
}

// ============================================================================
// helpers
// ============================================================================

fn sha256(data: &[u8]) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

fn compute_commitment_hash(result: u8, latency_ms: u32, blinding: &Hash) -> Hash {
    let mut data = Vec::new();
    data.push(result);
    data.extend_from_slice(&latency_ms.to_le_bytes());
    data.extend_from_slice(blinding);
    sha256(&data)
}

fn verify_ed25519(public_key: &PublicKey, message: &[u8], signature: &Signature) -> bool {
    use ed25519_dalek::{Signature as DalekSig, VerifyingKey, Verifier};

    let pk = match VerifyingKey::from_bytes(public_key) {
        Ok(k) => k,
        Err(_) => return false,
    };

    let sig = DalekSig::from_bytes(signature);
    pk.verify_strict(message, &sig).is_ok()
}

fn make_register_probe_msg(probe_id: &PublicKey, stake: u64) -> Vec<u8> {
    let mut msg = Vec::new();
    msg.extend_from_slice(b"register_probe:");
    msg.extend_from_slice(probe_id);
    msg.extend_from_slice(&stake.to_le_bytes());
    msg
}

fn make_register_node_msg(node_id: &Hash, owner: &PublicKey, stake: u64) -> Vec<u8> {
    let mut msg = Vec::new();
    msg.extend_from_slice(b"register_node:");
    msg.extend_from_slice(node_id);
    msg.extend_from_slice(owner);
    msg.extend_from_slice(&stake.to_le_bytes());
    msg
}

fn make_create_contract_msg(node_id: &Hash, customer: &PublicKey, uptime: u8) -> Vec<u8> {
    let mut msg = Vec::new();
    msg.extend_from_slice(b"create_contract:");
    msg.extend_from_slice(node_id);
    msg.extend_from_slice(customer);
    msg.push(uptime);
    msg
}

fn make_commitment_msg(probe_id: &PublicKey, node_id: &Hash, epoch: Epoch, hash: &Hash) -> Vec<u8> {
    let mut msg = Vec::new();
    msg.extend_from_slice(b"commit:");
    msg.extend_from_slice(probe_id);
    msg.extend_from_slice(node_id);
    msg.extend_from_slice(&epoch.to_le_bytes());
    msg.extend_from_slice(hash);
    msg
}

fn make_reveal_msg(probe_id: &PublicKey, node_id: &Hash, epoch: Epoch, result: u8, latency: u32) -> Vec<u8> {
    let mut msg = Vec::new();
    msg.extend_from_slice(b"reveal:");
    msg.extend_from_slice(probe_id);
    msg.extend_from_slice(node_id);
    msg.extend_from_slice(&epoch.to_le_bytes());
    msg.push(result);
    msg.extend_from_slice(&latency.to_le_bytes());
    msg
}

fn make_direct_submit_msg(probe_id: &PublicKey, node_id: &Hash, epoch: Epoch, result: u8, latency: u32) -> Vec<u8> {
    let mut msg = Vec::new();
    msg.extend_from_slice(b"direct:");
    msg.extend_from_slice(probe_id);
    msg.extend_from_slice(node_id);
    msg.extend_from_slice(&epoch.to_le_bytes());
    msg.push(result);
    msg.extend_from_slice(&latency.to_le_bytes());
    msg
}

fn decode_sla_op(data: &[u8]) -> Option<(SlaOp, usize)> {
    if data.is_empty() {
        return None;
    }

    let op_type = data[0];
    let mut offset = 1;

    match op_type {
        0 => {
            // RegisterProbe
            if data.len() < offset + 32 + 1 + 8 + 64 {
                return None;
            }
            let mut probe_id = [0u8; 32];
            probe_id.copy_from_slice(&data[offset..offset + 32]);
            offset += 32;

            let zone = GeographicZone::from_u8(data[offset])?;
            offset += 1;

            let (endpoint, consumed) = codec::decode_bytes(&data[offset..])?;
            offset += consumed;

            if data.len() < offset + 8 + 64 {
                return None;
            }
            let stake = u64::from_le_bytes(data[offset..offset + 8].try_into().ok()?);
            offset += 8;

            let mut signature = [0u8; 64];
            signature.copy_from_slice(&data[offset..offset + 64]);
            offset += 64;

            Some((SlaOp::RegisterProbe {
                probe_id,
                zone,
                endpoint: endpoint.to_vec(),
                stake,
                signature,
            }, offset))
        }
        // ... other ops similar pattern
        _ => None,
    }
}
