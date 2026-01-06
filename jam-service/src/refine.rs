//! refine phase - validate work items
//!
//! refine runs on cores and validates:
//! - oracle responses have enough signatures
//! - signatures are valid
//! - state updates are properly signed by owner
//! - namespace operations are authorized

use alloc::vec::Vec;
use sha2::{Sha256, Digest};

use crate::host;
use crate::codec;
use crate::types::*;
use crate::storage;

/// refine output - what gets passed to accumulate
#[derive(Clone)]
pub struct RefineOutput {
    pub valid: bool,
    pub item_type: u8,
    pub data_hash: Hash,
    pub request_id: Option<Hash>,
    pub key: Option<Vec<u8>>,
}

impl RefineOutput {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(if self.valid { 1 } else { 0 });
        out.push(self.item_type);
        out.extend_from_slice(&self.data_hash);

        if let Some(ref id) = self.request_id {
            out.push(1);
            out.extend_from_slice(id);
        } else {
            out.push(0);
        }

        if let Some(ref key) = self.key {
            out.extend_from_slice(&codec::encode_bytes(key));
        } else {
            out.push(0);
        }

        out
    }

    pub fn decode(data: &[u8]) -> Option<(Self, usize)> {
        let mut offset = 0;

        if data.len() < 2 + 32 + 1 {
            return None;
        }

        let valid = data[0] == 1;
        let item_type = data[1];
        offset = 2;

        let mut data_hash = [0u8; 32];
        data_hash.copy_from_slice(&data[offset..offset + 32]);
        offset += 32;

        let request_id = if data[offset] == 1 {
            offset += 1;
            if data.len() < offset + 32 {
                return None;
            }
            let mut id = [0u8; 32];
            id.copy_from_slice(&data[offset..offset + 32]);
            offset += 32;
            Some(id)
        } else {
            offset += 1;
            None
        };

        let (key, consumed) = if data.len() > offset && data[offset] > 0 {
            let (k, c) = codec::decode_bytes(&data[offset..])?;
            (Some(k.to_vec()), c)
        } else {
            offset += 1;
            (None, 0)
        };
        offset += consumed;

        Some((
            Self {
                valid,
                item_type,
                data_hash,
                request_id,
                key,
            },
            offset,
        ))
    }
}

/// main refine handler
pub fn handle_refine(args: &RefineArgs) {
    // fetch work payload
    let payload = host::fetch_work_payload(args.work_item_index);
    if payload.is_empty() {
        return_invalid();
    }

    // first byte is item type
    let item_type = match WorkItemType::from_u8(payload[0]) {
        Some(t) => t,
        None => return_invalid(),
    };

    let result = match item_type {
        WorkItemType::OracleData => refine_oracle(&payload[1..]),
        WorkItemType::StateUpdate => refine_state(&payload[1..]),
        WorkItemType::NamespaceOp => refine_namespace(&payload[1..]),
        WorkItemType::SlaOp => crate::sla_refine::refine_sla(&payload[1..]),
        WorkItemType::PrivateOp => crate::privacy_refine::refine_private(&payload[1..]),
    };

    host::return_result(&result.encode());
}

fn return_invalid() -> ! {
    let output = RefineOutput {
        valid: false,
        item_type: 0,
        data_hash: [0u8; 32],
        request_id: None,
        key: None,
    };
    host::return_result(&output.encode());
}

/// refine oracle data - verify threshold signatures
fn refine_oracle(payload: &[u8]) -> RefineOutput {
    let (response, _) = match OracleResponse::decode(payload) {
        Some(r) => r,
        None => {
            return RefineOutput {
                valid: false,
                item_type: WorkItemType::OracleData as u8,
                data_hash: [0u8; 32],
                request_id: None,
                key: None,
            };
        }
    };

    let threshold = storage::get_threshold();
    let worker_keys = storage::get_worker_keys();

    // count valid signatures
    let mut valid_sigs = 0u32;
    for sig in &response.signatures {
        if verify_worker_signature(&sig, &response.request_id, &response.data, &worker_keys) {
            valid_sigs += 1;
        }
    }

    if valid_sigs < threshold {
        return RefineOutput {
            valid: false,
            item_type: WorkItemType::OracleData as u8,
            data_hash: [0u8; 32],
            request_id: Some(response.request_id),
            key: None,
        };
    }

    // compute data hash
    let data_hash = sha256(&response.data);

    RefineOutput {
        valid: true,
        item_type: WorkItemType::OracleData as u8,
        data_hash,
        request_id: Some(response.request_id),
        key: None,
    }
}

/// refine state update - verify owner signature
fn refine_state(payload: &[u8]) -> RefineOutput {
    // decode state operation
    let (op, _) = match decode_state_op(payload) {
        Some(o) => o,
        None => {
            return RefineOutput {
                valid: false,
                item_type: WorkItemType::StateUpdate as u8,
                data_hash: [0u8; 32],
                request_id: None,
                key: None,
            };
        }
    };

    let (key, valid) = match &op {
        StateOp::Set { key, value, signature } => {
            // check if key exists and has owner
            let existing = storage::get_state(key);
            let valid = match existing {
                Some(entry) => {
                    // must be signed by owner
                    if let Some(owner) = entry.owner {
                        verify_ed25519(&owner, &make_state_message(key, value), signature)
                    } else {
                        true  // no owner, anyone can update
                    }
                }
                None => true,  // new key, allowed
            };
            (key.clone(), valid)
        }
        StateOp::Delete { key, signature } => {
            let existing = storage::get_state(key);
            let valid = match existing {
                Some(entry) => {
                    if let Some(owner) = entry.owner {
                        verify_ed25519(&owner, key, signature)
                    } else {
                        true
                    }
                }
                None => false,  // can't delete non-existent
            };
            (key.clone(), valid)
        }
        StateOp::Transfer { key, new_owner, signature } => {
            let existing = storage::get_state(key);
            let valid = match existing {
                Some(entry) => {
                    if let Some(owner) = entry.owner {
                        let msg = [key.as_slice(), new_owner.as_slice()].concat();
                        verify_ed25519(&owner, &msg, signature)
                    } else {
                        true
                    }
                }
                None => false,
            };
            (key.clone(), valid)
        }
    };

    let data_hash = sha256(&key);

    RefineOutput {
        valid,
        item_type: WorkItemType::StateUpdate as u8,
        data_hash,
        request_id: None,
        key: Some(key),
    }
}

/// refine namespace operation - verify domain owner signature
fn refine_namespace(payload: &[u8]) -> RefineOutput {
    let (op, _) = match decode_namespace_op(payload) {
        Some(o) => o,
        None => {
            return RefineOutput {
                valid: false,
                item_type: WorkItemType::NamespaceOp as u8,
                data_hash: [0u8; 32],
                request_id: None,
                key: None,
            };
        }
    };

    let (key, valid) = match &op {
        NamespaceOp::Register { name, namespace, owner, records: _, signature } => {
            // check domain doesn't exist
            let existing = storage::get_domain(namespace, name);
            let valid = if existing.is_some() {
                false  // already registered
            } else {
                // verify owner signed the registration
                let msg = [namespace.as_slice(), name.as_slice()].concat();
                verify_ed25519(owner, &msg, signature)
            };
            let key = [namespace.as_slice(), b":", name.as_slice()].concat();
            (key, valid)
        }
        NamespaceOp::Update { name, namespace, records: _, nonce, signature } => {
            let existing = storage::get_domain(namespace, name);
            let valid = match existing {
                Some(domain) => {
                    // check nonce
                    if *nonce <= domain.nonce {
                        false
                    } else {
                        // verify owner signature
                        let msg = [namespace.as_slice(), name.as_slice(), &nonce.to_le_bytes()].concat();
                        verify_ed25519(&domain.owner, &msg, signature)
                    }
                }
                None => false,
            };
            let key = [namespace.as_slice(), b":", name.as_slice()].concat();
            (key, valid)
        }
        NamespaceOp::Transfer { name, namespace, new_owner, signature } => {
            let existing = storage::get_domain(namespace, name);
            let valid = match existing {
                Some(domain) => {
                    let msg = [namespace.as_slice(), name.as_slice(), new_owner.as_slice()].concat();
                    verify_ed25519(&domain.owner, &msg, signature)
                }
                None => false,
            };
            let key = [namespace.as_slice(), b":", name.as_slice()].concat();
            (key, valid)
        }
        NamespaceOp::Renew { name, namespace, signature } => {
            let existing = storage::get_domain(namespace, name);
            let valid = match existing {
                Some(domain) => {
                    let msg = [namespace.as_slice(), name.as_slice(), b"renew"].concat();
                    verify_ed25519(&domain.owner, &msg, signature)
                }
                None => false,
            };
            let key = [namespace.as_slice(), b":", name.as_slice()].concat();
            (key, valid)
        }
    };

    let data_hash = sha256(&key);

    RefineOutput {
        valid,
        item_type: WorkItemType::NamespaceOp as u8,
        data_hash,
        request_id: None,
        key: Some(key),
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

fn verify_worker_signature(
    sig: &WorkerSignature,
    request_id: &Hash,
    data: &[u8],
    worker_keys: &[PublicKey],
) -> bool {
    // check worker is in allowed list
    if !worker_keys.iter().any(|k| k == &sig.worker_id) {
        return false;
    }

    // construct message
    let mut msg = Vec::new();
    msg.extend_from_slice(request_id);
    msg.extend_from_slice(data);
    msg.extend_from_slice(&sig.timestamp.to_le_bytes());

    verify_ed25519(&sig.worker_id, &msg, &sig.signature)
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

fn make_state_message(key: &[u8], value: &[u8]) -> Vec<u8> {
    [key, value].concat()
}

fn decode_state_op(data: &[u8]) -> Option<(StateOp, usize)> {
    if data.is_empty() {
        return None;
    }

    let op_type = data[0];
    let mut offset = 1;

    match op_type {
        0 => {
            // Set
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
            // Delete
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
            // Transfer
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
            // Register
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

            // decode records
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
            // Update
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
            // Transfer
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
            // Renew
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
