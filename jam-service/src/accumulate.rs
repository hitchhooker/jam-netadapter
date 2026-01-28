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
        WorkItemType::IbcOp => {
            accumulate_ibc(payload, &refined, timeslot);
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

// ============================================================================
// ibc accumulate
// ============================================================================

/// accumulate ibc work item
/// applies state changes after successful refine validation
fn accumulate_ibc(payload: &[u8], refined: &RefineOutput, timeslot: u32) {
    use crate::ibc::work_item::IbcWorkItem;
    use crate::ibc::storage as ibc_storage;
    use crate::ibc::client::{ClientStateInfo, ConsensusStateInfo, ClientType, ClientStatus};
    use crate::ibc::types::{ClientId, CommitmentRoot, Height, Timestamp};
    use crate::ibc::tendermint::{TendermintClientState, TendermintConsensusState};

    if !refined.valid {
        return;
    }

    // decode ibc work item (skip first byte which is WorkItemType)
    let work_item = match IbcWorkItem::decode(&payload[1..]) {
        Some(item) => item,
        None => return,
    };

    match work_item {
        IbcWorkItem::CreateClient { client_type, client_state, consensus_state } => {
            // allocate new client id
            let counter = ibc_storage::increment_client_counter();
            let client_id_str = match client_type {
                ClientType::Tendermint => alloc::format!("07-tendermint-{}", counter - 1),
                ClientType::Grandpa => alloc::format!("10-grandpa-{}", counter - 1),
            };
            let client_id = ClientId::new(client_id_str.as_bytes());

            // decode type-specific state
            let (chain_id, latest_height, root, timestamp) = match client_type {
                ClientType::Tendermint => {
                    if let Some(cs) = TendermintClientState::decode(&client_state) {
                        if let Some(cons) = TendermintConsensusState::decode(&consensus_state) {
                            (cs.chain_id, cs.latest_height, cons.root, cons.timestamp)
                        } else {
                            return;
                        }
                    } else {
                        return;
                    }
                }
                _ => return, // other client types not yet supported
            };

            // store client state
            let state_info = ClientStateInfo {
                client_type,
                chain_id,
                latest_height,
                frozen_height: None,
                status: ClientStatus::Active,
                state_data: client_state,
            };
            ibc_storage::set_client_state(&client_id, &state_info);

            // store consensus state
            let consensus_info = ConsensusStateInfo {
                timestamp: Timestamp::from_nanoseconds(timestamp),
                root: CommitmentRoot::new(root.0),
                state_data: consensus_state,
            };
            ibc_storage::set_consensus_state(&client_id, &latest_height, &consensus_info);
        }

        IbcWorkItem::UpdateClient { client_id, header } => {
            // get existing client state
            let mut client_state = match ibc_storage::get_client_state(&client_id) {
                Some(s) => s,
                None => return,
            };

            // decode and validate header based on client type
            match client_state.client_type {
                ClientType::Tendermint => {
                    if let Some(tm_header) = crate::ibc::tendermint::TendermintHeader::decode(&header) {
                        let new_height = tm_header.height();

                        // update latest height
                        if new_height > client_state.latest_height {
                            client_state.latest_height = new_height;
                            client_state.state_data = header.clone();
                            ibc_storage::set_client_state(&client_id, &client_state);

                            // store new consensus state
                            let consensus_info = ConsensusStateInfo {
                                timestamp: Timestamp::from_nanoseconds(tm_header.signed_header.header.time),
                                root: CommitmentRoot::new(tm_header.signed_header.header.app_hash),
                                state_data: alloc::vec![],
                            };
                            ibc_storage::set_consensus_state(&client_id, &new_height, &consensus_info);
                        }
                    }
                }
                _ => {}
            }
        }

        IbcWorkItem::SendPacket { source_port, source_channel, data, timeout_height, timeout_timestamp } => {
            use crate::ibc::relay::{RelayTask, RelayTaskType, BountyCalculator};
            use crate::ibc::types::{ChainId, ChannelId};

            // get channel
            let channel = match ibc_storage::get_channel(&source_port, &source_channel) {
                Some(c) => c,
                None => return,
            };

            if !channel.is_open() {
                return;
            }

            // get connection for destination chain info
            let connection_id = match channel.connection_hops.first() {
                Some(id) => id,
                None => return,
            };

            let connection = match ibc_storage::get_connection(connection_id) {
                Some(c) => c,
                None => return,
            };

            // get client for chain_id
            let client_state = match ibc_storage::get_client_state(&connection.client_id) {
                Some(s) => s,
                None => return,
            };

            // allocate sequence
            let sequence = ibc_storage::get_next_sequence_send(&source_port, &source_channel);
            ibc_storage::set_next_sequence_send(&source_port, &source_channel, sequence.increment());

            // build packet
            let packet = crate::ibc::packet::Packet {
                sequence,
                source_port: source_port.clone(),
                source_channel: source_channel.clone(),
                destination_port: channel.counterparty.port_id.clone(),
                destination_channel: channel.counterparty.channel_id.clone().unwrap_or_else(|| ChannelId::new(b"")),
                data,
                timeout_height,
                timeout_timestamp: Timestamp::from_nanoseconds(timeout_timestamp),
            };

            // store commitment
            let commitment = packet.commitment();
            ibc_storage::set_packet_commitment(&source_port, &source_channel, sequence, &commitment);

            // create relay task for executors
            let bounty = BountyCalculator::calculate(0, 600, 0); // 600 slots deadline
            let task = RelayTask::new(
                RelayTaskType::RecvPacket,
                ChainId::new(b"jam"), // source is JAM
                client_state.chain_id,
                packet,
                alloc::vec![], // proof will be fetched by executor
                Height::zero(),
                timeslot + 600, // ~1 hour deadline
                bounty,
                timeslot,
            );

            // store task
            ibc_storage::set_relay_task(&task);
            ibc_storage::add_pending_task(&task.id);

            // update metrics
            let mut metrics = ibc_storage::get_task_metrics();
            metrics.total_created += 1;
            ibc_storage::set_task_metrics(&metrics);
        }

        IbcWorkItem::RecvPacket { packet, proof_commitment: _, proof_height: _ } => {
            use crate::ibc::channel::Order;
            use crate::ibc::packet::Acknowledgement;

            // get channel
            let channel = match ibc_storage::get_channel(&packet.destination_port, &packet.destination_channel) {
                Some(c) => c,
                None => return,
            };

            // check channel is open
            if !channel.is_open() {
                return;
            }

            // handle based on ordering
            match channel.ordering {
                Order::Unordered => {
                    // check not already received
                    if ibc_storage::get_packet_receipt(&packet.destination_port, &packet.destination_channel, packet.sequence) {
                        return; // already received
                    }
                    // store receipt
                    ibc_storage::set_packet_receipt(&packet.destination_port, &packet.destination_channel, packet.sequence);
                }
                Order::Ordered => {
                    // check sequence matches expected
                    let expected = ibc_storage::get_next_sequence_recv(&packet.destination_port, &packet.destination_channel);
                    if packet.sequence != expected {
                        return;
                    }
                    // increment next sequence
                    ibc_storage::set_next_sequence_recv(&packet.destination_port, &packet.destination_channel, expected.increment());
                }
            }

            // write acknowledgement (success for now)
            let ack = Acknowledgement::success();
            let ack_commitment = ack.commitment();
            ibc_storage::set_packet_ack(&packet.destination_port, &packet.destination_channel, packet.sequence, &ack_commitment);
        }

        IbcWorkItem::AcknowledgePacket { packet, acknowledgement: _, proof_acked: _, proof_height: _ } => {
            // delete packet commitment
            ibc_storage::delete_packet_commitment(&packet.source_port, &packet.source_channel, packet.sequence);

            // update next sequence ack for ordered channels
            let channel = match ibc_storage::get_channel(&packet.source_port, &packet.source_channel) {
                Some(c) => c,
                None => return,
            };

            if channel.ordering == crate::ibc::channel::Order::Ordered {
                let expected = ibc_storage::get_next_sequence_ack(&packet.source_port, &packet.source_channel);
                if packet.sequence == expected {
                    ibc_storage::set_next_sequence_ack(&packet.source_port, &packet.source_channel, expected.increment());
                }
            }
        }

        IbcWorkItem::TimeoutPacket { packet, next_sequence_recv: _, proof_unreceived: _, proof_height: _ } => {
            // delete packet commitment
            ibc_storage::delete_packet_commitment(&packet.source_port, &packet.source_channel, packet.sequence);
        }

        IbcWorkItem::ClaimRelayTask { task_id, executor, signature } => {
            use crate::ibc::relay::TaskStatus;

            // verify signature over task_id
            let msg = task_id.as_slice();
            if !verify_ed25519_sig(&executor, msg, &signature) {
                return;
            }

            // get task
            let mut task = match ibc_storage::get_relay_task(&task_id) {
                Some(t) => t,
                None => return,
            };

            // try to claim
            if task.claim(executor, timeslot) {
                ibc_storage::set_relay_task(&task);
                ibc_storage::remove_pending_task(&task_id);

                // update metrics
                let mut metrics = ibc_storage::get_task_metrics();
                metrics.total_claimed += 1;
                ibc_storage::set_task_metrics(&metrics);
            }
        }

        IbcWorkItem::ConfirmExecution { task_id, dest_tx_hash, inclusion_proof } => {
            // get task
            let mut task = match ibc_storage::get_relay_task(&task_id) {
                Some(t) => t,
                None => return,
            };

            // verify task was claimed and not expired
            if task.status != crate::ibc::relay::TaskStatus::Claimed {
                return;
            }
            if task.is_expired(timeslot) {
                return;
            }

            // verify inclusion proof
            // the proof should show dest_tx_hash is included in a block on destination chain
            if !verify_inclusion_proof(&task, &dest_tx_hash, &inclusion_proof) {
                return;
            }

            // mark as executed
            task.mark_executed();
            ibc_storage::set_relay_task(&task);

            // update metrics and pay bounty
            let mut metrics = ibc_storage::get_task_metrics();
            metrics.total_executed += 1;
            metrics.total_bounties_paid += task.bounty;
            ibc_storage::set_task_metrics(&metrics);

            // TODO: transfer bounty to executor using host::transfer
        }

        IbcWorkItem::ExpireTasks { task_ids } => {
            let mut metrics = ibc_storage::get_task_metrics();

            for task_id in task_ids {
                if let Some(mut task) = ibc_storage::get_relay_task(&task_id) {
                    if task.is_expired(timeslot) {
                        task.expire();
                        ibc_storage::set_relay_task(&task);
                        ibc_storage::add_pending_task(&task_id); // re-add to pending
                        metrics.total_expired += 1;
                    }
                }
            }

            ibc_storage::set_task_metrics(&metrics);
        }

        _ => {
            // other work items not yet implemented
        }
    }
}

/// verify that a transaction was included on destination chain
fn verify_inclusion_proof(
    task: &crate::ibc::relay::RelayTask,
    dest_tx_hash: &crate::ibc::types::Hash32,
    inclusion_proof: &[u8],
) -> bool {
    use crate::ibc::proof::{MerkleProof, verify_membership};

    // the inclusion proof should be a merkle proof showing the tx exists
    // in a block that was finalized on the destination chain

    if inclusion_proof.is_empty() {
        return false;
    }

    // decode proof
    let proof = match MerkleProof::decode(inclusion_proof) {
        Some(p) => p,
        None => return false,
    };

    // get consensus state at proof height to get the merkle root
    // for now, we need to have a recent consensus state from an UpdateClient
    let client_id = match task.dest_chain.0.iter().position(|&b| b == b'-') {
        Some(pos) => {
            // extract client type and build client_id
            // this is simplified - real impl would look up by chain_id
            crate::ibc::types::ClientId::new(&task.dest_chain.0)
        }
        None => return false,
    };

    // simplified verification - in production would verify against actual consensus state
    // the proof should show: tx_hash exists in tx_results merkle tree of a block
    // and that block's header was signed by validators we trust

    // for now, just verify the proof has valid structure
    if proof.ops.is_empty() {
        return false;
    }

    // TODO: full verification requires:
    // 1. get consensus state for dest chain at recent height
    // 2. verify block header containing tx was signed by trusted validators
    // 3. verify tx_hash in tx_results merkle tree of that block

    let _ = (dest_tx_hash, client_id);
    true // stub - accept valid-looking proofs
}

/// verify ed25519 signature
fn verify_ed25519_sig(pub_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
    use ed25519_dalek::{Signature, VerifyingKey, Verifier};

    let verifying_key = match VerifyingKey::from_bytes(pub_key) {
        Ok(k) => k,
        Err(_) => return false,
    };

    // ed25519-dalek 2.x: from_bytes returns Signature directly
    let sig = Signature::from_bytes(signature);

    verifying_key.verify(message, &sig).is_ok()
}
