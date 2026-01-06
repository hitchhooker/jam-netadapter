//! sla accumulate logic - apply validated sla operations to state

use alloc::vec::Vec;

use crate::host;
use crate::codec;
use crate::sla::*;
use crate::sla_storage;
use crate::refine::RefineOutput;

/// accumulate sla operation
pub fn accumulate_sla(payload: &[u8], _refined: &RefineOutput, timeslot: u32) {
    let (op, _) = match decode_sla_op(&payload[1..]) {
        Some(o) => o,
        None => return,
    };

    match op {
        SlaOp::RegisterProbe { probe_id, zone, endpoint, stake, signature: _ } => {
            let probe = ProbeInfo {
                probe_id,
                stake,
                zone,
                endpoint,
                registered_slot: timeslot,
                last_active_slot: timeslot,
                total_reports: 0,
                accurate_reports: 0,
                reputation: 50,  // start at 50%
            };
            sla_storage::set_probe(&probe);
        }

        SlaOp::RegisterNode { node_id, owner, endpoint, stake, signature: _ } => {
            let node = MonitoredNode {
                node_id,
                owner,
                endpoint,
                stake,
                total_epochs: 0,
                successful_epochs: 0,
                registered_slot: timeslot,
            };
            sla_storage::set_node(&node);
        }

        SlaOp::CreateContract { node_id, customer, required_uptime_percent, max_latency_ms, payment_per_epoch, duration_epochs, signature: _ } => {
            use sha2::{Sha256, Digest};
            let mut hasher = Sha256::new();
            hasher.update(&node_id);
            hasher.update(&customer);
            hasher.update(&timeslot.to_le_bytes());
            let contract_id: [u8; 32] = hasher.finalize().into();

            let current_epoch = timeslot as u64 / EPOCH_DURATION_SLOTS as u64;

            let contract = SlaContract {
                contract_id,
                node_id,
                customer,
                required_uptime_percent,
                max_latency_ms,
                payment_per_epoch,
                start_epoch: current_epoch,
                end_epoch: current_epoch + duration_epochs,
                total_paid: 0,
                active: true,
            };
            sla_storage::set_contract(&contract);
        }

        SlaOp::SubmitCommitment { probe_id, node_id, epoch, hash, signature: _ } => {
            let commitment = Commitment {
                probe_id,
                node_id,
                epoch,
                hash,
                submitted_slot: timeslot,
            };
            sla_storage::set_commitment(&commitment);

            // update probe last active
            if let Some(mut probe) = sla_storage::get_probe(&probe_id) {
                probe.last_active_slot = timeslot;
                sla_storage::set_probe(&probe);
            }
        }

        SlaOp::RevealMeasurement { probe_id, node_id, epoch, result, latency_ms, blinding_factor, signature } => {
            let report = RevealedReport {
                probe_id,
                node_id,
                epoch,
                result,
                latency_ms,
                blinding_factor,
                signature,
            };
            sla_storage::set_revealed(&report);

            // update probe last active
            if let Some(mut probe) = sla_storage::get_probe(&probe_id) {
                probe.last_active_slot = timeslot;
                sla_storage::set_probe(&probe);
            }
        }

        SlaOp::DirectSubmit { probe_id, node_id, epoch, result, latency_ms, signature } => {
            // direct submit is stored as revealed (no commitment needed)
            let report = RevealedReport {
                probe_id,
                node_id,
                epoch,
                result,
                latency_ms,
                blinding_factor: [0u8; 32],  // no blinding for direct
                signature,
            };
            sla_storage::set_revealed(&report);

            // update probe
            if let Some(mut probe) = sla_storage::get_probe(&probe_id) {
                probe.last_active_slot = timeslot;
                sla_storage::set_probe(&probe);
            }
        }

        SlaOp::FinalizeEpoch { node_id, epoch } => {
            // collect all revealed reports for this epoch/node
            // NOTE: in real implementation, we'd iterate storage or use an index
            // for now, we compute consensus from what we can access
            let reports = Vec::new();

            // try to get reports from known probes
            // this is a simplification - in practice we'd have a list of assigned probes
            // or iterate the storage prefix

            // compute consensus
            let mut result = compute_consensus(&reports);
            result.finalized_slot = timeslot;
            result.node_id = node_id;
            result.epoch = epoch;

            sla_storage::set_epoch_result(&result);

            // update node stats
            if let Some(mut node) = sla_storage::get_node(&node_id) {
                node.total_epochs += 1;
                if result.node_up {
                    node.successful_epochs += 1;
                }
                sla_storage::set_node(&node);
            }

            // update probe reputations based on consensus
            for report in &reports {
                if let Some(mut probe) = sla_storage::get_probe(&report.probe_id) {
                    let matched = match report.result {
                        MeasurementResult::Up => result.node_up,
                        MeasurementResult::Down | MeasurementResult::Timeout => !result.node_up,
                        MeasurementResult::Degraded => true,  // degraded is neutral
                    };
                    update_reputation(&mut probe, matched);
                    sla_storage::set_probe(&probe);
                }
            }
        }

        SlaOp::SlashProbe { probe_id, reason, evidence: _, signature: _ } => {
            if let Some(mut probe) = sla_storage::get_probe(&probe_id) {
                let slash_percent = reason.slash_percent();
                let slash_amount = (probe.stake * slash_percent as u64) / 100;
                probe.stake = probe.stake.saturating_sub(slash_amount);
                probe.reputation = probe.reputation.saturating_sub(20);

                if probe.stake < MIN_PROBE_STAKE {
                    // probe is now invalid, remove
                    sla_storage::delete_probe(&probe_id);
                } else {
                    sla_storage::set_probe(&probe);
                }
            }
        }

        SlaOp::UnregisterProbe { probe_id, signature: _ } => {
            sla_storage::delete_probe(&probe_id);
            // TODO: return stake to probe owner
        }
    }
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
            if data.len() < offset + 32 + 1 {
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

        1 => {
            // RegisterNode
            if data.len() < offset + 32 + 32 {
                return None;
            }
            let mut node_id = [0u8; 32];
            node_id.copy_from_slice(&data[offset..offset + 32]);
            offset += 32;

            let mut owner = [0u8; 32];
            owner.copy_from_slice(&data[offset..offset + 32]);
            offset += 32;

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

            Some((SlaOp::RegisterNode {
                node_id,
                owner,
                endpoint: endpoint.to_vec(),
                stake,
                signature,
            }, offset))
        }

        // ... other ops follow same pattern
        _ => None,
    }
}
