//! privacy accumulate logic - apply validated private operations to state
//!
//! handles:
//! - marking nullifiers as spent
//! - adding new commitments to merkle tree
//! - updating merkle root

use alloc::vec::Vec;

use crate::types::Hash;
use crate::refine::RefineOutput;
use crate::privacy::{PrivateOp, SpendData, OutputData};
use crate::privacy_storage;

/// accumulate private operation
pub fn accumulate_private(payload: &[u8], _refined: &RefineOutput, timeslot: u32) {
    let (op, _) = match PrivateOp::decode(&payload[1..]) {
        Some(o) => o,
        None => return,
    };

    match op {
        PrivateOp::Spend { nullifier, anchor: _, proof: _ } => {
            // mark nullifier as spent
            privacy_storage::set_nullifier(&nullifier, timeslot);
        }

        PrivateOp::Output { commitment, encrypted_note: _ } => {
            // add commitment to merkle tree
            privacy_storage::add_commitment(&commitment);

            // store anchor history for this slot
            if let Some(root) = privacy_storage::get_merkle_root() {
                privacy_storage::store_anchor_history(timeslot, &root);
            }
        }

        PrivateOp::Transaction { spends, outputs, fee: _, binding_signature: _ } => {
            // process all spends
            for spend in &spends {
                privacy_storage::set_nullifier(&spend.nullifier, timeslot);
            }

            // process all outputs
            for output in &outputs {
                privacy_storage::add_commitment(&output.commitment);
            }

            // store anchor history
            if let Some(root) = privacy_storage::get_merkle_root() {
                privacy_storage::store_anchor_history(timeslot, &root);
            }
        }
    }
}

/// batch accumulate multiple private operations
/// more efficient than individual calls
pub fn accumulate_private_batch(
    ops: &[PrivateOp],
    timeslot: u32,
) {
    let mut nullifiers_to_add: Vec<Hash> = Vec::new();
    let mut commitments_to_add: Vec<Hash> = Vec::new();

    // collect all nullifiers and commitments
    for op in ops {
        match op {
            PrivateOp::Spend { nullifier, .. } => {
                nullifiers_to_add.push(*nullifier);
            }
            PrivateOp::Output { commitment, .. } => {
                commitments_to_add.push(*commitment);
            }
            PrivateOp::Transaction { spends, outputs, .. } => {
                for spend in spends {
                    nullifiers_to_add.push(spend.nullifier);
                }
                for output in outputs {
                    commitments_to_add.push(output.commitment);
                }
            }
        }
    }

    // batch mark nullifiers
    for nullifier in &nullifiers_to_add {
        privacy_storage::set_nullifier(nullifier, timeslot);
    }

    // batch add commitments
    for commitment in &commitments_to_add {
        privacy_storage::add_commitment(commitment);
    }

    // store final anchor
    if let Some(root) = privacy_storage::get_merkle_root() {
        privacy_storage::store_anchor_history(timeslot, &root);
    }
}

/// get current privacy state summary
pub struct PrivacyStateSummary {
    pub tree_size: u64,
    pub merkle_root: Option<Hash>,
    pub tree_depth: u32,
}

pub fn get_privacy_state() -> PrivacyStateSummary {
    PrivacyStateSummary {
        tree_size: privacy_storage::get_tree_size(),
        merkle_root: privacy_storage::get_merkle_root(),
        tree_depth: privacy_storage::get_tree_depth(),
    }
}

/// check if a note can be spent (not already spent)
pub fn can_spend(nullifier: &Hash) -> bool {
    !privacy_storage::nullifier_exists(nullifier)
}

/// get merkle proof for a commitment
pub fn get_inclusion_proof(position: u64) -> Option<Vec<Hash>> {
    // verify position is valid
    if position >= privacy_storage::get_tree_size() {
        return None;
    }

    Some(privacy_storage::get_merkle_proof(position))
}
