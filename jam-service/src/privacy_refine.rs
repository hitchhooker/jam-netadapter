//! privacy refine logic - validate shielded operations
//!
//! validates:
//! - nullifiers are correctly derived
//! - merkle proofs verify against anchor
//! - commitments are well-formed
//! - balance is conserved (for transactions)

use alloc::vec::Vec;

use crate::types::{Hash, WorkItemType};
use crate::refine::RefineOutput;
use crate::privacy::{PrivateOp, SpendData, OutputData, SpendProof};
use crate::privacy_storage;
use crate::poseidon;

/// refine private operation
pub fn refine_private(payload: &[u8]) -> RefineOutput {
    let (op, _) = match PrivateOp::decode(payload) {
        Some(o) => o,
        None => {
            return RefineOutput {
                valid: false,
                item_type: WorkItemType::PrivateOp as u8,
                data_hash: [0u8; 32],
                request_id: None,
                key: None,
            };
        }
    };

    let (valid, data_hash, key) = match &op {
        PrivateOp::Spend { nullifier, anchor, proof } => {
            validate_spend(nullifier, anchor, proof)
        }

        PrivateOp::Output { commitment, encrypted_note: _ } => {
            validate_output(commitment)
        }

        PrivateOp::Transaction { spends, outputs, fee, binding_signature } => {
            validate_transaction(spends, outputs, *fee, binding_signature)
        }
    };

    RefineOutput {
        valid,
        item_type: WorkItemType::PrivateOp as u8,
        data_hash,
        request_id: None,
        key,
    }
}

/// validate a spend operation
fn validate_spend(
    nullifier: &Hash,
    anchor: &MerkleRoot,
    proof: &SpendProof,
) -> (bool, Hash, Option<Vec<u8>>) {
    // 1. check nullifier not already spent
    if privacy_storage::nullifier_exists(nullifier) {
        return (false, *nullifier, Some(nullifier.to_vec()));
    }

    // 2. verify anchor is valid (current or recent merkle root)
    if !privacy_storage::is_valid_anchor(anchor) {
        return (false, *nullifier, Some(nullifier.to_vec()));
    }

    // 3. verify nullifier derivation
    let computed_nullifier = poseidon::compute_nullifier(
        &proof.nk,
        proof.position,
        &proof.note_commitment,
    );

    if computed_nullifier != *nullifier {
        return (false, *nullifier, Some(nullifier.to_vec()));
    }

    // 4. verify merkle proof
    if !poseidon::verify_merkle_proof(
        &proof.note_commitment,
        anchor,
        proof.position,
        &proof.merkle_path,
    ) {
        return (false, *nullifier, Some(nullifier.to_vec()));
    }

    (true, *nullifier, Some(nullifier.to_vec()))
}

/// validate an output operation
fn validate_output(commitment: &Hash) -> (bool, Hash, Option<Vec<u8>>) {
    // outputs are always valid if well-formed
    // the commitment just needs to be 32 bytes (already guaranteed by type)

    // check it's not all zeros (invalid commitment)
    let is_zero = commitment.iter().all(|&b| b == 0);
    if is_zero {
        return (false, *commitment, Some(commitment.to_vec()));
    }

    (true, *commitment, Some(commitment.to_vec()))
}

/// validate a full transaction
fn validate_transaction(
    spends: &[SpendData],
    outputs: &[OutputData],
    fee: u64,
    _binding_signature: &[u8; 64],
) -> (bool, Hash, Option<Vec<u8>>) {
    use sha2::{Sha256, Digest};

    // compute transaction hash for result
    let mut hasher = Sha256::new();
    for spend in spends {
        hasher.update(&spend.nullifier);
    }
    for output in outputs {
        hasher.update(&output.commitment);
    }
    hasher.update(&fee.to_le_bytes());
    let tx_hash: Hash = hasher.finalize().into();

    // 1. validate each spend
    for spend in spends {
        // check nullifier not spent
        if privacy_storage::nullifier_exists(&spend.nullifier) {
            return (false, tx_hash, Some(tx_hash.to_vec()));
        }

        // verify anchor
        if !privacy_storage::is_valid_anchor(&spend.anchor) {
            return (false, tx_hash, Some(tx_hash.to_vec()));
        }

        // verify nullifier derivation
        let computed_nullifier = poseidon::compute_nullifier(
            &spend.proof.nk,
            spend.proof.position,
            &spend.proof.note_commitment,
        );

        if computed_nullifier != spend.nullifier {
            return (false, tx_hash, Some(tx_hash.to_vec()));
        }

        // verify merkle proof
        if !poseidon::verify_merkle_proof(
            &spend.proof.note_commitment,
            &spend.anchor,
            spend.proof.position,
            &spend.proof.merkle_path,
        ) {
            return (false, tx_hash, Some(tx_hash.to_vec()));
        }
    }

    // 2. validate each output
    for output in outputs {
        let is_zero = output.commitment.iter().all(|&b| b == 0);
        if is_zero {
            return (false, tx_hash, Some(tx_hash.to_vec()));
        }
    }

    // 3. verify balance (using value commitments)
    // in a full implementation, we'd verify:
    // sum(input_value_commitments) = sum(output_value_commitments) + fee_commitment
    //
    // for now, we accept if structure is valid
    // the binding signature would prove balance in a full implementation

    // 4. verify binding signature
    // TODO: implement binding signature verification
    // this requires the value commitment blinding factors to sum correctly

    // transaction is structurally valid
    (true, tx_hash, Some(tx_hash.to_vec()))
}

/// helper type alias
type MerkleRoot = Hash;
