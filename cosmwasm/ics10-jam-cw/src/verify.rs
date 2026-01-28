//! verification functions

use std::collections::HashSet;

use crate::error::ContractError;
use crate::types::*;

/// slot duration in nanoseconds
const SLOT_DURATION_NS: u64 = 6_000_000_000;

/// jam common era start
const JAM_COMMON_ERA: u64 = 1735732800;

/// verification result
pub struct VerificationResult {
    pub new_consensus_state: JamConsensusState,
    pub new_client_state: Option<JamClientState>,
}

/// verify jam header with finality proof
pub fn verify_jam_header(
    client_state: &JamClientState,
    trusted_consensus: &JamConsensusState,
    header_with_proof: &JamHeaderWithProof,
) -> Result<VerificationResult, ContractError> {
    if client_state.is_frozen() {
        return Err(ContractError::ClientFrozen);
    }

    let header = &header_with_proof.header;
    let proof = &header_with_proof.finality_proof;

    if header.timeslot <= trusted_consensus.slot {
        return Err(ContractError::HeightTooOld);
    }

    // verify ancestry
    verify_ancestry(trusted_consensus, header, &header_with_proof.ancestry)?;

    // verify grandpa proof
    verify_grandpa_proof(
        &client_state.current_authorities,
        client_state.current_set_id,
        proof,
        &header.hash(),
        header.timeslot,
    )?;

    // check for authority set change
    let new_authorities = header.epoch_marker.as_ref().map(|em| {
        authorities_from_epoch_marker(em, client_state.current_set_id + 1)
    });

    let new_consensus = JamConsensusState {
        slot: header.timeslot,
        state_root: header.state_root,
        block_hash: header.hash(),
        timestamp: slot_to_timestamp(header.timeslot),
    };

    let new_client = {
        let mut new_state = client_state.clone();
        new_state.latest_slot = header.timeslot;
        if let Some(auths) = new_authorities {
            new_state.current_authorities = auths;
            new_state.current_set_id += 1;
        }
        Some(new_state)
    };

    Ok(VerificationResult {
        new_consensus_state: new_consensus,
        new_client_state: new_client,
    })
}

/// verify grandpa finality proof
pub fn verify_grandpa_proof(
    authorities: &AuthoritySet,
    set_id: u64,
    proof: &GrandpaFinalityProof,
    target_hash: &Hash32,
    target_number: u32,
) -> Result<(), ContractError> {
    if &proof.target_hash != target_hash || proof.target_number != target_number {
        return Err(ContractError::InvalidProof);
    }

    let mut valid_weight = 0u64;
    let mut seen_voters = HashSet::new();

    for signed in &proof.precommits {
        let authority = authorities.get(signed.authority_index as usize)
            .ok_or(ContractError::InvalidSignature)?;

        if !seen_voters.insert(signed.authority_index) {
            continue;
        }

        if signed.precommit.target_hash != proof.target_hash {
            continue;
        }

        let message = signed.precommit.signing_message(proof.round, set_id);
        verify_ed25519(&authority.ed25519_key, &message, &signed.signature)?;

        valid_weight += authority.weight;
    }

    let threshold = (authorities.total_weight() * 2 / 3) + 1;
    if valid_weight < threshold {
        return Err(ContractError::InsufficientVotingPower);
    }

    Ok(())
}

/// verify ancestry chain
fn verify_ancestry(
    trusted: &JamConsensusState,
    target: &JamHeader,
    ancestry: &[JamHeader],
) -> Result<(), ContractError> {
    if ancestry.is_empty() {
        if target.parent_hash != trusted.block_hash {
            return Err(ContractError::InvalidHeader);
        }
        return Ok(());
    }

    let mut expected_hash = trusted.block_hash;

    for header in ancestry {
        if header.parent_hash != expected_hash {
            return Err(ContractError::InvalidHeader);
        }
        expected_hash = header.hash();
    }

    if target.parent_hash != expected_hash {
        return Err(ContractError::InvalidHeader);
    }

    Ok(())
}

/// check misbehavior
pub fn check_misbehavior(
    client_state: &JamClientState,
    misbehavior: &JamMisbehavior,
) -> Result<u32, ContractError> {
    let h1 = &misbehavior.header_1;
    let h2 = &misbehavior.header_2;

    if h1.timeslot != h2.timeslot {
        return Err(ContractError::InvalidHeader);
    }

    if h1.state_root == h2.state_root {
        return Err(ContractError::InvalidHeader);
    }

    verify_grandpa_proof(
        &client_state.current_authorities,
        client_state.current_set_id,
        &misbehavior.proof_1,
        &h1.hash(),
        h1.timeslot,
    )?;

    verify_grandpa_proof(
        &client_state.current_authorities,
        client_state.current_set_id,
        &misbehavior.proof_2,
        &h2.hash(),
        h2.timeslot,
    )?;

    Ok(h1.timeslot)
}

/// verify jam state proof
pub fn verify_jam_state_proof(
    proof: &JamStateProof,
    state_root: &Hash32,
) -> Result<(), ContractError> {
    let mut current = blake2b_256(&[&proof.key[..], &proof.value[..]].concat());

    for node in &proof.proof {
        let combined = if node.position == 0 {
            [&node.hash[..], &current[..]].concat()
        } else {
            [&current[..], &node.hash[..]].concat()
        };
        current = blake2b_256(&combined);
    }

    if &current != state_root {
        return Err(ContractError::InvalidProof);
    }

    Ok(())
}

/// blake2b-256 hash
pub fn blake2b_256(data: &[u8]) -> Hash32 {
    use blake2::{Blake2b, Digest};
    use blake2::digest::consts::U32;

    let mut hasher = Blake2b::<U32>::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// verify ed25519 signature
fn verify_ed25519(
    pubkey: &Hash32,
    message: &[u8],
    signature: &[u8],
) -> Result<(), ContractError> {
    use ed25519_dalek::{Signature, VerifyingKey, Verifier};

    let key = VerifyingKey::from_bytes(pubkey)
        .map_err(|_| ContractError::InvalidSignature)?;

    if signature.len() != 64 {
        return Err(ContractError::InvalidSignature);
    }

    let sig_bytes: [u8; 64] = signature.try_into()
        .map_err(|_| ContractError::InvalidSignature)?;

    let sig = Signature::from_bytes(&sig_bytes);

    key.verify(message, &sig)
        .map_err(|_| ContractError::InvalidSignature)?;

    Ok(())
}

fn slot_to_timestamp(slot: u32) -> u64 {
    JAM_COMMON_ERA * 1_000_000_000 + (slot as u64) * SLOT_DURATION_NS
}

fn authorities_from_epoch_marker(marker: &EpochMarker, new_set_id: u64) -> AuthoritySet {
    let authorities = marker.validators.iter().map(|v| {
        Authority {
            ed25519_key: v.ed25519_key,
            bandersnatch_key: v.bandersnatch_key,
            weight: 1,
        }
    }).collect();

    AuthoritySet {
        set_id: new_set_id,
        authorities,
    }
}
