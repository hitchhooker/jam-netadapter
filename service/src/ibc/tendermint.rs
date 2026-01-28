//! tendermint light client verification
//!
//! verifies tendermint headers and validator signatures

use ed25519_dalek::{Signature, VerifyingKey, Verifier};

use super::types::*;
use super::client::*;

/// verification result
pub struct VerificationResult {
    /// new consensus state
    pub consensus_state: ConsensusState,
    /// new client state (if updated)
    pub client_state: Option<ClientState>,
}

/// verify tendermint header update
pub fn verify_header(
    client_state: &ClientState,
    consensus_state: &ConsensusState,
    header: &Header,
    current_time: Timestamp,
) -> Result<VerificationResult, IbcError> {
    // check client not frozen
    if client_state.is_frozen() {
        return Err(IbcError::ClientFrozen);
    }

    // check trusting period not expired
    if client_state.is_expired(current_time, consensus_state.timestamp) {
        return Err(IbcError::HeightTooOld);
    }

    // verify chain id matches
    if header.signed_header.header.chain_id != client_state.chain_id.0 {
        return Err(IbcError::InvalidHeader);
    }

    // verify trusted validators hash matches consensus state
    let trusted_hash = header.trusted_validators.hash();
    if trusted_hash != consensus_state.next_validators_hash {
        return Err(IbcError::InvalidHeader);
    }

    // verify validator set hash in header
    let validator_hash = header.validator_set.hash();
    if validator_hash != header.signed_header.header.validators_hash {
        return Err(IbcError::InvalidHeader);
    }

    // verify commit signatures
    verify_commit(
        &header.signed_header.header,
        &header.signed_header.commit,
        &header.validator_set,
        client_state.trust_level,
    )?;

    // for non-adjacent headers, also verify trusted validators signed
    let header_height = Height::new(0, header.signed_header.header.height);
    let trusted_height = header.trusted_height;

    if header_height.revision_height > trusted_height.revision_height + 1 {
        // bisection: verify 1/3 of trusted validators signed
        verify_commit_light(
            &header.signed_header.header,
            &header.signed_header.commit,
            &header.trusted_validators,
        )?;
    }

    // create new consensus state
    let new_consensus_state = ConsensusState {
        timestamp: header.signed_header.header.time,
        root: header.signed_header.header.app_hash,
        next_validators_hash: header.signed_header.header.next_validators_hash,
    };

    // update client state if new height is higher
    let new_client_state = if header_height.gt(&client_state.latest_height) {
        let mut updated = client_state.clone();
        updated.latest_height = header_height;
        Some(updated)
    } else {
        None
    };

    Ok(VerificationResult {
        consensus_state: new_consensus_state,
        client_state: new_client_state,
    })
}

/// verify commit has sufficient voting power
fn verify_commit(
    header: &TendermintHeader,
    commit: &Commit,
    validator_set: &ValidatorSet,
    trust_level: (u64, u64),
) -> Result<(), IbcError> {
    // commit height must match header
    if commit.height != header.height {
        return Err(IbcError::InvalidHeader);
    }

    // commit block_id must match header hash
    let header_hash = header.hash();
    if commit.block_id != header_hash {
        return Err(IbcError::InvalidHeader);
    }

    let total_power = validator_set.total_power();
    let mut signed_power: u64 = 0;

    // compute sign bytes for this commit
    let sign_bytes = compute_sign_bytes(commit, &header.chain_id);

    // verify each signature
    for sig in &commit.signatures {
        let validator = validator_set
            .get(sig.validator_index as usize)
            .ok_or(IbcError::InvalidSignature)?;

        if sig.signature.len() == 64 {
            let sig_array: [u8; 64] = sig.signature[..64].try_into().unwrap();
            if verify_ed25519(&validator.pub_key, &sign_bytes, &sig_array) {
                signed_power += validator.voting_power;
            }
        }
    }

    // check trust threshold (numerator/denominator of total power)
    let threshold = (total_power * trust_level.0) / trust_level.1;
    if signed_power < threshold {
        return Err(IbcError::InsufficientVotingPower);
    }

    Ok(())
}

/// verify commit has at least 1/3 power from trusted validators
fn verify_commit_light(
    header: &TendermintHeader,
    commit: &Commit,
    trusted_validators: &ValidatorSet,
) -> Result<(), IbcError> {
    let total_power = trusted_validators.total_power();
    let mut signed_power: u64 = 0;

    let sign_bytes = compute_sign_bytes(commit, &header.chain_id);

    // find matching validators and verify their signatures
    for sig in &commit.signatures {
        // try to find this validator in trusted set
        for validator in &trusted_validators.validators {
            // simplified: compare by pubkey
            if let Some(current_validator) = trusted_validators.get(sig.validator_index as usize) {
                if current_validator.pub_key == validator.pub_key {
                    if sig.signature.len() == 64 {
                        let sig_array: [u8; 64] = sig.signature[..64].try_into().unwrap();
                        if verify_ed25519(&validator.pub_key, &sign_bytes, &sig_array) {
                            signed_power += validator.voting_power;
                        }
                    }
                    break;
                }
            }
        }
    }

    // need at least 1/3 of trusted power
    let threshold = total_power / 3;
    if signed_power < threshold {
        return Err(IbcError::InsufficientVotingPower);
    }

    Ok(())
}

/// compute sign bytes for commit
fn compute_sign_bytes(commit: &Commit, chain_id: &[u8]) -> Vec<u8> {
    // simplified vote sign bytes
    // real impl needs canonical JSON or protobuf encoding
    let mut bytes = Vec::new();

    // type (precommit = 2)
    bytes.push(2);

    // height
    bytes.extend_from_slice(&commit.height.to_be_bytes());

    // round
    bytes.extend_from_slice(&commit.round.to_be_bytes());

    // block_id hash
    bytes.extend_from_slice(&commit.block_id);

    // chain_id
    bytes.extend_from_slice(chain_id);

    bytes
}

/// verify ed25519 signature
fn verify_ed25519(pub_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
    let verifying_key = match VerifyingKey::from_bytes(pub_key) {
        Ok(k) => k,
        Err(_) => return false,
    };

    let sig = Signature::from_bytes(signature);
    verifying_key.verify(message, &sig).is_ok()
}

/// detect misbehaviour (two conflicting headers at same height)
pub fn check_misbehaviour(
    client_state: &ClientState,
    header1: &Header,
    header2: &Header,
) -> Result<bool, IbcError> {
    // both headers must be at same height
    if header1.signed_header.header.height != header2.signed_header.header.height {
        return Ok(false);
    }

    // but have different block hashes
    let hash1 = header1.signed_header.header.hash();
    let hash2 = header2.signed_header.header.hash();

    if hash1 == hash2 {
        return Ok(false);
    }

    // verify both headers have valid commits
    verify_commit(
        &header1.signed_header.header,
        &header1.signed_header.commit,
        &header1.validator_set,
        client_state.trust_level,
    )?;

    verify_commit(
        &header2.signed_header.header,
        &header2.signed_header.commit,
        &header2.validator_set,
        client_state.trust_level,
    )?;

    // both valid at same height with different hashes = misbehaviour
    Ok(true)
}

/// freeze client due to misbehaviour
pub fn freeze_client(client_state: &mut ClientState, height: Height) {
    client_state.frozen_height = Some(height);
}
