//! tendermint light client types and verification
//!
//! implements ics-007 tendermint client

use alloc::vec::Vec;
use sha2::{Sha256, Digest};
use crate::ibc::types::*;

/// tendermint client state
#[derive(Clone, Debug)]
pub struct TendermintClientState {
    pub chain_id: ChainId,
    /// trust threshold numerator/denominator (e.g., 2/3)
    pub trust_threshold_num: u64,
    pub trust_threshold_den: u64,
    /// trusting period in nanoseconds
    pub trusting_period: u64,
    /// unbonding period in nanoseconds
    pub unbonding_period: u64,
    /// max clock drift in nanoseconds
    pub max_clock_drift: u64,
    /// latest verified height
    pub latest_height: Height,
    /// frozen height (if misbehaviour detected)
    pub frozen_height: Option<Height>,
}

impl TendermintClientState {
    pub fn is_frozen(&self) -> bool {
        self.frozen_height.is_some()
    }

    pub fn is_expired(&self, current_time: u64, consensus_time: u64) -> bool {
        current_time.saturating_sub(consensus_time) > self.trusting_period
    }

    pub fn encode(&self, buf: &mut Vec<u8>) {
        self.chain_id.encode(buf);
        buf.extend_from_slice(&self.trust_threshold_num.to_le_bytes());
        buf.extend_from_slice(&self.trust_threshold_den.to_le_bytes());
        buf.extend_from_slice(&self.trusting_period.to_le_bytes());
        buf.extend_from_slice(&self.unbonding_period.to_le_bytes());
        buf.extend_from_slice(&self.max_clock_drift.to_le_bytes());
        self.latest_height.encode(buf);
        match &self.frozen_height {
            Some(h) => {
                buf.push(1);
                h.encode(buf);
            }
            None => buf.push(0),
        }
    }

    pub fn decode(data: &[u8]) -> Option<Self> {
        let mut offset = 0;

        let (chain_id, len) = ChainId::decode(&data[offset..])?;
        offset += len;

        if data.len() < offset + 56 {
            return None;
        }

        let trust_threshold_num = u64::from_le_bytes(data[offset..offset + 8].try_into().ok()?);
        offset += 8;
        let trust_threshold_den = u64::from_le_bytes(data[offset..offset + 8].try_into().ok()?);
        offset += 8;
        let trusting_period = u64::from_le_bytes(data[offset..offset + 8].try_into().ok()?);
        offset += 8;
        let unbonding_period = u64::from_le_bytes(data[offset..offset + 8].try_into().ok()?);
        offset += 8;
        let max_clock_drift = u64::from_le_bytes(data[offset..offset + 8].try_into().ok()?);
        offset += 8;

        let latest_height = Height::decode(&data[offset..])?;
        offset += 16;

        let frozen_height = if data.get(offset)? == &1 {
            offset += 1;
            let h = Height::decode(&data[offset..])?;
            Some(h)
        } else {
            None
        };

        Some(Self {
            chain_id,
            trust_threshold_num,
            trust_threshold_den,
            trusting_period,
            unbonding_period,
            max_clock_drift,
            latest_height,
            frozen_height,
        })
    }
}

/// tendermint consensus state
#[derive(Clone, Debug)]
pub struct TendermintConsensusState {
    /// timestamp in nanoseconds
    pub timestamp: u64,
    /// merkle root (app_hash)
    pub root: CommitmentRoot,
    /// hash of next validator set
    pub next_validators_hash: Hash32,
}

impl TendermintConsensusState {
    pub fn encode(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.timestamp.to_le_bytes());
        self.root.encode(buf);
        buf.extend_from_slice(&self.next_validators_hash);
    }

    pub fn decode(data: &[u8]) -> Option<Self> {
        if data.len() < 8 + 32 + 32 {
            return None;
        }

        let timestamp = u64::from_le_bytes(data[0..8].try_into().ok()?);
        let root = CommitmentRoot::decode(&data[8..])?;

        let mut next_validators_hash = [0u8; 32];
        next_validators_hash.copy_from_slice(&data[40..72]);

        Some(Self { timestamp, root, next_validators_hash })
    }
}

/// tendermint header for client updates
#[derive(Clone, Debug)]
pub struct TendermintHeader {
    /// signed header (block header + commit)
    pub signed_header: SignedHeader,
    /// validator set that signed the commit
    pub validator_set: ValidatorSet,
    /// trusted height (for bisection)
    pub trusted_height: Height,
    /// trusted validator set (at trusted_height)
    pub trusted_validators: ValidatorSet,
}

impl TendermintHeader {
    pub fn height(&self) -> Height {
        self.signed_header.header.height
    }

    pub fn encode(&self, buf: &mut Vec<u8>) {
        self.signed_header.encode(buf);
        self.validator_set.encode(buf);
        self.trusted_height.encode(buf);
        self.trusted_validators.encode(buf);
    }

    pub fn decode(data: &[u8]) -> Option<Self> {
        let mut offset = 0;

        let (signed_header, len) = SignedHeader::decode(&data[offset..])?;
        offset += len;

        let (validator_set, len) = ValidatorSet::decode(&data[offset..])?;
        offset += len;

        let trusted_height = Height::decode(&data[offset..])?;
        offset += 16;

        let (trusted_validators, _) = ValidatorSet::decode(&data[offset..])?;

        Some(Self {
            signed_header,
            validator_set,
            trusted_height,
            trusted_validators,
        })
    }
}

/// signed block header
#[derive(Clone, Debug)]
pub struct SignedHeader {
    pub header: BlockHeader,
    pub commit: Commit,
}

impl SignedHeader {
    pub fn encode(&self, buf: &mut Vec<u8>) {
        self.header.encode(buf);
        self.commit.encode(buf);
    }

    pub fn decode(data: &[u8]) -> Option<(Self, usize)> {
        let mut offset = 0;

        let (header, len) = BlockHeader::decode(&data[offset..])?;
        offset += len;

        let (commit, len) = Commit::decode(&data[offset..])?;
        offset += len;

        Some((Self { header, commit }, offset))
    }
}

/// tendermint block header
#[derive(Clone, Debug)]
pub struct BlockHeader {
    pub chain_id: ChainId,
    pub height: Height,
    pub time: u64, // nanoseconds since epoch
    pub validators_hash: Hash32,
    pub next_validators_hash: Hash32,
    pub app_hash: Hash32, // this becomes the commitment root
}

impl BlockHeader {
    /// compute header hash (simplified - real implementation uses amino/protobuf)
    pub fn hash(&self) -> Hash32 {
        let mut hasher = Sha256::new();
        hasher.update(&self.chain_id.0);
        hasher.update(&self.height.revision_height.to_be_bytes());
        hasher.update(&self.time.to_be_bytes());
        hasher.update(&self.validators_hash);
        hasher.update(&self.next_validators_hash);
        hasher.update(&self.app_hash);
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }

    pub fn encode(&self, buf: &mut Vec<u8>) {
        self.chain_id.encode(buf);
        self.height.encode(buf);
        buf.extend_from_slice(&self.time.to_le_bytes());
        buf.extend_from_slice(&self.validators_hash);
        buf.extend_from_slice(&self.next_validators_hash);
        buf.extend_from_slice(&self.app_hash);
    }

    pub fn decode(data: &[u8]) -> Option<(Self, usize)> {
        let mut offset = 0;

        let (chain_id, len) = ChainId::decode(&data[offset..])?;
        offset += len;

        let height = Height::decode(&data[offset..])?;
        offset += 16;

        if data.len() < offset + 8 + 96 {
            return None;
        }

        let time = u64::from_le_bytes(data[offset..offset + 8].try_into().ok()?);
        offset += 8;

        let mut validators_hash = [0u8; 32];
        validators_hash.copy_from_slice(&data[offset..offset + 32]);
        offset += 32;

        let mut next_validators_hash = [0u8; 32];
        next_validators_hash.copy_from_slice(&data[offset..offset + 32]);
        offset += 32;

        let mut app_hash = [0u8; 32];
        app_hash.copy_from_slice(&data[offset..offset + 32]);
        offset += 32;

        Some((Self {
            chain_id,
            height,
            time,
            validators_hash,
            next_validators_hash,
            app_hash,
        }, offset))
    }
}

/// commit with validator signatures
#[derive(Clone, Debug)]
pub struct Commit {
    pub height: Height,
    pub round: u32,
    pub block_id: BlockId,
    pub signatures: Vec<CommitSig>,
}

impl Commit {
    pub fn encode(&self, buf: &mut Vec<u8>) {
        self.height.encode(buf);
        buf.extend_from_slice(&self.round.to_le_bytes());
        self.block_id.encode(buf);
        buf.extend_from_slice(&(self.signatures.len() as u32).to_le_bytes());
        for sig in &self.signatures {
            sig.encode(buf);
        }
    }

    pub fn decode(data: &[u8]) -> Option<(Self, usize)> {
        let mut offset = 0;

        let height = Height::decode(&data[offset..])?;
        offset += 16;

        if data.len() < offset + 4 {
            return None;
        }
        let round = u32::from_le_bytes(data[offset..offset + 4].try_into().ok()?);
        offset += 4;

        let (block_id, len) = BlockId::decode(&data[offset..])?;
        offset += len;

        if data.len() < offset + 4 {
            return None;
        }
        let sig_count = u32::from_le_bytes(data[offset..offset + 4].try_into().ok()?) as usize;
        offset += 4;

        let mut signatures = Vec::with_capacity(sig_count);
        for _ in 0..sig_count {
            let (sig, len) = CommitSig::decode(&data[offset..])?;
            offset += len;
            signatures.push(sig);
        }

        Some((Self { height, round, block_id, signatures }, offset))
    }
}

/// block identifier
#[derive(Clone, Debug)]
pub struct BlockId {
    pub hash: Hash32,
    pub parts_total: u32,
    pub parts_hash: Hash32,
}

impl BlockId {
    pub fn encode(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.hash);
        buf.extend_from_slice(&self.parts_total.to_le_bytes());
        buf.extend_from_slice(&self.parts_hash);
    }

    pub fn decode(data: &[u8]) -> Option<(Self, usize)> {
        if data.len() < 68 {
            return None;
        }

        let mut hash = [0u8; 32];
        hash.copy_from_slice(&data[0..32]);

        let parts_total = u32::from_le_bytes(data[32..36].try_into().ok()?);

        let mut parts_hash = [0u8; 32];
        parts_hash.copy_from_slice(&data[36..68]);

        Some((Self { hash, parts_total, parts_hash }, 68))
    }
}

/// commit signature
#[derive(Clone, Debug)]
pub struct CommitSig {
    pub block_id_flag: BlockIdFlag,
    pub validator_address: [u8; 20],
    pub timestamp: u64,
    pub signature: Option<[u8; 64]>, // ed25519 signature
}

impl CommitSig {
    pub fn encode(&self, buf: &mut Vec<u8>) {
        buf.push(self.block_id_flag as u8);
        buf.extend_from_slice(&self.validator_address);
        buf.extend_from_slice(&self.timestamp.to_le_bytes());
        match &self.signature {
            Some(sig) => {
                buf.push(1);
                buf.extend_from_slice(sig);
            }
            None => buf.push(0),
        }
    }

    pub fn decode(data: &[u8]) -> Option<(Self, usize)> {
        let mut offset = 0;

        let block_id_flag = BlockIdFlag::from_u8(*data.get(offset)?)?;
        offset += 1;

        if data.len() < offset + 20 {
            return None;
        }
        let mut validator_address = [0u8; 20];
        validator_address.copy_from_slice(&data[offset..offset + 20]);
        offset += 20;

        if data.len() < offset + 8 {
            return None;
        }
        let timestamp = u64::from_le_bytes(data[offset..offset + 8].try_into().ok()?);
        offset += 8;

        let signature = if data.get(offset)? == &1 {
            offset += 1;
            if data.len() < offset + 64 {
                return None;
            }
            let mut sig = [0u8; 64];
            sig.copy_from_slice(&data[offset..offset + 64]);
            offset += 64;
            Some(sig)
        } else {
            offset += 1;
            None
        };

        Some((Self { block_id_flag, validator_address, timestamp, signature }, offset))
    }
}

/// block id flag for commit signatures
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum BlockIdFlag {
    Absent = 1,
    Commit = 2,
    Nil = 3,
}

impl BlockIdFlag {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::Absent),
            2 => Some(Self::Commit),
            3 => Some(Self::Nil),
            _ => None,
        }
    }
}

/// validator set
#[derive(Clone, Debug)]
pub struct ValidatorSet {
    pub validators: Vec<Validator>,
    pub total_voting_power: u64,
}

impl ValidatorSet {
    pub fn hash(&self) -> Hash32 {
        // simplified merkle hash of validators
        let mut hasher = Sha256::new();
        for v in &self.validators {
            hasher.update(&v.address);
            hasher.update(&v.pub_key);
            hasher.update(&v.voting_power.to_be_bytes());
        }
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }

    pub fn encode(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&(self.validators.len() as u32).to_le_bytes());
        for v in &self.validators {
            v.encode(buf);
        }
        buf.extend_from_slice(&self.total_voting_power.to_le_bytes());
    }

    pub fn decode(data: &[u8]) -> Option<(Self, usize)> {
        let mut offset = 0;

        if data.len() < 4 {
            return None;
        }
        let val_count = u32::from_le_bytes(data[offset..offset + 4].try_into().ok()?) as usize;
        offset += 4;

        let mut validators = Vec::with_capacity(val_count);
        for _ in 0..val_count {
            let (v, len) = Validator::decode(&data[offset..])?;
            offset += len;
            validators.push(v);
        }

        if data.len() < offset + 8 {
            return None;
        }
        let total_voting_power = u64::from_le_bytes(data[offset..offset + 8].try_into().ok()?);
        offset += 8;

        Some((Self { validators, total_voting_power }, offset))
    }
}

/// validator info
#[derive(Clone, Debug)]
pub struct Validator {
    pub address: [u8; 20],
    pub pub_key: [u8; 32], // ed25519 public key
    pub voting_power: u64,
}

impl Validator {
    pub fn encode(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.address);
        buf.extend_from_slice(&self.pub_key);
        buf.extend_from_slice(&self.voting_power.to_le_bytes());
    }

    pub fn decode(data: &[u8]) -> Option<(Self, usize)> {
        if data.len() < 60 {
            return None;
        }

        let mut address = [0u8; 20];
        address.copy_from_slice(&data[0..20]);

        let mut pub_key = [0u8; 32];
        pub_key.copy_from_slice(&data[20..52]);

        let voting_power = u64::from_le_bytes(data[52..60].try_into().ok()?);

        Some((Self { address, pub_key, voting_power }, 60))
    }
}

// ============================================================================
// header verification
// ============================================================================

/// verify tendermint header
pub fn verify_header(
    client_state: &TendermintClientState,
    consensus_state: &TendermintConsensusState,
    header: &TendermintHeader,
    current_time: u64,
) -> Result<(), IbcError> {
    // 1. check client is not frozen
    if client_state.is_frozen() {
        return Err(IbcError::ClientFrozen);
    }

    // 2. check within trusting period
    if client_state.is_expired(current_time, consensus_state.timestamp) {
        return Err(IbcError::ClientExpired);
    }

    // 3. check header height > trusted height
    if header.height() <= header.trusted_height {
        return Err(IbcError::InvalidHeight);
    }

    // 4. check chain_id matches
    if header.signed_header.header.chain_id.0 != client_state.chain_id.0 {
        return Err(IbcError::InvalidProof);
    }

    // 5. verify validators_hash matches trusted consensus state
    let trusted_val_hash = header.trusted_validators.hash();
    if trusted_val_hash != consensus_state.next_validators_hash {
        return Err(IbcError::InvalidProof);
    }

    // 6. verify commit signatures (2/3+ voting power)
    verify_commit_signatures(
        &header.signed_header,
        &header.validator_set,
        client_state.trust_threshold_num,
        client_state.trust_threshold_den,
    )?;

    Ok(())
}

/// verify commit has sufficient signatures
fn verify_commit_signatures(
    signed_header: &SignedHeader,
    validator_set: &ValidatorSet,
    trust_num: u64,
    trust_den: u64,
) -> Result<(), IbcError> {
    let mut signed_power: u64 = 0;
    let total_power = validator_set.total_voting_power;

    // build map of validator address -> validator
    for sig in &signed_header.commit.signatures {
        if sig.block_id_flag != BlockIdFlag::Commit {
            continue;
        }

        // find validator by address
        let validator = validator_set.validators.iter()
            .find(|v| v.address == sig.validator_address);

        let validator = match validator {
            Some(v) => v,
            None => continue, // unknown validator
        };

        // verify ed25519 signature
        let signature = match &sig.signature {
            Some(s) => s,
            None => continue,
        };

        // compute sign bytes (simplified)
        let sign_bytes = compute_sign_bytes(signed_header, sig.timestamp);

        if !verify_ed25519(&validator.pub_key, &sign_bytes, signature) {
            continue; // invalid signature, skip
        }

        signed_power = signed_power.saturating_add(validator.voting_power);

        // check if we have enough
        // signed_power / total_power >= trust_num / trust_den
        // equivalent to: signed_power * trust_den >= trust_num * total_power
        if signed_power.saturating_mul(trust_den) >= trust_num.saturating_mul(total_power) {
            return Ok(());
        }
    }

    Err(IbcError::InsufficientSignatures)
}

/// compute canonical sign bytes for commit
fn compute_sign_bytes(signed_header: &SignedHeader, timestamp: u64) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&signed_header.header.chain_id.0);
    buf.extend_from_slice(&signed_header.commit.height.revision_height.to_be_bytes());
    buf.extend_from_slice(&signed_header.commit.round.to_be_bytes());
    buf.extend_from_slice(&signed_header.commit.block_id.hash);
    buf.extend_from_slice(&timestamp.to_be_bytes());
    buf
}

/// verify ed25519 signature using ed25519-dalek
fn verify_ed25519(pub_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
    use ed25519_dalek::{Signature, VerifyingKey, Verifier};

    let verifying_key = match VerifyingKey::from_bytes(pub_key) {
        Ok(k) => k,
        Err(_) => return false,
    };

    // ed25519-dalek 2.x: from_bytes returns Signature directly
    let sig = Signature::from_bytes(signature);

    verifying_key.verify(message, &sig).is_ok()
}
