//! ibc light client (ics-002)
//!
//! tendermint light client implementation for cosmos chain verification

use serde::{Deserialize, Serialize};
use serde_bytes;
use sha2::{Sha256, Digest};

use super::types::*;

/// tendermint client state
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClientState {
    /// chain id
    pub chain_id: ChainId,
    /// trust level (numerator, denominator) - typically 1/3
    pub trust_level: (u64, u64),
    /// trusting period in seconds
    pub trusting_period: u64,
    /// unbonding period in seconds
    pub unbonding_period: u64,
    /// max clock drift in seconds
    pub max_clock_drift: u64,
    /// latest height
    pub latest_height: Height,
    /// frozen height (Some if client is frozen)
    pub frozen_height: Option<Height>,
}

impl ClientState {
    /// check if client is frozen
    pub fn is_frozen(&self) -> bool {
        self.frozen_height.is_some()
    }

    /// check if client is expired
    pub fn is_expired(&self, current_time: u64, consensus_time: u64) -> bool {
        current_time > consensus_time + self.trusting_period
    }

    /// validate header height
    pub fn validate_header_height(&self, header_height: &Height) -> Result<(), IbcError> {
        if header_height.revision_number != self.latest_height.revision_number {
            // revision mismatch - could be valid for upgrade
            if header_height.revision_height != 1 {
                return Err(IbcError::InvalidHeader);
            }
        }
        Ok(())
    }
}

/// tendermint consensus state
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConsensusState {
    /// block timestamp
    pub timestamp: Timestamp,
    /// merkle root of app state
    pub root: CommitmentRoot,
    /// hash of next validator set
    pub next_validators_hash: Hash32,
}

impl ConsensusState {
    /// compute commitment for storage
    pub fn commitment(&self) -> Hash32 {
        let mut hasher = Sha256::new();
        hasher.update(&self.timestamp.to_be_bytes());
        hasher.update(&self.root);
        hasher.update(&self.next_validators_hash);
        hasher.finalize().into()
    }
}

/// tendermint header for client updates
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Header {
    /// signed header
    pub signed_header: SignedHeader,
    /// validator set that signed the header
    pub validator_set: ValidatorSet,
    /// trusted height (for bisection)
    pub trusted_height: Height,
    /// trusted validators at trusted_height
    pub trusted_validators: ValidatorSet,
}

/// signed tendermint header
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedHeader {
    /// header
    pub header: TendermintHeader,
    /// commit (validator signatures)
    pub commit: Commit,
}

/// tendermint block header
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TendermintHeader {
    /// block version
    pub version: (u64, u64),
    /// chain id
    pub chain_id: Vec<u8>,
    /// block height
    pub height: u64,
    /// block time (unix timestamp)
    pub time: Timestamp,
    /// previous block hash
    pub last_block_id: Hash32,
    /// merkle root of last commit signatures
    pub last_commit_hash: Hash32,
    /// merkle root of txs in block
    pub data_hash: Hash32,
    /// merkle root of validators
    pub validators_hash: Hash32,
    /// merkle root of next validators
    pub next_validators_hash: Hash32,
    /// merkle root of consensus params
    pub consensus_hash: Hash32,
    /// app state after prev block
    pub app_hash: Hash32,
    /// merkle root of begin block events
    pub last_results_hash: Hash32,
    /// merkle root of evidence
    pub evidence_hash: Hash32,
    /// proposer address
    pub proposer_address: Vec<u8>,
}

impl TendermintHeader {
    /// compute header hash
    pub fn hash(&self) -> Hash32 {
        // simplified - real impl needs proper amino/protobuf encoding
        let mut hasher = Sha256::new();
        hasher.update(&self.version.0.to_be_bytes());
        hasher.update(&self.version.1.to_be_bytes());
        hasher.update(&self.chain_id);
        hasher.update(&self.height.to_be_bytes());
        hasher.update(&self.time.to_be_bytes());
        hasher.update(&self.last_block_id);
        hasher.update(&self.last_commit_hash);
        hasher.update(&self.data_hash);
        hasher.update(&self.validators_hash);
        hasher.update(&self.next_validators_hash);
        hasher.update(&self.consensus_hash);
        hasher.update(&self.app_hash);
        hasher.update(&self.last_results_hash);
        hasher.update(&self.evidence_hash);
        hasher.update(&self.proposer_address);
        hasher.finalize().into()
    }
}

/// commit with validator signatures
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Commit {
    /// block height
    pub height: u64,
    /// commit round
    pub round: u32,
    /// block hash being committed
    pub block_id: Hash32,
    /// validator signatures
    pub signatures: Vec<CommitSig>,
}

/// individual commit signature
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommitSig {
    /// validator index in validator set
    pub validator_index: u32,
    /// signature (ed25519) - stored as vec for serde compat
    #[serde(with = "serde_bytes")]
    pub signature: Vec<u8>,
    /// timestamp of signature
    pub timestamp: Timestamp,
}

/// validator set
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidatorSet {
    /// validators
    pub validators: Vec<Validator>,
    /// proposer (optional)
    pub proposer: Option<Validator>,
}

impl ValidatorSet {
    /// compute total voting power
    pub fn total_power(&self) -> u64 {
        self.validators.iter().map(|v| v.voting_power).sum()
    }

    /// compute validator set hash
    pub fn hash(&self) -> Hash32 {
        let mut hasher = Sha256::new();
        for v in &self.validators {
            hasher.update(&v.pub_key);
            hasher.update(&v.voting_power.to_be_bytes());
        }
        hasher.finalize().into()
    }

    /// get validator by index
    pub fn get(&self, index: usize) -> Option<&Validator> {
        self.validators.get(index)
    }
}

/// individual validator
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Validator {
    /// ed25519 public key
    pub pub_key: [u8; 32],
    /// voting power
    pub voting_power: u64,
}
