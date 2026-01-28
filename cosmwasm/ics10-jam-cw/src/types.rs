//! jam light client types for cosmwasm

use cosmwasm_schema::cw_serde;

/// 32-byte hash
pub type Hash32 = [u8; 32];

/// ibc height
#[cw_serde]
#[derive(Copy)]
pub struct Height {
    pub revision_number: u64,
    pub revision_height: u64,
}

impl Height {
    pub fn to_key(&self) -> Vec<u8> {
        let mut key = Vec::with_capacity(16);
        key.extend_from_slice(&self.revision_number.to_be_bytes());
        key.extend_from_slice(&self.revision_height.to_be_bytes());
        key
    }
}

/// jam client state
#[cw_serde]
pub struct JamClientState {
    /// chain id
    pub chain_id: Vec<u8>,
    /// latest finalized slot
    pub latest_slot: u32,
    /// frozen slot (0 = not frozen)
    pub frozen_slot: u32,
    /// trusting period in slots
    pub trusting_period: u32,
    /// current grandpa set id
    pub current_set_id: u64,
    /// current authority set
    pub current_authorities: AuthoritySet,
    /// epoch length
    pub epoch_length: u32,
}

impl JamClientState {
    pub fn is_frozen(&self) -> bool {
        self.frozen_slot > 0
    }

    pub fn freeze(&mut self, slot: u32) {
        self.frozen_slot = slot;
    }

    pub fn vote_threshold(&self) -> u64 {
        let total: u64 = self.current_authorities.authorities.iter()
            .map(|a| a.weight)
            .sum();
        (total * 2 / 3) + 1
    }
}

/// jam consensus state
#[cw_serde]
pub struct JamConsensusState {
    pub slot: u32,
    pub state_root: Hash32,
    pub block_hash: Hash32,
    pub timestamp: u64,
}

/// authority set
#[cw_serde]
pub struct AuthoritySet {
    pub set_id: u64,
    pub authorities: Vec<Authority>,
}

impl AuthoritySet {
    pub fn total_weight(&self) -> u64 {
        self.authorities.iter().map(|a| a.weight).sum()
    }

    pub fn get(&self, index: usize) -> Option<&Authority> {
        self.authorities.get(index)
    }
}

/// single authority
#[cw_serde]
pub struct Authority {
    pub ed25519_key: Hash32,
    pub bandersnatch_key: Hash32,
    pub weight: u64,
}

/// jam header
#[cw_serde]
pub struct JamHeader {
    pub parent_hash: Hash32,
    pub state_root: Hash32,
    pub extrinsic_hash: Hash32,
    pub timeslot: u32,
    pub epoch_marker: Option<EpochMarker>,
    pub offenders: Vec<Hash32>,
    pub author_index: u16,
    pub vrf_signature: Vec<u8>,
    pub seal: Vec<u8>,
}

impl JamHeader {
    pub fn hash(&self) -> Hash32 {
        let encoded = self.encode_for_hash();
        crate::verify::blake2b_256(&encoded)
    }

    fn encode_for_hash(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&self.parent_hash);
        buf.extend_from_slice(&self.state_root);
        buf.extend_from_slice(&self.extrinsic_hash);
        buf.extend_from_slice(&self.timeslot.to_le_bytes());

        if let Some(ref em) = self.epoch_marker {
            buf.push(1);
            buf.extend_from_slice(&em.entropy);
            buf.extend_from_slice(&em.previous_entropy);
            buf.extend_from_slice(&(em.validators.len() as u32).to_le_bytes());
            for v in &em.validators {
                buf.extend_from_slice(&v.bandersnatch_key);
                buf.extend_from_slice(&v.ed25519_key);
            }
        } else {
            buf.push(0);
        }

        buf.extend_from_slice(&(self.offenders.len() as u32).to_le_bytes());
        for off in &self.offenders {
            buf.extend_from_slice(off);
        }

        buf.extend_from_slice(&self.author_index.to_le_bytes());
        buf.extend_from_slice(&self.vrf_signature);
        buf
    }
}

/// epoch marker
#[cw_serde]
pub struct EpochMarker {
    pub entropy: Hash32,
    pub previous_entropy: Hash32,
    pub validators: Vec<ValidatorKeys>,
}

/// validator keys
#[cw_serde]
pub struct ValidatorKeys {
    pub bandersnatch_key: Hash32,
    pub ed25519_key: Hash32,
}

/// header with finality proof
#[cw_serde]
pub struct JamHeaderWithProof {
    pub header: JamHeader,
    pub finality_proof: GrandpaFinalityProof,
    pub ancestry: Vec<JamHeader>,
}

/// grandpa finality proof
#[cw_serde]
pub struct GrandpaFinalityProof {
    pub round: u64,
    pub target_hash: Hash32,
    pub target_number: u32,
    pub precommits: Vec<SignedPrecommit>,
}

/// signed precommit
#[cw_serde]
pub struct SignedPrecommit {
    pub authority_index: u32,
    pub precommit: Precommit,
    pub signature: Vec<u8>,
}

/// precommit vote
#[cw_serde]
pub struct Precommit {
    pub target_hash: Hash32,
    pub target_number: u32,
}

impl Precommit {
    pub fn signing_message(&self, round: u64, set_id: u64) -> Vec<u8> {
        let mut msg = Vec::new();
        msg.push(1); // precommit type
        msg.extend_from_slice(&round.to_le_bytes());
        msg.extend_from_slice(&set_id.to_le_bytes());
        msg.extend_from_slice(&self.target_hash);
        msg.extend_from_slice(&self.target_number.to_le_bytes());
        msg
    }
}

/// jam state proof
#[cw_serde]
pub struct JamStateProof {
    pub key: Vec<u8>,
    pub value: Vec<u8>,
    pub proof: Vec<MerkleNode>,
}

/// merkle node
#[cw_serde]
pub struct MerkleNode {
    pub position: u8,
    pub hash: Hash32,
}

/// misbehavior evidence
#[cw_serde]
pub struct JamMisbehavior {
    pub header_1: JamHeader,
    pub header_2: JamHeader,
    pub proof_1: GrandpaFinalityProof,
    pub proof_2: GrandpaFinalityProof,
}
