//! jam light client for ibc (ics-10 style)
//!
//! trustless verification of jam chain state on cosmos chains.
//! follows composable's grandpa light client pattern.
//!
//! jam uses:
//! - safrole for block production (ring vrf tickets)
//! - grandpa for finality (2/3+1 prevote + precommit)
//! - blake2b-256 for hashing
//! - ed25519 for grandpa votes, bandersnatch for block seals

use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};

use super::types::*;

// ============================================================================
// constants
// ============================================================================

/// jam client type identifier
pub const JAM_CLIENT_TYPE: &str = "10-jam";

/// epoch length in slots (full mode)
pub const EPOCH_LENGTH_FULL: u32 = 600;

/// epoch length in slots (tiny mode for testing)
pub const EPOCH_LENGTH_TINY: u32 = 12;

/// slot duration in nanoseconds (6 seconds)
pub const SLOT_DURATION_NS: u64 = 6_000_000_000;

/// jam common era start (2025-01-01 12:00:00 UTC)
pub const JAM_COMMON_ERA: u64 = 1735732800;

// ============================================================================
// client state (stored on cosmos chain)
// ============================================================================

/// jam client state for cosmos-side verification
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JamClientState {
    /// chain identifier
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
    /// epoch length (600 for full, 12 for tiny)
    pub epoch_length: u32,
}

impl JamClientState {
    /// create new client state
    pub fn new(
        chain_id: &str,
        authorities: Vec<Authority>,
        epoch_length: u32,
        trusting_period: u32,
    ) -> Self {
        Self {
            chain_id: chain_id.as_bytes().to_vec(),
            latest_slot: 0,
            frozen_slot: 0,
            trusting_period,
            current_set_id: 0,
            current_authorities: AuthoritySet::new(0, authorities),
            epoch_length,
        }
    }

    /// check if frozen
    pub fn is_frozen(&self) -> bool {
        self.frozen_slot > 0
    }

    /// check if expired
    pub fn is_expired(&self, current_slot: u32) -> bool {
        current_slot > self.latest_slot + self.trusting_period
    }

    /// freeze at slot
    pub fn freeze(&mut self, slot: u32) {
        self.frozen_slot = slot;
    }

    /// client type
    pub fn client_type(&self) -> &'static str {
        JAM_CLIENT_TYPE
    }

    /// get required vote threshold (2/3 + 1)
    pub fn vote_threshold(&self) -> u64 {
        let total_weight: u64 = self.current_authorities.authorities.iter()
            .map(|a| a.weight)
            .sum();
        (total_weight * 2 / 3) + 1
    }
}

// ============================================================================
// consensus state (stored per height)
// ============================================================================

/// jam consensus state at specific slot
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JamConsensusState {
    /// slot number
    pub slot: u32,
    /// state root (blake2b-256)
    pub state_root: Hash32,
    /// block hash
    pub block_hash: Hash32,
    /// timestamp (slot * 6 seconds + era start)
    pub timestamp: u64,
}

impl JamConsensusState {
    /// compute commitment
    pub fn commitment(&self) -> Hash32 {
        // use blake2b for jam compatibility
        blake2b_256(&[
            &self.slot.to_le_bytes()[..],
            &self.state_root[..],
            &self.block_hash[..],
            &self.timestamp.to_le_bytes()[..],
        ].concat())
    }

    /// from header
    pub fn from_header(header: &JamHeader) -> Self {
        Self {
            slot: header.timeslot,
            state_root: header.state_root,
            block_hash: header.hash(),
            timestamp: slot_to_timestamp(header.timeslot),
        }
    }
}

// ============================================================================
// authority set (grandpa validators)
// ============================================================================

/// grandpa authority set
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthoritySet {
    /// set id (increments on each change)
    pub set_id: u64,
    /// authorities with weights
    pub authorities: Vec<Authority>,
}

impl AuthoritySet {
    pub fn new(set_id: u64, authorities: Vec<Authority>) -> Self {
        Self { set_id, authorities }
    }

    /// compute authority set hash
    pub fn hash(&self) -> Hash32 {
        let mut data = Vec::new();
        data.extend_from_slice(&self.set_id.to_le_bytes());
        for auth in &self.authorities {
            data.extend_from_slice(&auth.ed25519_key);
            data.extend_from_slice(&auth.weight.to_le_bytes());
        }
        blake2b_256(&data)
    }

    /// total voting weight
    pub fn total_weight(&self) -> u64 {
        self.authorities.iter().map(|a| a.weight).sum()
    }

    /// get authority by index
    pub fn get(&self, index: usize) -> Option<&Authority> {
        self.authorities.get(index)
    }
}

/// single authority (validator)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Authority {
    /// ed25519 public key (for grandpa votes)
    pub ed25519_key: Hash32,
    /// bandersnatch public key (for block seals)
    pub bandersnatch_key: Hash32,
    /// voting weight
    pub weight: u64,
}

// ============================================================================
// jam header with finality proof
// ============================================================================

/// jam block header
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JamHeader {
    /// parent block hash
    pub parent_hash: Hash32,
    /// state root after this block
    pub state_root: Hash32,
    /// extrinsic hash
    pub extrinsic_hash: Hash32,
    /// slot number
    pub timeslot: u32,
    /// epoch marker (on epoch boundaries)
    pub epoch_marker: Option<EpochMarker>,
    /// offending validators to be slashed
    pub offenders: Vec<Hash32>,
    /// block author validator index
    pub author_index: u16,
    /// vrf signature (bandersnatch, 96 bytes)
    pub vrf_signature: Vec<u8>,
    /// block seal (bandersnatch, 96 bytes)
    pub seal: Vec<u8>,
}

impl JamHeader {
    /// compute block hash (blake2b-256 of encoded header)
    pub fn hash(&self) -> Hash32 {
        let encoded = self.encode_for_hash();
        blake2b_256(&encoded)
    }

    /// encode header for hashing (excludes seal)
    fn encode_for_hash(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&self.parent_hash);
        buf.extend_from_slice(&self.state_root);
        buf.extend_from_slice(&self.extrinsic_hash);
        buf.extend_from_slice(&self.timeslot.to_le_bytes());

        // epoch marker
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

        // offenders
        buf.extend_from_slice(&(self.offenders.len() as u32).to_le_bytes());
        for off in &self.offenders {
            buf.extend_from_slice(off);
        }

        buf.extend_from_slice(&self.author_index.to_le_bytes());
        buf.extend_from_slice(&self.vrf_signature);
        // seal NOT included in hash
        buf
    }
}

/// epoch marker for validator set changes
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EpochMarker {
    /// new epoch entropy
    pub entropy: Hash32,
    /// previous epoch entropy
    pub previous_entropy: Hash32,
    /// new validator set
    pub validators: Vec<ValidatorKeys>,
}

/// validator key pair
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidatorKeys {
    pub bandersnatch_key: Hash32,
    pub ed25519_key: Hash32,
}

// ============================================================================
// grandpa finality proof
// ============================================================================

/// grandpa finality proof for a block
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GrandpaFinalityProof {
    /// round number
    pub round: u64,
    /// target block hash
    pub target_hash: Hash32,
    /// target block number (slot)
    pub target_number: u32,
    /// precommits from validators
    pub precommits: Vec<SignedPrecommit>,
}

/// signed precommit vote
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedPrecommit {
    /// voter authority index
    pub authority_index: u32,
    /// precommit data
    pub precommit: Precommit,
    /// ed25519 signature (64 bytes)
    pub signature: Vec<u8>,
}

/// precommit vote
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Precommit {
    /// target block hash
    pub target_hash: Hash32,
    /// target block number
    pub target_number: u32,
}

impl Precommit {
    /// encode for signing
    pub fn signing_message(&self, round: u64, set_id: u64) -> Vec<u8> {
        let mut msg = Vec::new();
        // grandpa message format: type || round || set_id || target_hash || target_number
        msg.push(1); // precommit type
        msg.extend_from_slice(&round.to_le_bytes());
        msg.extend_from_slice(&set_id.to_le_bytes());
        msg.extend_from_slice(&self.target_hash);
        msg.extend_from_slice(&self.target_number.to_le_bytes());
        msg
    }
}

// ============================================================================
// header with finality proof (client message)
// ============================================================================

/// jam header with grandpa finality proof
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JamHeaderWithProof {
    /// the header being finalized
    pub header: JamHeader,
    /// grandpa finality proof
    pub finality_proof: GrandpaFinalityProof,
    /// ancestry proof (headers from trusted to target)
    pub ancestry: Vec<JamHeader>,
}

// ============================================================================
// verification functions
// ============================================================================

/// verify jam header with finality proof
pub fn verify_jam_header(
    client_state: &JamClientState,
    trusted_consensus: &JamConsensusState,
    header_with_proof: &JamHeaderWithProof,
) -> Result<VerificationResult, IbcError> {
    // check client not frozen
    if client_state.is_frozen() {
        return Err(IbcError::ClientFrozen);
    }

    let header = &header_with_proof.header;
    let proof = &header_with_proof.finality_proof;

    // verify header is newer
    if header.timeslot <= trusted_consensus.slot {
        return Err(IbcError::HeightTooOld);
    }

    // verify ancestry connects trusted to target
    verify_ancestry(trusted_consensus, header, &header_with_proof.ancestry)?;

    // verify grandpa finality proof
    verify_grandpa_proof(
        &client_state.current_authorities,
        client_state.current_set_id,
        proof,
        &header.hash(),
        header.timeslot,
    )?;

    // check for authority set change
    let new_authorities = if let Some(ref epoch_marker) = header.epoch_marker {
        Some(authorities_from_epoch_marker(
            epoch_marker,
            client_state.current_set_id + 1,
        ))
    } else {
        None
    };

    // create new consensus state
    let new_consensus = JamConsensusState::from_header(header);

    Ok(VerificationResult {
        new_consensus_state: new_consensus,
        new_client_state: if new_authorities.is_some() {
            let mut new_state = client_state.clone();
            new_state.latest_slot = header.timeslot;
            new_state.current_authorities = new_authorities.unwrap();
            new_state.current_set_id += 1;
            Some(new_state)
        } else {
            let mut new_state = client_state.clone();
            new_state.latest_slot = header.timeslot;
            Some(new_state)
        },
    })
}

/// verify grandpa finality proof
pub fn verify_grandpa_proof(
    authorities: &AuthoritySet,
    set_id: u64,
    proof: &GrandpaFinalityProof,
    target_hash: &Hash32,
    target_number: u32,
) -> Result<(), IbcError> {
    // verify target matches
    if &proof.target_hash != target_hash || proof.target_number != target_number {
        return Err(IbcError::InvalidProof);
    }

    // count valid precommit weight
    let mut valid_weight = 0u64;
    let mut seen_voters = std::collections::HashSet::new();

    for signed in &proof.precommits {
        // check authority exists
        let authority = authorities.get(signed.authority_index as usize)
            .ok_or(IbcError::InvalidSignature)?;

        // prevent double voting
        if !seen_voters.insert(signed.authority_index) {
            continue; // skip duplicate votes
        }

        // verify precommit targets the right block
        if signed.precommit.target_hash != proof.target_hash {
            continue; // skip votes for different blocks
        }

        // verify signature
        let message = signed.precommit.signing_message(proof.round, set_id);
        verify_ed25519_signature(&authority.ed25519_key, &message, &signed.signature)?;

        valid_weight += authority.weight;
    }

    // check supermajority (2/3 + 1)
    let threshold = (authorities.total_weight() * 2 / 3) + 1;
    if valid_weight < threshold {
        return Err(IbcError::InsufficientVotingPower);
    }

    Ok(())
}

/// verify ancestry chain from trusted to target
fn verify_ancestry(
    trusted: &JamConsensusState,
    target: &JamHeader,
    ancestry: &[JamHeader],
) -> Result<(), IbcError> {
    if ancestry.is_empty() {
        // direct descendant - parent must match
        if target.parent_hash != trusted.block_hash {
            return Err(IbcError::InvalidHeader);
        }
        return Ok(());
    }

    // verify chain: trusted -> ancestry[0] -> ... -> ancestry[n] -> target
    let mut expected_hash = trusted.block_hash;

    for header in ancestry {
        if header.parent_hash != expected_hash {
            return Err(IbcError::InvalidHeader);
        }
        expected_hash = header.hash();
    }

    // final header's child should be target
    if target.parent_hash != expected_hash {
        return Err(IbcError::InvalidHeader);
    }

    Ok(())
}

/// verification result
#[derive(Clone, Debug)]
pub struct VerificationResult {
    pub new_consensus_state: JamConsensusState,
    pub new_client_state: Option<JamClientState>,
}

// ============================================================================
// state proofs
// ============================================================================

/// jam state proof (binary merkle tree)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JamStateProof {
    /// key being proven
    pub key: Vec<u8>,
    /// value (empty for non-existence)
    pub value: Vec<u8>,
    /// merkle proof nodes
    pub proof: Vec<MerkleNode>,
}

/// merkle proof node
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MerkleNode {
    /// 0 = sibling on left, 1 = sibling on right
    pub position: u8,
    /// sibling hash
    pub hash: Hash32,
}

/// verify jam state proof against state root
pub fn verify_jam_state_proof(
    proof: &JamStateProof,
    state_root: &Hash32,
) -> Result<(), IbcError> {
    // compute leaf hash
    let mut current = blake2b_256(&[&proof.key[..], &proof.value[..]].concat());

    // walk up the tree
    for node in &proof.proof {
        let combined = if node.position == 0 {
            [&node.hash[..], &current[..]].concat()
        } else {
            [&current[..], &node.hash[..]].concat()
        };
        current = blake2b_256(&combined);
    }

    if &current != state_root {
        return Err(IbcError::InvalidProof);
    }

    Ok(())
}

// ============================================================================
// misbehavior detection
// ============================================================================

/// misbehavior evidence
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JamMisbehavior {
    /// first header at conflicting slot
    pub header_1: JamHeader,
    /// second header at same slot
    pub header_2: JamHeader,
    /// finality proof for header 1
    pub proof_1: GrandpaFinalityProof,
    /// finality proof for header 2
    pub proof_2: GrandpaFinalityProof,
}

/// check misbehavior and return slot to freeze
pub fn check_misbehavior(
    client_state: &JamClientState,
    misbehavior: &JamMisbehavior,
) -> Result<u32, IbcError> {
    let h1 = &misbehavior.header_1;
    let h2 = &misbehavior.header_2;

    // must be same slot with different state roots
    if h1.timeslot != h2.timeslot {
        return Err(IbcError::InvalidHeader);
    }

    if h1.state_root == h2.state_root {
        return Err(IbcError::InvalidHeader);
    }

    // verify both have valid finality proofs
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

    // misbehavior confirmed
    Ok(h1.timeslot)
}

// ============================================================================
// entity registry (jam services as ibc entities)
// ============================================================================

/// ibc entity representing a jam service or polkadot parachain
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IbcEntity {
    /// entity id (hash of service index + type)
    pub entity_id: Hash32,
    /// service index on jam
    pub service_index: u32,
    /// entity type
    pub entity_type: EntityType,
    /// owner (can update metadata, transfer)
    pub owner: Hash32,
    /// ibc port id
    pub port_id: PortId,
    /// metadata
    pub metadata: EntityMetadata,
}

/// entity types
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum EntityType {
    /// jam service (pvm program)
    JamService,
    /// polkadot parachain
    Parachain { para_id: u32 },
    /// polkadot asset
    Asset { asset_id: u32 },
    /// custom
    Custom { type_id: Vec<u8> },
}

/// entity metadata
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct EntityMetadata {
    pub name: Vec<u8>,
    pub description: Vec<u8>,
    pub website: Vec<u8>,
}

impl IbcEntity {
    /// create jam service entity
    pub fn new_service(service_index: u32, owner: Hash32) -> Self {
        let entity_id = derive_entity_id(service_index, &EntityType::JamService);
        Self {
            entity_id,
            service_index,
            entity_type: EntityType::JamService,
            owner,
            port_id: PortId::new(&format!("jam-{}", service_index)),
            metadata: EntityMetadata::default(),
        }
    }

    /// create parachain entity
    pub fn new_parachain(service_index: u32, para_id: u32, owner: Hash32) -> Self {
        let entity_type = EntityType::Parachain { para_id };
        let entity_id = derive_entity_id(service_index, &entity_type);
        Self {
            entity_id,
            service_index,
            entity_type,
            owner,
            port_id: PortId::new(&format!("polkadot-{}", para_id)),
            metadata: EntityMetadata::default(),
        }
    }
}

fn derive_entity_id(service_index: u32, entity_type: &EntityType) -> Hash32 {
    let mut data = Vec::new();
    data.extend_from_slice(b"jam-ibc-entity-v1");
    data.extend_from_slice(&service_index.to_le_bytes());
    match entity_type {
        EntityType::JamService => data.push(0),
        EntityType::Parachain { para_id } => {
            data.push(1);
            data.extend_from_slice(&para_id.to_le_bytes());
        }
        EntityType::Asset { asset_id } => {
            data.push(2);
            data.extend_from_slice(&asset_id.to_le_bytes());
        }
        EntityType::Custom { type_id } => {
            data.push(3);
            data.extend_from_slice(type_id);
        }
    }
    blake2b_256(&data)
}

/// entity registry
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct EntityRegistry {
    pub entities: Vec<IbcEntity>,
}

impl EntityRegistry {
    /// register entity
    pub fn register(&mut self, entity: IbcEntity) -> Result<Hash32, IbcError> {
        if self.entities.iter().any(|e| e.entity_id == entity.entity_id) {
            return Err(IbcError::InvalidStateTransition);
        }
        let id = entity.entity_id;
        self.entities.push(entity);
        Ok(id)
    }

    /// get entity by id
    pub fn get(&self, id: &Hash32) -> Option<&IbcEntity> {
        self.entities.iter().find(|e| e.entity_id == *id)
    }

    /// get entity by port
    pub fn get_by_port(&self, port: &PortId) -> Option<&IbcEntity> {
        self.entities.iter().find(|e| e.port_id == *port)
    }
}

// ============================================================================
// crypto helpers
// ============================================================================

/// blake2b-256 hash (jam's primary hash)
pub fn blake2b_256(data: &[u8]) -> Hash32 {
    use blake2::{Blake2b, Digest as Blake2Digest};
    use blake2::digest::consts::U32;

    let mut hasher = Blake2b::<U32>::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// verify ed25519 signature
fn verify_ed25519_signature(
    pubkey: &Hash32,
    message: &[u8],
    signature: &[u8],
) -> Result<(), IbcError> {
    use ed25519_dalek::{Signature, VerifyingKey, Verifier};

    let key = VerifyingKey::from_bytes(pubkey)
        .map_err(|_| IbcError::InvalidSignature)?;

    if signature.len() != 64 {
        return Err(IbcError::InvalidSignature);
    }

    let sig_bytes: [u8; 64] = signature.try_into()
        .map_err(|_| IbcError::InvalidSignature)?;

    let sig = Signature::from_bytes(&sig_bytes);

    key.verify(message, &sig)
        .map_err(|_| IbcError::InvalidSignature)?;

    Ok(())
}

/// convert slot to timestamp
fn slot_to_timestamp(slot: u32) -> u64 {
    JAM_COMMON_ERA * 1_000_000_000 + (slot as u64) * SLOT_DURATION_NS
}

/// extract authorities from epoch marker
fn authorities_from_epoch_marker(marker: &EpochMarker, new_set_id: u64) -> AuthoritySet {
    let authorities = marker.validators.iter().map(|v| {
        Authority {
            ed25519_key: v.ed25519_key,
            bandersnatch_key: v.bandersnatch_key,
            weight: 1, // equal weight by default
        }
    }).collect();

    AuthoritySet::new(new_set_id, authorities)
}

// ============================================================================
// tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn test_authority(index: u8) -> Authority {
        Authority {
            ed25519_key: [index; 32],
            bandersnatch_key: [index + 100; 32],
            weight: 1,
        }
    }

    #[test]
    fn test_client_state_threshold() {
        let authorities = (0..6).map(test_authority).collect();
        let state = JamClientState::new("jam-testnet", authorities, 12, 100);

        // 6 validators with weight 1 each = total 6
        // threshold = (6 * 2 / 3) + 1 = 4 + 1 = 5
        assert_eq!(state.vote_threshold(), 5);
    }

    #[test]
    fn test_authority_set_hash() {
        let authorities = vec![test_authority(1), test_authority(2)];
        let set = AuthoritySet::new(0, authorities);

        let hash = set.hash();
        assert_ne!(hash, [0u8; 32]);

        // same set should give same hash
        let authorities2 = vec![test_authority(1), test_authority(2)];
        let set2 = AuthoritySet::new(0, authorities2);
        assert_eq!(set.hash(), set2.hash());
    }

    #[test]
    fn test_precommit_signing_message() {
        let precommit = Precommit {
            target_hash: [42u8; 32],
            target_number: 100,
        };

        let msg = precommit.signing_message(5, 0);

        // should contain: type(1) || round(8) || set_id(8) || hash(32) || number(4)
        assert_eq!(msg.len(), 1 + 8 + 8 + 32 + 4);
        assert_eq!(msg[0], 1); // precommit type
    }

    #[test]
    fn test_consensus_state_from_header() {
        let header = JamHeader {
            parent_hash: [0u8; 32],
            state_root: [1u8; 32],
            extrinsic_hash: [2u8; 32],
            timeslot: 100,
            epoch_marker: None,
            offenders: vec![],
            author_index: 0,
            vrf_signature: vec![0u8; 96],
            seal: vec![0u8; 96],
        };

        let cs = JamConsensusState::from_header(&header);

        assert_eq!(cs.slot, 100);
        assert_eq!(cs.state_root, [1u8; 32]);
    }

    #[test]
    fn test_blake2b_256() {
        let hash = blake2b_256(b"test");
        assert_ne!(hash, [0u8; 32]);
        assert_eq!(hash.len(), 32);

        // deterministic
        let hash2 = blake2b_256(b"test");
        assert_eq!(hash, hash2);
    }

    #[test]
    fn test_entity_creation() {
        let owner = [42u8; 32];

        let service = IbcEntity::new_service(5, owner);
        assert_eq!(service.port_id.0, b"jam-5");
        assert!(matches!(service.entity_type, EntityType::JamService));

        let para = IbcEntity::new_parachain(0, 2000, owner);
        assert_eq!(para.port_id.0, b"polkadot-2000");
        assert!(matches!(para.entity_type, EntityType::Parachain { para_id: 2000 }));
    }

    #[test]
    fn test_entity_registry() {
        let mut registry = EntityRegistry::default();
        let owner = [42u8; 32];

        let e1 = IbcEntity::new_service(1, owner);
        let e2 = IbcEntity::new_parachain(0, 2000, owner);

        let id1 = registry.register(e1).unwrap();
        let id2 = registry.register(e2).unwrap();

        assert!(registry.get(&id1).is_some());
        assert!(registry.get(&id2).is_some());

        let port = PortId::new("jam-1");
        assert!(registry.get_by_port(&port).is_some());
    }

    #[test]
    fn test_state_proof_verification() {
        let proof = JamStateProof {
            key: b"key".to_vec(),
            value: b"value".to_vec(),
            proof: vec![],
        };

        // with no proof nodes, root should be leaf hash
        let expected_root = blake2b_256(&[b"key".as_slice(), b"value".as_slice()].concat());

        assert!(verify_jam_state_proof(&proof, &expected_root).is_ok());
        assert!(verify_jam_state_proof(&proof, &[0u8; 32]).is_err());
    }

    #[test]
    fn test_slot_to_timestamp() {
        let ts = slot_to_timestamp(0);
        assert_eq!(ts, JAM_COMMON_ERA * 1_000_000_000);

        let ts1 = slot_to_timestamp(1);
        assert_eq!(ts1, ts + SLOT_DURATION_NS);
    }
}
