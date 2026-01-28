//! jam light client for cosmos chains
//!
//! implements ics-02 client interface so cosmos chains can verify jam state.
//! this module defines the client type that gets deployed on cosmos side.

use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};

use super::types::*;

/// jam client type identifier for cosmos
pub const JAM_CLIENT_TYPE: &str = "099-jam";

/// jam client state (stored on cosmos chain)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JamClientState {
    /// jam chain identifier
    pub chain_id: Vec<u8>,
    /// latest verified jam slot
    pub latest_slot: u32,
    /// latest verified state root
    pub latest_state_root: Hash32,
    /// minimum validators required (2/3 + 1)
    pub validator_threshold: u32,
    /// total validator count
    pub validator_count: u32,
    /// trusting period in slots
    pub trusting_period: u32,
    /// frozen height (0 if not frozen)
    pub frozen_slot: u32,
    /// service index for this ibc module
    pub service_index: u32,
}

impl JamClientState {
    /// create new jam client state
    pub fn new(
        chain_id: &str,
        service_index: u32,
        validator_count: u32,
        trusting_period: u32,
    ) -> Self {
        Self {
            chain_id: chain_id.as_bytes().to_vec(),
            latest_slot: 0,
            latest_state_root: [0u8; 32],
            validator_threshold: (validator_count * 2 / 3) + 1,
            validator_count,
            trusting_period,
            frozen_slot: 0,
            service_index,
        }
    }

    /// check if client is frozen
    pub fn is_frozen(&self) -> bool {
        self.frozen_slot > 0
    }

    /// check if client is expired
    pub fn is_expired(&self, current_slot: u32) -> bool {
        current_slot > self.latest_slot + self.trusting_period
    }

    /// freeze the client at given slot
    pub fn freeze(&mut self, slot: u32) {
        self.frozen_slot = slot;
    }

    /// get client type
    pub fn client_type(&self) -> &'static str {
        JAM_CLIENT_TYPE
    }
}

/// jam consensus state (stored per height on cosmos)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JamConsensusState {
    /// jam slot number
    pub slot: u32,
    /// state root commitment
    pub state_root: Hash32,
    /// accumulate root (service state)
    pub accumulate_root: Hash32,
    /// validator set hash
    pub validators_hash: Hash32,
    /// timestamp (slot * 6 seconds)
    pub timestamp: u64,
}

impl JamConsensusState {
    /// compute commitment for this consensus state
    pub fn commitment(&self) -> Hash32 {
        let mut hasher = Sha256::new();
        hasher.update(&self.slot.to_le_bytes());
        hasher.update(&self.state_root);
        hasher.update(&self.accumulate_root);
        hasher.update(&self.validators_hash);
        hasher.update(&self.timestamp.to_le_bytes());
        hasher.finalize().into()
    }
}

/// jam header for client updates
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JamHeader {
    /// slot number
    pub slot: u32,
    /// parent slot
    pub parent_slot: u32,
    /// state root after this block
    pub state_root: Hash32,
    /// accumulate root (service state commitment)
    pub accumulate_root: Hash32,
    /// extrinsic root
    pub extrinsic_root: Hash32,
    /// validator set hash
    pub validators_hash: Hash32,
    /// author validator index
    pub author_index: u32,
    /// seal (ed25519 signature from author)
    pub seal: Vec<u8>,
    /// epoch marker (for validator transitions)
    pub epoch_marker: Option<EpochMarker>,
    /// validator signatures for finality
    pub finality_signatures: Vec<FinalitySignature>,
}

/// epoch marker for validator set transitions
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EpochMarker {
    /// new epoch number
    pub epoch: u32,
    /// new validator set
    pub validators: Vec<JamValidator>,
    /// randomness for this epoch
    pub entropy: Hash32,
}

/// jam validator
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JamValidator {
    /// ed25519 public key
    pub pubkey: Hash32,
    /// bandersnatch key (for safrole)
    pub bandersnatch: Hash32,
    /// metadata/index
    pub index: u32,
}

impl JamValidator {
    /// compute validator hash
    pub fn hash(&self) -> Hash32 {
        let mut hasher = Sha256::new();
        hasher.update(&self.pubkey);
        hasher.update(&self.bandersnatch);
        hasher.update(&self.index.to_le_bytes());
        hasher.finalize().into()
    }
}

/// finality signature from a validator
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FinalitySignature {
    /// validator index
    pub validator_index: u32,
    /// ed25519 signature over (slot, state_root)
    pub signature: Vec<u8>,
}

/// verify jam header against client state
pub fn verify_jam_header(
    client_state: &JamClientState,
    consensus_state: &JamConsensusState,
    header: &JamHeader,
    validators: &[JamValidator],
) -> Result<JamConsensusState, IbcError> {
    // check not frozen
    if client_state.is_frozen() {
        return Err(IbcError::ClientFrozen);
    }

    // verify header is newer than trusted
    if header.slot <= consensus_state.slot {
        return Err(IbcError::HeightTooOld);
    }

    // verify parent relationship for adjacent slots
    if header.slot == consensus_state.slot + 1 {
        // for adjacent blocks, verify state chain
        // parent state should match trusted state
    }

    // verify validator set hash matches
    let computed_validators_hash = compute_validators_hash(validators);
    if header.validators_hash != computed_validators_hash {
        return Err(IbcError::InvalidHeader);
    }

    // verify author seal
    if header.author_index as usize >= validators.len() {
        return Err(IbcError::InvalidHeader);
    }
    let author = &validators[header.author_index as usize];
    verify_seal(header, &author.pubkey)?;

    // verify finality (2/3 + 1 signatures)
    let valid_sigs = count_valid_finality_signatures(header, validators)?;
    if valid_sigs < client_state.validator_threshold {
        return Err(IbcError::InsufficientVotingPower);
    }

    // create new consensus state
    Ok(JamConsensusState {
        slot: header.slot,
        state_root: header.state_root,
        accumulate_root: header.accumulate_root,
        validators_hash: header.validators_hash,
        timestamp: (header.slot as u64) * 6_000_000_000, // 6 second slots
    })
}

/// compute hash of validator set
pub fn compute_validators_hash(validators: &[JamValidator]) -> Hash32 {
    let mut hasher = Sha256::new();
    for v in validators {
        hasher.update(&v.hash());
    }
    hasher.finalize().into()
}

/// verify author seal on header
fn verify_seal(header: &JamHeader, author_pubkey: &Hash32) -> Result<(), IbcError> {
    use ed25519_dalek::{Signature, VerifyingKey, Verifier};

    // message is hash of header without seal
    let message = header_signing_message(header);

    let pubkey = VerifyingKey::from_bytes(author_pubkey)
        .map_err(|_| IbcError::InvalidSignature)?;

    if header.seal.len() != 64 {
        return Err(IbcError::InvalidSignature);
    }

    let sig_bytes: [u8; 64] = header.seal[..64]
        .try_into()
        .map_err(|_| IbcError::InvalidSignature)?;

    let signature = Signature::from_bytes(&sig_bytes);

    pubkey.verify(&message, &signature)
        .map_err(|_| IbcError::InvalidSignature)?;

    Ok(())
}

/// compute header signing message
fn header_signing_message(header: &JamHeader) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(&header.slot.to_le_bytes());
    hasher.update(&header.parent_slot.to_le_bytes());
    hasher.update(&header.state_root);
    hasher.update(&header.accumulate_root);
    hasher.update(&header.extrinsic_root);
    hasher.update(&header.validators_hash);
    hasher.update(&header.author_index.to_le_bytes());
    hasher.finalize().to_vec()
}

/// count valid finality signatures
fn count_valid_finality_signatures(
    header: &JamHeader,
    validators: &[JamValidator],
) -> Result<u32, IbcError> {
    use ed25519_dalek::{Signature, VerifyingKey, Verifier};

    // finality message is (slot, state_root)
    let mut message = Vec::new();
    message.extend_from_slice(&header.slot.to_le_bytes());
    message.extend_from_slice(&header.state_root);

    let mut valid_count = 0u32;

    for sig in &header.finality_signatures {
        if sig.validator_index as usize >= validators.len() {
            continue;
        }

        let validator = &validators[sig.validator_index as usize];

        let pubkey = match VerifyingKey::from_bytes(&validator.pubkey) {
            Ok(k) => k,
            Err(_) => continue,
        };

        if sig.signature.len() != 64 {
            continue;
        }

        let sig_bytes: [u8; 64] = match sig.signature[..64].try_into() {
            Ok(b) => b,
            Err(_) => continue,
        };

        let signature = Signature::from_bytes(&sig_bytes);

        if pubkey.verify(&message, &signature).is_ok() {
            valid_count += 1;
        }
    }

    Ok(valid_count)
}

/// jam state proof for verifying service state on cosmos
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JamStateProof {
    /// service index
    pub service_index: u32,
    /// key being proven
    pub key: Vec<u8>,
    /// value (empty for non-existence)
    pub value: Vec<u8>,
    /// merkle proof from service accumulate root
    pub proof: Vec<JamProofNode>,
}

/// node in jam merkle proof (binary merkle tree)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JamProofNode {
    /// 0 = left sibling, 1 = right sibling
    pub position: u8,
    /// sibling hash
    pub hash: Hash32,
}

/// verify jam state proof
pub fn verify_jam_state_proof(
    proof: &JamStateProof,
    accumulate_root: &Hash32,
) -> Result<(), IbcError> {
    // compute leaf hash
    let mut leaf_hash = Sha256::new();
    leaf_hash.update(&proof.service_index.to_le_bytes());
    leaf_hash.update(&proof.key);
    leaf_hash.update(&proof.value);
    let mut current: Hash32 = leaf_hash.finalize().into();

    // walk up the tree
    for node in &proof.proof {
        let mut hasher = Sha256::new();
        if node.position == 0 {
            // sibling is on left
            hasher.update(&node.hash);
            hasher.update(&current);
        } else {
            // sibling is on right
            hasher.update(&current);
            hasher.update(&node.hash);
        }
        current = hasher.finalize().into();
    }

    // verify root
    if &current != accumulate_root {
        return Err(IbcError::InvalidProof);
    }

    Ok(())
}

/// misbehavior evidence for freezing client
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JamMisbehavior {
    /// conflicting header 1
    pub header_1: JamHeader,
    /// conflicting header 2
    pub header_2: JamHeader,
}

/// check for misbehavior (double signing at same slot)
pub fn check_misbehavior(
    _client_state: &JamClientState,
    misbehavior: &JamMisbehavior,
    validators: &[JamValidator],
) -> Result<u32, IbcError> {
    let h1 = &misbehavior.header_1;
    let h2 = &misbehavior.header_2;

    // must be same slot
    if h1.slot != h2.slot {
        return Err(IbcError::InvalidHeader);
    }

    // must have different state roots (conflicting)
    if h1.state_root == h2.state_root {
        return Err(IbcError::InvalidHeader);
    }

    // verify both headers are validly signed
    if h1.author_index as usize >= validators.len() {
        return Err(IbcError::InvalidHeader);
    }
    let author = &validators[h1.author_index as usize];
    verify_seal(h1, &author.pubkey)?;
    verify_seal(h2, &author.pubkey)?;

    // misbehavior confirmed - return slot to freeze at
    Ok(h1.slot)
}

// ============================================================================
// ibc entity registration
// ============================================================================

/// ibc entity representing a polkadot/jam service
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IbcEntity {
    /// unique entity id (derived from service index)
    pub entity_id: Hash32,
    /// service index on jam
    pub service_index: u32,
    /// entity type
    pub entity_type: EntityType,
    /// owner address
    pub owner: Hash32,
    /// ibc port id for this entity
    pub port_id: PortId,
    /// metadata
    pub metadata: EntityMetadata,
}

/// entity type
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum EntityType {
    /// jam service (pvm program)
    Service,
    /// polkadot parachain (via xcm bridge)
    Parachain { para_id: u32 },
    /// asset hub token
    Asset { asset_id: u32 },
    /// custom entity
    Custom { type_id: Vec<u8> },
}

/// entity metadata
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct EntityMetadata {
    /// human-readable name
    pub name: Vec<u8>,
    /// description
    pub description: Vec<u8>,
    /// logo url
    pub logo: Vec<u8>,
    /// website
    pub website: Vec<u8>,
}

impl IbcEntity {
    /// create new service entity
    pub fn new_service(service_index: u32, owner: Hash32) -> Self {
        let entity_id = Self::derive_entity_id(service_index, &EntityType::Service);
        let port_id = PortId::new(&format!("jam-service-{}", service_index));

        Self {
            entity_id,
            service_index,
            entity_type: EntityType::Service,
            owner,
            port_id,
            metadata: EntityMetadata::default(),
        }
    }

    /// create new parachain entity
    pub fn new_parachain(service_index: u32, para_id: u32, owner: Hash32) -> Self {
        let entity_type = EntityType::Parachain { para_id };
        let entity_id = Self::derive_entity_id(service_index, &entity_type);
        let port_id = PortId::new(&format!("polkadot-para-{}", para_id));

        Self {
            entity_id,
            service_index,
            entity_type,
            owner,
            port_id,
            metadata: EntityMetadata::default(),
        }
    }

    /// derive entity id from service index and type
    fn derive_entity_id(service_index: u32, entity_type: &EntityType) -> Hash32 {
        let mut hasher = Sha256::new();
        hasher.update(b"jam-ibc-entity-v1");
        hasher.update(&service_index.to_le_bytes());
        match entity_type {
            EntityType::Service => hasher.update(&[0u8]),
            EntityType::Parachain { para_id } => {
                hasher.update(&[1u8]);
                hasher.update(&para_id.to_le_bytes());
            }
            EntityType::Asset { asset_id } => {
                hasher.update(&[2u8]);
                hasher.update(&asset_id.to_le_bytes());
            }
            EntityType::Custom { type_id } => {
                hasher.update(&[3u8]);
                hasher.update(type_id);
            }
        }
        hasher.finalize().into()
    }
}

/// entity registry for managing ibc entities
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct EntityRegistry {
    /// registered entities by id
    pub entities: Vec<IbcEntity>,
    /// port to entity mapping
    pub port_to_entity: Vec<(PortId, Hash32)>,
}

impl EntityRegistry {
    /// register new entity
    pub fn register(&mut self, entity: IbcEntity) -> Result<Hash32, IbcError> {
        // check for duplicate
        if self.entities.iter().any(|e| e.entity_id == entity.entity_id) {
            return Err(IbcError::InvalidStateTransition);
        }

        let id = entity.entity_id;
        let port = entity.port_id.clone();

        self.entities.push(entity);
        self.port_to_entity.push((port, id));

        Ok(id)
    }

    /// get entity by id
    pub fn get_entity(&self, entity_id: &Hash32) -> Option<&IbcEntity> {
        self.entities.iter().find(|e| e.entity_id == *entity_id)
    }

    /// get entity by port
    pub fn get_entity_by_port(&self, port: &PortId) -> Option<&IbcEntity> {
        self.port_to_entity.iter()
            .find(|(p, _)| p == port)
            .and_then(|(_, id)| self.get_entity(id))
    }

    /// check if entity can send on port
    pub fn can_send(&self, port: &PortId, sender: &Hash32) -> bool {
        self.get_entity_by_port(port)
            .map(|e| e.owner == *sender)
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jam_client_state() {
        let state = JamClientState::new("jam-mainnet", 0, 1024, 28800);

        assert!(!state.is_frozen());
        assert_eq!(state.validator_threshold, 683); // 2/3 + 1 of 1024
        assert_eq!(state.client_type(), "099-jam");
    }

    #[test]
    fn test_jam_consensus_commitment() {
        let cs = JamConsensusState {
            slot: 100,
            state_root: [1u8; 32],
            accumulate_root: [2u8; 32],
            validators_hash: [3u8; 32],
            timestamp: 600_000_000_000,
        };

        let commitment = cs.commitment();
        assert_ne!(commitment, [0u8; 32]);
    }

    #[test]
    fn test_ibc_entity_service() {
        let owner = [42u8; 32];
        let entity = IbcEntity::new_service(5, owner);

        assert_eq!(entity.service_index, 5);
        assert!(matches!(entity.entity_type, EntityType::Service));
        assert_eq!(entity.port_id.0, b"jam-service-5");
    }

    #[test]
    fn test_ibc_entity_parachain() {
        let owner = [42u8; 32];
        let entity = IbcEntity::new_parachain(0, 2000, owner);

        assert!(matches!(entity.entity_type, EntityType::Parachain { para_id: 2000 }));
        assert_eq!(entity.port_id.0, b"polkadot-para-2000");
    }

    #[test]
    fn test_entity_registry() {
        let mut registry = EntityRegistry::default();
        let owner = [42u8; 32];

        let entity1 = IbcEntity::new_service(1, owner);
        let entity2 = IbcEntity::new_parachain(0, 2000, owner);

        let id1 = registry.register(entity1).unwrap();
        let id2 = registry.register(entity2).unwrap();

        assert!(registry.get_entity(&id1).is_some());
        assert!(registry.get_entity(&id2).is_some());

        let port1 = PortId::new("jam-service-1");
        assert!(registry.can_send(&port1, &owner));
        assert!(!registry.can_send(&port1, &[0u8; 32]));
    }

    #[test]
    fn test_jam_state_proof_verification() {
        // create a simple proof
        let proof = JamStateProof {
            service_index: 0,
            key: b"test_key".to_vec(),
            value: b"test_value".to_vec(),
            proof: vec![],
        };

        // compute expected root (leaf hash with no siblings)
        let mut leaf_hash = Sha256::new();
        leaf_hash.update(&0u32.to_le_bytes());
        leaf_hash.update(b"test_key");
        leaf_hash.update(b"test_value");
        let root: Hash32 = leaf_hash.finalize().into();

        // verify
        assert!(verify_jam_state_proof(&proof, &root).is_ok());

        // wrong root should fail
        let wrong_root = [0u8; 32];
        assert!(verify_jam_state_proof(&proof, &wrong_root).is_err());
    }

    #[test]
    fn test_validators_hash() {
        let validators = vec![
            JamValidator {
                pubkey: [1u8; 32],
                bandersnatch: [2u8; 32],
                index: 0,
            },
            JamValidator {
                pubkey: [3u8; 32],
                bandersnatch: [4u8; 32],
                index: 1,
            },
        ];

        let hash = compute_validators_hash(&validators);
        assert_ne!(hash, [0u8; 32]);

        // same validators should give same hash
        let hash2 = compute_validators_hash(&validators);
        assert_eq!(hash, hash2);
    }
}
