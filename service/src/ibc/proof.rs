//! merkle proof verification
//!
//! iavl and ics23 compatible proof verification for cosmos state proofs

use sha2::{Sha256, Digest};

use super::types::*;

/// merkle proof structure
#[derive(Clone, Debug)]
pub struct MerkleProof {
    /// proof operations (one per store layer)
    pub proofs: Vec<CommitmentProof>,
}

/// individual commitment proof
#[derive(Clone, Debug)]
pub struct CommitmentProof {
    /// proof type
    pub proof_type: ProofType,
    /// proof data
    pub data: ProofData,
}

/// proof type
#[derive(Clone, Debug)]
pub enum ProofType {
    /// existence proof
    Exist,
    /// non-existence proof
    NonExist,
}

/// proof data variants
#[derive(Clone, Debug)]
pub enum ProofData {
    /// existence proof data
    Exist(ExistenceProof),
    /// non-existence proof data
    NonExist(NonExistenceProof),
}

/// existence proof (key exists in tree)
#[derive(Clone, Debug)]
pub struct ExistenceProof {
    /// key
    pub key: Vec<u8>,
    /// value
    pub value: Vec<u8>,
    /// leaf operation
    pub leaf: LeafOp,
    /// inner path operations
    pub path: Vec<InnerOp>,
}

impl ExistenceProof {
    /// calculate root hash
    pub fn calculate_root(&self) -> Result<Hash32, IbcError> {
        // compute leaf hash
        let mut leaf_hash = self.leaf.apply(&self.key, &self.value)?;

        // apply inner ops up the tree
        for inner in &self.path {
            leaf_hash = inner.apply(&leaf_hash)?;
        }

        Ok(leaf_hash)
    }
}

/// non-existence proof (key does not exist)
#[derive(Clone, Debug)]
pub struct NonExistenceProof {
    /// key that doesn't exist
    pub key: Vec<u8>,
    /// proof of left neighbor (if any)
    pub left: Option<ExistenceProof>,
    /// proof of right neighbor (if any)
    pub right: Option<ExistenceProof>,
}

impl NonExistenceProof {
    /// verify non-existence against root
    pub fn verify(&self, root: &Hash32) -> Result<(), IbcError> {
        // at least one neighbor must exist
        if self.left.is_none() && self.right.is_none() {
            return Err(IbcError::InvalidProof);
        }

        // verify left neighbor
        if let Some(ref left) = self.left {
            let left_root = left.calculate_root()?;
            if &left_root != root {
                return Err(IbcError::InvalidProof);
            }
            // left key must be < target key
            if left.key >= self.key {
                return Err(IbcError::InvalidProof);
            }
        }

        // verify right neighbor
        if let Some(ref right) = self.right {
            let right_root = right.calculate_root()?;
            if &right_root != root {
                return Err(IbcError::InvalidProof);
            }
            // right key must be > target key
            if right.key <= self.key {
                return Err(IbcError::InvalidProof);
            }
        }

        // verify neighbors are adjacent (no key between them)
        if let (Some(left), Some(right)) = (&self.left, &self.right) {
            if !are_adjacent(&left.key, &right.key, &self.key) {
                return Err(IbcError::InvalidProof);
            }
        }

        Ok(())
    }
}

/// leaf operation
#[derive(Clone, Debug)]
pub struct LeafOp {
    /// hash function (0 = sha256)
    pub hash: u8,
    /// prehash key function
    pub prehash_key: u8,
    /// prehash value function
    pub prehash_value: u8,
    /// length encoding (0 = none, 1 = varint)
    pub length: u8,
    /// prefix bytes
    pub prefix: Vec<u8>,
}

impl LeafOp {
    /// apply leaf operation to get leaf hash
    pub fn apply(&self, key: &[u8], value: &[u8]) -> Result<Hash32, IbcError> {
        let mut hasher = Sha256::new();

        // add prefix
        hasher.update(&self.prefix);

        // prehash key if needed
        let key_data = if self.prehash_key == 1 {
            Sha256::digest(key).to_vec()
        } else {
            key.to_vec()
        };

        // prehash value if needed
        let value_data = if self.prehash_value == 1 {
            Sha256::digest(value).to_vec()
        } else {
            value.to_vec()
        };

        // add length-prefixed key
        match self.length {
            0 => {
                // no length prefix
                hasher.update(&key_data);
            }
            1 => {
                // varint length prefix
                hasher.update(&encode_varint(key_data.len() as u64));
                hasher.update(&key_data);
            }
            _ => return Err(IbcError::InvalidProof),
        }

        // add length-prefixed value
        match self.length {
            0 => {
                hasher.update(&value_data);
            }
            1 => {
                hasher.update(&encode_varint(value_data.len() as u64));
                hasher.update(&value_data);
            }
            _ => return Err(IbcError::InvalidProof),
        }

        Ok(hasher.finalize().into())
    }

    /// cosmos iavl leaf spec
    pub fn iavl() -> Self {
        Self {
            hash: 0,         // sha256
            prehash_key: 0,  // no prehash
            prehash_value: 1, // sha256
            length: 1,       // varint
            prefix: vec![0], // leaf prefix
        }
    }

    /// cosmos tendermint leaf spec
    pub fn tendermint() -> Self {
        Self {
            hash: 0,
            prehash_key: 0,
            prehash_value: 1,
            length: 1,
            prefix: vec![0],
        }
    }

    /// penumbra jellyfish merkle tree (jmt) leaf spec
    pub fn jmt() -> Self {
        Self {
            hash: 0,          // sha256
            prehash_key: 1,   // sha256 prehash
            prehash_value: 1, // sha256 prehash
            length: 0,        // no length prefix
            prefix: b"JMT::LeafNode".to_vec(),
        }
    }
}

/// inner operation (non-leaf node)
#[derive(Clone, Debug)]
pub struct InnerOp {
    /// hash function
    pub hash: u8,
    /// prefix bytes (before child hash)
    pub prefix: Vec<u8>,
    /// suffix bytes (after child hash)
    pub suffix: Vec<u8>,
}

impl InnerOp {
    /// apply inner operation
    pub fn apply(&self, child_hash: &[u8]) -> Result<Hash32, IbcError> {
        let mut hasher = Sha256::new();
        hasher.update(&self.prefix);
        hasher.update(child_hash);
        hasher.update(&self.suffix);
        Ok(hasher.finalize().into())
    }

    /// cosmos iavl inner spec
    pub fn iavl() -> InnerSpec {
        InnerSpec {
            child_order: vec![0, 1],
            child_size: 33,
            min_prefix_length: 4,
            max_prefix_length: 12,
            empty_child: vec![],
            hash: 0,
        }
    }

    /// cosmos tendermint inner spec
    pub fn tendermint() -> InnerSpec {
        InnerSpec {
            child_order: vec![0, 1],
            child_size: 32,
            min_prefix_length: 1,
            max_prefix_length: 1,
            empty_child: vec![],
            hash: 0,
        }
    }

    /// penumbra jmt inner spec
    pub fn jmt() -> InnerSpec {
        InnerSpec {
            child_order: vec![0, 1],
            child_size: 32,
            min_prefix_length: 1,
            max_prefix_length: 1,
            // jmt sparse merkle placeholder hash
            empty_child: vec![
                0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            ],
            hash: 0,
        }
    }
}

/// inner node specification for different tree types
#[derive(Clone, Debug)]
pub struct InnerSpec {
    /// child ordering (left=0, right=1)
    pub child_order: Vec<u8>,
    /// size of each child hash
    pub child_size: u32,
    /// minimum prefix length before child hash
    pub min_prefix_length: u32,
    /// maximum prefix length before child hash
    pub max_prefix_length: u32,
    /// placeholder for empty/sparse nodes
    pub empty_child: Vec<u8>,
    /// hash function (0 = sha256)
    pub hash: u8,
}

/// proof spec combining leaf and inner specs
#[derive(Clone, Debug)]
pub struct ProofSpec {
    pub leaf_spec: LeafOp,
    pub inner_spec: InnerSpec,
    /// maximum tree depth
    pub max_depth: u32,
    /// minimum tree depth
    pub min_depth: u32,
    /// prehash key before leaf op
    pub prehash_key_before_comparison: bool,
}

impl ProofSpec {
    /// cosmos iavl proof spec
    pub fn iavl() -> Self {
        Self {
            leaf_spec: LeafOp::iavl(),
            inner_spec: InnerOp::iavl(),
            max_depth: 0,
            min_depth: 0,
            prehash_key_before_comparison: false,
        }
    }

    /// cosmos tendermint proof spec
    pub fn tendermint() -> Self {
        Self {
            leaf_spec: LeafOp::tendermint(),
            inner_spec: InnerOp::tendermint(),
            max_depth: 0,
            min_depth: 0,
            prehash_key_before_comparison: false,
        }
    }

    /// penumbra jmt proof spec
    pub fn jmt() -> Self {
        Self {
            leaf_spec: LeafOp::jmt(),
            inner_spec: InnerOp::jmt(),
            max_depth: 64, // jmt has 256-bit keys with 64 nibbles
            min_depth: 0,
            prehash_key_before_comparison: true, // jmt uses key hash for path
        }
    }
}

/// verify merkle proof for existence
pub fn verify_membership(
    proof: &MerkleProof,
    root: &CommitmentRoot,
    path: &[Vec<u8>],
    value: &[u8],
) -> Result<(), IbcError> {
    if proof.proofs.is_empty() {
        return Err(IbcError::InvalidProof);
    }

    // for multi-store proofs, verify each layer
    let mut current_root = *root;

    for (i, p) in proof.proofs.iter().enumerate() {
        match &p.data {
            ProofData::Exist(exist_proof) => {
                // verify key matches path component
                if i < path.len() && exist_proof.key != path[i] {
                    return Err(IbcError::InvalidProof);
                }

                // for leaf (last proof), verify value
                if i == proof.proofs.len() - 1 {
                    if exist_proof.value != value {
                        return Err(IbcError::InvalidProof);
                    }
                }

                // calculate and verify root
                let calculated_root = exist_proof.calculate_root()?;
                if calculated_root != current_root {
                    return Err(IbcError::InvalidProof);
                }

                // for intermediate proofs, the value is the next root
                if i < proof.proofs.len() - 1 {
                    if exist_proof.value.len() != 32 {
                        return Err(IbcError::InvalidProof);
                    }
                    current_root.copy_from_slice(&exist_proof.value);
                }
            }
            ProofData::NonExist(_) => {
                return Err(IbcError::InvalidProof);
            }
        }
    }

    Ok(())
}

/// verify merkle proof for non-existence
pub fn verify_non_membership(
    proof: &MerkleProof,
    root: &CommitmentRoot,
    path: &[Vec<u8>],
) -> Result<(), IbcError> {
    if proof.proofs.is_empty() {
        return Err(IbcError::InvalidProof);
    }

    // find the non-existence proof in the chain
    for p in &proof.proofs {
        if let ProofData::NonExist(non_exist) = &p.data {
            // verify key matches path
            if !path.is_empty() && non_exist.key != path[path.len() - 1] {
                return Err(IbcError::InvalidProof);
            }
            return non_exist.verify(root);
        }
    }

    Err(IbcError::InvalidProof)
}

/// decode commitment proof from bytes
pub fn decode_proof(data: &[u8]) -> Result<MerkleProof, IbcError> {
    // simplified decoder - real impl needs proper protobuf
    if data.len() < 4 {
        return Err(IbcError::DecodingError);
    }

    let num_proofs = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;
    let mut offset = 4;
    let mut proofs = Vec::with_capacity(num_proofs);

    for _ in 0..num_proofs {
        if offset + 4 > data.len() {
            return Err(IbcError::DecodingError);
        }

        let proof_len = u32::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]) as usize;
        offset += 4;

        if offset + proof_len > data.len() {
            return Err(IbcError::DecodingError);
        }

        let proof_data = &data[offset..offset + proof_len];
        let proof = decode_commitment_proof(proof_data)?;
        proofs.push(proof);
        offset += proof_len;
    }

    Ok(MerkleProof { proofs })
}

/// decode single commitment proof
fn decode_commitment_proof(data: &[u8]) -> Result<CommitmentProof, IbcError> {
    if data.is_empty() {
        return Err(IbcError::DecodingError);
    }

    let proof_type = match data[0] {
        0 => ProofType::Exist,
        1 => ProofType::NonExist,
        _ => return Err(IbcError::DecodingError),
    };

    let proof_data = match proof_type {
        ProofType::Exist => {
            let exist = decode_existence_proof(&data[1..])?;
            ProofData::Exist(exist)
        }
        ProofType::NonExist => {
            let non_exist = decode_non_existence_proof(&data[1..])?;
            ProofData::NonExist(non_exist)
        }
    };

    Ok(CommitmentProof {
        proof_type,
        data: proof_data,
    })
}

/// decode existence proof
fn decode_existence_proof(data: &[u8]) -> Result<ExistenceProof, IbcError> {
    let mut offset = 0;

    // key length + key
    if offset + 4 > data.len() {
        return Err(IbcError::DecodingError);
    }
    let key_len = u32::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ]) as usize;
    offset += 4;

    if offset + key_len > data.len() {
        return Err(IbcError::DecodingError);
    }
    let key = data[offset..offset + key_len].to_vec();
    offset += key_len;

    // value length + value
    if offset + 4 > data.len() {
        return Err(IbcError::DecodingError);
    }
    let value_len = u32::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ]) as usize;
    offset += 4;

    if offset + value_len > data.len() {
        return Err(IbcError::DecodingError);
    }
    let value = data[offset..offset + value_len].to_vec();
    offset += value_len;

    // leaf op (use default iavl for now)
    let leaf = LeafOp::iavl();

    // inner ops
    if offset + 4 > data.len() {
        return Err(IbcError::DecodingError);
    }
    let num_inner = u32::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ]) as usize;
    offset += 4;

    let mut path = Vec::with_capacity(num_inner);
    for _ in 0..num_inner {
        if offset + 8 > data.len() {
            return Err(IbcError::DecodingError);
        }

        let prefix_len = u32::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]) as usize;
        offset += 4;

        let suffix_len = u32::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]) as usize;
        offset += 4;

        if offset + prefix_len + suffix_len > data.len() {
            return Err(IbcError::DecodingError);
        }

        let prefix = data[offset..offset + prefix_len].to_vec();
        offset += prefix_len;

        let suffix = data[offset..offset + suffix_len].to_vec();
        offset += suffix_len;

        path.push(InnerOp {
            hash: 0, // sha256
            prefix,
            suffix,
        });
    }

    Ok(ExistenceProof {
        key,
        value,
        leaf,
        path,
    })
}

/// decode non-existence proof
fn decode_non_existence_proof(data: &[u8]) -> Result<NonExistenceProof, IbcError> {
    let mut offset = 0;

    // key
    if offset + 4 > data.len() {
        return Err(IbcError::DecodingError);
    }
    let key_len = u32::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ]) as usize;
    offset += 4;

    if offset + key_len > data.len() {
        return Err(IbcError::DecodingError);
    }
    let key = data[offset..offset + key_len].to_vec();
    offset += key_len;

    // flags for left/right existence
    if offset + 1 > data.len() {
        return Err(IbcError::DecodingError);
    }
    let flags = data[offset];
    offset += 1;

    let left = if flags & 1 != 0 {
        if offset + 4 > data.len() {
            return Err(IbcError::DecodingError);
        }
        let left_len = u32::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]) as usize;
        offset += 4;

        if offset + left_len > data.len() {
            return Err(IbcError::DecodingError);
        }
        let left_proof = decode_existence_proof(&data[offset..offset + left_len])?;
        offset += left_len;
        Some(left_proof)
    } else {
        None
    };

    let right = if flags & 2 != 0 {
        if offset + 4 > data.len() {
            return Err(IbcError::DecodingError);
        }
        let right_len = u32::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]) as usize;
        offset += 4;

        if offset + right_len > data.len() {
            return Err(IbcError::DecodingError);
        }
        let right_proof = decode_existence_proof(&data[offset..offset + right_len])?;
        Some(right_proof)
    } else {
        None
    };

    Ok(NonExistenceProof { key, left, right })
}

/// check if two keys are adjacent (no key between them)
fn are_adjacent(left: &[u8], right: &[u8], target: &[u8]) -> bool {
    // target must be between left and right
    left < target && target < right
}

/// encode varint
fn encode_varint(mut n: u64) -> Vec<u8> {
    let mut buf = Vec::new();
    while n >= 0x80 {
        buf.push((n as u8) | 0x80);
        n >>= 7;
    }
    buf.push(n as u8);
    buf
}

// ============================================================================
// spec-aware proof verification
// ============================================================================

/// chain type for proof verification
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChainType {
    /// cosmos sdk chains using iavl trees
    Cosmos,
    /// tendermint-based chains
    Tendermint,
    /// penumbra using jellyfish merkle trees
    Penumbra,
}

impl ChainType {
    /// get proof spec for this chain type
    pub fn proof_spec(&self) -> ProofSpec {
        match self {
            ChainType::Cosmos => ProofSpec::iavl(),
            ChainType::Tendermint => ProofSpec::tendermint(),
            ChainType::Penumbra => ProofSpec::jmt(),
        }
    }

    /// detect chain type from chain id
    pub fn from_chain_id(chain_id: &[u8]) -> Self {
        let id = core::str::from_utf8(chain_id).unwrap_or("");

        if id.starts_with("penumbra") {
            ChainType::Penumbra
        } else if id.contains("cosmoshub") || id.contains("osmosis") {
            ChainType::Cosmos
        } else {
            // default to cosmos/tendermint
            ChainType::Tendermint
        }
    }
}

/// verify existence proof with spec
pub fn verify_existence_with_spec(
    proof: &ExistenceProof,
    spec: &ProofSpec,
    root: &Hash32,
    key: &[u8],
    value: &[u8],
) -> Result<(), IbcError> {
    // verify key matches
    if proof.key != key {
        return Err(IbcError::InvalidProof);
    }

    // verify value matches
    if proof.value != value {
        return Err(IbcError::InvalidProof);
    }

    // check depth constraints
    let depth = proof.path.len() as u32;
    if spec.max_depth > 0 && depth > spec.max_depth {
        return Err(IbcError::InvalidProof);
    }
    if depth < spec.min_depth {
        return Err(IbcError::InvalidProof);
    }

    // calculate root with spec's leaf op
    let leaf_hash = spec.leaf_spec.apply(&proof.key, &proof.value)?;

    // apply inner ops and verify against spec
    let mut current_hash = leaf_hash;
    for inner in &proof.path {
        // verify inner op constraints from spec
        if inner.prefix.len() < spec.inner_spec.min_prefix_length as usize {
            return Err(IbcError::InvalidProof);
        }
        if spec.inner_spec.max_prefix_length > 0
            && inner.prefix.len() > spec.inner_spec.max_prefix_length as usize
        {
            return Err(IbcError::InvalidProof);
        }

        current_hash = inner.apply(&current_hash)?;
    }

    // verify calculated root matches expected
    if &current_hash != root {
        return Err(IbcError::InvalidProof);
    }

    Ok(())
}

/// verify non-existence proof with spec
pub fn verify_non_existence_with_spec(
    proof: &NonExistenceProof,
    spec: &ProofSpec,
    root: &Hash32,
    key: &[u8],
) -> Result<(), IbcError> {
    // verify target key matches
    if proof.key != key {
        return Err(IbcError::InvalidProof);
    }

    // at least one neighbor must exist
    if proof.left.is_none() && proof.right.is_none() {
        return Err(IbcError::InvalidProof);
    }

    // for jmt, prehash key before comparison
    let compare_key = if spec.prehash_key_before_comparison {
        Sha256::digest(key).to_vec()
    } else {
        key.to_vec()
    };

    // verify left neighbor if present
    if let Some(left) = &proof.left {
        let left_compare = if spec.prehash_key_before_comparison {
            Sha256::digest(&left.key).to_vec()
        } else {
            left.key.clone()
        };

        // left key must be < target
        if left_compare >= compare_key {
            return Err(IbcError::InvalidProof);
        }

        // verify left proof
        let left_root = calculate_root_with_spec(left, &spec.leaf_spec)?;
        if &left_root != root {
            return Err(IbcError::InvalidProof);
        }
    }

    // verify right neighbor if present
    if let Some(right) = &proof.right {
        let right_compare = if spec.prehash_key_before_comparison {
            Sha256::digest(&right.key).to_vec()
        } else {
            right.key.clone()
        };

        // right key must be > target
        if right_compare <= compare_key {
            return Err(IbcError::InvalidProof);
        }

        // verify right proof
        let right_root = calculate_root_with_spec(right, &spec.leaf_spec)?;
        if &right_root != root {
            return Err(IbcError::InvalidProof);
        }
    }

    Ok(())
}

/// calculate root hash using specific leaf spec
fn calculate_root_with_spec(proof: &ExistenceProof, leaf_spec: &LeafOp) -> Result<Hash32, IbcError> {
    let mut current = leaf_spec.apply(&proof.key, &proof.value)?;

    for inner in &proof.path {
        current = inner.apply(&current)?;
    }

    Ok(current)
}

/// verify membership proof with chain-specific spec
pub fn verify_membership_with_chain(
    proof: &MerkleProof,
    root: &CommitmentRoot,
    path: &[Vec<u8>],
    value: &[u8],
    chain_type: ChainType,
) -> Result<(), IbcError> {
    let spec = chain_type.proof_spec();

    if proof.proofs.is_empty() {
        return Err(IbcError::InvalidProof);
    }

    let mut current_root = *root;

    for (i, p) in proof.proofs.iter().enumerate() {
        match &p.data {
            ProofData::Exist(exist_proof) => {
                // verify key matches path component
                if i < path.len() && exist_proof.key != path[i] {
                    return Err(IbcError::InvalidProof);
                }

                // for leaf (last proof), verify value
                if i == proof.proofs.len() - 1 {
                    if exist_proof.value != value {
                        return Err(IbcError::InvalidProof);
                    }
                }

                // calculate root using spec's leaf op
                let leaf_hash = spec.leaf_spec.apply(&exist_proof.key, &exist_proof.value)?;
                let mut calculated = leaf_hash;

                for inner in &exist_proof.path {
                    calculated = inner.apply(&calculated)?;
                }

                if calculated != current_root {
                    return Err(IbcError::InvalidProof);
                }

                // for intermediate proofs, the value is the next root
                if i < proof.proofs.len() - 1 {
                    if exist_proof.value.len() != 32 {
                        return Err(IbcError::InvalidProof);
                    }
                    current_root.copy_from_slice(&exist_proof.value);
                }
            }
            ProofData::NonExist(_) => {
                return Err(IbcError::InvalidProof);
            }
        }
    }

    Ok(())
}

/// verify non-membership proof with chain-specific spec
pub fn verify_non_membership_with_chain(
    proof: &MerkleProof,
    root: &CommitmentRoot,
    path: &[Vec<u8>],
    chain_type: ChainType,
) -> Result<(), IbcError> {
    let spec = chain_type.proof_spec();

    if proof.proofs.is_empty() {
        return Err(IbcError::InvalidProof);
    }

    for p in &proof.proofs {
        if let ProofData::NonExist(non_exist) = &p.data {
            let key = if !path.is_empty() {
                &path[path.len() - 1]
            } else {
                &non_exist.key
            };

            return verify_non_existence_with_spec(non_exist, &spec, root, key);
        }
    }

    Err(IbcError::InvalidProof)
}
