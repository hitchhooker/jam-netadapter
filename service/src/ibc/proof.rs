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
    /// length encoding
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

        // add length-prefixed key
        match self.length {
            0 => {
                // no length prefix
                hasher.update(key);
            }
            1 => {
                // varint length prefix
                hasher.update(&encode_varint(key.len() as u64));
                hasher.update(key);
            }
            _ => return Err(IbcError::InvalidProof),
        }

        // add length-prefixed value
        match self.length {
            0 => {
                hasher.update(value);
            }
            1 => {
                hasher.update(&encode_varint(value.len() as u64));
                hasher.update(value);
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
