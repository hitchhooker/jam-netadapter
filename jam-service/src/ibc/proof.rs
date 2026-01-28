//! ibc proof verification (ics-023)
//!
//! iavl and simple merkle proof verification for cosmos chains

use alloc::vec::Vec;
use sha2::{Sha256, Digest};
use crate::ibc::types::*;

/// leaf prefix for iavl tree
const LEAF_PREFIX: u8 = 0x00;
/// inner node prefix for iavl tree
const INNER_PREFIX: u8 = 0x01;

/// proof operation type
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ProofOpType {
    /// iavl leaf operation
    IavlLeaf = 0,
    /// iavl inner node operation
    IavlInner = 1,
    /// simple merkle commitment operation
    SimpleMerkle = 2,
}

impl ProofOpType {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::IavlLeaf),
            1 => Some(Self::IavlInner),
            2 => Some(Self::SimpleMerkle),
            _ => None,
        }
    }
}

/// proof operation
#[derive(Clone, Debug)]
pub struct ProofOp {
    pub op_type: ProofOpType,
    pub key: Vec<u8>,
    pub data: Vec<u8>,
}

impl ProofOp {
    pub fn encode(&self, buf: &mut Vec<u8>) {
        buf.push(self.op_type as u8);
        buf.extend_from_slice(&(self.key.len() as u32).to_le_bytes());
        buf.extend_from_slice(&self.key);
        buf.extend_from_slice(&(self.data.len() as u32).to_le_bytes());
        buf.extend_from_slice(&self.data);
    }

    pub fn decode(data: &[u8]) -> Option<(Self, usize)> {
        let mut offset = 0;

        let op_type = ProofOpType::from_u8(*data.get(offset)?)?;
        offset += 1;

        if data.len() < offset + 4 {
            return None;
        }
        let key_len = u32::from_le_bytes(data[offset..offset + 4].try_into().ok()?) as usize;
        offset += 4;

        if data.len() < offset + key_len {
            return None;
        }
        let key = data[offset..offset + key_len].to_vec();
        offset += key_len;

        if data.len() < offset + 4 {
            return None;
        }
        let data_len = u32::from_le_bytes(data[offset..offset + 4].try_into().ok()?) as usize;
        offset += 4;

        if data.len() < offset + data_len {
            return None;
        }
        let op_data = data[offset..offset + data_len].to_vec();
        offset += data_len;

        Some((Self { op_type, key, data: op_data }, offset))
    }
}

/// merkle proof (list of operations)
#[derive(Clone, Debug)]
pub struct MerkleProof {
    pub ops: Vec<ProofOp>,
}

impl MerkleProof {
    pub fn encode(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&(self.ops.len() as u32).to_le_bytes());
        for op in &self.ops {
            op.encode(buf);
        }
    }

    pub fn decode(data: &[u8]) -> Option<Self> {
        let mut offset = 0;

        if data.len() < 4 {
            return None;
        }
        let ops_count = u32::from_le_bytes(data[offset..offset + 4].try_into().ok()?) as usize;
        offset += 4;

        let mut ops = Vec::with_capacity(ops_count);
        for _ in 0..ops_count {
            let (op, len) = ProofOp::decode(&data[offset..])?;
            offset += len;
            ops.push(op);
        }

        Some(Self { ops })
    }
}

/// iavl inner node structure
#[derive(Clone, Debug)]
pub struct IavlInnerNode {
    pub left: Hash32,
    pub right: Hash32,
}

impl IavlInnerNode {
    /// compute inner node hash
    /// hash = sha256(0x01 || left || right)
    pub fn hash(&self) -> Hash32 {
        let mut hasher = Sha256::new();
        hasher.update([INNER_PREFIX]);
        hasher.update(&self.left);
        hasher.update(&self.right);
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }

    pub fn decode(data: &[u8]) -> Option<Self> {
        if data.len() < 64 {
            return None;
        }
        let mut left = [0u8; 32];
        left.copy_from_slice(&data[0..32]);
        let mut right = [0u8; 32];
        right.copy_from_slice(&data[32..64]);
        Some(Self { left, right })
    }
}

/// iavl leaf structure
#[derive(Clone, Debug)]
pub struct IavlLeaf {
    pub key: Vec<u8>,
    pub value_hash: Hash32,
    pub version: u64,
}

impl IavlLeaf {
    /// compute leaf hash
    /// hash = sha256(0x00 || key_len || key || version || value_hash)
    pub fn hash(&self) -> Hash32 {
        let mut hasher = Sha256::new();
        hasher.update([LEAF_PREFIX]);

        // encode key length as varint
        let key_len = self.key.len() as u64;
        let mut buf = [0u8; 10];
        let n = encode_varint(key_len, &mut buf);
        hasher.update(&buf[..n]);

        hasher.update(&self.key);

        // encode version as varint
        let n = encode_varint(self.version, &mut buf);
        hasher.update(&buf[..n]);

        // value hash (32 bytes, prefixed with length)
        let n = encode_varint(32, &mut buf);
        hasher.update(&buf[..n]);
        hasher.update(&self.value_hash);

        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }
}

/// verify membership proof
/// proves that key exists with value at the given root
pub fn verify_membership(
    proof: &MerkleProof,
    root: &CommitmentRoot,
    path: &[u8],
    value: &[u8],
) -> Result<(), IbcError> {
    if proof.ops.is_empty() {
        return Err(IbcError::InvalidProof);
    }

    // compute value hash
    let value_hash = {
        let result = Sha256::digest(value);
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    };

    // start with leaf
    let leaf_op = &proof.ops[0];
    if leaf_op.op_type != ProofOpType::IavlLeaf {
        return Err(IbcError::InvalidProof);
    }

    // decode leaf and verify key/value
    let leaf = decode_iavl_leaf(&leaf_op.data)?;
    if leaf.key != path {
        return Err(IbcError::InvalidProof);
    }
    if leaf.value_hash != value_hash {
        return Err(IbcError::InvalidProof);
    }

    // compute leaf hash
    let mut current_hash = leaf.hash();

    // walk up the tree
    for op in &proof.ops[1..] {
        match op.op_type {
            ProofOpType::IavlInner => {
                let inner = decode_iavl_inner(&op.data, &current_hash)?;
                current_hash = inner.hash();
            }
            ProofOpType::SimpleMerkle => {
                // simple merkle just wraps
                current_hash = compute_simple_hash(&op.key, &current_hash);
            }
            _ => return Err(IbcError::InvalidProof),
        }
    }

    // verify root
    if current_hash != root.0 {
        return Err(IbcError::ProofVerificationFailed);
    }

    Ok(())
}

/// verify non-membership proof
/// proves that key does not exist at the given root
pub fn verify_non_membership(
    proof: &MerkleProof,
    root: &CommitmentRoot,
    path: &[u8],
) -> Result<(), IbcError> {
    if proof.ops.is_empty() {
        return Err(IbcError::InvalidProof);
    }

    // for non-membership, we need to show the path where key would be
    // and prove that adjacent keys don't match
    let leaf_op = &proof.ops[0];

    // compute hash from proof
    let mut current_hash = match leaf_op.op_type {
        ProofOpType::IavlLeaf => {
            let leaf = decode_iavl_leaf(&leaf_op.data)?;
            // key must NOT match for non-membership
            if leaf.key == path {
                return Err(IbcError::InvalidProof);
            }
            leaf.hash()
        }
        _ => return Err(IbcError::InvalidProof),
    };

    // walk up the tree
    for op in &proof.ops[1..] {
        match op.op_type {
            ProofOpType::IavlInner => {
                let inner = decode_iavl_inner(&op.data, &current_hash)?;
                current_hash = inner.hash();
            }
            ProofOpType::SimpleMerkle => {
                current_hash = compute_simple_hash(&op.key, &current_hash);
            }
            _ => return Err(IbcError::InvalidProof),
        }
    }

    // verify root
    if current_hash != root.0 {
        return Err(IbcError::ProofVerificationFailed);
    }

    Ok(())
}

// ============================================================================
// helper functions
// ============================================================================

fn decode_iavl_leaf(data: &[u8]) -> Result<IavlLeaf, IbcError> {
    if data.len() < 41 {
        return Err(IbcError::DecodeError);
    }

    let mut offset = 0;

    // key length (varint)
    let (key_len, n) = decode_varint(&data[offset..]).ok_or(IbcError::DecodeError)?;
    offset += n;

    // key
    if data.len() < offset + key_len as usize {
        return Err(IbcError::DecodeError);
    }
    let key = data[offset..offset + key_len as usize].to_vec();
    offset += key_len as usize;

    // version (varint)
    let (version, n) = decode_varint(&data[offset..]).ok_or(IbcError::DecodeError)?;
    offset += n;

    // value hash length (should be 32)
    let (vh_len, n) = decode_varint(&data[offset..]).ok_or(IbcError::DecodeError)?;
    offset += n;

    if vh_len != 32 || data.len() < offset + 32 {
        return Err(IbcError::DecodeError);
    }

    let mut value_hash = [0u8; 32];
    value_hash.copy_from_slice(&data[offset..offset + 32]);

    Ok(IavlLeaf { key, value_hash, version })
}

fn decode_iavl_inner(data: &[u8], child_hash: &Hash32) -> Result<IavlInnerNode, IbcError> {
    // inner node data contains the sibling hash and direction
    if data.len() < 33 {
        return Err(IbcError::DecodeError);
    }

    let direction = data[0]; // 0 = child is left, 1 = child is right
    let mut sibling = [0u8; 32];
    sibling.copy_from_slice(&data[1..33]);

    let (left, right) = if direction == 0 {
        (*child_hash, sibling)
    } else {
        (sibling, *child_hash)
    };

    Ok(IavlInnerNode { left, right })
}

fn compute_simple_hash(prefix: &[u8], hash: &Hash32) -> Hash32 {
    let mut hasher = Sha256::new();
    hasher.update(prefix);
    hasher.update(hash);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// encode unsigned varint
fn encode_varint(mut value: u64, buf: &mut [u8; 10]) -> usize {
    let mut i = 0;
    while value >= 0x80 {
        buf[i] = (value as u8) | 0x80;
        value >>= 7;
        i += 1;
    }
    buf[i] = value as u8;
    i + 1
}

/// decode unsigned varint
fn decode_varint(data: &[u8]) -> Option<(u64, usize)> {
    let mut value: u64 = 0;
    let mut shift = 0;
    for (i, &byte) in data.iter().enumerate() {
        if i >= 10 {
            return None; // overflow
        }
        value |= ((byte & 0x7f) as u64) << shift;
        if byte < 0x80 {
            return Some((value, i + 1));
        }
        shift += 7;
    }
    None
}
