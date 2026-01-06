//! privacy storage schema
//!
//! key prefixes:
//! - 0x20: note commitments (merkle tree leaves)
//! - 0x21: nullifiers (spent notes)
//! - 0x22: merkle tree nodes
//! - 0x23: commitment tree metadata

use alloc::vec::Vec;
use crate::host;
use crate::types::Hash;
use crate::codec;
use crate::privacy::{NoteCommitment, Nullifier, MerkleRoot};

// storage key prefixes
pub const PREFIX_COMMITMENT: u8 = 0x20;
pub const PREFIX_NULLIFIER: u8 = 0x21;
pub const PREFIX_MERKLE_NODE: u8 = 0x22;
pub const PREFIX_TREE_META: u8 = 0x23;

// metadata keys
pub const META_TREE_SIZE: &[u8] = &[PREFIX_TREE_META, 0x01];
pub const META_TREE_ROOT: &[u8] = &[PREFIX_TREE_META, 0x02];
pub const META_TREE_DEPTH: &[u8] = &[PREFIX_TREE_META, 0x03];

/// default tree depth (supports 2^20 = ~1M notes)
pub const DEFAULT_TREE_DEPTH: u32 = 20;

// ============================================================================
// commitment tree operations
// ============================================================================

/// get current tree size (number of commitments)
pub fn get_tree_size() -> u64 {
    host::storage_read(META_TREE_SIZE)
        .and_then(|v| codec::decode_u64(&v).map(|(s, _)| s))
        .unwrap_or(0)
}

/// set tree size
pub fn set_tree_size(size: u64) {
    let _ = host::storage_write(META_TREE_SIZE, &codec::encode_u64(size));
}

/// get current merkle root
pub fn get_merkle_root() -> Option<MerkleRoot> {
    host::storage_read(META_TREE_ROOT).and_then(|v| {
        if v.len() >= 32 {
            let mut root = [0u8; 32];
            root.copy_from_slice(&v[0..32]);
            Some(root)
        } else {
            None
        }
    })
}

/// set merkle root
pub fn set_merkle_root(root: &MerkleRoot) {
    let _ = host::storage_write(META_TREE_ROOT, root);
}

/// get tree depth
pub fn get_tree_depth() -> u32 {
    host::storage_read(META_TREE_DEPTH)
        .and_then(|v| codec::decode_u32(&v).map(|(d, _)| d))
        .unwrap_or(DEFAULT_TREE_DEPTH)
}

// ============================================================================
// commitment storage
// ============================================================================

fn commitment_key(position: u64) -> Vec<u8> {
    let mut key = Vec::with_capacity(9);
    key.push(PREFIX_COMMITMENT);
    key.extend_from_slice(&position.to_le_bytes());
    key
}

/// get commitment at position
pub fn get_commitment(position: u64) -> Option<NoteCommitment> {
    let key = commitment_key(position);
    host::storage_read(&key).and_then(|v| {
        if v.len() >= 32 {
            let mut commitment = [0u8; 32];
            commitment.copy_from_slice(&v[0..32]);
            Some(commitment)
        } else {
            None
        }
    })
}

/// store commitment at position
pub fn set_commitment(position: u64, commitment: &NoteCommitment) {
    let key = commitment_key(position);
    let _ = host::storage_write(&key, commitment);
}

/// add new commitment and return its position
pub fn add_commitment(commitment: &NoteCommitment) -> u64 {
    let position = get_tree_size();
    set_commitment(position, commitment);
    set_tree_size(position + 1);

    // update merkle tree
    update_merkle_tree(position, commitment);

    position
}

// ============================================================================
// nullifier storage
// ============================================================================

fn nullifier_key(nullifier: &Nullifier) -> Vec<u8> {
    let mut key = Vec::with_capacity(33);
    key.push(PREFIX_NULLIFIER);
    key.extend_from_slice(nullifier);
    key
}

/// check if nullifier exists (note was spent)
pub fn nullifier_exists(nullifier: &Nullifier) -> bool {
    let key = nullifier_key(nullifier);
    host::storage_read(&key).is_some()
}

/// mark nullifier as spent
pub fn set_nullifier(nullifier: &Nullifier, spent_slot: u32) {
    let key = nullifier_key(nullifier);
    let _ = host::storage_write(&key, &spent_slot.to_le_bytes());
}

/// get slot when nullifier was spent
pub fn get_nullifier_slot(nullifier: &Nullifier) -> Option<u32> {
    let key = nullifier_key(nullifier);
    host::storage_read(&key).and_then(|v| {
        if v.len() >= 4 {
            Some(u32::from_le_bytes(v[0..4].try_into().ok()?))
        } else {
            None
        }
    })
}

// ============================================================================
// merkle tree storage
// ============================================================================

fn merkle_node_key(level: u32, index: u64) -> Vec<u8> {
    let mut key = Vec::with_capacity(13);
    key.push(PREFIX_MERKLE_NODE);
    key.extend_from_slice(&level.to_le_bytes());
    key.extend_from_slice(&index.to_le_bytes());
    key
}

/// get merkle node at (level, index)
pub fn get_merkle_node(level: u32, index: u64) -> Option<Hash> {
    let key = merkle_node_key(level, index);
    host::storage_read(&key).and_then(|v| {
        if v.len() >= 32 {
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&v[0..32]);
            Some(hash)
        } else {
            None
        }
    })
}

/// set merkle node at (level, index)
pub fn set_merkle_node(level: u32, index: u64, hash: &Hash) {
    let key = merkle_node_key(level, index);
    let _ = host::storage_write(&key, hash);
}

/// update merkle tree after adding commitment at position
fn update_merkle_tree(position: u64, commitment: &NoteCommitment) {
    use crate::poseidon::{poseidon_hash, domain};

    let depth = get_tree_depth();
    let mut current_hash = *commitment;
    let mut current_index = position;

    // update path from leaf to root
    for level in 0..depth {
        // store current hash at this level
        set_merkle_node(level, current_index, &current_hash);

        // compute parent
        let sibling_index = if current_index & 1 == 0 {
            current_index + 1
        } else {
            current_index - 1
        };

        let sibling = get_merkle_node(level, sibling_index)
            .unwrap_or([0u8; 32]);  // empty node = zero

        // order for hashing depends on position
        let (left, right) = if current_index & 1 == 0 {
            (&current_hash, &sibling)
        } else {
            (&sibling, &current_hash)
        };

        // compute parent hash chunk by chunk
        let mut parent = [0u8; 32];
        for chunk_idx in 0..8 {
            let left_chunk = u32::from_le_bytes(
                left[chunk_idx*4..(chunk_idx+1)*4].try_into().unwrap()
            );
            let right_chunk = u32::from_le_bytes(
                right[chunk_idx*4..(chunk_idx+1)*4].try_into().unwrap()
            );

            let hash = poseidon_hash(domain::MERKLE_NODE, &[left_chunk, right_chunk]);
            parent[chunk_idx*4..(chunk_idx+1)*4].copy_from_slice(&hash.to_le_bytes());
        }

        current_hash = parent;
        current_index >>= 1;  // parent index
    }

    // store root
    set_merkle_root(&current_hash);
}

/// get merkle proof for commitment at position
pub fn get_merkle_proof(position: u64) -> Vec<Hash> {
    let depth = get_tree_depth();
    let mut path = Vec::with_capacity(depth as usize);
    let mut current_index = position;

    for level in 0..depth {
        let sibling_index = if current_index & 1 == 0 {
            current_index + 1
        } else {
            current_index - 1
        };

        let sibling = get_merkle_node(level, sibling_index)
            .unwrap_or([0u8; 32]);

        path.push(sibling);
        current_index >>= 1;
    }

    path
}

/// verify a historical merkle root is valid
/// (for transaction anchors that reference older tree states)
pub fn is_valid_anchor(anchor: &MerkleRoot) -> bool {
    // for now, just check if it matches current root
    // in production, we'd keep a history of recent roots
    get_merkle_root()
        .map(|root| root == *anchor)
        .unwrap_or(false)
}

// ============================================================================
// historical anchors (for transaction validity window)
// ============================================================================

const PREFIX_ANCHOR_HISTORY: u8 = 0x24;
const MAX_ANCHOR_HISTORY: u32 = 100;  // keep ~10 minutes of history at 6s blocks

fn anchor_history_key(slot: u32) -> Vec<u8> {
    let mut key = Vec::with_capacity(5);
    key.push(PREFIX_ANCHOR_HISTORY);
    key.extend_from_slice(&slot.to_le_bytes());
    key
}

/// store anchor at slot for historical lookups
pub fn store_anchor_history(slot: u32, anchor: &MerkleRoot) {
    let key = anchor_history_key(slot);
    let _ = host::storage_write(&key, anchor);
}

/// check if anchor was valid at any recent slot
pub fn is_anchor_in_history(anchor: &MerkleRoot, current_slot: u32) -> bool {
    // check current root first
    if get_merkle_root().map(|r| r == *anchor).unwrap_or(false) {
        return true;
    }

    // check historical roots
    let start_slot = current_slot.saturating_sub(MAX_ANCHOR_HISTORY);
    for slot in start_slot..current_slot {
        let key = anchor_history_key(slot);
        if let Some(stored) = host::storage_read(&key) {
            if stored.len() >= 32 && stored[0..32] == anchor[..] {
                return true;
            }
        }
    }

    false
}
