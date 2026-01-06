//! poseidon hash for privacy commitments (no_std)
//!
//! simplified poseidon for polkavm environment
//! uses pre-computed round constants for deterministic generation
//!
//! based on zeratul-circuit poseidon but adapted for no_std

use alloc::vec::Vec;
use crate::types::Hash;

/// poseidon state width
const WIDTH: usize = 3;

/// number of full rounds at beginning
const ROUNDS_F_BEGIN: usize = 4;

/// number of partial rounds
const ROUNDS_P: usize = 56;

/// number of full rounds at end
const ROUNDS_F_END: usize = 4;

/// total rounds
const TOTAL_ROUNDS: usize = ROUNDS_F_BEGIN + ROUNDS_P + ROUNDS_F_END;

/// irreducible polynomial for GF(2^32): x^32 + x^7 + x^3 + x^2 + 1
const IRREDUCIBLE: u64 = 0x1_0000_008D;

/// pre-computed round constants for poseidon
/// total_rounds = 4 + 56 + 4 = 64 rounds
/// constants per round = 3 (width)
/// total constants = 64 * 3 = 192
const ROUND_CONSTANTS: [u32; 192] = [
    // round 0-3 (full) - 12 constants
    0x6a09e667, 0xbb67ae85, 0x3c6ef372,
    0xa54ff53a, 0x510e527f, 0x9b05688c,
    0x1f83d9ab, 0x5be0cd19, 0x428a2f98,
    0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    // round 4-59 (partial) - 168 constants
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01,
    0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa,
    0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138,
    0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624,
    0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f,
    0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    // more constants (continued from sha2/sha3 K values)
    0xca273ece, 0xd186b8c7, 0xeada7dd6, 0xf57d4f7f, 0x06f067aa, 0x0a637dc5,
    0x113f9804, 0x1b710b35, 0x28db77f5, 0x32caab7b, 0x3c9ebe0a, 0x431d67c4,
    0x4cc5d4be, 0x597f299c, 0x5fcb6fab, 0x6c44198c, 0x7641a2d9, 0x846b7d1a,
    0x8f3f5c1e, 0x9a4e2c0e, 0xa1f6b813, 0xab893a38, 0xb66ad4c0, 0xc16b5932,
    0xcbb67ae8, 0xd53d9d7a, 0xdf6db5e0, 0xe84c3c6e, 0xf3f8bb16, 0xfc7c2b9e,
    0x05d36b2c, 0x10d4dc4d, 0x1b9172d6, 0x26514f0a, 0x3016df88, 0x3ad2821b,
    0x458f2f3d, 0x504de851, 0x5b0b1d8e, 0x65c7619b, 0x7084ad63, 0x7b4000f1,
    0x85fa3756, 0x90b38196, 0x9b6bd6f7, 0xa6243769, 0xb0dba312, 0xbb9219d6,
    0xc6489ee3, 0xd0fe3110, 0xdbb2c83c, 0xe666661f, 0xf11907cb, 0xfbcba5b0,
    0x067e35d8, 0x112fcf91, 0x1be072f7, 0x269019d4, 0x313fc7ee, 0x3bee7cfa,
    0x469c3964, 0x5148fde1, 0x5bf4c98e, 0x669f9d3e, 0x71497a1b, 0x7bf25f0d,
    // additional constants to fill 168 (56*3)
    0x869a54f7, 0x9142516c, 0x9be952a5, 0xa68f59b1, 0xb134657e, 0xbbd97730,
    0xc67d8df2, 0xd1209e89, 0xdbc2b4a1, 0xe663cf8f, 0xf103ef55, 0xfba3143e,
    0x0645c77d, 0x11a5a11e, 0x1ce4e85e, 0x282300f4, 0x3360263e, 0x3e9c4a2f,
    0x49d76e3c, 0x55119064, 0x604ab0d3, 0x6b82d066, 0x76b9ef74, 0x81f00dc7,
    0x8d2529e5, 0x985944a3, 0xa38c5e07, 0xaebe75fa, 0xb9ef8b95, 0xc51f9ffd,
    0xd04eb35b, 0xdb7cc5cc, 0xe6a9d75a, 0xf1d5e788, 0xfd00f669, 0x082b03ea,
    0x13540ffe, 0x1e7c1aa3, 0x29a323dd, 0x34c92bab, 0x3fee3243, 0x4b1237ad,
    // round 60-63 (full) - 12 constants
    0x56353c06, 0x61573f56, 0x6c7841b4, 0x77984329, 0x82b743c0, 0x8dd5439c,
    0x98f242cf, 0xa40e4176, 0xaf293f9a, 0xba433d35, 0xc55c3a5a, 0xd0743718,
];

/// MDS matrix for width=3 (Cauchy construction)
/// M[i][j] = gf32_inv(x[i] XOR y[j]) where x=[1,2,3], y=[4,5,6]
const MDS: [[u32; 3]; 3] = [
    [0x9999999a, 0xcccccccd, 0x24924925],  // inv(5), inv(4), inv(7)
    [0xaaaaaaab, 0x24924925, 0xcccccccd],  // inv(6), inv(7), inv(4)
    [0x24924925, 0xaaaaaaab, 0x9999999a],  // inv(7), inv(6), inv(5)
];

/// domain separators
pub mod domain {
    /// note commitment domain
    pub const NOTE_COMMITMENT: u32 = 0x5a455241;  // "ZERA" in LE

    /// nullifier domain
    pub const NULLIFIER: u32 = 0x4e554c4c;  // "NULL" in LE

    /// merkle node domain
    pub const MERKLE_NODE: u32 = 0x4d45524b;  // "MERK" in LE

    /// merkle leaf domain
    pub const MERKLE_LEAF: u32 = 0x4c454146;  // "LEAF" in LE
}

/// compute poseidon hash with domain separator
pub fn poseidon_hash(domain_sep: u32, inputs: &[u32]) -> u32 {
    let mut state = [0u32; WIDTH];

    // absorb domain separator and inputs
    state[0] = domain_sep;

    for (i, &input) in inputs.iter().enumerate() {
        let idx = i % 2;
        state[idx] ^= input;

        // permutation after rate elements absorbed
        if idx == 1 || i == inputs.len() - 1 {
            state = poseidon_permutation(state);
        }
    }

    state[0]
}

/// compute poseidon hash from bytes (32 bytes -> 32 bytes)
pub fn poseidon_hash_bytes(domain_sep: u32, input: &[u8; 32]) -> Hash {
    // convert input bytes to u32 chunks
    let mut inputs = [0u32; 8];
    for i in 0..8 {
        inputs[i] = u32::from_le_bytes(input[i*4..(i+1)*4].try_into().unwrap());
    }

    // hash each chunk
    let mut output = [0u8; 32];
    for i in 0..8 {
        let chunk_inputs = if i == 0 {
            &inputs[0..2]
        } else {
            &[inputs[i]]
        };

        let hash = poseidon_hash(domain_sep, chunk_inputs);
        output[i*4..(i+1)*4].copy_from_slice(&hash.to_le_bytes());
    }

    output
}

/// compute note commitment
/// commitment = poseidon(domain, blinding, amount, asset_id)
pub fn note_commitment(
    blinding: &Hash,
    amount: u64,
    asset_id: &Hash,
) -> Hash {
    let mut inputs = Vec::with_capacity(18);

    // blinding (8 chunks)
    for i in 0..8 {
        inputs.push(u32::from_le_bytes(blinding[i*4..(i+1)*4].try_into().unwrap()));
    }

    // amount (2 chunks)
    inputs.push((amount & 0xFFFFFFFF) as u32);
    inputs.push((amount >> 32) as u32);

    // asset_id (8 chunks)
    for i in 0..8 {
        inputs.push(u32::from_le_bytes(asset_id[i*4..(i+1)*4].try_into().unwrap()));
    }

    // hash with chaining
    let mut result = [0u8; 32];
    let mut prev = poseidon_hash(domain::NOTE_COMMITMENT, &inputs[0..6]);

    result[0..4].copy_from_slice(&prev.to_le_bytes());

    for i in 1..8 {
        let chunk_start = 6 + (i - 1) * 2;
        let chunk = if chunk_start + 2 <= inputs.len() {
            &inputs[chunk_start..chunk_start + 2]
        } else if chunk_start + 1 <= inputs.len() {
            &inputs[chunk_start..chunk_start + 1]
        } else {
            &[prev]
        };
        prev = poseidon_hash(domain::NOTE_COMMITMENT, &[prev, chunk[0]]);
        result[i*4..(i+1)*4].copy_from_slice(&prev.to_le_bytes());
    }

    result
}

/// compute nullifier
/// nullifier = poseidon(domain, nk, position, commitment)
pub fn compute_nullifier(nk: &Hash, position: u64, commitment: &Hash) -> Hash {
    let mut result = [0u8; 32];

    for i in 0..8 {
        let nk_chunk = u32::from_le_bytes(nk[i*4..(i+1)*4].try_into().unwrap());
        let pos_chunk = if i < 2 {
            ((position >> (i * 32)) & 0xFFFFFFFF) as u32
        } else {
            (position >> 32) as u32
        };
        let commit_chunk = u32::from_le_bytes(commitment[i*4..(i+1)*4].try_into().unwrap());

        let hash = poseidon_hash(domain::NULLIFIER, &[nk_chunk, pos_chunk, commit_chunk]);
        result[i*4..(i+1)*4].copy_from_slice(&hash.to_le_bytes());
    }

    result
}

/// verify merkle proof
pub fn verify_merkle_proof(
    leaf: &Hash,
    root: &Hash,
    position: u64,
    path: &[Hash],
) -> bool {
    // verify chunk by chunk
    for chunk_idx in 0..8 {
        let leaf_chunk = u32::from_le_bytes(
            leaf[chunk_idx*4..(chunk_idx+1)*4].try_into().unwrap()
        );

        let mut current = leaf_chunk;
        for (level, sibling) in path.iter().enumerate() {
            let sibling_chunk = u32::from_le_bytes(
                sibling[chunk_idx*4..(chunk_idx+1)*4].try_into().unwrap()
            );

            // extract position bit for this level
            let pos_bit = (position >> level) & 1;

            // conditional swap based on position bit
            let (left, right) = if pos_bit == 0 {
                (current, sibling_chunk)
            } else {
                (sibling_chunk, current)
            };

            current = poseidon_hash(domain::MERKLE_NODE, &[left, right]);
        }

        let root_chunk = u32::from_le_bytes(
            root[chunk_idx*4..(chunk_idx+1)*4].try_into().unwrap()
        );

        if current != root_chunk {
            return false;
        }
    }

    true
}

// ============================================================================
// internal functions
// ============================================================================

fn poseidon_permutation(mut state: [u32; 3]) -> [u32; 3] {
    let mut round_ctr = 0;

    // full rounds beginning
    for _ in 0..ROUNDS_F_BEGIN {
        state = full_round(state, round_ctr);
        round_ctr += WIDTH;
    }

    // partial rounds
    for _ in 0..ROUNDS_P {
        state = partial_round(state, round_ctr);
        round_ctr += WIDTH;
    }

    // full rounds end
    for _ in 0..ROUNDS_F_END {
        state = full_round(state, round_ctr);
        round_ctr += WIDTH;
    }

    state
}

fn full_round(mut state: [u32; 3], round_ctr: usize) -> [u32; 3] {
    // add round constants
    for i in 0..3 {
        state[i] ^= ROUND_CONSTANTS[round_ctr + i];
    }

    // s-box to all elements
    for i in 0..3 {
        state[i] = sbox(state[i]);
    }

    // mds multiply
    mds_multiply(state)
}

fn partial_round(mut state: [u32; 3], round_ctr: usize) -> [u32; 3] {
    // add round constants
    for i in 0..3 {
        state[i] ^= ROUND_CONSTANTS[round_ctr + i];
    }

    // s-box only to first element
    state[0] = sbox(state[0]);

    // mds multiply
    mds_multiply(state)
}

/// s-box: x^3 in GF(2^32)
fn sbox(x: u32) -> u32 {
    let x2 = gf32_mul(x, x);
    gf32_mul(x2, x)
}

/// multiply in GF(2^32)
fn gf32_mul(a: u32, b: u32) -> u32 {
    let mut result: u64 = 0;
    let mut a64 = a as u64;
    let mut b64 = b as u64;

    for _ in 0..32 {
        if b64 & 1 != 0 {
            result ^= a64;
        }
        a64 <<= 1;
        b64 >>= 1;
    }

    // reduce modulo irreducible polynomial
    for i in (32..64).rev() {
        if result & (1 << i) != 0 {
            result ^= IRREDUCIBLE << (i - 32);
        }
    }

    result as u32
}

/// MDS matrix multiplication
fn mds_multiply(state: [u32; 3]) -> [u32; 3] {
    let mut result = [0u32; 3];

    for i in 0..3 {
        for j in 0..3 {
            result[i] ^= gf32_mul(MDS[i][j], state[j]);
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_poseidon_deterministic() {
        let inputs = [0x11111111u32, 0x22222222u32];

        let hash1 = poseidon_hash(domain::NOTE_COMMITMENT, &inputs);
        let hash2 = poseidon_hash(domain::NOTE_COMMITMENT, &inputs);

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_poseidon_different_domain() {
        let inputs = [0x11111111u32];

        let hash1 = poseidon_hash(domain::NOTE_COMMITMENT, &inputs);
        let hash2 = poseidon_hash(domain::NULLIFIER, &inputs);

        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_note_commitment() {
        let blinding = [0x42u8; 32];
        let amount = 1000u64;
        let asset_id = [0xFFu8; 32];

        let commit1 = note_commitment(&blinding, amount, &asset_id);
        let commit2 = note_commitment(&blinding, amount, &asset_id);

        assert_eq!(commit1, commit2);

        // different amount should give different commitment
        let commit3 = note_commitment(&blinding, 999, &asset_id);
        assert_ne!(commit1, commit3);
    }

    #[test]
    fn test_nullifier() {
        let nk = [0x11u8; 32];
        let position = 42u64;
        let commitment = [0x22u8; 32];

        let null1 = compute_nullifier(&nk, position, &commitment);
        let null2 = compute_nullifier(&nk, position, &commitment);

        assert_eq!(null1, null2);

        // different position should give different nullifier
        let null3 = compute_nullifier(&nk, 43, &commitment);
        assert_ne!(null1, null3);
    }

    #[test]
    fn test_gf32_mul() {
        // 1 * x = x
        assert_eq!(gf32_mul(1, 0x12345678), 0x12345678);
        // x * 1 = x
        assert_eq!(gf32_mul(0x12345678, 1), 0x12345678);
        // 0 * x = 0
        assert_eq!(gf32_mul(0, 0x12345678), 0);
    }
}
