//! privacy types for confidential transactions
//!
//! implements shielded notes following zeratul-circuit patterns:
//! - note commitments hide values
//! - nullifiers prevent double-spend
//! - merkle proofs for inclusion
//!
//! simplified for no_std polkavm environment

use alloc::vec::Vec;
use crate::types::{Hash, Signature, PublicKey};
use crate::codec;

/// note commitment - hides note contents
pub type NoteCommitment = Hash;

/// nullifier - reveals note was spent without revealing which
pub type Nullifier = Hash;

/// merkle root for commitment tree
pub type MerkleRoot = Hash;

/// position in commitment tree
pub type Position = u64;

/// private operation types
#[derive(Clone, Debug)]
pub enum PrivateOp {
    /// spend a note (reveal nullifier, prove inclusion)
    Spend {
        nullifier: Nullifier,
        anchor: MerkleRoot,
        proof: SpendProof,
    },
    /// create a note (publish commitment)
    Output {
        commitment: NoteCommitment,
        encrypted_note: Vec<u8>,
    },
    /// full transaction (spends + outputs)
    Transaction {
        spends: Vec<SpendData>,
        outputs: Vec<OutputData>,
        fee: u64,
        binding_signature: Signature,
    },
}

/// spend data for transaction
#[derive(Clone, Debug)]
pub struct SpendData {
    pub nullifier: Nullifier,
    pub anchor: MerkleRoot,
    pub value_commitment: Hash,
    pub proof: SpendProof,
}

/// output data for transaction
#[derive(Clone, Debug)]
pub struct OutputData {
    pub commitment: NoteCommitment,
    pub value_commitment: Hash,
    pub encrypted_note: Vec<u8>,
}

/// simplified spend proof
/// in full implementation this would be a ZK proof
/// for now we use a witness-based proof that can be verified
#[derive(Clone, Debug)]
pub struct SpendProof {
    /// merkle path siblings (32 bytes each)
    pub merkle_path: Vec<Hash>,
    /// position in tree
    pub position: Position,
    /// nullifier key (revealed for verification)
    pub nk: PublicKey,
    /// note commitment being spent
    pub note_commitment: NoteCommitment,
}

impl SpendProof {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();

        // merkle path
        out.extend_from_slice(&codec::encode_u64(self.merkle_path.len() as u64));
        for hash in &self.merkle_path {
            out.extend_from_slice(hash);
        }

        // position
        out.extend_from_slice(&self.position.to_le_bytes());

        // nk
        out.extend_from_slice(&self.nk);

        // note commitment
        out.extend_from_slice(&self.note_commitment);

        out
    }

    pub fn decode(data: &[u8]) -> Option<(Self, usize)> {
        let mut offset = 0;

        // merkle path
        let (num_siblings, consumed) = codec::decode_u64(data)?;
        offset += consumed;

        let mut merkle_path = Vec::with_capacity(num_siblings as usize);
        for _ in 0..num_siblings {
            if data.len() < offset + 32 {
                return None;
            }
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&data[offset..offset + 32]);
            offset += 32;
            merkle_path.push(hash);
        }

        // position
        if data.len() < offset + 8 {
            return None;
        }
        let position = u64::from_le_bytes(data[offset..offset + 8].try_into().ok()?);
        offset += 8;

        // nk
        if data.len() < offset + 32 {
            return None;
        }
        let mut nk = [0u8; 32];
        nk.copy_from_slice(&data[offset..offset + 32]);
        offset += 32;

        // note commitment
        if data.len() < offset + 32 {
            return None;
        }
        let mut note_commitment = [0u8; 32];
        note_commitment.copy_from_slice(&data[offset..offset + 32]);
        offset += 32;

        Some((Self { merkle_path, position, nk, note_commitment }, offset))
    }
}

impl SpendData {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.nullifier);
        out.extend_from_slice(&self.anchor);
        out.extend_from_slice(&self.value_commitment);
        out.extend_from_slice(&self.proof.encode());
        out
    }

    pub fn decode(data: &[u8]) -> Option<(Self, usize)> {
        let mut offset = 0;

        if data.len() < 32 * 3 {
            return None;
        }

        let mut nullifier = [0u8; 32];
        nullifier.copy_from_slice(&data[0..32]);
        offset += 32;

        let mut anchor = [0u8; 32];
        anchor.copy_from_slice(&data[32..64]);
        offset += 32;

        let mut value_commitment = [0u8; 32];
        value_commitment.copy_from_slice(&data[64..96]);
        offset += 32;

        let (proof, consumed) = SpendProof::decode(&data[offset..])?;
        offset += consumed;

        Some((Self { nullifier, anchor, value_commitment, proof }, offset))
    }
}

impl OutputData {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.commitment);
        out.extend_from_slice(&self.value_commitment);
        out.extend_from_slice(&codec::encode_bytes(&self.encrypted_note));
        out
    }

    pub fn decode(data: &[u8]) -> Option<(Self, usize)> {
        let mut offset = 0;

        if data.len() < 64 {
            return None;
        }

        let mut commitment = [0u8; 32];
        commitment.copy_from_slice(&data[0..32]);
        offset += 32;

        let mut value_commitment = [0u8; 32];
        value_commitment.copy_from_slice(&data[32..64]);
        offset += 32;

        let (encrypted_note, consumed) = codec::decode_bytes(&data[offset..])?;
        offset += consumed;

        Some((Self {
            commitment,
            value_commitment,
            encrypted_note: encrypted_note.to_vec()
        }, offset))
    }
}

impl PrivateOp {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();

        match self {
            PrivateOp::Spend { nullifier, anchor, proof } => {
                out.push(0);
                out.extend_from_slice(nullifier);
                out.extend_from_slice(anchor);
                out.extend_from_slice(&proof.encode());
            }
            PrivateOp::Output { commitment, encrypted_note } => {
                out.push(1);
                out.extend_from_slice(commitment);
                out.extend_from_slice(&codec::encode_bytes(encrypted_note));
            }
            PrivateOp::Transaction { spends, outputs, fee, binding_signature } => {
                out.push(2);

                out.extend_from_slice(&codec::encode_u64(spends.len() as u64));
                for spend in spends {
                    out.extend_from_slice(&spend.encode());
                }

                out.extend_from_slice(&codec::encode_u64(outputs.len() as u64));
                for output in outputs {
                    out.extend_from_slice(&output.encode());
                }

                out.extend_from_slice(&fee.to_le_bytes());
                out.extend_from_slice(binding_signature);
            }
        }

        out
    }

    pub fn decode(data: &[u8]) -> Option<(Self, usize)> {
        if data.is_empty() {
            return None;
        }

        let op_type = data[0];
        let mut offset = 1;

        match op_type {
            0 => {
                // Spend
                if data.len() < offset + 64 {
                    return None;
                }

                let mut nullifier = [0u8; 32];
                nullifier.copy_from_slice(&data[offset..offset + 32]);
                offset += 32;

                let mut anchor = [0u8; 32];
                anchor.copy_from_slice(&data[offset..offset + 32]);
                offset += 32;

                let (proof, consumed) = SpendProof::decode(&data[offset..])?;
                offset += consumed;

                Some((PrivateOp::Spend { nullifier, anchor, proof }, offset))
            }
            1 => {
                // Output
                if data.len() < offset + 32 {
                    return None;
                }

                let mut commitment = [0u8; 32];
                commitment.copy_from_slice(&data[offset..offset + 32]);
                offset += 32;

                let (encrypted_note, consumed) = codec::decode_bytes(&data[offset..])?;
                offset += consumed;

                Some((PrivateOp::Output {
                    commitment,
                    encrypted_note: encrypted_note.to_vec()
                }, offset))
            }
            2 => {
                // Transaction
                let (num_spends, consumed) = codec::decode_u64(&data[offset..])?;
                offset += consumed;

                let mut spends = Vec::with_capacity(num_spends as usize);
                for _ in 0..num_spends {
                    let (spend, consumed) = SpendData::decode(&data[offset..])?;
                    offset += consumed;
                    spends.push(spend);
                }

                let (num_outputs, consumed) = codec::decode_u64(&data[offset..])?;
                offset += consumed;

                let mut outputs = Vec::with_capacity(num_outputs as usize);
                for _ in 0..num_outputs {
                    let (output, consumed) = OutputData::decode(&data[offset..])?;
                    offset += consumed;
                    outputs.push(output);
                }

                if data.len() < offset + 8 + 64 {
                    return None;
                }

                let fee = u64::from_le_bytes(data[offset..offset + 8].try_into().ok()?);
                offset += 8;

                let mut binding_signature = [0u8; 64];
                binding_signature.copy_from_slice(&data[offset..offset + 64]);
                offset += 64;

                Some((PrivateOp::Transaction {
                    spends,
                    outputs,
                    fee,
                    binding_signature
                }, offset))
            }
            _ => None,
        }
    }
}
