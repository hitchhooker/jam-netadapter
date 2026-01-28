//! ibc client types
//!
//! light client state and consensus state abstractions

use alloc::vec::Vec;
use crate::ibc::types::*;

/// client type discriminator
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum ClientType {
    Tendermint = 0,
    Grandpa = 1,
    // future: ethereum, near, solana
}

impl ClientType {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Tendermint),
            1 => Some(Self::Grandpa),
            _ => None,
        }
    }
}

/// client status
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClientStatus {
    Active,
    Frozen,
    Expired,
}

/// generic client state (stored per client_id)
#[derive(Clone, Debug)]
pub struct ClientStateInfo {
    pub client_type: ClientType,
    pub chain_id: ChainId,
    pub latest_height: Height,
    pub frozen_height: Option<Height>,
    pub status: ClientStatus,
    /// type-specific state (TendermintClientState encoded)
    pub state_data: Vec<u8>,
}

impl ClientStateInfo {
    pub fn is_frozen(&self) -> bool {
        self.frozen_height.is_some() || self.status == ClientStatus::Frozen
    }

    pub fn encode(&self, buf: &mut Vec<u8>) {
        buf.push(self.client_type as u8);
        self.chain_id.encode(buf);
        self.latest_height.encode(buf);

        // encode frozen_height as option
        match &self.frozen_height {
            Some(h) => {
                buf.push(1);
                h.encode(buf);
            }
            None => buf.push(0),
        }

        buf.push(self.status as u8);
        buf.extend_from_slice(&(self.state_data.len() as u32).to_le_bytes());
        buf.extend_from_slice(&self.state_data);
    }

    pub fn decode(data: &[u8]) -> Option<Self> {
        if data.len() < 2 {
            return None;
        }
        let mut offset = 0;

        let client_type = ClientType::from_u8(data[offset])?;
        offset += 1;

        let (chain_id, len) = ChainId::decode(&data[offset..])?;
        offset += len;

        let latest_height = Height::decode(&data[offset..])?;
        offset += 16;

        let frozen_height = if data[offset] == 1 {
            offset += 1;
            let h = Height::decode(&data[offset..])?;
            offset += 16;
            Some(h)
        } else {
            offset += 1;
            None
        };

        let status = match data.get(offset)? {
            0 => ClientStatus::Active,
            1 => ClientStatus::Frozen,
            2 => ClientStatus::Expired,
            _ => return None,
        };
        offset += 1;

        if data.len() < offset + 4 {
            return None;
        }
        let state_len = u32::from_le_bytes(data[offset..offset + 4].try_into().ok()?) as usize;
        offset += 4;

        if data.len() < offset + state_len {
            return None;
        }
        let state_data = data[offset..offset + state_len].to_vec();

        Some(Self {
            client_type,
            chain_id,
            latest_height,
            frozen_height,
            status,
            state_data,
        })
    }
}

/// consensus state stored at specific height
#[derive(Clone, Debug)]
pub struct ConsensusStateInfo {
    pub timestamp: Timestamp,
    pub root: CommitmentRoot,
    /// type-specific data (e.g., next_validators_hash for tendermint)
    pub state_data: Vec<u8>,
}

impl ConsensusStateInfo {
    pub fn encode(&self, buf: &mut Vec<u8>) {
        self.timestamp.encode(buf);
        self.root.encode(buf);
        buf.extend_from_slice(&(self.state_data.len() as u32).to_le_bytes());
        buf.extend_from_slice(&self.state_data);
    }

    pub fn decode(data: &[u8]) -> Option<Self> {
        if data.len() < 8 + 32 + 4 {
            return None;
        }
        let mut offset = 0;

        let timestamp = Timestamp::decode(&data[offset..])?;
        offset += 8;

        let root = CommitmentRoot::decode(&data[offset..])?;
        offset += 32;

        let state_len = u32::from_le_bytes(data[offset..offset + 4].try_into().ok()?) as usize;
        offset += 4;

        if data.len() < offset + state_len {
            return None;
        }
        let state_data = data[offset..offset + state_len].to_vec();

        Some(Self {
            timestamp,
            root,
            state_data,
        })
    }
}
