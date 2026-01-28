//! ibc connection types (ics-003)
//!
//! connection handshake state machine

use alloc::vec::Vec;
use crate::ibc::types::*;

/// connection state
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum ConnectionState {
    Uninitialized = 0,
    Init = 1,
    TryOpen = 2,
    Open = 3,
}

impl ConnectionState {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Uninitialized),
            1 => Some(Self::Init),
            2 => Some(Self::TryOpen),
            3 => Some(Self::Open),
            _ => None,
        }
    }
}

/// counterparty connection info
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnectionCounterparty {
    pub client_id: ClientId,
    pub connection_id: Option<ConnectionId>,
    pub prefix: CommitmentPrefix,
}

impl ConnectionCounterparty {
    pub fn encode(&self, buf: &mut Vec<u8>) {
        self.client_id.encode(buf);
        match &self.connection_id {
            Some(id) => {
                buf.push(1);
                id.encode(buf);
            }
            None => buf.push(0),
        }
        buf.extend_from_slice(&(self.prefix.0.len() as u32).to_le_bytes());
        buf.extend_from_slice(&self.prefix.0);
    }

    pub fn decode(data: &[u8]) -> Option<(Self, usize)> {
        let mut offset = 0;

        let (client_id, len) = ClientId::decode(&data[offset..])?;
        offset += len;

        let connection_id = if data.get(offset)? == &1 {
            offset += 1;
            let (id, len) = ConnectionId::decode(&data[offset..])?;
            offset += len;
            Some(id)
        } else {
            offset += 1;
            None
        };

        if data.len() < offset + 4 {
            return None;
        }
        let prefix_len = u32::from_le_bytes(data[offset..offset + 4].try_into().ok()?) as usize;
        offset += 4;

        if data.len() < offset + prefix_len {
            return None;
        }
        let prefix = CommitmentPrefix(data[offset..offset + prefix_len].to_vec());
        offset += prefix_len;

        Some((Self { client_id, connection_id, prefix }, offset))
    }
}

/// connection end (ics-003)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnectionEnd {
    pub state: ConnectionState,
    pub client_id: ClientId,
    pub counterparty: ConnectionCounterparty,
    pub versions: Vec<Version>,
    /// delay period in nanoseconds
    pub delay_period: u64,
}

impl ConnectionEnd {
    pub fn new_init(
        client_id: ClientId,
        counterparty: ConnectionCounterparty,
        version: Version,
        delay_period: u64,
    ) -> Self {
        Self {
            state: ConnectionState::Init,
            client_id,
            counterparty,
            versions: alloc::vec![version],
            delay_period,
        }
    }

    pub fn is_open(&self) -> bool {
        self.state == ConnectionState::Open
    }

    pub fn encode(&self, buf: &mut Vec<u8>) {
        buf.push(self.state as u8);
        self.client_id.encode(buf);
        self.counterparty.encode(buf);

        buf.extend_from_slice(&(self.versions.len() as u32).to_le_bytes());
        for v in &self.versions {
            v.encode(buf);
        }

        buf.extend_from_slice(&self.delay_period.to_le_bytes());
    }

    pub fn decode(data: &[u8]) -> Option<Self> {
        let mut offset = 0;

        let state = ConnectionState::from_u8(*data.get(offset)?)?;
        offset += 1;

        let (client_id, len) = ClientId::decode(&data[offset..])?;
        offset += len;

        let (counterparty, len) = ConnectionCounterparty::decode(&data[offset..])?;
        offset += len;

        if data.len() < offset + 4 {
            return None;
        }
        let versions_count = u32::from_le_bytes(data[offset..offset + 4].try_into().ok()?) as usize;
        offset += 4;

        let mut versions = Vec::with_capacity(versions_count);
        for _ in 0..versions_count {
            let (v, len) = Version::decode(&data[offset..])?;
            offset += len;
            versions.push(v);
        }

        if data.len() < offset + 8 {
            return None;
        }
        let delay_period = u64::from_le_bytes(data[offset..offset + 8].try_into().ok()?);

        Some(Self {
            state,
            client_id,
            counterparty,
            versions,
            delay_period,
        })
    }
}

// ============================================================================
// connection handshake messages
// ============================================================================

/// conn_open_init parameters
#[derive(Clone, Debug)]
pub struct MsgConnectionOpenInit {
    pub client_id: ClientId,
    pub counterparty: ConnectionCounterparty,
    pub version: Option<Version>,
    pub delay_period: u64,
}

/// conn_open_try parameters
#[derive(Clone, Debug)]
pub struct MsgConnectionOpenTry {
    pub client_id: ClientId,
    pub counterparty: ConnectionCounterparty,
    pub counterparty_versions: Vec<Version>,
    pub delay_period: u64,
    pub proof_init: Vec<u8>,
    pub proof_client: Vec<u8>,
    pub proof_consensus: Vec<u8>,
    pub proof_height: Height,
    pub consensus_height: Height,
}

/// conn_open_ack parameters
#[derive(Clone, Debug)]
pub struct MsgConnectionOpenAck {
    pub connection_id: ConnectionId,
    pub counterparty_connection_id: ConnectionId,
    pub version: Version,
    pub proof_try: Vec<u8>,
    pub proof_client: Vec<u8>,
    pub proof_consensus: Vec<u8>,
    pub proof_height: Height,
    pub consensus_height: Height,
}

/// conn_open_confirm parameters
#[derive(Clone, Debug)]
pub struct MsgConnectionOpenConfirm {
    pub connection_id: ConnectionId,
    pub proof_ack: Vec<u8>,
    pub proof_height: Height,
}
