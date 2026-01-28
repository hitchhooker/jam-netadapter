//! ibc channel types (ics-004)
//!
//! channel handshake state machine and ordering

use alloc::vec::Vec;
use crate::ibc::types::*;

/// channel state
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum ChannelState {
    Uninitialized = 0,
    Init = 1,
    TryOpen = 2,
    Open = 3,
    Closed = 4,
}

impl ChannelState {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Uninitialized),
            1 => Some(Self::Init),
            2 => Some(Self::TryOpen),
            3 => Some(Self::Open),
            4 => Some(Self::Closed),
            _ => None,
        }
    }
}

/// channel ordering
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Order {
    Unordered = 1,
    Ordered = 2,
}

impl Order {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::Unordered),
            2 => Some(Self::Ordered),
            _ => None,
        }
    }
}

/// channel counterparty
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChannelCounterparty {
    pub port_id: PortId,
    pub channel_id: Option<ChannelId>,
}

impl ChannelCounterparty {
    pub fn encode(&self, buf: &mut Vec<u8>) {
        self.port_id.encode(buf);
        match &self.channel_id {
            Some(id) => {
                buf.push(1);
                id.encode(buf);
            }
            None => buf.push(0),
        }
    }

    pub fn decode(data: &[u8]) -> Option<(Self, usize)> {
        let mut offset = 0;

        let (port_id, len) = PortId::decode(&data[offset..])?;
        offset += len;

        let channel_id = if data.get(offset)? == &1 {
            offset += 1;
            let (id, len) = ChannelId::decode(&data[offset..])?;
            offset += len;
            Some(id)
        } else {
            offset += 1;
            None
        };

        Some((Self { port_id, channel_id }, offset))
    }
}

/// channel end (ics-004)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChannelEnd {
    pub state: ChannelState,
    pub ordering: Order,
    pub counterparty: ChannelCounterparty,
    pub connection_hops: Vec<ConnectionId>,
    pub version: Vec<u8>,
}

impl ChannelEnd {
    pub fn new_init(
        ordering: Order,
        counterparty: ChannelCounterparty,
        connection_hops: Vec<ConnectionId>,
        version: Vec<u8>,
    ) -> Self {
        Self {
            state: ChannelState::Init,
            ordering,
            counterparty,
            connection_hops,
            version,
        }
    }

    pub fn is_open(&self) -> bool {
        self.state == ChannelState::Open
    }

    pub fn encode(&self, buf: &mut Vec<u8>) {
        buf.push(self.state as u8);
        buf.push(self.ordering as u8);
        self.counterparty.encode(buf);

        buf.extend_from_slice(&(self.connection_hops.len() as u32).to_le_bytes());
        for hop in &self.connection_hops {
            hop.encode(buf);
        }

        buf.extend_from_slice(&(self.version.len() as u32).to_le_bytes());
        buf.extend_from_slice(&self.version);
    }

    pub fn decode(data: &[u8]) -> Option<Self> {
        let mut offset = 0;

        let state = ChannelState::from_u8(*data.get(offset)?)?;
        offset += 1;

        let ordering = Order::from_u8(*data.get(offset)?)?;
        offset += 1;

        let (counterparty, len) = ChannelCounterparty::decode(&data[offset..])?;
        offset += len;

        if data.len() < offset + 4 {
            return None;
        }
        let hops_count = u32::from_le_bytes(data[offset..offset + 4].try_into().ok()?) as usize;
        offset += 4;

        let mut connection_hops = Vec::with_capacity(hops_count);
        for _ in 0..hops_count {
            let (hop, len) = ConnectionId::decode(&data[offset..])?;
            offset += len;
            connection_hops.push(hop);
        }

        if data.len() < offset + 4 {
            return None;
        }
        let version_len = u32::from_le_bytes(data[offset..offset + 4].try_into().ok()?) as usize;
        offset += 4;

        if data.len() < offset + version_len {
            return None;
        }
        let version = data[offset..offset + version_len].to_vec();

        Some(Self {
            state,
            ordering,
            counterparty,
            connection_hops,
            version,
        })
    }
}

// ============================================================================
// channel handshake messages
// ============================================================================

/// chan_open_init parameters
#[derive(Clone, Debug)]
pub struct MsgChannelOpenInit {
    pub port_id: PortId,
    pub channel: ChannelEnd,
}

/// chan_open_try parameters
#[derive(Clone, Debug)]
pub struct MsgChannelOpenTry {
    pub port_id: PortId,
    pub channel: ChannelEnd,
    pub counterparty_version: Vec<u8>,
    pub proof_init: Vec<u8>,
    pub proof_height: Height,
}

/// chan_open_ack parameters
#[derive(Clone, Debug)]
pub struct MsgChannelOpenAck {
    pub port_id: PortId,
    pub channel_id: ChannelId,
    pub counterparty_channel_id: ChannelId,
    pub counterparty_version: Vec<u8>,
    pub proof_try: Vec<u8>,
    pub proof_height: Height,
}

/// chan_open_confirm parameters
#[derive(Clone, Debug)]
pub struct MsgChannelOpenConfirm {
    pub port_id: PortId,
    pub channel_id: ChannelId,
    pub proof_ack: Vec<u8>,
    pub proof_height: Height,
}

/// chan_close_init parameters
#[derive(Clone, Debug)]
pub struct MsgChannelCloseInit {
    pub port_id: PortId,
    pub channel_id: ChannelId,
}

/// chan_close_confirm parameters
#[derive(Clone, Debug)]
pub struct MsgChannelCloseConfirm {
    pub port_id: PortId,
    pub channel_id: ChannelId,
    pub proof_init: Vec<u8>,
    pub proof_height: Height,
}
