//! ics-004 channel semantics
//!
//! channel handshake state machine

use serde::{Deserialize, Serialize};

use super::types::*;

/// channel state
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChannelState {
    /// no channel exists
    Uninitialized,
    /// channel init sent
    Init,
    /// channel try received
    TryOpen,
    /// channel is open
    Open,
    /// channel is closed
    Closed,
}

impl Default for ChannelState {
    fn default() -> Self {
        Self::Uninitialized
    }
}

/// channel ordering
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Order {
    /// no ordering guarantees
    Unordered,
    /// packets delivered in order
    Ordered,
}

impl Default for Order {
    fn default() -> Self {
        Self::Unordered
    }
}

/// channel end
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ChannelEnd {
    /// current state
    pub state: ChannelState,
    /// channel ordering
    pub ordering: Order,
    /// counterparty channel info
    pub counterparty: ChannelCounterparty,
    /// connection hops (typically one)
    pub connection_hops: Vec<ConnectionId>,
    /// channel version
    pub version: Vec<u8>,
}

/// counterparty channel info
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ChannelCounterparty {
    /// port id on counterparty
    pub port_id: PortId,
    /// channel id on counterparty (if known)
    pub channel_id: Option<ChannelId>,
}

impl ChannelEnd {
    /// create new channel in init state
    pub fn new_init(
        ordering: Order,
        counterparty_port: PortId,
        connection_hops: Vec<ConnectionId>,
        version: Vec<u8>,
    ) -> Self {
        Self {
            state: ChannelState::Init,
            ordering,
            counterparty: ChannelCounterparty {
                port_id: counterparty_port,
                channel_id: None,
            },
            connection_hops,
            version,
        }
    }

    /// transition to try open state
    pub fn try_open(
        &mut self,
        counterparty_channel_id: ChannelId,
        version: Vec<u8>,
    ) -> Result<(), IbcError> {
        if self.state != ChannelState::Uninitialized && self.state != ChannelState::Init {
            return Err(IbcError::InvalidStateTransition);
        }

        self.state = ChannelState::TryOpen;
        self.counterparty.channel_id = Some(counterparty_channel_id);
        self.version = version;
        Ok(())
    }

    /// transition to open state
    pub fn open(&mut self) -> Result<(), IbcError> {
        match self.state {
            ChannelState::Init | ChannelState::TryOpen => {
                self.state = ChannelState::Open;
                Ok(())
            }
            _ => Err(IbcError::InvalidStateTransition),
        }
    }

    /// close the channel
    pub fn close(&mut self) -> Result<(), IbcError> {
        if self.state != ChannelState::Open {
            return Err(IbcError::InvalidStateTransition);
        }
        self.state = ChannelState::Closed;
        Ok(())
    }

    /// check if channel is open
    pub fn is_open(&self) -> bool {
        self.state == ChannelState::Open
    }

    /// check if channel is closed
    pub fn is_closed(&self) -> bool {
        self.state == ChannelState::Closed
    }
}

/// channel handshake messages
#[derive(Clone, Debug)]
pub enum ChannelMsg {
    /// initiate channel
    Init {
        port_id: PortId,
        ordering: Order,
        counterparty_port: PortId,
        connection_id: ConnectionId,
        version: Vec<u8>,
    },
    /// respond to init
    TryOpen {
        port_id: PortId,
        ordering: Order,
        counterparty_port: PortId,
        counterparty_channel: ChannelId,
        connection_id: ConnectionId,
        version: Vec<u8>,
        proof_init: Vec<u8>,
        proof_height: Height,
    },
    /// acknowledge try open
    Ack {
        port_id: PortId,
        channel_id: ChannelId,
        counterparty_channel: ChannelId,
        counterparty_version: Vec<u8>,
        proof_try: Vec<u8>,
        proof_height: Height,
    },
    /// confirm open
    Confirm {
        port_id: PortId,
        channel_id: ChannelId,
        proof_ack: Vec<u8>,
        proof_height: Height,
    },
    /// close init
    CloseInit {
        port_id: PortId,
        channel_id: ChannelId,
    },
    /// close confirm
    CloseConfirm {
        port_id: PortId,
        channel_id: ChannelId,
        proof_init: Vec<u8>,
        proof_height: Height,
    },
}

/// process channel init
pub fn process_channel_init(
    msg: &ChannelMsg,
    next_channel_id: u64,
) -> Result<(ChannelId, ChannelEnd), IbcError> {
    match msg {
        ChannelMsg::Init {
            port_id: _,
            ordering,
            counterparty_port,
            connection_id,
            version,
        } => {
            let channel_id = ChannelId::new(&format!("channel-{}", next_channel_id));

            let channel = ChannelEnd::new_init(
                *ordering,
                counterparty_port.clone(),
                vec![connection_id.clone()],
                version.clone(),
            );

            Ok((channel_id, channel))
        }
        _ => Err(IbcError::InvalidStateTransition),
    }
}

/// process channel try open
pub fn process_channel_try_open(
    msg: &ChannelMsg,
    next_channel_id: u64,
) -> Result<(ChannelId, ChannelEnd), IbcError> {
    match msg {
        ChannelMsg::TryOpen {
            port_id: _,
            ordering,
            counterparty_port,
            counterparty_channel,
            connection_id,
            version,
            proof_init: _,
            proof_height: _,
        } => {
            // TODO: verify proof_init

            let channel_id = ChannelId::new(&format!("channel-{}", next_channel_id));

            let mut channel = ChannelEnd::new_init(
                *ordering,
                counterparty_port.clone(),
                vec![connection_id.clone()],
                version.clone(),
            );

            channel.try_open(counterparty_channel.clone(), version.clone())?;

            Ok((channel_id, channel))
        }
        _ => Err(IbcError::InvalidStateTransition),
    }
}

/// process channel ack
pub fn process_channel_ack(
    channel: &mut ChannelEnd,
    msg: &ChannelMsg,
) -> Result<(), IbcError> {
    match msg {
        ChannelMsg::Ack {
            port_id: _,
            channel_id: _,
            counterparty_channel,
            counterparty_version,
            proof_try: _,
            proof_height: _,
        } => {
            // TODO: verify proof_try

            if channel.state != ChannelState::Init {
                return Err(IbcError::InvalidStateTransition);
            }

            channel.counterparty.channel_id = Some(counterparty_channel.clone());
            channel.version = counterparty_version.clone();
            channel.open()?;

            Ok(())
        }
        _ => Err(IbcError::InvalidStateTransition),
    }
}

/// process channel confirm
pub fn process_channel_confirm(
    channel: &mut ChannelEnd,
    msg: &ChannelMsg,
) -> Result<(), IbcError> {
    match msg {
        ChannelMsg::Confirm {
            port_id: _,
            channel_id: _,
            proof_ack: _,
            proof_height: _,
        } => {
            // TODO: verify proof_ack

            if channel.state != ChannelState::TryOpen {
                return Err(IbcError::InvalidStateTransition);
            }

            channel.open()?;
            Ok(())
        }
        _ => Err(IbcError::InvalidStateTransition),
    }
}

/// process channel close init
pub fn process_channel_close_init(
    channel: &mut ChannelEnd,
    msg: &ChannelMsg,
) -> Result<(), IbcError> {
    match msg {
        ChannelMsg::CloseInit {
            port_id: _,
            channel_id: _,
        } => {
            channel.close()?;
            Ok(())
        }
        _ => Err(IbcError::InvalidStateTransition),
    }
}

/// process channel close confirm
pub fn process_channel_close_confirm(
    channel: &mut ChannelEnd,
    msg: &ChannelMsg,
) -> Result<(), IbcError> {
    match msg {
        ChannelMsg::CloseConfirm {
            port_id: _,
            channel_id: _,
            proof_init: _,
            proof_height: _,
        } => {
            // TODO: verify proof_init

            if channel.state != ChannelState::Open {
                return Err(IbcError::InvalidStateTransition);
            }

            channel.close()?;
            Ok(())
        }
        _ => Err(IbcError::InvalidStateTransition),
    }
}

/// packet sequence tracking
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct SequenceState {
    /// next sequence to send
    pub next_send: Sequence,
    /// next sequence to receive
    pub next_recv: Sequence,
    /// next sequence to acknowledge
    pub next_ack: Sequence,
}

impl SequenceState {
    pub fn new() -> Self {
        Self {
            next_send: 1,
            next_recv: 1,
            next_ack: 1,
        }
    }

    /// allocate next send sequence
    pub fn alloc_send(&mut self) -> Sequence {
        let seq = self.next_send;
        self.next_send += 1;
        seq
    }

    /// advance recv sequence
    pub fn advance_recv(&mut self, seq: Sequence) -> Result<(), IbcError> {
        if seq != self.next_recv {
            return Err(IbcError::InvalidPacketData);
        }
        self.next_recv += 1;
        Ok(())
    }

    /// advance ack sequence
    pub fn advance_ack(&mut self, seq: Sequence) -> Result<(), IbcError> {
        if seq != self.next_ack {
            return Err(IbcError::InvalidPacketData);
        }
        self.next_ack += 1;
        Ok(())
    }
}
