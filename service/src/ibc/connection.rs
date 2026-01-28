//! ics-003 connection semantics
//!
//! connection handshake state machine

use serde::{Deserialize, Serialize};

use super::types::*;

/// connection state
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConnectionState {
    /// no connection exists
    Uninitialized,
    /// connection init sent
    Init,
    /// connection try received
    TryOpen,
    /// connection is open
    Open,
}

impl Default for ConnectionState {
    fn default() -> Self {
        Self::Uninitialized
    }
}

/// connection end
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ConnectionEnd {
    /// current state
    pub state: ConnectionState,
    /// client id on this chain
    pub client_id: ClientId,
    /// counterparty connection info
    pub counterparty: Counterparty,
    /// supported versions
    pub versions: Vec<Version>,
    /// delay period (in nanoseconds)
    pub delay_period: u64,
}

/// counterparty connection info
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Counterparty {
    /// client id on counterparty
    pub client_id: ClientId,
    /// connection id on counterparty (if known)
    pub connection_id: Option<ConnectionId>,
    /// commitment prefix
    pub prefix: Vec<u8>,
}

impl ConnectionEnd {
    /// create new connection in init state
    pub fn new_init(
        client_id: ClientId,
        counterparty_client_id: ClientId,
        counterparty_prefix: Vec<u8>,
        versions: Vec<Version>,
        delay_period: u64,
    ) -> Self {
        Self {
            state: ConnectionState::Init,
            client_id,
            counterparty: Counterparty {
                client_id: counterparty_client_id,
                connection_id: None,
                prefix: counterparty_prefix,
            },
            versions,
            delay_period,
        }
    }

    /// transition to try open state
    pub fn try_open(
        &mut self,
        counterparty_connection_id: ConnectionId,
        versions: Vec<Version>,
    ) -> Result<(), IbcError> {
        if self.state != ConnectionState::Uninitialized && self.state != ConnectionState::Init {
            return Err(IbcError::InvalidStateTransition);
        }

        self.state = ConnectionState::TryOpen;
        self.counterparty.connection_id = Some(counterparty_connection_id);
        self.versions = versions;
        Ok(())
    }

    /// transition to open state
    pub fn open(&mut self) -> Result<(), IbcError> {
        match self.state {
            ConnectionState::Init | ConnectionState::TryOpen => {
                self.state = ConnectionState::Open;
                Ok(())
            }
            _ => Err(IbcError::InvalidStateTransition),
        }
    }

    /// check if connection is open
    pub fn is_open(&self) -> bool {
        self.state == ConnectionState::Open
    }

    /// check version compatibility
    pub fn pick_version(&self, proposed: &[Version]) -> Option<Version> {
        for v in proposed {
            for supported in &self.versions {
                if v.identifier == supported.identifier {
                    return Some(v.clone());
                }
            }
        }
        None
    }
}

/// connection handshake messages
#[derive(Clone, Debug)]
pub enum ConnectionMsg {
    /// initiate connection
    Init {
        client_id: ClientId,
        counterparty_client_id: ClientId,
        counterparty_prefix: Vec<u8>,
        versions: Vec<Version>,
        delay_period: u64,
    },
    /// respond to init
    TryOpen {
        client_id: ClientId,
        counterparty_client_id: ClientId,
        counterparty_connection_id: ConnectionId,
        counterparty_prefix: Vec<u8>,
        versions: Vec<Version>,
        delay_period: u64,
        proof_init: Vec<u8>,
        proof_height: Height,
    },
    /// acknowledge try open
    Ack {
        connection_id: ConnectionId,
        counterparty_connection_id: ConnectionId,
        version: Version,
        proof_try: Vec<u8>,
        proof_height: Height,
    },
    /// confirm open
    Confirm {
        connection_id: ConnectionId,
        proof_ack: Vec<u8>,
        proof_height: Height,
    },
}

/// process connection init
pub fn process_init(
    msg: &ConnectionMsg,
    next_connection_id: u64,
) -> Result<(ConnectionId, ConnectionEnd), IbcError> {
    match msg {
        ConnectionMsg::Init {
            client_id,
            counterparty_client_id,
            counterparty_prefix,
            versions,
            delay_period,
        } => {
            let conn_id = ConnectionId::new(&format!("connection-{}", next_connection_id));

            let conn = ConnectionEnd::new_init(
                client_id.clone(),
                counterparty_client_id.clone(),
                counterparty_prefix.clone(),
                versions.clone(),
                *delay_period,
            );

            Ok((conn_id, conn))
        }
        _ => Err(IbcError::InvalidStateTransition),
    }
}

/// process connection try open
pub fn process_try_open(
    msg: &ConnectionMsg,
    next_connection_id: u64,
) -> Result<(ConnectionId, ConnectionEnd), IbcError> {
    match msg {
        ConnectionMsg::TryOpen {
            client_id,
            counterparty_client_id,
            counterparty_connection_id,
            counterparty_prefix,
            versions,
            delay_period,
            proof_init: _,
            proof_height: _,
        } => {
            // TODO: verify proof_init against client state

            let conn_id = ConnectionId::new(&format!("connection-{}", next_connection_id));

            let mut conn = ConnectionEnd::new_init(
                client_id.clone(),
                counterparty_client_id.clone(),
                counterparty_prefix.clone(),
                versions.clone(),
                *delay_period,
            );

            conn.try_open(counterparty_connection_id.clone(), versions.clone())?;

            Ok((conn_id, conn))
        }
        _ => Err(IbcError::InvalidStateTransition),
    }
}

/// process connection ack
pub fn process_ack(
    conn: &mut ConnectionEnd,
    msg: &ConnectionMsg,
) -> Result<(), IbcError> {
    match msg {
        ConnectionMsg::Ack {
            connection_id: _,
            counterparty_connection_id,
            version,
            proof_try: _,
            proof_height: _,
        } => {
            // TODO: verify proof_try against client state

            if conn.state != ConnectionState::Init {
                return Err(IbcError::InvalidStateTransition);
            }

            // verify version is compatible
            if conn.pick_version(&[version.clone()]).is_none() {
                return Err(IbcError::InvalidStateTransition);
            }

            conn.counterparty.connection_id = Some(counterparty_connection_id.clone());
            conn.versions = vec![version.clone()];
            conn.open()?;

            Ok(())
        }
        _ => Err(IbcError::InvalidStateTransition),
    }
}

/// process connection confirm
pub fn process_confirm(
    conn: &mut ConnectionEnd,
    msg: &ConnectionMsg,
) -> Result<(), IbcError> {
    match msg {
        ConnectionMsg::Confirm {
            connection_id: _,
            proof_ack: _,
            proof_height: _,
        } => {
            // TODO: verify proof_ack against client state

            if conn.state != ConnectionState::TryOpen {
                return Err(IbcError::InvalidStateTransition);
            }

            conn.open()?;
            Ok(())
        }
        _ => Err(IbcError::InvalidStateTransition),
    }
}

/// default ibc version
pub fn default_ibc_version() -> Version {
    Version::new("1", &["ORDER_ORDERED", "ORDER_UNORDERED"])
}
