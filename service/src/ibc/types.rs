//! ibc core types
//!
//! minimal types for ibc protocol - no_std compatible

use serde::{Deserialize, Serialize};

/// 32-byte hash
pub type Hash32 = [u8; 32];

/// ibc height (revision_number, revision_height)
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Height {
    pub revision_number: u64,
    pub revision_height: u64,
}

impl Height {
    pub fn new(revision_number: u64, revision_height: u64) -> Self {
        Self { revision_number, revision_height }
    }

    pub fn is_zero(&self) -> bool {
        self.revision_number == 0 && self.revision_height == 0
    }

    /// check if self > other
    pub fn gt(&self, other: &Height) -> bool {
        if self.revision_number != other.revision_number {
            return self.revision_number > other.revision_number;
        }
        self.revision_height > other.revision_height
    }

    /// check if self >= other
    pub fn gte(&self, other: &Height) -> bool {
        self == other || self.gt(other)
    }
}

/// client identifier
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientId(pub Vec<u8>);

impl ClientId {
    pub fn new(s: &str) -> Self {
        Self(s.as_bytes().to_vec())
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// connection identifier
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectionId(pub Vec<u8>);

impl ConnectionId {
    pub fn new(s: &str) -> Self {
        Self(s.as_bytes().to_vec())
    }
}

/// channel identifier
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelId(pub Vec<u8>);

impl ChannelId {
    pub fn new(s: &str) -> Self {
        Self(s.as_bytes().to_vec())
    }
}

/// port identifier
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortId(pub Vec<u8>);

impl PortId {
    pub fn new(s: &str) -> Self {
        Self(s.as_bytes().to_vec())
    }
}

/// chain identifier
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainId(pub Vec<u8>);

impl ChainId {
    pub fn new(s: &str) -> Self {
        Self(s.as_bytes().to_vec())
    }

    pub fn as_str(&self) -> &str {
        core::str::from_utf8(&self.0).unwrap_or("")
    }
}

/// packet sequence number
pub type Sequence = u64;

/// unix timestamp in nanoseconds
pub type Timestamp = u64;

/// commitment root hash
pub type CommitmentRoot = Hash32;

/// ibc version string
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Version {
    pub identifier: Vec<u8>,
    pub features: Vec<Vec<u8>>,
}

impl Version {
    pub fn new(id: &str, features: &[&str]) -> Self {
        Self {
            identifier: id.as_bytes().to_vec(),
            features: features.iter().map(|f| f.as_bytes().to_vec()).collect(),
        }
    }
}

/// ibc error types
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IbcError {
    /// client not found
    ClientNotFound,
    /// client is frozen
    ClientFrozen,
    /// consensus state not found
    ConsensusStateNotFound,
    /// connection not found
    ConnectionNotFound,
    /// channel not found
    ChannelNotFound,
    /// invalid proof
    InvalidProof,
    /// invalid header
    InvalidHeader,
    /// invalid signature
    InvalidSignature,
    /// height too old
    HeightTooOld,
    /// height in future
    HeightInFuture,
    /// packet already received
    PacketAlreadyReceived,
    /// packet not found
    PacketNotFound,
    /// invalid packet data
    InvalidPacketData,
    /// timeout
    Timeout,
    /// invalid state transition
    InvalidStateTransition,
    /// insufficient voting power
    InsufficientVotingPower,
    /// encoding error
    EncodingError,
    /// decoding error
    DecodingError,
    /// storage error
    StorageError,
    /// task not found
    TaskNotFound,
    /// task already claimed
    TaskAlreadyClaimed,
    /// task expired
    TaskExpired,
    /// unauthorized
    Unauthorized,
}

/// ibc packet
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Packet {
    pub sequence: Sequence,
    pub source_port: PortId,
    pub source_channel: ChannelId,
    pub destination_port: PortId,
    pub destination_channel: ChannelId,
    pub data: Vec<u8>,
    pub timeout_height: Height,
    pub timeout_timestamp: Timestamp,
}

impl Packet {
    /// compute packet commitment hash
    pub fn commitment(&self) -> Hash32 {
        use sha2::{Sha256, Digest};

        let mut hasher = Sha256::new();
        hasher.update(&self.timeout_timestamp.to_be_bytes());
        hasher.update(&self.timeout_height.revision_number.to_be_bytes());
        hasher.update(&self.timeout_height.revision_height.to_be_bytes());

        // hash of data
        let data_hash = Sha256::digest(&self.data);
        hasher.update(&data_hash);

        hasher.finalize().into()
    }

    /// check if packet has timed out
    pub fn is_timed_out(&self, current_height: &Height, current_timestamp: Timestamp) -> bool {
        // check height timeout
        if !self.timeout_height.is_zero() && current_height.gte(&self.timeout_height) {
            return true;
        }

        // check timestamp timeout
        if self.timeout_timestamp > 0 && current_timestamp >= self.timeout_timestamp {
            return true;
        }

        false
    }
}

/// packet acknowledgement
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Acknowledgement {
    pub data: Vec<u8>,
}

impl Acknowledgement {
    /// compute acknowledgement commitment
    pub fn commitment(&self) -> Hash32 {
        use sha2::{Sha256, Digest};
        Sha256::digest(&self.data).into()
    }
}
