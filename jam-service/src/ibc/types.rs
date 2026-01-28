//! core ibc types
//!
//! minimal no_std types ported from ibc-rs

use alloc::vec::Vec;
use alloc::string::String;
use core::cmp::Ordering;

/// ibc height with revision number and height
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub struct Height {
    pub revision_number: u64,
    pub revision_height: u64,
}

impl Height {
    pub const fn new(revision_number: u64, revision_height: u64) -> Self {
        Self { revision_number, revision_height }
    }

    pub const fn zero() -> Self {
        Self { revision_number: 0, revision_height: 0 }
    }

    pub fn is_zero(&self) -> bool {
        self.revision_height == 0
    }

    pub fn increment(&self) -> Self {
        Self {
            revision_number: self.revision_number,
            revision_height: self.revision_height + 1,
        }
    }

    pub fn encode(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.revision_number.to_le_bytes());
        buf.extend_from_slice(&self.revision_height.to_le_bytes());
    }

    pub fn decode(data: &[u8]) -> Option<Self> {
        if data.len() < 16 {
            return None;
        }
        let revision_number = u64::from_le_bytes(data[0..8].try_into().ok()?);
        let revision_height = u64::from_le_bytes(data[8..16].try_into().ok()?);
        Some(Self { revision_number, revision_height })
    }
}

impl PartialOrd for Height {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Height {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.revision_number.cmp(&other.revision_number) {
            Ordering::Equal => self.revision_height.cmp(&other.revision_height),
            ord => ord,
        }
    }
}

/// timestamp in nanoseconds since unix epoch
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Timestamp(pub u64);

impl Timestamp {
    pub const fn from_nanoseconds(nanos: u64) -> Self {
        Self(nanos)
    }

    pub fn nanoseconds(&self) -> u64 {
        self.0
    }

    pub fn seconds(&self) -> u64 {
        self.0 / 1_000_000_000
    }

    pub fn encode(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.0.to_le_bytes());
    }

    pub fn decode(data: &[u8]) -> Option<Self> {
        if data.len() < 8 {
            return None;
        }
        Some(Self(u64::from_le_bytes(data[0..8].try_into().ok()?)))
    }
}

/// client identifier (e.g., "07-tendermint-0")
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ClientId(pub Vec<u8>);

impl ClientId {
    pub fn new(s: &[u8]) -> Self {
        Self(s.to_vec())
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn encode(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&(self.0.len() as u32).to_le_bytes());
        buf.extend_from_slice(&self.0);
    }

    pub fn decode(data: &[u8]) -> Option<(Self, usize)> {
        if data.len() < 4 {
            return None;
        }
        let len = u32::from_le_bytes(data[0..4].try_into().ok()?) as usize;
        if data.len() < 4 + len {
            return None;
        }
        Some((Self(data[4..4 + len].to_vec()), 4 + len))
    }
}

/// connection identifier (e.g., "connection-0")
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ConnectionId(pub Vec<u8>);

impl ConnectionId {
    pub fn new(s: &[u8]) -> Self {
        Self(s.to_vec())
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn encode(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&(self.0.len() as u32).to_le_bytes());
        buf.extend_from_slice(&self.0);
    }

    pub fn decode(data: &[u8]) -> Option<(Self, usize)> {
        if data.len() < 4 {
            return None;
        }
        let len = u32::from_le_bytes(data[0..4].try_into().ok()?) as usize;
        if data.len() < 4 + len {
            return None;
        }
        Some((Self(data[4..4 + len].to_vec()), 4 + len))
    }
}

/// channel identifier (e.g., "channel-0")
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ChannelId(pub Vec<u8>);

impl ChannelId {
    pub fn new(s: &[u8]) -> Self {
        Self(s.to_vec())
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn encode(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&(self.0.len() as u32).to_le_bytes());
        buf.extend_from_slice(&self.0);
    }

    pub fn decode(data: &[u8]) -> Option<(Self, usize)> {
        if data.len() < 4 {
            return None;
        }
        let len = u32::from_le_bytes(data[0..4].try_into().ok()?) as usize;
        if data.len() < 4 + len {
            return None;
        }
        Some((Self(data[4..4 + len].to_vec()), 4 + len))
    }
}

/// port identifier (e.g., "transfer")
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PortId(pub Vec<u8>);

impl PortId {
    pub fn new(s: &[u8]) -> Self {
        Self(s.to_vec())
    }

    pub fn transfer() -> Self {
        Self(b"transfer".to_vec())
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn encode(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&(self.0.len() as u32).to_le_bytes());
        buf.extend_from_slice(&self.0);
    }

    pub fn decode(data: &[u8]) -> Option<(Self, usize)> {
        if data.len() < 4 {
            return None;
        }
        let len = u32::from_le_bytes(data[0..4].try_into().ok()?) as usize;
        if data.len() < 4 + len {
            return None;
        }
        Some((Self(data[4..4 + len].to_vec()), 4 + len))
    }
}

/// packet sequence number
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Sequence(pub u64);

impl Sequence {
    pub const fn new(seq: u64) -> Self {
        Self(seq)
    }

    pub fn increment(&self) -> Self {
        Self(self.0 + 1)
    }

    pub fn encode(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.0.to_le_bytes());
    }

    pub fn decode(data: &[u8]) -> Option<Self> {
        if data.len() < 8 {
            return None;
        }
        Some(Self(u64::from_le_bytes(data[0..8].try_into().ok()?)))
    }
}

/// chain identifier (e.g., "osmosis-1")
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ChainId(pub Vec<u8>);

impl ChainId {
    pub fn new(s: &[u8]) -> Self {
        Self(s.to_vec())
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// extract revision number from chain id
    /// e.g., "osmosis-1" -> 1
    pub fn revision_number(&self) -> u64 {
        // find last '-' and parse number after it
        if let Some(pos) = self.0.iter().rposition(|&b| b == b'-') {
            if let Ok(s) = core::str::from_utf8(&self.0[pos + 1..]) {
                return s.parse().unwrap_or(0);
            }
        }
        0
    }

    pub fn encode(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&(self.0.len() as u32).to_le_bytes());
        buf.extend_from_slice(&self.0);
    }

    pub fn decode(data: &[u8]) -> Option<(Self, usize)> {
        if data.len() < 4 {
            return None;
        }
        let len = u32::from_le_bytes(data[0..4].try_into().ok()?) as usize;
        if data.len() < 4 + len {
            return None;
        }
        Some((Self(data[4..4 + len].to_vec()), 4 + len))
    }
}

/// 32-byte hash (sha256)
pub type Hash32 = [u8; 32];

/// commitment root (merkle root)
#[derive(Clone, Debug, PartialEq, Eq, Hash, Default)]
pub struct CommitmentRoot(pub Hash32);

impl CommitmentRoot {
    pub fn new(hash: Hash32) -> Self {
        Self(hash)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn encode(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.0);
    }

    pub fn decode(data: &[u8]) -> Option<Self> {
        if data.len() < 32 {
            return None;
        }
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&data[0..32]);
        Some(Self(hash))
    }
}

/// commitment prefix for ibc paths
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct CommitmentPrefix(pub Vec<u8>);

impl CommitmentPrefix {
    pub fn new(prefix: &[u8]) -> Self {
        Self(prefix.to_vec())
    }

    /// default ibc prefix
    pub fn ibc() -> Self {
        Self(b"ibc".to_vec())
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// ibc version for connection handshake
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Version {
    pub identifier: Vec<u8>,
    pub features: Vec<Vec<u8>>,
}

impl Version {
    pub fn default_ibc() -> Self {
        Self {
            identifier: b"1".to_vec(),
            features: alloc::vec![b"ORDER_ORDERED".to_vec(), b"ORDER_UNORDERED".to_vec()],
        }
    }

    pub fn encode(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&(self.identifier.len() as u32).to_le_bytes());
        buf.extend_from_slice(&self.identifier);
        buf.extend_from_slice(&(self.features.len() as u32).to_le_bytes());
        for f in &self.features {
            buf.extend_from_slice(&(f.len() as u32).to_le_bytes());
            buf.extend_from_slice(f);
        }
    }

    pub fn decode(data: &[u8]) -> Option<(Self, usize)> {
        let mut offset = 0;
        if data.len() < 4 {
            return None;
        }
        let id_len = u32::from_le_bytes(data[offset..offset + 4].try_into().ok()?) as usize;
        offset += 4;
        if data.len() < offset + id_len {
            return None;
        }
        let identifier = data[offset..offset + id_len].to_vec();
        offset += id_len;

        if data.len() < offset + 4 {
            return None;
        }
        let feat_count = u32::from_le_bytes(data[offset..offset + 4].try_into().ok()?) as usize;
        offset += 4;

        let mut features = Vec::with_capacity(feat_count);
        for _ in 0..feat_count {
            if data.len() < offset + 4 {
                return None;
            }
            let f_len = u32::from_le_bytes(data[offset..offset + 4].try_into().ok()?) as usize;
            offset += 4;
            if data.len() < offset + f_len {
                return None;
            }
            features.push(data[offset..offset + f_len].to_vec());
            offset += f_len;
        }

        Some((Self { identifier, features }, offset))
    }
}

/// error types for ibc operations
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IbcError {
    InvalidHeight,
    InvalidProof,
    InvalidSignature,
    InvalidTimestamp,
    ClientNotFound,
    ClientFrozen,
    ClientExpired,
    ConnectionNotFound,
    ChannelNotFound,
    PacketNotFound,
    InvalidSequence,
    PacketTimeout,
    PacketAlreadyReceived,
    AcknowledgementNotFound,
    InvalidCommitment,
    ProofVerificationFailed,
    InsufficientSignatures,
    UnknownClientType,
    DecodeError,
}
