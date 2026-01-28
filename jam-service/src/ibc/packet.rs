//! ibc packet types (ics-004)
//!
//! packet structure and relay messages

use alloc::vec::Vec;
use crate::ibc::types::*;

/// ibc packet
#[derive(Clone, Debug, PartialEq, Eq)]
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
    /// commitment = sha256(timeout_timestamp || timeout_height.revision_number || timeout_height.revision_height || sha256(data))
    pub fn commitment(&self) -> Hash32 {
        use sha2::{Sha256, Digest};

        let data_hash = Sha256::digest(&self.data);

        let mut preimage = Vec::with_capacity(32 + 24);
        preimage.extend_from_slice(&self.timeout_timestamp.0.to_be_bytes());
        preimage.extend_from_slice(&self.timeout_height.revision_number.to_be_bytes());
        preimage.extend_from_slice(&self.timeout_height.revision_height.to_be_bytes());
        preimage.extend_from_slice(&data_hash);

        let result = Sha256::digest(&preimage);
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }

    /// check if packet has timed out
    pub fn is_timed_out(&self, current_height: Height, current_timestamp: Timestamp) -> bool {
        // timeout by height
        if !self.timeout_height.is_zero() && current_height >= self.timeout_height {
            return true;
        }

        // timeout by timestamp
        if self.timeout_timestamp.0 > 0 && current_timestamp >= self.timeout_timestamp {
            return true;
        }

        false
    }

    pub fn encode(&self, buf: &mut Vec<u8>) {
        self.sequence.encode(buf);
        self.source_port.encode(buf);
        self.source_channel.encode(buf);
        self.destination_port.encode(buf);
        self.destination_channel.encode(buf);

        buf.extend_from_slice(&(self.data.len() as u32).to_le_bytes());
        buf.extend_from_slice(&self.data);

        self.timeout_height.encode(buf);
        self.timeout_timestamp.encode(buf);
    }

    pub fn decode(data: &[u8]) -> Option<Self> {
        let mut offset = 0;

        let sequence = Sequence::decode(&data[offset..])?;
        offset += 8;

        let (source_port, len) = PortId::decode(&data[offset..])?;
        offset += len;

        let (source_channel, len) = ChannelId::decode(&data[offset..])?;
        offset += len;

        let (destination_port, len) = PortId::decode(&data[offset..])?;
        offset += len;

        let (destination_channel, len) = ChannelId::decode(&data[offset..])?;
        offset += len;

        if data.len() < offset + 4 {
            return None;
        }
        let data_len = u32::from_le_bytes(data[offset..offset + 4].try_into().ok()?) as usize;
        offset += 4;

        if data.len() < offset + data_len {
            return None;
        }
        let packet_data = data[offset..offset + data_len].to_vec();
        offset += data_len;

        let timeout_height = Height::decode(&data[offset..])?;
        offset += 16;

        let timeout_timestamp = Timestamp::decode(&data[offset..])?;

        Some(Self {
            sequence,
            source_port,
            source_channel,
            destination_port,
            destination_channel,
            data: packet_data,
            timeout_height,
            timeout_timestamp,
        })
    }
}

/// acknowledgement data
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Acknowledgement(pub Vec<u8>);

impl Acknowledgement {
    pub fn new(data: Vec<u8>) -> Self {
        Self(data)
    }

    /// success acknowledgement (ics-020 transfer)
    pub fn success() -> Self {
        // {"result":"AQ=="} base64 of [1]
        Self(b"{\"result\":\"AQ==\"}".to_vec())
    }

    /// error acknowledgement
    pub fn error(msg: &[u8]) -> Self {
        let mut data = b"{\"error\":\"".to_vec();
        data.extend_from_slice(msg);
        data.extend_from_slice(b"\"}");
        Self(data)
    }

    /// compute acknowledgement commitment
    pub fn commitment(&self) -> Hash32 {
        use sha2::{Sha256, Digest};
        let result = Sha256::digest(&self.0);
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// packet receipt (for unordered channels)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PacketReceipt;

impl PacketReceipt {
    /// receipt is just the byte 0x01 (successful receipt)
    pub fn commitment() -> [u8; 1] {
        [0x01]
    }
}

// ============================================================================
// packet relay messages
// ============================================================================

/// recv_packet parameters
#[derive(Clone, Debug)]
pub struct MsgRecvPacket {
    pub packet: Packet,
    pub proof_commitment: Vec<u8>,
    pub proof_height: Height,
}

/// acknowledge_packet parameters
#[derive(Clone, Debug)]
pub struct MsgAcknowledgement {
    pub packet: Packet,
    pub acknowledgement: Acknowledgement,
    pub proof_acked: Vec<u8>,
    pub proof_height: Height,
}

/// timeout_packet parameters
#[derive(Clone, Debug)]
pub struct MsgTimeout {
    pub packet: Packet,
    pub next_sequence_recv: Sequence,
    pub proof_unreceived: Vec<u8>,
    pub proof_height: Height,
}

/// timeout_on_close parameters
#[derive(Clone, Debug)]
pub struct MsgTimeoutOnClose {
    pub packet: Packet,
    pub next_sequence_recv: Sequence,
    pub proof_unreceived: Vec<u8>,
    pub proof_close: Vec<u8>,
    pub proof_height: Height,
}
