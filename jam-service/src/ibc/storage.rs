//! ibc storage operations
//!
//! jam service storage for ibc state

use alloc::vec::Vec;
use crate::host::{storage_read, storage_write};
use crate::ibc::types::*;
use crate::ibc::client::*;
use crate::ibc::connection::ConnectionEnd;
use crate::ibc::channel::ChannelEnd;

// ============================================================================
// storage prefixes for ibc state
// ============================================================================

/// storage prefix for client states
pub const PREFIX_CLIENT_STATE: u8 = 0x30;
/// storage prefix for consensus states
pub const PREFIX_CONSENSUS_STATE: u8 = 0x31;
/// storage prefix for connections
pub const PREFIX_CONNECTION: u8 = 0x32;
/// storage prefix for channels
pub const PREFIX_CHANNEL: u8 = 0x33;
/// storage prefix for packet commitments
pub const PREFIX_PACKET_COMMITMENT: u8 = 0x34;
/// storage prefix for packet receipts
pub const PREFIX_PACKET_RECEIPT: u8 = 0x35;
/// storage prefix for packet acknowledgements
pub const PREFIX_PACKET_ACK: u8 = 0x36;
/// storage prefix for next sequence send
pub const PREFIX_NEXT_SEQ_SEND: u8 = 0x37;
/// storage prefix for next sequence recv
pub const PREFIX_NEXT_SEQ_RECV: u8 = 0x38;
/// storage prefix for next sequence ack
pub const PREFIX_NEXT_SEQ_ACK: u8 = 0x39;
/// storage prefix for relay tasks
pub const PREFIX_RELAY_TASK: u8 = 0x3A;
/// storage prefix for client counter
pub const PREFIX_CLIENT_COUNTER: u8 = 0x3B;
/// storage prefix for connection counter
pub const PREFIX_CONNECTION_COUNTER: u8 = 0x3C;
/// storage prefix for channel counter
pub const PREFIX_CHANNEL_COUNTER: u8 = 0x3D;

// ============================================================================
// key construction
// ============================================================================

fn client_state_key(client_id: &ClientId) -> Vec<u8> {
    let mut key = alloc::vec![PREFIX_CLIENT_STATE];
    key.extend_from_slice(&client_id.0);
    key
}

fn consensus_state_key(client_id: &ClientId, height: &Height) -> Vec<u8> {
    let mut key = alloc::vec![PREFIX_CONSENSUS_STATE];
    key.extend_from_slice(&client_id.0);
    key.push(0); // separator
    key.extend_from_slice(&height.revision_number.to_le_bytes());
    key.extend_from_slice(&height.revision_height.to_le_bytes());
    key
}

fn connection_key(connection_id: &ConnectionId) -> Vec<u8> {
    let mut key = alloc::vec![PREFIX_CONNECTION];
    key.extend_from_slice(&connection_id.0);
    key
}

fn channel_key(port_id: &PortId, channel_id: &ChannelId) -> Vec<u8> {
    let mut key = alloc::vec![PREFIX_CHANNEL];
    key.extend_from_slice(&port_id.0);
    key.push(0); // separator
    key.extend_from_slice(&channel_id.0);
    key
}

fn packet_commitment_key(port_id: &PortId, channel_id: &ChannelId, sequence: Sequence) -> Vec<u8> {
    let mut key = alloc::vec![PREFIX_PACKET_COMMITMENT];
    key.extend_from_slice(&port_id.0);
    key.push(0);
    key.extend_from_slice(&channel_id.0);
    key.push(0);
    key.extend_from_slice(&sequence.0.to_le_bytes());
    key
}

fn packet_receipt_key(port_id: &PortId, channel_id: &ChannelId, sequence: Sequence) -> Vec<u8> {
    let mut key = alloc::vec![PREFIX_PACKET_RECEIPT];
    key.extend_from_slice(&port_id.0);
    key.push(0);
    key.extend_from_slice(&channel_id.0);
    key.push(0);
    key.extend_from_slice(&sequence.0.to_le_bytes());
    key
}

fn packet_ack_key(port_id: &PortId, channel_id: &ChannelId, sequence: Sequence) -> Vec<u8> {
    let mut key = alloc::vec![PREFIX_PACKET_ACK];
    key.extend_from_slice(&port_id.0);
    key.push(0);
    key.extend_from_slice(&channel_id.0);
    key.push(0);
    key.extend_from_slice(&sequence.0.to_le_bytes());
    key
}

fn next_seq_send_key(port_id: &PortId, channel_id: &ChannelId) -> Vec<u8> {
    let mut key = alloc::vec![PREFIX_NEXT_SEQ_SEND];
    key.extend_from_slice(&port_id.0);
    key.push(0);
    key.extend_from_slice(&channel_id.0);
    key
}

fn next_seq_recv_key(port_id: &PortId, channel_id: &ChannelId) -> Vec<u8> {
    let mut key = alloc::vec![PREFIX_NEXT_SEQ_RECV];
    key.extend_from_slice(&port_id.0);
    key.push(0);
    key.extend_from_slice(&channel_id.0);
    key
}

fn next_seq_ack_key(port_id: &PortId, channel_id: &ChannelId) -> Vec<u8> {
    let mut key = alloc::vec![PREFIX_NEXT_SEQ_ACK];
    key.extend_from_slice(&port_id.0);
    key.push(0);
    key.extend_from_slice(&channel_id.0);
    key
}

// ============================================================================
// client operations
// ============================================================================

pub fn get_client_state(client_id: &ClientId) -> Option<ClientStateInfo> {
    let key = client_state_key(client_id);
    let data = storage_read(&key)?;
    ClientStateInfo::decode(&data)
}

pub fn set_client_state(client_id: &ClientId, state: &ClientStateInfo) {
    let key = client_state_key(client_id);
    let mut data = Vec::new();
    state.encode(&mut data);
    let _ = storage_write(&key, &data);
}

pub fn get_consensus_state(client_id: &ClientId, height: &Height) -> Option<ConsensusStateInfo> {
    let key = consensus_state_key(client_id, height);
    let data = storage_read(&key)?;
    ConsensusStateInfo::decode(&data)
}

pub fn set_consensus_state(client_id: &ClientId, height: &Height, state: &ConsensusStateInfo) {
    let key = consensus_state_key(client_id, height);
    let mut data = Vec::new();
    state.encode(&mut data);
    let _ = storage_write(&key, &data);
}

// ============================================================================
// connection operations
// ============================================================================

pub fn get_connection(connection_id: &ConnectionId) -> Option<ConnectionEnd> {
    let key = connection_key(connection_id);
    let data = storage_read(&key)?;
    ConnectionEnd::decode(&data)
}

pub fn set_connection(connection_id: &ConnectionId, conn: &ConnectionEnd) {
    let key = connection_key(connection_id);
    let mut data = Vec::new();
    conn.encode(&mut data);
    let _ = storage_write(&key, &data);
}

// ============================================================================
// channel operations
// ============================================================================

pub fn get_channel(port_id: &PortId, channel_id: &ChannelId) -> Option<ChannelEnd> {
    let key = channel_key(port_id, channel_id);
    let data = storage_read(&key)?;
    ChannelEnd::decode(&data)
}

pub fn set_channel(port_id: &PortId, channel_id: &ChannelId, channel: &ChannelEnd) {
    let key = channel_key(port_id, channel_id);
    let mut data = Vec::new();
    channel.encode(&mut data);
    let _ = storage_write(&key, &data);
}

// ============================================================================
// packet operations
// ============================================================================

pub fn get_packet_commitment(port_id: &PortId, channel_id: &ChannelId, sequence: Sequence) -> Option<Hash32> {
    let key = packet_commitment_key(port_id, channel_id, sequence);
    let data = storage_read(&key)?;
    if data.len() != 32 {
        return None;
    }
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&data);
    Some(hash)
}

pub fn set_packet_commitment(port_id: &PortId, channel_id: &ChannelId, sequence: Sequence, commitment: &Hash32) {
    let key = packet_commitment_key(port_id, channel_id, sequence);
    let _ = storage_write(&key, commitment);
}

pub fn delete_packet_commitment(port_id: &PortId, channel_id: &ChannelId, sequence: Sequence) {
    let key = packet_commitment_key(port_id, channel_id, sequence);
    let _ = storage_write(&key, &[]);
}

pub fn get_packet_receipt(port_id: &PortId, channel_id: &ChannelId, sequence: Sequence) -> bool {
    let key = packet_receipt_key(port_id, channel_id, sequence);
    storage_read(&key).map(|d| !d.is_empty()).unwrap_or(false)
}

pub fn set_packet_receipt(port_id: &PortId, channel_id: &ChannelId, sequence: Sequence) {
    let key = packet_receipt_key(port_id, channel_id, sequence);
    let _ = storage_write(&key, &[0x01]); // receipt marker
}

pub fn get_packet_ack(port_id: &PortId, channel_id: &ChannelId, sequence: Sequence) -> Option<Hash32> {
    let key = packet_ack_key(port_id, channel_id, sequence);
    let data = storage_read(&key)?;
    if data.len() != 32 {
        return None;
    }
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&data);
    Some(hash)
}

pub fn set_packet_ack(port_id: &PortId, channel_id: &ChannelId, sequence: Sequence, ack_commitment: &Hash32) {
    let key = packet_ack_key(port_id, channel_id, sequence);
    let _ = storage_write(&key, ack_commitment);
}

// ============================================================================
// sequence operations
// ============================================================================

pub fn get_next_sequence_send(port_id: &PortId, channel_id: &ChannelId) -> Sequence {
    let key = next_seq_send_key(port_id, channel_id);
    storage_read(&key)
        .and_then(|d| Sequence::decode(&d))
        .unwrap_or(Sequence::new(1))
}

pub fn set_next_sequence_send(port_id: &PortId, channel_id: &ChannelId, seq: Sequence) {
    let key = next_seq_send_key(port_id, channel_id);
    let mut data = Vec::new();
    seq.encode(&mut data);
    let _ = storage_write(&key, &data);
}

pub fn get_next_sequence_recv(port_id: &PortId, channel_id: &ChannelId) -> Sequence {
    let key = next_seq_recv_key(port_id, channel_id);
    storage_read(&key)
        .and_then(|d| Sequence::decode(&d))
        .unwrap_or(Sequence::new(1))
}

pub fn set_next_sequence_recv(port_id: &PortId, channel_id: &ChannelId, seq: Sequence) {
    let key = next_seq_recv_key(port_id, channel_id);
    let mut data = Vec::new();
    seq.encode(&mut data);
    let _ = storage_write(&key, &data);
}

pub fn get_next_sequence_ack(port_id: &PortId, channel_id: &ChannelId) -> Sequence {
    let key = next_seq_ack_key(port_id, channel_id);
    storage_read(&key)
        .and_then(|d| Sequence::decode(&d))
        .unwrap_or(Sequence::new(1))
}

pub fn set_next_sequence_ack(port_id: &PortId, channel_id: &ChannelId, seq: Sequence) {
    let key = next_seq_ack_key(port_id, channel_id);
    let mut data = Vec::new();
    seq.encode(&mut data);
    let _ = storage_write(&key, &data);
}

// ============================================================================
// counters
// ============================================================================

pub fn get_client_counter() -> u64 {
    let key = alloc::vec![PREFIX_CLIENT_COUNTER];
    storage_read(&key)
        .and_then(|d| if d.len() >= 8 {
            Some(u64::from_le_bytes(d[0..8].try_into().ok()?))
        } else {
            None
        })
        .unwrap_or(0)
}

pub fn increment_client_counter() -> u64 {
    let counter = get_client_counter() + 1;
    let key = alloc::vec![PREFIX_CLIENT_COUNTER];
    let _ = storage_write(&key, &counter.to_le_bytes());
    counter
}

pub fn get_connection_counter() -> u64 {
    let key = alloc::vec![PREFIX_CONNECTION_COUNTER];
    storage_read(&key)
        .and_then(|d| if d.len() >= 8 {
            Some(u64::from_le_bytes(d[0..8].try_into().ok()?))
        } else {
            None
        })
        .unwrap_or(0)
}

pub fn increment_connection_counter() -> u64 {
    let counter = get_connection_counter() + 1;
    let key = alloc::vec![PREFIX_CONNECTION_COUNTER];
    let _ = storage_write(&key, &counter.to_le_bytes());
    counter
}

pub fn get_channel_counter() -> u64 {
    let key = alloc::vec![PREFIX_CHANNEL_COUNTER];
    storage_read(&key)
        .and_then(|d| if d.len() >= 8 {
            Some(u64::from_le_bytes(d[0..8].try_into().ok()?))
        } else {
            None
        })
        .unwrap_or(0)
}

pub fn increment_channel_counter() -> u64 {
    let counter = get_channel_counter() + 1;
    let key = alloc::vec![PREFIX_CHANNEL_COUNTER];
    let _ = storage_write(&key, &counter.to_le_bytes());
    counter
}
