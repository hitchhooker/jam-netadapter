//! ibc commitment paths (ics-024)
//!
//! standardized paths for ibc state commitments

use alloc::vec::Vec;
use crate::ibc::types::*;

/// build client state path
/// path: clients/{client_id}/clientState
pub fn client_state_path(client_id: &ClientId) -> Vec<u8> {
    let mut path = b"clients/".to_vec();
    path.extend_from_slice(&client_id.0);
    path.extend_from_slice(b"/clientState");
    path
}

/// build consensus state path
/// path: clients/{client_id}/consensusStates/{revision_number}-{revision_height}
pub fn consensus_state_path(client_id: &ClientId, height: &Height) -> Vec<u8> {
    let mut path = b"clients/".to_vec();
    path.extend_from_slice(&client_id.0);
    path.extend_from_slice(b"/consensusStates/");
    path.extend_from_slice(format_height(height).as_bytes());
    path
}

/// build connection path
/// path: connections/{connection_id}
pub fn connection_path(connection_id: &ConnectionId) -> Vec<u8> {
    let mut path = b"connections/".to_vec();
    path.extend_from_slice(&connection_id.0);
    path
}

/// build channel path
/// path: channelEnds/ports/{port_id}/channels/{channel_id}
pub fn channel_path(port_id: &PortId, channel_id: &ChannelId) -> Vec<u8> {
    let mut path = b"channelEnds/ports/".to_vec();
    path.extend_from_slice(&port_id.0);
    path.extend_from_slice(b"/channels/");
    path.extend_from_slice(&channel_id.0);
    path
}

/// build packet commitment path
/// path: commitments/ports/{port_id}/channels/{channel_id}/sequences/{sequence}
pub fn packet_commitment_path(port_id: &PortId, channel_id: &ChannelId, sequence: Sequence) -> Vec<u8> {
    let mut path = b"commitments/ports/".to_vec();
    path.extend_from_slice(&port_id.0);
    path.extend_from_slice(b"/channels/");
    path.extend_from_slice(&channel_id.0);
    path.extend_from_slice(b"/sequences/");
    path.extend_from_slice(format_u64(sequence.0).as_bytes());
    path
}

/// build packet receipt path (for unordered channels)
/// path: receipts/ports/{port_id}/channels/{channel_id}/sequences/{sequence}
pub fn packet_receipt_path(port_id: &PortId, channel_id: &ChannelId, sequence: Sequence) -> Vec<u8> {
    let mut path = b"receipts/ports/".to_vec();
    path.extend_from_slice(&port_id.0);
    path.extend_from_slice(b"/channels/");
    path.extend_from_slice(&channel_id.0);
    path.extend_from_slice(b"/sequences/");
    path.extend_from_slice(format_u64(sequence.0).as_bytes());
    path
}

/// build packet acknowledgement path
/// path: acks/ports/{port_id}/channels/{channel_id}/sequences/{sequence}
pub fn packet_ack_path(port_id: &PortId, channel_id: &ChannelId, sequence: Sequence) -> Vec<u8> {
    let mut path = b"acks/ports/".to_vec();
    path.extend_from_slice(&port_id.0);
    path.extend_from_slice(b"/channels/");
    path.extend_from_slice(&channel_id.0);
    path.extend_from_slice(b"/sequences/");
    path.extend_from_slice(format_u64(sequence.0).as_bytes());
    path
}

/// build next sequence send path
/// path: nextSequenceSend/ports/{port_id}/channels/{channel_id}
pub fn next_sequence_send_path(port_id: &PortId, channel_id: &ChannelId) -> Vec<u8> {
    let mut path = b"nextSequenceSend/ports/".to_vec();
    path.extend_from_slice(&port_id.0);
    path.extend_from_slice(b"/channels/");
    path.extend_from_slice(&channel_id.0);
    path
}

/// build next sequence recv path
/// path: nextSequenceRecv/ports/{port_id}/channels/{channel_id}
pub fn next_sequence_recv_path(port_id: &PortId, channel_id: &ChannelId) -> Vec<u8> {
    let mut path = b"nextSequenceRecv/ports/".to_vec();
    path.extend_from_slice(&port_id.0);
    path.extend_from_slice(b"/channels/");
    path.extend_from_slice(&channel_id.0);
    path
}

/// build next sequence ack path
/// path: nextSequenceAck/ports/{port_id}/channels/{channel_id}
pub fn next_sequence_ack_path(port_id: &PortId, channel_id: &ChannelId) -> Vec<u8> {
    let mut path = b"nextSequenceAck/ports/".to_vec();
    path.extend_from_slice(&port_id.0);
    path.extend_from_slice(b"/channels/");
    path.extend_from_slice(&channel_id.0);
    path
}

// ============================================================================
// helper functions
// ============================================================================

fn format_height(height: &Height) -> alloc::string::String {
    use alloc::string::ToString;
    let mut s = height.revision_number.to_string();
    s.push('-');
    s.push_str(&height.revision_height.to_string());
    s
}

fn format_u64(n: u64) -> alloc::string::String {
    use alloc::string::ToString;
    n.to_string()
}
