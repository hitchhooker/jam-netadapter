//! ibc work items for jam service
//!
//! work item types for ibc operations

use alloc::vec::Vec;
use crate::ibc::types::*;
use crate::ibc::client::ClientType;
use crate::ibc::connection::*;
use crate::ibc::channel::*;
use crate::ibc::packet::*;

/// ibc work item type discriminator
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum IbcWorkItemType {
    // client operations
    CreateClient = 0,
    UpdateClient = 1,
    UpgradeClient = 2,
    SubmitMisbehaviour = 3,

    // connection handshake
    ConnectionOpenInit = 10,
    ConnectionOpenTry = 11,
    ConnectionOpenAck = 12,
    ConnectionOpenConfirm = 13,

    // channel handshake
    ChannelOpenInit = 20,
    ChannelOpenTry = 21,
    ChannelOpenAck = 22,
    ChannelOpenConfirm = 23,
    ChannelCloseInit = 24,
    ChannelCloseConfirm = 25,

    // packet relay
    RecvPacket = 30,
    AcknowledgePacket = 31,
    TimeoutPacket = 32,
    TimeoutOnClose = 33,

    // relay task management
    ClaimRelayTask = 40,
    ConfirmExecution = 41,
}

impl IbcWorkItemType {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::CreateClient),
            1 => Some(Self::UpdateClient),
            2 => Some(Self::UpgradeClient),
            3 => Some(Self::SubmitMisbehaviour),
            10 => Some(Self::ConnectionOpenInit),
            11 => Some(Self::ConnectionOpenTry),
            12 => Some(Self::ConnectionOpenAck),
            13 => Some(Self::ConnectionOpenConfirm),
            20 => Some(Self::ChannelOpenInit),
            21 => Some(Self::ChannelOpenTry),
            22 => Some(Self::ChannelOpenAck),
            23 => Some(Self::ChannelOpenConfirm),
            24 => Some(Self::ChannelCloseInit),
            25 => Some(Self::ChannelCloseConfirm),
            30 => Some(Self::RecvPacket),
            31 => Some(Self::AcknowledgePacket),
            32 => Some(Self::TimeoutPacket),
            33 => Some(Self::TimeoutOnClose),
            40 => Some(Self::ClaimRelayTask),
            41 => Some(Self::ConfirmExecution),
            _ => None,
        }
    }
}

/// ibc work item
#[derive(Clone, Debug)]
pub enum IbcWorkItem {
    // ========================================================================
    // client operations
    // ========================================================================

    /// create a new light client
    CreateClient {
        client_type: ClientType,
        /// encoded client state (type-specific)
        client_state: Vec<u8>,
        /// encoded consensus state (type-specific)
        consensus_state: Vec<u8>,
    },

    /// update light client with new header
    UpdateClient {
        client_id: ClientId,
        /// encoded header (type-specific)
        header: Vec<u8>,
    },

    /// upgrade light client
    UpgradeClient {
        client_id: ClientId,
        upgraded_client_state: Vec<u8>,
        upgraded_consensus_state: Vec<u8>,
        proof_upgrade_client: Vec<u8>,
        proof_upgrade_consensus: Vec<u8>,
    },

    /// submit misbehaviour evidence
    SubmitMisbehaviour {
        client_id: ClientId,
        /// encoded misbehaviour (two conflicting headers)
        misbehaviour: Vec<u8>,
    },

    // ========================================================================
    // connection handshake
    // ========================================================================

    ConnectionOpenInit {
        client_id: ClientId,
        counterparty: ConnectionCounterparty,
        version: Version,
        delay_period: u64,
    },

    ConnectionOpenTry {
        client_id: ClientId,
        counterparty: ConnectionCounterparty,
        counterparty_versions: Vec<Version>,
        delay_period: u64,
        proof_init: Vec<u8>,
        proof_client: Vec<u8>,
        proof_consensus: Vec<u8>,
        proof_height: Height,
        consensus_height: Height,
    },

    ConnectionOpenAck {
        connection_id: ConnectionId,
        counterparty_connection_id: ConnectionId,
        version: Version,
        proof_try: Vec<u8>,
        proof_client: Vec<u8>,
        proof_consensus: Vec<u8>,
        proof_height: Height,
        consensus_height: Height,
    },

    ConnectionOpenConfirm {
        connection_id: ConnectionId,
        proof_ack: Vec<u8>,
        proof_height: Height,
    },

    // ========================================================================
    // channel handshake
    // ========================================================================

    ChannelOpenInit {
        port_id: PortId,
        channel: ChannelEnd,
    },

    ChannelOpenTry {
        port_id: PortId,
        channel: ChannelEnd,
        counterparty_version: Vec<u8>,
        proof_init: Vec<u8>,
        proof_height: Height,
    },

    ChannelOpenAck {
        port_id: PortId,
        channel_id: ChannelId,
        counterparty_channel_id: ChannelId,
        counterparty_version: Vec<u8>,
        proof_try: Vec<u8>,
        proof_height: Height,
    },

    ChannelOpenConfirm {
        port_id: PortId,
        channel_id: ChannelId,
        proof_ack: Vec<u8>,
        proof_height: Height,
    },

    ChannelCloseInit {
        port_id: PortId,
        channel_id: ChannelId,
    },

    ChannelCloseConfirm {
        port_id: PortId,
        channel_id: ChannelId,
        proof_init: Vec<u8>,
        proof_height: Height,
    },

    // ========================================================================
    // packet relay
    // ========================================================================

    /// receive packet from source chain
    RecvPacket {
        packet: Packet,
        proof_commitment: Vec<u8>,
        proof_height: Height,
    },

    /// acknowledge packet on source chain
    AcknowledgePacket {
        packet: Packet,
        acknowledgement: Vec<u8>,
        proof_acked: Vec<u8>,
        proof_height: Height,
    },

    /// timeout packet (not received before deadline)
    TimeoutPacket {
        packet: Packet,
        next_sequence_recv: Sequence,
        proof_unreceived: Vec<u8>,
        proof_height: Height,
    },

    /// timeout packet due to channel close
    TimeoutOnClose {
        packet: Packet,
        next_sequence_recv: Sequence,
        proof_unreceived: Vec<u8>,
        proof_close: Vec<u8>,
        proof_height: Height,
    },

    // ========================================================================
    // relay task management
    // ========================================================================

    /// claim a relay task for execution
    ClaimRelayTask {
        task_id: Hash32,
        executor: [u8; 32], // ed25519 public key
        signature: [u8; 64],
    },

    /// confirm relay task execution
    ConfirmExecution {
        task_id: Hash32,
        /// transaction hash on destination chain
        dest_tx_hash: Hash32,
        /// inclusion proof
        inclusion_proof: Vec<u8>,
    },
}

impl IbcWorkItem {
    /// decode work item from bytes
    pub fn decode(data: &[u8]) -> Option<Self> {
        if data.is_empty() {
            return None;
        }

        let item_type = IbcWorkItemType::from_u8(data[0])?;
        let payload = &data[1..];

        match item_type {
            IbcWorkItemType::CreateClient => {
                let mut offset = 0;
                let client_type = ClientType::from_u8(*payload.get(offset)?)?;
                offset += 1;

                if payload.len() < offset + 4 {
                    return None;
                }
                let cs_len = u32::from_le_bytes(payload[offset..offset + 4].try_into().ok()?) as usize;
                offset += 4;
                let client_state = payload.get(offset..offset + cs_len)?.to_vec();
                offset += cs_len;

                if payload.len() < offset + 4 {
                    return None;
                }
                let cons_len = u32::from_le_bytes(payload[offset..offset + 4].try_into().ok()?) as usize;
                offset += 4;
                let consensus_state = payload.get(offset..offset + cons_len)?.to_vec();

                Some(IbcWorkItem::CreateClient {
                    client_type,
                    client_state,
                    consensus_state,
                })
            }

            IbcWorkItemType::UpdateClient => {
                let mut offset = 0;
                let (client_id, len) = ClientId::decode(&payload[offset..])?;
                offset += len;

                if payload.len() < offset + 4 {
                    return None;
                }
                let header_len = u32::from_le_bytes(payload[offset..offset + 4].try_into().ok()?) as usize;
                offset += 4;
                let header = payload.get(offset..offset + header_len)?.to_vec();

                Some(IbcWorkItem::UpdateClient { client_id, header })
            }

            IbcWorkItemType::RecvPacket => {
                let packet = Packet::decode(payload)?;
                let mut offset = packet_encoded_len(&packet);

                if payload.len() < offset + 4 {
                    return None;
                }
                let proof_len = u32::from_le_bytes(payload[offset..offset + 4].try_into().ok()?) as usize;
                offset += 4;
                let proof_commitment = payload.get(offset..offset + proof_len)?.to_vec();
                offset += proof_len;

                let proof_height = Height::decode(&payload[offset..])?;

                Some(IbcWorkItem::RecvPacket {
                    packet,
                    proof_commitment,
                    proof_height,
                })
            }

            IbcWorkItemType::AcknowledgePacket => {
                let packet = Packet::decode(payload)?;
                let mut offset = packet_encoded_len(&packet);

                if payload.len() < offset + 4 {
                    return None;
                }
                let ack_len = u32::from_le_bytes(payload[offset..offset + 4].try_into().ok()?) as usize;
                offset += 4;
                let acknowledgement = payload.get(offset..offset + ack_len)?.to_vec();
                offset += ack_len;

                if payload.len() < offset + 4 {
                    return None;
                }
                let proof_len = u32::from_le_bytes(payload[offset..offset + 4].try_into().ok()?) as usize;
                offset += 4;
                let proof_acked = payload.get(offset..offset + proof_len)?.to_vec();
                offset += proof_len;

                let proof_height = Height::decode(&payload[offset..])?;

                Some(IbcWorkItem::AcknowledgePacket {
                    packet,
                    acknowledgement,
                    proof_acked,
                    proof_height,
                })
            }

            IbcWorkItemType::ClaimRelayTask => {
                if payload.len() < 32 + 32 + 64 {
                    return None;
                }
                let mut task_id = [0u8; 32];
                task_id.copy_from_slice(&payload[0..32]);
                let mut executor = [0u8; 32];
                executor.copy_from_slice(&payload[32..64]);
                let mut signature = [0u8; 64];
                signature.copy_from_slice(&payload[64..128]);

                Some(IbcWorkItem::ClaimRelayTask {
                    task_id,
                    executor,
                    signature,
                })
            }

            IbcWorkItemType::ConfirmExecution => {
                if payload.len() < 64 + 4 {
                    return None;
                }
                let mut task_id = [0u8; 32];
                task_id.copy_from_slice(&payload[0..32]);
                let mut dest_tx_hash = [0u8; 32];
                dest_tx_hash.copy_from_slice(&payload[32..64]);

                let proof_len = u32::from_le_bytes(payload[64..68].try_into().ok()?) as usize;
                let inclusion_proof = payload.get(68..68 + proof_len)?.to_vec();

                Some(IbcWorkItem::ConfirmExecution {
                    task_id,
                    dest_tx_hash,
                    inclusion_proof,
                })
            }

            // TODO: implement remaining decoders
            _ => None,
        }
    }

    /// encode work item to bytes
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();

        match self {
            IbcWorkItem::CreateClient { client_type, client_state, consensus_state } => {
                buf.push(IbcWorkItemType::CreateClient as u8);
                buf.push(*client_type as u8);
                buf.extend_from_slice(&(client_state.len() as u32).to_le_bytes());
                buf.extend_from_slice(client_state);
                buf.extend_from_slice(&(consensus_state.len() as u32).to_le_bytes());
                buf.extend_from_slice(consensus_state);
            }

            IbcWorkItem::UpdateClient { client_id, header } => {
                buf.push(IbcWorkItemType::UpdateClient as u8);
                client_id.encode(&mut buf);
                buf.extend_from_slice(&(header.len() as u32).to_le_bytes());
                buf.extend_from_slice(header);
            }

            IbcWorkItem::RecvPacket { packet, proof_commitment, proof_height } => {
                buf.push(IbcWorkItemType::RecvPacket as u8);
                packet.encode(&mut buf);
                buf.extend_from_slice(&(proof_commitment.len() as u32).to_le_bytes());
                buf.extend_from_slice(proof_commitment);
                proof_height.encode(&mut buf);
            }

            IbcWorkItem::AcknowledgePacket { packet, acknowledgement, proof_acked, proof_height } => {
                buf.push(IbcWorkItemType::AcknowledgePacket as u8);
                packet.encode(&mut buf);
                buf.extend_from_slice(&(acknowledgement.len() as u32).to_le_bytes());
                buf.extend_from_slice(acknowledgement);
                buf.extend_from_slice(&(proof_acked.len() as u32).to_le_bytes());
                buf.extend_from_slice(proof_acked);
                proof_height.encode(&mut buf);
            }

            IbcWorkItem::ClaimRelayTask { task_id, executor, signature } => {
                buf.push(IbcWorkItemType::ClaimRelayTask as u8);
                buf.extend_from_slice(task_id);
                buf.extend_from_slice(executor);
                buf.extend_from_slice(signature);
            }

            IbcWorkItem::ConfirmExecution { task_id, dest_tx_hash, inclusion_proof } => {
                buf.push(IbcWorkItemType::ConfirmExecution as u8);
                buf.extend_from_slice(task_id);
                buf.extend_from_slice(dest_tx_hash);
                buf.extend_from_slice(&(inclusion_proof.len() as u32).to_le_bytes());
                buf.extend_from_slice(inclusion_proof);
            }

            // TODO: implement remaining encoders
            _ => {}
        }

        buf
    }
}

/// helper to compute encoded packet length
fn packet_encoded_len(packet: &Packet) -> usize {
    8 // sequence
    + 4 + packet.source_port.0.len()
    + 4 + packet.source_channel.0.len()
    + 4 + packet.destination_port.0.len()
    + 4 + packet.destination_channel.0.len()
    + 4 + packet.data.len()
    + 16 // timeout_height
    + 8 // timeout_timestamp
}
