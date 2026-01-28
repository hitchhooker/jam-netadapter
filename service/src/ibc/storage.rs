//! ibc storage layer
//!
//! persistent storage for ibc state with prefix-based keys

use serde::{Deserialize, Serialize};

use super::types::*;
use super::client::*;
use super::connection::*;
use super::channel::*;
use super::relay::*;
use super::transfer::*;

/// storage key prefixes
pub mod prefix {
    pub const CLIENT_STATE: u8 = 0x30;
    pub const CONSENSUS_STATE: u8 = 0x31;
    pub const CONNECTION: u8 = 0x32;
    pub const CHANNEL: u8 = 0x33;
    pub const PACKET_COMMITMENT: u8 = 0x34;
    pub const PACKET_RECEIPT: u8 = 0x35;
    pub const PACKET_ACK: u8 = 0x36;
    pub const NEXT_SEQ_SEND: u8 = 0x37;
    pub const NEXT_SEQ_RECV: u8 = 0x38;
    pub const NEXT_SEQ_ACK: u8 = 0x39;
    pub const RELAY_TASK: u8 = 0x3A;
    pub const COUNTERS: u8 = 0x3B;
    pub const ESCROW: u8 = 0x3C;
    pub const TOKEN_REGISTRY: u8 = 0x3D;
    pub const USER_BALANCE: u8 = 0x3E;
    pub const PENDING_TASKS: u8 = 0x3F;
}

/// ibc counters
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct IbcCounters {
    pub next_client_id: u64,
    pub next_connection_id: u64,
    pub next_channel_id: u64,
}

/// in-memory ibc storage (for testing and reference)
#[derive(Clone, Debug, Default)]
pub struct InMemoryIbcStorage {
    pub clients: std::collections::HashMap<Vec<u8>, ClientState>,
    pub consensus_states: std::collections::HashMap<Vec<u8>, ConsensusState>,
    pub connections: std::collections::HashMap<Vec<u8>, ConnectionEnd>,
    pub channels: std::collections::HashMap<Vec<u8>, ChannelEnd>,
    pub packet_commitments: std::collections::HashMap<Vec<u8>, Hash32>,
    pub packet_receipts: std::collections::HashMap<Vec<u8>, Hash32>,
    pub packet_acks: std::collections::HashMap<Vec<u8>, Vec<u8>>,
    pub sequences: std::collections::HashMap<Vec<u8>, SequenceState>,
    pub relay_tasks: std::collections::HashMap<Hash32, RelayTask>,
    pub pending_task_ids: Vec<Hash32>,
    pub counters: IbcCounters,
    pub transfer_state: TransferModuleState,
    pub user_balances: std::collections::HashMap<Hash32, UserBalance>,
}

impl InMemoryIbcStorage {
    pub fn new() -> Self {
        Self::default()
    }

    // =========================================================================
    // key construction
    // =========================================================================

    fn client_key(client_id: &ClientId) -> Vec<u8> {
        let mut key = vec![prefix::CLIENT_STATE];
        key.extend_from_slice(&client_id.0);
        key
    }

    fn consensus_key(client_id: &ClientId, height: &Height) -> Vec<u8> {
        let mut key = vec![prefix::CONSENSUS_STATE];
        key.extend_from_slice(&client_id.0);
        key.push(b'/');
        key.extend_from_slice(&height.revision_number.to_be_bytes());
        key.push(b'-');
        key.extend_from_slice(&height.revision_height.to_be_bytes());
        key
    }

    fn connection_key(conn_id: &ConnectionId) -> Vec<u8> {
        let mut key = vec![prefix::CONNECTION];
        key.extend_from_slice(&conn_id.0);
        key
    }

    fn channel_key(port_id: &PortId, channel_id: &ChannelId) -> Vec<u8> {
        let mut key = vec![prefix::CHANNEL];
        key.extend_from_slice(&port_id.0);
        key.push(b'/');
        key.extend_from_slice(&channel_id.0);
        key
    }

    fn packet_commitment_key(port_id: &PortId, channel_id: &ChannelId, sequence: Sequence) -> Vec<u8> {
        let mut key = vec![prefix::PACKET_COMMITMENT];
        key.extend_from_slice(&port_id.0);
        key.push(b'/');
        key.extend_from_slice(&channel_id.0);
        key.push(b'/');
        key.extend_from_slice(&sequence.to_be_bytes());
        key
    }

    fn packet_receipt_key(port_id: &PortId, channel_id: &ChannelId, sequence: Sequence) -> Vec<u8> {
        let mut key = vec![prefix::PACKET_RECEIPT];
        key.extend_from_slice(&port_id.0);
        key.push(b'/');
        key.extend_from_slice(&channel_id.0);
        key.push(b'/');
        key.extend_from_slice(&sequence.to_be_bytes());
        key
    }

    fn packet_ack_key(port_id: &PortId, channel_id: &ChannelId, sequence: Sequence) -> Vec<u8> {
        let mut key = vec![prefix::PACKET_ACK];
        key.extend_from_slice(&port_id.0);
        key.push(b'/');
        key.extend_from_slice(&channel_id.0);
        key.push(b'/');
        key.extend_from_slice(&sequence.to_be_bytes());
        key
    }

    fn sequence_key(port_id: &PortId, channel_id: &ChannelId) -> Vec<u8> {
        let mut key = vec![prefix::NEXT_SEQ_SEND];
        key.extend_from_slice(&port_id.0);
        key.push(b'/');
        key.extend_from_slice(&channel_id.0);
        key
    }

    // =========================================================================
    // client operations
    // =========================================================================

    pub fn get_client_state(&self, client_id: &ClientId) -> Option<&ClientState> {
        let key = Self::client_key(client_id);
        self.clients.get(&key)
    }

    pub fn set_client_state(&mut self, client_id: &ClientId, state: ClientState) {
        let key = Self::client_key(client_id);
        self.clients.insert(key, state);
    }

    pub fn get_consensus_state(&self, client_id: &ClientId, height: &Height) -> Option<&ConsensusState> {
        let key = Self::consensus_key(client_id, height);
        self.consensus_states.get(&key)
    }

    pub fn set_consensus_state(&mut self, client_id: &ClientId, height: &Height, state: ConsensusState) {
        let key = Self::consensus_key(client_id, height);
        self.consensus_states.insert(key, state);
    }

    pub fn alloc_client_id(&mut self) -> ClientId {
        let id = self.counters.next_client_id;
        self.counters.next_client_id += 1;
        ClientId::new(&format!("07-tendermint-{}", id))
    }

    // =========================================================================
    // connection operations
    // =========================================================================

    pub fn get_connection(&self, conn_id: &ConnectionId) -> Option<&ConnectionEnd> {
        let key = Self::connection_key(conn_id);
        self.connections.get(&key)
    }

    pub fn get_connection_mut(&mut self, conn_id: &ConnectionId) -> Option<&mut ConnectionEnd> {
        let key = Self::connection_key(conn_id);
        self.connections.get_mut(&key)
    }

    pub fn set_connection(&mut self, conn_id: &ConnectionId, conn: ConnectionEnd) {
        let key = Self::connection_key(conn_id);
        self.connections.insert(key, conn);
    }

    pub fn alloc_connection_id(&mut self) -> ConnectionId {
        let id = self.counters.next_connection_id;
        self.counters.next_connection_id += 1;
        ConnectionId::new(&format!("connection-{}", id))
    }

    // =========================================================================
    // channel operations
    // =========================================================================

    pub fn get_channel(&self, port_id: &PortId, channel_id: &ChannelId) -> Option<&ChannelEnd> {
        let key = Self::channel_key(port_id, channel_id);
        self.channels.get(&key)
    }

    pub fn get_channel_mut(&mut self, port_id: &PortId, channel_id: &ChannelId) -> Option<&mut ChannelEnd> {
        let key = Self::channel_key(port_id, channel_id);
        self.channels.get_mut(&key)
    }

    pub fn set_channel(&mut self, port_id: &PortId, channel_id: &ChannelId, channel: ChannelEnd) {
        let key = Self::channel_key(port_id, channel_id);
        self.channels.insert(key, channel);
    }

    pub fn alloc_channel_id(&mut self) -> ChannelId {
        let id = self.counters.next_channel_id;
        self.counters.next_channel_id += 1;
        ChannelId::new(&format!("channel-{}", id))
    }

    // =========================================================================
    // packet operations
    // =========================================================================

    pub fn get_packet_commitment(&self, port_id: &PortId, channel_id: &ChannelId, sequence: Sequence) -> Option<&Hash32> {
        let key = Self::packet_commitment_key(port_id, channel_id, sequence);
        self.packet_commitments.get(&key)
    }

    pub fn set_packet_commitment(&mut self, port_id: &PortId, channel_id: &ChannelId, sequence: Sequence, commitment: Hash32) {
        let key = Self::packet_commitment_key(port_id, channel_id, sequence);
        self.packet_commitments.insert(key, commitment);
    }

    pub fn delete_packet_commitment(&mut self, port_id: &PortId, channel_id: &ChannelId, sequence: Sequence) {
        let key = Self::packet_commitment_key(port_id, channel_id, sequence);
        self.packet_commitments.remove(&key);
    }

    pub fn has_packet_receipt(&self, port_id: &PortId, channel_id: &ChannelId, sequence: Sequence) -> bool {
        let key = Self::packet_receipt_key(port_id, channel_id, sequence);
        self.packet_receipts.contains_key(&key)
    }

    pub fn set_packet_receipt(&mut self, port_id: &PortId, channel_id: &ChannelId, sequence: Sequence) {
        let key = Self::packet_receipt_key(port_id, channel_id, sequence);
        self.packet_receipts.insert(key, [1u8; 32]); // marker value
    }

    pub fn get_packet_ack(&self, port_id: &PortId, channel_id: &ChannelId, sequence: Sequence) -> Option<&Vec<u8>> {
        let key = Self::packet_ack_key(port_id, channel_id, sequence);
        self.packet_acks.get(&key)
    }

    pub fn set_packet_ack(&mut self, port_id: &PortId, channel_id: &ChannelId, sequence: Sequence, ack: Vec<u8>) {
        let key = Self::packet_ack_key(port_id, channel_id, sequence);
        self.packet_acks.insert(key, ack);
    }

    // =========================================================================
    // sequence operations
    // =========================================================================

    pub fn get_sequences(&self, port_id: &PortId, channel_id: &ChannelId) -> SequenceState {
        let key = Self::sequence_key(port_id, channel_id);
        self.sequences.get(&key).cloned().unwrap_or_else(SequenceState::new)
    }

    pub fn set_sequences(&mut self, port_id: &PortId, channel_id: &ChannelId, state: SequenceState) {
        let key = Self::sequence_key(port_id, channel_id);
        self.sequences.insert(key, state);
    }

    pub fn alloc_send_sequence(&mut self, port_id: &PortId, channel_id: &ChannelId) -> Sequence {
        let key = Self::sequence_key(port_id, channel_id);
        let state = self.sequences.entry(key).or_insert_with(SequenceState::new);
        state.alloc_send()
    }

    // =========================================================================
    // relay task operations
    // =========================================================================

    pub fn get_relay_task(&self, task_id: &Hash32) -> Option<&RelayTask> {
        self.relay_tasks.get(task_id)
    }

    pub fn get_relay_task_mut(&mut self, task_id: &Hash32) -> Option<&mut RelayTask> {
        self.relay_tasks.get_mut(task_id)
    }

    pub fn set_relay_task(&mut self, task: RelayTask) {
        let id = task.id;
        let is_pending = task.status == TaskStatus::Pending;

        self.relay_tasks.insert(id, task);

        if is_pending && !self.pending_task_ids.contains(&id) {
            self.pending_task_ids.push(id);
        }
    }

    pub fn get_pending_tasks(&self) -> Vec<&RelayTask> {
        self.pending_task_ids.iter()
            .filter_map(|id| self.relay_tasks.get(id))
            .filter(|t| t.status == TaskStatus::Pending)
            .collect()
    }

    pub fn remove_from_pending(&mut self, task_id: &Hash32) {
        self.pending_task_ids.retain(|id| id != task_id);
    }

    // =========================================================================
    // transfer operations
    // =========================================================================

    pub fn get_transfer_state(&self) -> &TransferModuleState {
        &self.transfer_state
    }

    pub fn get_transfer_state_mut(&mut self) -> &mut TransferModuleState {
        &mut self.transfer_state
    }

    // =========================================================================
    // user balance operations
    // =========================================================================

    pub fn get_user_balance(&self, address: &Hash32) -> Option<&UserBalance> {
        self.user_balances.get(address)
    }

    pub fn get_or_create_user_balance(&mut self, address: Hash32) -> &mut UserBalance {
        self.user_balances.entry(address).or_insert_with(|| UserBalance::new(address))
    }

    pub fn credit_user(&mut self, address: Hash32, token_id: &Hash32, amount: u128) -> Result<(), IbcError> {
        let balance = self.get_or_create_user_balance(address);
        balance.credit(token_id, amount)
    }

    pub fn debit_user(&mut self, address: &Hash32, token_id: &Hash32, amount: u128) -> Result<(), IbcError> {
        let balance = self.user_balances.get_mut(address)
            .ok_or(IbcError::InvalidPacketData)?;
        balance.debit(token_id, amount)
    }
}

/// implement IbcStorage trait for InMemoryIbcStorage
impl super::IbcStorage for InMemoryIbcStorage {
    fn get_client_state(&self, client_id: &ClientId) -> Option<ClientState> {
        self.get_client_state(client_id).cloned()
    }

    fn set_client_state(&mut self, client_id: &ClientId, state: &ClientState) -> Result<(), IbcError> {
        self.set_client_state(client_id, state.clone());
        Ok(())
    }

    fn get_consensus_state(&self, client_id: &ClientId, height: &Height) -> Option<ConsensusState> {
        self.get_consensus_state(client_id, height).cloned()
    }

    fn set_consensus_state(&mut self, client_id: &ClientId, height: &Height, state: &ConsensusState) -> Result<(), IbcError> {
        self.set_consensus_state(client_id, height, state.clone());
        Ok(())
    }

    fn get_relay_task(&self, task_id: &Hash32) -> Option<RelayTask> {
        self.get_relay_task(task_id).cloned()
    }

    fn set_relay_task(&mut self, task: &RelayTask) -> Result<(), IbcError> {
        self.set_relay_task(task.clone());
        Ok(())
    }

    fn set_packet_receipt(&mut self, channel: &ChannelId, sequence: Sequence, _commitment: &Hash32) -> Result<(), IbcError> {
        // use default port for now
        let port = PortId::new("transfer");
        self.set_packet_receipt(&port, channel, sequence);
        Ok(())
    }
}

/// implement ClientReader trait
impl super::ClientReader for InMemoryIbcStorage {
    fn get_client_state(&self, client_id: &ClientId) -> Option<ClientState> {
        self.get_client_state(client_id).cloned()
    }

    fn get_consensus_state(&self, client_id: &ClientId, height: &Height) -> Option<ConsensusState> {
        self.get_consensus_state(client_id, height).cloned()
    }
}
