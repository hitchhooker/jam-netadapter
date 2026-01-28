//! ics-20 fungible token transfer
//!
//! implements cross-chain asset custody with escrow accounts

use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};

use super::types::*;

/// fungible token packet data (ics-20)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FungibleTokenPacketData {
    /// denomination (e.g., "uatom" or "transfer/channel-0/uatom")
    pub denom: Denom,
    /// amount as string (to handle large numbers)
    pub amount: u128,
    /// sender address on source chain
    pub sender: Vec<u8>,
    /// receiver address on destination chain
    pub receiver: Vec<u8>,
    /// optional memo
    pub memo: Option<Vec<u8>>,
}

impl FungibleTokenPacketData {
    /// encode to bytes for packet data
    pub fn encode(&self) -> Vec<u8> {
        // simplified encoding - production should use json or protobuf
        let mut buf = Vec::new();

        // denom
        let denom_bytes = self.denom.full_path();
        buf.extend_from_slice(&(denom_bytes.len() as u32).to_le_bytes());
        buf.extend_from_slice(&denom_bytes);

        // amount (u128)
        buf.extend_from_slice(&self.amount.to_le_bytes());

        // sender
        buf.extend_from_slice(&(self.sender.len() as u32).to_le_bytes());
        buf.extend_from_slice(&self.sender);

        // receiver
        buf.extend_from_slice(&(self.receiver.len() as u32).to_le_bytes());
        buf.extend_from_slice(&self.receiver);

        // memo
        if let Some(ref memo) = self.memo {
            buf.push(1);
            buf.extend_from_slice(&(memo.len() as u32).to_le_bytes());
            buf.extend_from_slice(memo);
        } else {
            buf.push(0);
        }

        buf
    }

    /// decode from bytes
    pub fn decode(data: &[u8]) -> Result<Self, IbcError> {
        let mut offset = 0;

        // denom
        if offset + 4 > data.len() {
            return Err(IbcError::DecodingError);
        }
        let denom_len = u32::from_le_bytes([
            data[offset], data[offset + 1], data[offset + 2], data[offset + 3]
        ]) as usize;
        offset += 4;

        if offset + denom_len > data.len() {
            return Err(IbcError::DecodingError);
        }
        let denom_bytes = &data[offset..offset + denom_len];
        let denom = Denom::from_path(denom_bytes)?;
        offset += denom_len;

        // amount
        if offset + 16 > data.len() {
            return Err(IbcError::DecodingError);
        }
        let amount = u128::from_le_bytes([
            data[offset], data[offset + 1], data[offset + 2], data[offset + 3],
            data[offset + 4], data[offset + 5], data[offset + 6], data[offset + 7],
            data[offset + 8], data[offset + 9], data[offset + 10], data[offset + 11],
            data[offset + 12], data[offset + 13], data[offset + 14], data[offset + 15],
        ]);
        offset += 16;

        // sender
        if offset + 4 > data.len() {
            return Err(IbcError::DecodingError);
        }
        let sender_len = u32::from_le_bytes([
            data[offset], data[offset + 1], data[offset + 2], data[offset + 3]
        ]) as usize;
        offset += 4;

        if offset + sender_len > data.len() {
            return Err(IbcError::DecodingError);
        }
        let sender = data[offset..offset + sender_len].to_vec();
        offset += sender_len;

        // receiver
        if offset + 4 > data.len() {
            return Err(IbcError::DecodingError);
        }
        let receiver_len = u32::from_le_bytes([
            data[offset], data[offset + 1], data[offset + 2], data[offset + 3]
        ]) as usize;
        offset += 4;

        if offset + receiver_len > data.len() {
            return Err(IbcError::DecodingError);
        }
        let receiver = data[offset..offset + receiver_len].to_vec();
        offset += receiver_len;

        // memo
        if offset >= data.len() {
            return Err(IbcError::DecodingError);
        }
        let has_memo = data[offset] == 1;
        offset += 1;

        let memo = if has_memo {
            if offset + 4 > data.len() {
                return Err(IbcError::DecodingError);
            }
            let memo_len = u32::from_le_bytes([
                data[offset], data[offset + 1], data[offset + 2], data[offset + 3]
            ]) as usize;
            offset += 4;

            if offset + memo_len > data.len() {
                return Err(IbcError::DecodingError);
            }
            Some(data[offset..offset + memo_len].to_vec())
        } else {
            None
        };

        Ok(Self {
            denom,
            amount,
            sender,
            receiver,
            memo,
        })
    }
}

/// token denomination with trace path
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Denom {
    /// trace path (e.g., ["transfer/channel-0", "transfer/channel-1"])
    pub trace_path: Vec<TracePath>,
    /// base denomination (e.g., "uatom")
    pub base_denom: Vec<u8>,
}

/// single hop in denomination trace
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TracePath {
    pub port_id: PortId,
    pub channel_id: ChannelId,
}

impl Denom {
    /// create native denomination (no trace)
    pub fn native(base: &str) -> Self {
        Self {
            trace_path: vec![],
            base_denom: base.as_bytes().to_vec(),
        }
    }

    /// create denomination with trace
    pub fn with_trace(base: &str, trace: Vec<TracePath>) -> Self {
        Self {
            trace_path: trace,
            base_denom: base.as_bytes().to_vec(),
        }
    }

    /// check if this is a native token (no trace path)
    pub fn is_native(&self) -> bool {
        self.trace_path.is_empty()
    }

    /// check if token originated from source chain (returning home)
    ///
    /// a token is "source" if its trace path starts with this port/channel,
    /// meaning it was previously sent from here and is now returning.
    /// native tokens (no trace) are NOT source - they're being sent OUT.
    pub fn is_source(&self, port: &PortId, channel: &ChannelId) -> bool {
        if self.trace_path.is_empty() {
            // native token - not source (being sent out for first time)
            return false;
        }

        // check if first trace element matches this channel
        // if so, token is returning home
        let first = &self.trace_path[0];
        first.port_id == *port && first.channel_id == *channel
    }

    /// add trace prefix (when receiving)
    pub fn add_prefix(&mut self, port: &PortId, channel: &ChannelId) {
        self.trace_path.insert(0, TracePath {
            port_id: port.clone(),
            channel_id: channel.clone(),
        });
    }

    /// remove trace prefix (when sending back)
    pub fn remove_prefix(&mut self) -> Option<TracePath> {
        if self.trace_path.is_empty() {
            None
        } else {
            Some(self.trace_path.remove(0))
        }
    }

    /// get full path string
    pub fn full_path(&self) -> Vec<u8> {
        let mut path = Vec::new();
        for trace in &self.trace_path {
            path.extend_from_slice(&trace.port_id.0);
            path.push(b'/');
            path.extend_from_slice(&trace.channel_id.0);
            path.push(b'/');
        }
        path.extend_from_slice(&self.base_denom);
        path
    }

    /// parse from path bytes
    pub fn from_path(data: &[u8]) -> Result<Self, IbcError> {
        let path_str = core::str::from_utf8(data)
            .map_err(|_| IbcError::DecodingError)?;

        let parts: Vec<&str> = path_str.split('/').collect();

        if parts.len() == 1 {
            // native denom
            return Ok(Self::native(parts[0]));
        }

        if parts.len() % 2 == 0 {
            return Err(IbcError::DecodingError);
        }

        let mut trace_path = Vec::new();
        let mut i = 0;
        while i + 2 < parts.len() {
            trace_path.push(TracePath {
                port_id: PortId::new(parts[i]),
                channel_id: ChannelId::new(parts[i + 1]),
            });
            i += 2;
        }

        let base_denom = parts[parts.len() - 1].as_bytes().to_vec();

        Ok(Self {
            trace_path,
            base_denom,
        })
    }

    /// compute ibc denom hash (for wrapped tokens)
    pub fn ibc_hash(&self) -> Hash32 {
        let path = self.full_path();
        Sha256::digest(&path).into()
    }
}

/// escrow account for a channel
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct EscrowAccount {
    /// channel id
    pub channel_id: ChannelId,
    /// port id
    pub port_id: PortId,
    /// locked balances by denomination hash
    pub balances: Vec<EscrowBalance>,
}

/// single denomination balance in escrow
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EscrowBalance {
    /// denomination hash
    pub denom_hash: Hash32,
    /// full denomination (for reference)
    pub denom: Denom,
    /// locked amount
    pub amount: u128,
}

impl EscrowAccount {
    /// create new escrow account
    pub fn new(port: &PortId, channel: &ChannelId) -> Self {
        Self {
            port_id: port.clone(),
            channel_id: channel.clone(),
            balances: vec![],
        }
    }

    /// lock tokens in escrow
    pub fn lock(&mut self, denom: &Denom, amount: u128) -> Result<(), IbcError> {
        let hash = denom.ibc_hash();

        if let Some(balance) = self.balances.iter_mut().find(|b| b.denom_hash == hash) {
            balance.amount = balance.amount
                .checked_add(amount)
                .ok_or(IbcError::InvalidPacketData)?;
        } else {
            self.balances.push(EscrowBalance {
                denom_hash: hash,
                denom: denom.clone(),
                amount,
            });
        }

        Ok(())
    }

    /// unlock tokens from escrow
    pub fn unlock(&mut self, denom: &Denom, amount: u128) -> Result<(), IbcError> {
        let hash = denom.ibc_hash();

        let balance = self.balances.iter_mut()
            .find(|b| b.denom_hash == hash)
            .ok_or(IbcError::InvalidPacketData)?;

        balance.amount = balance.amount
            .checked_sub(amount)
            .ok_or(IbcError::InvalidPacketData)?;

        Ok(())
    }

    /// get locked amount for denomination
    pub fn get_balance(&self, denom: &Denom) -> u128 {
        let hash = denom.ibc_hash();
        self.balances.iter()
            .find(|b| b.denom_hash == hash)
            .map(|b| b.amount)
            .unwrap_or(0)
    }
}

/// wrapped token registry (minted on jam side)
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct TokenRegistry {
    /// registered wrapped tokens
    pub tokens: Vec<WrappedToken>,
    /// total supply per token hash
    pub supplies: Vec<TokenSupply>,
}

/// wrapped token metadata
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WrappedToken {
    /// ibc denomination hash (token id on jam)
    pub token_id: Hash32,
    /// original denomination
    pub denom: Denom,
    /// source channel
    pub source_channel: ChannelId,
    /// source port
    pub source_port: PortId,
    /// creation timestamp
    pub created_at: u32,
}

/// token supply tracking
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TokenSupply {
    pub token_id: Hash32,
    pub total_supply: u128,
}

impl TokenRegistry {
    /// register new wrapped token
    pub fn register(&mut self, denom: &Denom, port: &PortId, channel: &ChannelId, timeslot: u32) -> Hash32 {
        let token_id = denom.ibc_hash();

        // check if already registered
        if self.tokens.iter().any(|t| t.token_id == token_id) {
            return token_id;
        }

        self.tokens.push(WrappedToken {
            token_id,
            denom: denom.clone(),
            source_channel: channel.clone(),
            source_port: port.clone(),
            created_at: timeslot,
        });

        self.supplies.push(TokenSupply {
            token_id,
            total_supply: 0,
        });

        token_id
    }

    /// mint wrapped tokens
    pub fn mint(&mut self, token_id: &Hash32, amount: u128) -> Result<(), IbcError> {
        let supply = self.supplies.iter_mut()
            .find(|s| s.token_id == *token_id)
            .ok_or(IbcError::InvalidPacketData)?;

        supply.total_supply = supply.total_supply
            .checked_add(amount)
            .ok_or(IbcError::InvalidPacketData)?;

        Ok(())
    }

    /// burn wrapped tokens
    pub fn burn(&mut self, token_id: &Hash32, amount: u128) -> Result<(), IbcError> {
        let supply = self.supplies.iter_mut()
            .find(|s| s.token_id == *token_id)
            .ok_or(IbcError::InvalidPacketData)?;

        supply.total_supply = supply.total_supply
            .checked_sub(amount)
            .ok_or(IbcError::InvalidPacketData)?;

        Ok(())
    }

    /// get token by id
    pub fn get_token(&self, token_id: &Hash32) -> Option<&WrappedToken> {
        self.tokens.iter().find(|t| t.token_id == *token_id)
    }

    /// get total supply
    pub fn get_supply(&self, token_id: &Hash32) -> u128 {
        self.supplies.iter()
            .find(|s| s.token_id == *token_id)
            .map(|s| s.total_supply)
            .unwrap_or(0)
    }
}

/// user balance for wrapped tokens
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct UserBalance {
    /// user address (32 bytes)
    pub address: Hash32,
    /// balances per token
    pub balances: Vec<UserTokenBalance>,
}

/// single token balance
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UserTokenBalance {
    pub token_id: Hash32,
    pub amount: u128,
}

impl UserBalance {
    pub fn new(address: Hash32) -> Self {
        Self {
            address,
            balances: vec![],
        }
    }

    /// credit tokens to user
    pub fn credit(&mut self, token_id: &Hash32, amount: u128) -> Result<(), IbcError> {
        if let Some(balance) = self.balances.iter_mut().find(|b| b.token_id == *token_id) {
            balance.amount = balance.amount
                .checked_add(amount)
                .ok_or(IbcError::InvalidPacketData)?;
        } else {
            self.balances.push(UserTokenBalance {
                token_id: *token_id,
                amount,
            });
        }
        Ok(())
    }

    /// debit tokens from user
    pub fn debit(&mut self, token_id: &Hash32, amount: u128) -> Result<(), IbcError> {
        let balance = self.balances.iter_mut()
            .find(|b| b.token_id == *token_id)
            .ok_or(IbcError::InvalidPacketData)?;

        balance.amount = balance.amount
            .checked_sub(amount)
            .ok_or(IbcError::InvalidPacketData)?;

        Ok(())
    }

    /// get balance for token
    pub fn get_balance(&self, token_id: &Hash32) -> u128 {
        self.balances.iter()
            .find(|b| b.token_id == *token_id)
            .map(|b| b.amount)
            .unwrap_or(0)
    }
}

/// ics-20 transfer module state
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct TransferModuleState {
    /// escrow accounts per channel
    pub escrows: Vec<EscrowAccount>,
    /// wrapped token registry
    pub registry: TokenRegistry,
}

impl TransferModuleState {
    /// get or create escrow account
    pub fn get_or_create_escrow(&mut self, port: &PortId, channel: &ChannelId) -> &mut EscrowAccount {
        let idx = self.escrows.iter().position(|e| {
            e.port_id == *port && e.channel_id == *channel
        });

        if let Some(i) = idx {
            &mut self.escrows[i]
        } else {
            self.escrows.push(EscrowAccount::new(port, channel));
            self.escrows.last_mut().unwrap()
        }
    }

    /// get escrow account (read-only)
    pub fn get_escrow(&self, port: &PortId, channel: &ChannelId) -> Option<&EscrowAccount> {
        self.escrows.iter().find(|e| {
            e.port_id == *port && e.channel_id == *channel
        })
    }
}

/// process incoming transfer (RecvPacket)
pub fn on_recv_packet(
    state: &mut TransferModuleState,
    packet: &Packet,
    timeslot: u32,
) -> Result<(Hash32, u128), IbcError> {
    let data = FungibleTokenPacketData::decode(&packet.data)?;

    let mut denom = data.denom.clone();

    // determine if this is a source or sink
    let is_source = denom.is_source(&packet.destination_port, &packet.destination_channel);

    if is_source {
        // token is returning to source chain
        // remove the trace prefix and unlock from escrow
        denom.remove_prefix();

        let escrow = state.get_or_create_escrow(
            &packet.destination_port,
            &packet.destination_channel,
        );
        escrow.unlock(&denom, data.amount)?;

        // return native token id
        let token_id = denom.ibc_hash();
        Ok((token_id, data.amount))
    } else {
        // token is coming from another chain
        // add trace prefix and mint wrapped token
        denom.add_prefix(&packet.destination_port, &packet.destination_channel);

        let token_id = state.registry.register(
            &denom,
            &packet.destination_port,
            &packet.destination_channel,
            timeslot,
        );

        state.registry.mint(&token_id, data.amount)?;

        Ok((token_id, data.amount))
    }
}

/// process outgoing transfer (SendPacket)
pub fn on_send_packet(
    state: &mut TransferModuleState,
    denom: &Denom,
    amount: u128,
    port: &PortId,
    channel: &ChannelId,
) -> Result<Denom, IbcError> {
    let is_source = denom.is_source(port, channel);

    if is_source {
        // token originally came from counterparty via this channel
        // sending it back: burn wrapped and remove prefix
        let token_id = denom.ibc_hash();
        state.registry.burn(&token_id, amount)?;

        let mut return_denom = denom.clone();
        return_denom.remove_prefix();

        Ok(return_denom)
    } else {
        // token is native or from different channel
        // sending out: lock in escrow
        let escrow = state.get_or_create_escrow(port, channel);
        escrow.lock(denom, amount)?;

        Ok(denom.clone())
    }
}

/// process transfer acknowledgement
pub fn on_acknowledge_packet(
    state: &mut TransferModuleState,
    packet: &Packet,
    ack_success: bool,
) -> Result<(), IbcError> {
    if ack_success {
        // transfer succeeded, nothing to do
        return Ok(());
    }

    // transfer failed, refund
    let data = FungibleTokenPacketData::decode(&packet.data)?;
    let denom = data.denom;

    let is_source = denom.is_source(&packet.source_port, &packet.source_channel);

    if is_source {
        // unlock from escrow (refund)
        let escrow = state.get_or_create_escrow(
            &packet.source_port,
            &packet.source_channel,
        );
        escrow.unlock(&denom, data.amount)?;
    } else {
        // re-mint burned tokens (refund)
        let token_id = denom.ibc_hash();
        state.registry.mint(&token_id, data.amount)?;
    }

    Ok(())
}

/// process transfer timeout
pub fn on_timeout_packet(
    state: &mut TransferModuleState,
    packet: &Packet,
) -> Result<(), IbcError> {
    // timeout is equivalent to failed ack
    on_acknowledge_packet(state, packet, false)
}

// ============================================================================
// penumbra compatibility
// ============================================================================

/// timestamp quantization for penumbra privacy
/// penumbra requires timestamps to be quantized to 1-minute intervals
/// to prevent timing correlation attacks on shielded transfers
pub mod privacy {
    use super::*;

    /// quantization interval in nanoseconds (60 seconds)
    pub const TIMESTAMP_QUANTUM_NS: u64 = 60_000_000_000;

    /// quantization interval in seconds
    pub const TIMESTAMP_QUANTUM_SECS: u64 = 60;

    /// quantize timestamp to nearest minute boundary (floor)
    pub fn quantize_timestamp(timestamp: Timestamp) -> Timestamp {
        (timestamp / TIMESTAMP_QUANTUM_NS) * TIMESTAMP_QUANTUM_NS
    }

    /// quantize timestamp to next minute boundary (ceiling)
    pub fn quantize_timestamp_ceil(timestamp: Timestamp) -> Timestamp {
        let base = quantize_timestamp(timestamp);
        if timestamp > base {
            base + TIMESTAMP_QUANTUM_NS
        } else {
            base
        }
    }

    /// check if timestamp is properly quantized
    pub fn is_quantized(timestamp: Timestamp) -> bool {
        timestamp % TIMESTAMP_QUANTUM_NS == 0
    }

    /// penumbra-compatible transfer config
    #[derive(Clone, Debug)]
    pub struct PenumbraTransferConfig {
        /// enforce timestamp quantization
        pub enforce_quantization: bool,
        /// minimum timeout (quantized)
        pub min_timeout_ns: u64,
        /// default timeout delta (quantized)
        pub default_timeout_delta_ns: u64,
    }

    impl Default for PenumbraTransferConfig {
        fn default() -> Self {
            Self {
                enforce_quantization: true,
                // minimum 10 minutes
                min_timeout_ns: 10 * TIMESTAMP_QUANTUM_NS,
                // default 1 hour
                default_timeout_delta_ns: 60 * TIMESTAMP_QUANTUM_NS,
            }
        }
    }

    impl PenumbraTransferConfig {
        /// calculate quantized timeout for penumbra transfers
        pub fn calculate_timeout(&self, current_timestamp: Timestamp) -> Timestamp {
            let raw_timeout = current_timestamp + self.default_timeout_delta_ns;
            quantize_timestamp_ceil(raw_timeout)
        }

        /// validate packet timeout for penumbra compatibility
        pub fn validate_timeout(&self, timeout: Timestamp) -> Result<(), IbcError> {
            if self.enforce_quantization && !is_quantized(timeout) {
                return Err(IbcError::InvalidPacketData);
            }
            Ok(())
        }
    }

    /// penumbra receiver address encoding
    /// penumbra uses bech32m with specific prefixes
    pub struct PenumbraReceiver;

    impl PenumbraReceiver {
        /// penumbra address prefix
        pub const PREFIX: &'static str = "penumbra";

        /// check if address is a penumbra address
        pub fn is_penumbra_address(addr: &[u8]) -> bool {
            // check for penumbra bech32m prefix
            if addr.len() < 8 {
                return false;
            }
            addr.starts_with(Self::PREFIX.as_bytes())
        }

        /// validate penumbra receiver address format
        pub fn validate(addr: &[u8]) -> Result<(), IbcError> {
            if !Self::is_penumbra_address(addr) {
                return Err(IbcError::InvalidPacketData);
            }

            // penumbra addresses are 80 bytes in decoded form
            // bech32m encoding makes them longer
            if addr.len() < 50 || addr.len() > 150 {
                return Err(IbcError::InvalidPacketData);
            }

            Ok(())
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn test_timestamp_quantization() {
            // exact boundary
            let t1 = 60_000_000_000u64;
            assert!(is_quantized(t1));
            assert_eq!(quantize_timestamp(t1), t1);

            // mid-minute
            let t2 = 90_000_000_000u64; // 1.5 minutes
            assert!(!is_quantized(t2));
            assert_eq!(quantize_timestamp(t2), 60_000_000_000);
            assert_eq!(quantize_timestamp_ceil(t2), 120_000_000_000);

            // just past boundary
            let t3 = 60_000_000_001u64;
            assert!(!is_quantized(t3));
            assert_eq!(quantize_timestamp_ceil(t3), 120_000_000_000);
        }

        #[test]
        fn test_penumbra_timeout() {
            let config = PenumbraTransferConfig::default();

            let current = 1000_000_000_000u64; // some timestamp
            let timeout = config.calculate_timeout(current);

            // should be quantized
            assert!(is_quantized(timeout));

            // should be >= current + default_timeout
            assert!(timeout >= current + config.default_timeout_delta_ns);

            // validate should pass
            assert!(config.validate_timeout(timeout).is_ok());

            // non-quantized should fail
            assert!(config.validate_timeout(timeout + 1).is_err());
        }

        #[test]
        fn test_penumbra_address_detection() {
            let valid = b"penumbra1abc123...";
            assert!(PenumbraReceiver::is_penumbra_address(valid));

            let invalid = b"cosmos1abc123";
            assert!(!PenumbraReceiver::is_penumbra_address(invalid));
        }
    }
}
