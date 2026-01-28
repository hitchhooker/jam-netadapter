//! ibc module tests

#[cfg(test)]
mod tests {
    use super::super::*;
    use super::super::transfer::*;
    use super::super::connection::*;
    use super::super::channel::*;
    use super::super::storage::*;

    #[test]
    fn test_height_comparison() {
        let h1 = Height::new(0, 100);
        let h2 = Height::new(0, 200);
        let h3 = Height::new(1, 50);

        assert!(h2.gt(&h1));
        assert!(!h1.gt(&h2));
        assert!(h3.gt(&h2)); // higher revision wins
        assert!(h2.gte(&h2));
    }

    #[test]
    fn test_height_is_zero() {
        let zero = Height::default();
        let non_zero = Height::new(0, 1);

        assert!(zero.is_zero());
        assert!(!non_zero.is_zero());
    }

    #[test]
    fn test_packet_commitment() {
        let packet = Packet {
            sequence: 1,
            source_port: PortId::new("transfer"),
            source_channel: ChannelId::new("channel-0"),
            destination_port: PortId::new("transfer"),
            destination_channel: ChannelId::new("channel-1"),
            data: b"test data".to_vec(),
            timeout_height: Height::new(0, 1000),
            timeout_timestamp: 0,
        };

        let commitment = packet.commitment();
        assert_ne!(commitment, [0u8; 32]);

        // same packet should produce same commitment
        let commitment2 = packet.commitment();
        assert_eq!(commitment, commitment2);
    }

    #[test]
    fn test_packet_timeout() {
        let packet = Packet {
            sequence: 1,
            source_port: PortId::new("transfer"),
            source_channel: ChannelId::new("channel-0"),
            destination_port: PortId::new("transfer"),
            destination_channel: ChannelId::new("channel-1"),
            data: b"test".to_vec(),
            timeout_height: Height::new(0, 100),
            timeout_timestamp: 1000,
        };

        // not timed out
        let current_height = Height::new(0, 50);
        assert!(!packet.is_timed_out(&current_height, 500));

        // height timeout
        let current_height = Height::new(0, 100);
        assert!(packet.is_timed_out(&current_height, 500));

        // timestamp timeout
        let current_height = Height::new(0, 50);
        assert!(packet.is_timed_out(&current_height, 1000));
    }

    #[test]
    fn test_client_state() {
        let client_state = ClientState {
            chain_id: ChainId::new("cosmoshub-4"),
            trust_level: (1, 3),
            trusting_period: 1209600, // 14 days
            unbonding_period: 1814400, // 21 days
            max_clock_drift: 10,
            latest_height: Height::new(0, 100),
            frozen_height: None,
        };

        assert!(!client_state.is_frozen());

        // not expired
        let current_time = 100_000;
        let consensus_time = 90_000;
        assert!(!client_state.is_expired(current_time, consensus_time));

        // expired
        let current_time = consensus_time + 1209601;
        assert!(client_state.is_expired(current_time, consensus_time));
    }

    #[test]
    fn test_consensus_state_commitment() {
        let cs = ConsensusState {
            timestamp: 1704067200_000_000_000,
            root: [1u8; 32],
            next_validators_hash: [2u8; 32],
        };

        let commitment = cs.commitment();
        assert_ne!(commitment, [0u8; 32]);
    }

    #[test]
    fn test_validator_set_hash() {
        use crate::ibc::client::{Validator, ValidatorSet};

        let vs = ValidatorSet {
            validators: vec![
                Validator {
                    pub_key: [1u8; 32],
                    voting_power: 100,
                },
                Validator {
                    pub_key: [2u8; 32],
                    voting_power: 200,
                },
            ],
            proposer: None,
        };

        assert_eq!(vs.total_power(), 300);

        let hash = vs.hash();
        assert_ne!(hash, [0u8; 32]);
    }

    #[test]
    fn test_relay_task() {
        let packet = Packet {
            sequence: 1,
            source_port: PortId::new("transfer"),
            source_channel: ChannelId::new("channel-0"),
            destination_port: PortId::new("transfer"),
            destination_channel: ChannelId::new("channel-1"),
            data: b"test".to_vec(),
            timeout_height: Height::new(0, 1000),
            timeout_timestamp: 0,
        };

        let mut task = RelayTask::new(
            packet,
            RelayTaskType::RecvPacket,
            ChainId::new("jam"),
            ChainId::new("osmosis-1"),
            vec![],
            Height::default(),
            500,
            100, // deadline
            10,  // created
        );

        assert!(task.is_claimable(50));
        assert!(!task.is_claimable(100)); // at deadline

        // claim task
        let executor = [3u8; 32];
        assert!(task.claim(executor, 50).is_ok());
        assert_eq!(task.status, TaskStatus::Claimed);
        assert_eq!(task.claimed_by, Some(executor));

        // can't claim again
        assert!(task.claim([4u8; 32], 51).is_err());
    }

    #[test]
    fn test_bounty_calculator() {
        let calc = BountyCalculator::default();

        // base bounty
        let bounty = calc.calculate(0, 100);
        assert!(bounty >= calc.base_bounty);

        // larger proof = higher bounty
        let bounty_large = calc.calculate(10240, 100); // 10kb
        assert!(bounty_large > bounty);

        // urgency bonus
        let bounty_urgent = calc.calculate(0, 5); // 5 slots until deadline
        assert!(bounty_urgent > bounty);
    }

    #[test]
    fn test_task_queue_metrics() {
        let mut metrics = TaskQueueMetrics::default();

        metrics.task_created();
        assert_eq!(metrics.total_created, 1);
        assert_eq!(metrics.pending_count, 1);

        metrics.task_executed(500);
        assert_eq!(metrics.total_executed, 1);
        assert_eq!(metrics.total_bounties_paid, 500);
        assert_eq!(metrics.pending_count, 0);
    }

    #[test]
    fn test_leaf_op_iavl() {
        let leaf = LeafOp::iavl();

        let key = b"test-key";
        let value = b"test-value";

        let hash = leaf.apply(key, value).unwrap();
        assert_ne!(hash, [0u8; 32]);

        // same inputs = same hash
        let hash2 = leaf.apply(key, value).unwrap();
        assert_eq!(hash, hash2);

        // different value = different hash
        let hash3 = leaf.apply(key, b"different").unwrap();
        assert_ne!(hash, hash3);
    }

    #[test]
    fn test_inner_op() {
        let inner = InnerOp {
            hash: 0,
            prefix: vec![1, 2, 3],
            suffix: vec![4, 5, 6],
        };

        let child_hash = [7u8; 32];
        let hash = inner.apply(&child_hash).unwrap();
        assert_ne!(hash, [0u8; 32]);
    }

    #[test]
    fn test_existence_proof_calculate_root() {
        let proof = ExistenceProof {
            key: b"key".to_vec(),
            value: b"value".to_vec(),
            leaf: LeafOp::iavl(),
            path: vec![
                InnerOp {
                    hash: 0,
                    prefix: vec![1],
                    suffix: vec![],
                },
            ],
        };

        let root = proof.calculate_root().unwrap();
        assert_ne!(root, [0u8; 32]);
    }

    // =========================================================================
    // ics-20 transfer tests
    // =========================================================================

    #[test]
    fn test_denom_native() {
        let denom = Denom::native("uatom");
        assert!(denom.is_native());
        assert_eq!(denom.full_path(), b"uatom");
    }

    #[test]
    fn test_denom_with_trace() {
        let denom = Denom::with_trace("uatom", vec![
            TracePath {
                port_id: PortId::new("transfer"),
                channel_id: ChannelId::new("channel-0"),
            },
        ]);

        assert!(!denom.is_native());
        assert_eq!(denom.full_path(), b"transfer/channel-0/uatom");
    }

    #[test]
    fn test_denom_from_path() {
        // native
        let denom = Denom::from_path(b"uatom").unwrap();
        assert!(denom.is_native());

        // with trace
        let denom = Denom::from_path(b"transfer/channel-0/uatom").unwrap();
        assert!(!denom.is_native());
        assert_eq!(denom.trace_path.len(), 1);
        assert_eq!(denom.base_denom, b"uatom");

        // multi-hop trace
        let denom = Denom::from_path(b"transfer/channel-1/transfer/channel-0/uatom").unwrap();
        assert_eq!(denom.trace_path.len(), 2);
    }

    #[test]
    fn test_denom_is_source() {
        let port = PortId::new("transfer");
        let channel = ChannelId::new("channel-0");

        // native token is NOT source (being sent out)
        let native = Denom::native("uatom");
        assert!(!native.is_source(&port, &channel));

        // token with matching trace prefix IS source (returning home)
        let traced = Denom::with_trace("uatom", vec![
            TracePath {
                port_id: port.clone(),
                channel_id: channel.clone(),
            },
        ]);
        assert!(traced.is_source(&port, &channel));

        // token with different trace is not source
        let other = Denom::with_trace("uatom", vec![
            TracePath {
                port_id: PortId::new("transfer"),
                channel_id: ChannelId::new("channel-99"),
            },
        ]);
        assert!(!other.is_source(&port, &channel));
    }

    #[test]
    fn test_denom_add_remove_prefix() {
        let mut denom = Denom::native("uatom");

        // add prefix
        denom.add_prefix(&PortId::new("transfer"), &ChannelId::new("channel-0"));
        assert!(!denom.is_native());
        assert_eq!(denom.trace_path.len(), 1);

        // remove prefix
        let removed = denom.remove_prefix();
        assert!(removed.is_some());
        assert!(denom.is_native());
    }

    #[test]
    fn test_escrow_account() {
        let port = PortId::new("transfer");
        let channel = ChannelId::new("channel-0");
        let mut escrow = EscrowAccount::new(&port, &channel);

        let denom = Denom::native("uatom");

        // lock
        escrow.lock(&denom, 100).unwrap();
        assert_eq!(escrow.get_balance(&denom), 100);

        // lock more
        escrow.lock(&denom, 50).unwrap();
        assert_eq!(escrow.get_balance(&denom), 150);

        // unlock
        escrow.unlock(&denom, 75).unwrap();
        assert_eq!(escrow.get_balance(&denom), 75);

        // can't unlock more than locked
        assert!(escrow.unlock(&denom, 100).is_err());
    }

    #[test]
    fn test_token_registry() {
        let mut registry = TokenRegistry::default();

        let denom = Denom::with_trace("uatom", vec![
            TracePath {
                port_id: PortId::new("transfer"),
                channel_id: ChannelId::new("channel-0"),
            },
        ]);

        // register
        let token_id = registry.register(
            &denom,
            &PortId::new("transfer"),
            &ChannelId::new("channel-0"),
            100,
        );

        assert!(registry.get_token(&token_id).is_some());
        assert_eq!(registry.get_supply(&token_id), 0);

        // mint
        registry.mint(&token_id, 1000).unwrap();
        assert_eq!(registry.get_supply(&token_id), 1000);

        // burn
        registry.burn(&token_id, 400).unwrap();
        assert_eq!(registry.get_supply(&token_id), 600);

        // can't burn more than supply
        assert!(registry.burn(&token_id, 700).is_err());
    }

    #[test]
    fn test_user_balance() {
        let mut balance = UserBalance::new([1u8; 32]);
        let token_id = [2u8; 32];

        // credit
        balance.credit(&token_id, 500).unwrap();
        assert_eq!(balance.get_balance(&token_id), 500);

        // debit
        balance.debit(&token_id, 200).unwrap();
        assert_eq!(balance.get_balance(&token_id), 300);

        // can't debit more than balance
        assert!(balance.debit(&token_id, 400).is_err());
    }

    #[test]
    fn test_fungible_token_packet_encode_decode() {
        let data = FungibleTokenPacketData {
            denom: Denom::native("uatom"),
            amount: 1_000_000,
            sender: b"cosmos1abc...".to_vec(),
            receiver: b"jam1xyz...".to_vec(),
            memo: Some(b"test memo".to_vec()),
        };

        let encoded = data.encode();
        let decoded = FungibleTokenPacketData::decode(&encoded).unwrap();

        assert_eq!(decoded.denom, data.denom);
        assert_eq!(decoded.amount, data.amount);
        assert_eq!(decoded.sender, data.sender);
        assert_eq!(decoded.receiver, data.receiver);
        assert_eq!(decoded.memo, data.memo);
    }

    #[test]
    fn test_on_recv_packet_mint_wrapped() {
        let mut state = TransferModuleState::default();

        // create packet data for incoming transfer
        let data = FungibleTokenPacketData {
            denom: Denom::native("uatom"),  // native on cosmos
            amount: 1000,
            sender: b"cosmos1...".to_vec(),
            receiver: b"jam1...".to_vec(),
            memo: None,
        };

        let packet = Packet {
            sequence: 1,
            source_port: PortId::new("transfer"),
            source_channel: ChannelId::new("channel-0"),
            destination_port: PortId::new("transfer"),
            destination_channel: ChannelId::new("channel-1"),
            data: data.encode(),
            timeout_height: Height::new(0, 1000),
            timeout_timestamp: 0,
        };

        // receive packet - should mint wrapped tokens
        let (token_id, amount) = on_recv_packet(&mut state, &packet, 100).unwrap();

        assert_eq!(amount, 1000);
        assert_eq!(state.registry.get_supply(&token_id), 1000);
    }

    #[test]
    fn test_on_send_packet_escrow() {
        let mut state = TransferModuleState::default();

        let denom = Denom::native("ujam");
        let port = PortId::new("transfer");
        let channel = ChannelId::new("channel-0");

        // send native token - should lock in escrow
        let result_denom = on_send_packet(&mut state, &denom, 500, &port, &channel).unwrap();

        assert_eq!(result_denom, denom);

        let escrow = state.get_escrow(&port, &channel).unwrap();
        assert_eq!(escrow.get_balance(&denom), 500);
    }

    #[test]
    fn test_transfer_roundtrip() {
        let mut state = TransferModuleState::default();
        let port = PortId::new("transfer");
        let channel = ChannelId::new("channel-0");

        // 1. receive atom from cosmos (mint wrapped)
        let incoming_data = FungibleTokenPacketData {
            denom: Denom::native("uatom"),
            amount: 1000,
            sender: b"cosmos1...".to_vec(),
            receiver: b"jam1...".to_vec(),
            memo: None,
        };

        let recv_packet = Packet {
            sequence: 1,
            source_port: port.clone(),
            source_channel: channel.clone(),
            destination_port: port.clone(),
            destination_channel: ChannelId::new("channel-1"),
            data: incoming_data.encode(),
            timeout_height: Height::new(0, 1000),
            timeout_timestamp: 0,
        };

        let (token_id, _) = on_recv_packet(&mut state, &recv_packet, 100).unwrap();
        assert_eq!(state.registry.get_supply(&token_id), 1000);

        // 2. send wrapped atom back to cosmos (burn)
        let wrapped_denom = state.registry.get_token(&token_id).unwrap().denom.clone();

        on_send_packet(&mut state, &wrapped_denom, 400, &port, &ChannelId::new("channel-1")).unwrap();

        // supply reduced by burn
        assert_eq!(state.registry.get_supply(&token_id), 600);
    }

    // =========================================================================
    // connection handshake tests
    // =========================================================================

    #[test]
    fn test_connection_init() {
        let msg = ConnectionMsg::Init {
            client_id: ClientId::new("07-tendermint-0"),
            counterparty_client_id: ClientId::new("07-tendermint-1"),
            counterparty_prefix: b"ibc".to_vec(),
            versions: vec![default_ibc_version()],
            delay_period: 0,
        };

        let (conn_id, conn) = process_init(&msg, 0).unwrap();

        assert_eq!(conn_id.0, b"connection-0");
        assert_eq!(conn.state, ConnectionState::Init);
        assert!(!conn.is_open());
    }

    #[test]
    fn test_connection_open_flow() {
        // init
        let init_msg = ConnectionMsg::Init {
            client_id: ClientId::new("07-tendermint-0"),
            counterparty_client_id: ClientId::new("07-tendermint-1"),
            counterparty_prefix: b"ibc".to_vec(),
            versions: vec![default_ibc_version()],
            delay_period: 0,
        };

        let (conn_id, mut conn) = process_init(&init_msg, 0).unwrap();
        assert_eq!(conn.state, ConnectionState::Init);

        // ack (skipping try_open as we're the initiator)
        let ack_msg = ConnectionMsg::Ack {
            connection_id: conn_id.clone(),
            counterparty_connection_id: ConnectionId::new("connection-0"),
            version: default_ibc_version(),
            proof_try: vec![1, 2, 3],
            proof_height: Height::new(0, 100),
        };

        process_ack(&mut conn, &ack_msg).unwrap();
        assert!(conn.is_open());
    }

    // =========================================================================
    // channel handshake tests
    // =========================================================================

    #[test]
    fn test_channel_init() {
        let msg = ChannelMsg::Init {
            port_id: PortId::new("transfer"),
            ordering: Order::Unordered,
            counterparty_port: PortId::new("transfer"),
            connection_id: ConnectionId::new("connection-0"),
            version: b"ics20-1".to_vec(),
        };

        let (channel_id, channel) = process_channel_init(&msg, 0).unwrap();

        assert_eq!(channel_id.0, b"channel-0");
        assert_eq!(channel.state, ChannelState::Init);
        assert_eq!(channel.ordering, Order::Unordered);
    }

    #[test]
    fn test_channel_open_flow() {
        // init
        let init_msg = ChannelMsg::Init {
            port_id: PortId::new("transfer"),
            ordering: Order::Unordered,
            counterparty_port: PortId::new("transfer"),
            connection_id: ConnectionId::new("connection-0"),
            version: b"ics20-1".to_vec(),
        };

        let (channel_id, mut channel) = process_channel_init(&init_msg, 0).unwrap();
        assert_eq!(channel.state, ChannelState::Init);

        // ack
        let ack_msg = ChannelMsg::Ack {
            port_id: PortId::new("transfer"),
            channel_id: channel_id.clone(),
            counterparty_channel: ChannelId::new("channel-0"),
            counterparty_version: b"ics20-1".to_vec(),
            proof_try: vec![1, 2, 3],
            proof_height: Height::new(0, 100),
        };

        process_channel_ack(&mut channel, &ack_msg).unwrap();
        assert!(channel.is_open());
    }

    #[test]
    fn test_channel_close() {
        let mut channel = ChannelEnd::new_init(
            Order::Unordered,
            PortId::new("transfer"),
            vec![ConnectionId::new("connection-0")],
            b"ics20-1".to_vec(),
        );

        // open the channel first
        channel.open().unwrap();
        assert!(channel.is_open());

        // close
        channel.close().unwrap();
        assert!(channel.is_closed());

        // can't close again
        assert!(channel.close().is_err());
    }

    #[test]
    fn test_sequence_state() {
        let mut seq = SequenceState::new();

        assert_eq!(seq.alloc_send(), 1);
        assert_eq!(seq.alloc_send(), 2);
        assert_eq!(seq.next_send, 3);

        assert!(seq.advance_recv(1).is_ok());
        assert!(seq.advance_recv(2).is_ok());
        assert!(seq.advance_recv(4).is_err()); // skip not allowed
    }

    // =========================================================================
    // storage tests
    // =========================================================================

    #[test]
    fn test_in_memory_storage_clients() {
        let mut storage = InMemoryIbcStorage::new();

        let client_id = storage.alloc_client_id();
        assert_eq!(client_id.0, b"07-tendermint-0");

        let client_state = ClientState {
            chain_id: ChainId::new("osmosis-1"),
            trust_level: (1, 3),
            trusting_period: 1209600,
            unbonding_period: 1814400,
            max_clock_drift: 10,
            latest_height: Height::new(0, 100),
            frozen_height: None,
        };

        storage.set_client_state(&client_id, client_state.clone());
        let retrieved = storage.get_client_state(&client_id).unwrap();
        assert_eq!(retrieved.chain_id, client_state.chain_id);
    }

    #[test]
    fn test_in_memory_storage_packets() {
        let mut storage = InMemoryIbcStorage::new();

        let port = PortId::new("transfer");
        let channel = ChannelId::new("channel-0");

        // packet commitment
        let commitment = [42u8; 32];
        storage.set_packet_commitment(&port, &channel, 1, commitment);
        assert_eq!(storage.get_packet_commitment(&port, &channel, 1), Some(&commitment));

        // packet receipt
        assert!(!storage.has_packet_receipt(&port, &channel, 1));
        storage.set_packet_receipt(&port, &channel, 1);
        assert!(storage.has_packet_receipt(&port, &channel, 1));
    }

    #[test]
    fn test_in_memory_storage_relay_tasks() {
        let mut storage = InMemoryIbcStorage::new();

        let packet = Packet {
            sequence: 1,
            source_port: PortId::new("transfer"),
            source_channel: ChannelId::new("channel-0"),
            destination_port: PortId::new("transfer"),
            destination_channel: ChannelId::new("channel-1"),
            data: b"test".to_vec(),
            timeout_height: Height::new(0, 1000),
            timeout_timestamp: 0,
        };

        let task = RelayTask::new(
            packet,
            RelayTaskType::RecvPacket,
            ChainId::new("jam"),
            ChainId::new("osmosis-1"),
            vec![],
            Height::default(),
            500,
            100,
            10,
        );

        let task_id = task.id;
        storage.set_relay_task(task);

        assert!(storage.get_relay_task(&task_id).is_some());
        assert_eq!(storage.get_pending_tasks().len(), 1);
    }

    #[test]
    fn test_in_memory_storage_user_balances() {
        let mut storage = InMemoryIbcStorage::new();

        let user = [1u8; 32];
        let token_id = [2u8; 32];

        storage.credit_user(user, &token_id, 1000).unwrap();
        let balance = storage.get_user_balance(&user).unwrap();
        assert_eq!(balance.get_balance(&token_id), 1000);

        storage.debit_user(&user, &token_id, 300).unwrap();
        let balance = storage.get_user_balance(&user).unwrap();
        assert_eq!(balance.get_balance(&token_id), 700);
    }

    // =========================================================================
    // integration test: full transfer flow with storage
    // =========================================================================

    #[test]
    fn test_full_transfer_flow_with_storage() {
        let mut storage = InMemoryIbcStorage::new();

        // setup: create client, connection, channel
        let client_id = storage.alloc_client_id();
        let client_state = ClientState {
            chain_id: ChainId::new("osmosis-1"),
            trust_level: (1, 3),
            trusting_period: 1209600,
            unbonding_period: 1814400,
            max_clock_drift: 10,
            latest_height: Height::new(0, 100),
            frozen_height: None,
        };
        storage.set_client_state(&client_id, client_state);

        let conn_id = storage.alloc_connection_id();
        let mut conn = ConnectionEnd::new_init(
            client_id.clone(),
            ClientId::new("07-tendermint-0"),
            b"ibc".to_vec(),
            vec![default_ibc_version()],
            0,
        );
        conn.open().unwrap();
        storage.set_connection(&conn_id, conn);

        let port = PortId::new("transfer");
        let channel_id = storage.alloc_channel_id();
        let mut channel = ChannelEnd::new_init(
            Order::Unordered,
            port.clone(),
            vec![conn_id],
            b"ics20-1".to_vec(),
        );
        channel.counterparty.channel_id = Some(ChannelId::new("channel-0"));
        channel.open().unwrap();
        storage.set_channel(&port, &channel_id, channel);

        // 1. receive atom from cosmos
        let incoming_data = FungibleTokenPacketData {
            denom: Denom::native("uatom"),
            amount: 1000,
            sender: b"cosmos1sender".to_vec(),
            receiver: [1u8; 32].to_vec(), // jam address
            memo: None,
        };

        let recv_packet = Packet {
            sequence: 1,
            source_port: port.clone(),
            source_channel: ChannelId::new("channel-0"),
            destination_port: port.clone(),
            destination_channel: channel_id.clone(),
            data: incoming_data.encode(),
            timeout_height: Height::new(0, 1000),
            timeout_timestamp: 0,
        };

        // process recv
        let transfer_state = storage.get_transfer_state_mut();
        let (token_id, amount) = on_recv_packet(transfer_state, &recv_packet, 100).unwrap();

        // credit user
        let receiver: Hash32 = [1u8; 32];
        storage.credit_user(receiver, &token_id, amount).unwrap();

        // set receipt
        storage.set_packet_receipt(&port, &channel_id, 1);

        // verify state
        assert!(storage.has_packet_receipt(&port, &channel_id, 1));
        assert_eq!(storage.get_user_balance(&receiver).unwrap().get_balance(&token_id), 1000);
        assert_eq!(storage.get_transfer_state().registry.get_supply(&token_id), 1000);

        // 2. send some back
        let wrapped_denom = storage.get_transfer_state().registry.get_token(&token_id).unwrap().denom.clone();

        // debit user
        storage.debit_user(&receiver, &token_id, 400).unwrap();

        // process send
        let transfer_state = storage.get_transfer_state_mut();
        let _send_denom = on_send_packet(transfer_state, &wrapped_denom, 400, &port, &channel_id).unwrap();

        // create outgoing packet
        let seq = storage.alloc_send_sequence(&port, &channel_id);
        let send_packet = Packet {
            sequence: seq,
            source_port: port.clone(),
            source_channel: channel_id.clone(),
            destination_port: port.clone(),
            destination_channel: ChannelId::new("channel-0"),
            data: FungibleTokenPacketData {
                denom: Denom::native("uatom"), // unwrapped
                amount: 400,
                sender: receiver.to_vec(),
                receiver: b"cosmos1receiver".to_vec(),
                memo: None,
            }.encode(),
            timeout_height: Height::new(0, 2000),
            timeout_timestamp: 0,
        };

        // set commitment
        storage.set_packet_commitment(&port, &channel_id, seq, send_packet.commitment());

        // verify final state
        assert_eq!(storage.get_user_balance(&receiver).unwrap().get_balance(&token_id), 600);
        assert_eq!(storage.get_transfer_state().registry.get_supply(&token_id), 600);
        assert!(storage.get_packet_commitment(&port, &channel_id, seq).is_some());
    }
}
