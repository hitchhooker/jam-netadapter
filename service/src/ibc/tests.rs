//! ibc module tests

#[cfg(test)]
mod tests {
    use super::super::*;

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
}
