//! ibc module for cosmos bridge
//!
//! implements ibc light client, packet relay, and task queue

pub mod types;
pub mod client;
pub mod proof;
pub mod tendermint;
pub mod relay;

use ed25519_dalek::{Signature, VerifyingKey, Verifier};

pub use types::*;
pub use client::*;
pub use proof::*;
pub use relay::*;

/// ibc work item
#[derive(Clone, Debug)]
pub enum IbcWorkItem {
    /// create new light client
    CreateClient {
        client_state: ClientState,
        consensus_state: ConsensusState,
    },
    /// update light client with new header
    UpdateClient {
        client_id: ClientId,
        header: Header,
    },
    /// send packet from jam to cosmos
    SendPacket {
        packet: Packet,
    },
    /// receive packet from cosmos with proof
    RecvPacket {
        packet: Packet,
        proof: Vec<u8>,
        proof_height: Height,
    },
    /// acknowledge packet
    AcknowledgePacket {
        packet: Packet,
        acknowledgement: Vec<u8>,
        proof: Vec<u8>,
        proof_height: Height,
    },
    /// timeout packet
    TimeoutPacket {
        packet: Packet,
        proof: Vec<u8>,
        proof_height: Height,
        next_sequence_recv: u64,
    },
    /// claim relay task
    ClaimRelayTask {
        task_id: Hash32,
        executor: Hash32,
        signature: [u8; 64],
    },
    /// confirm task execution
    ConfirmExecution {
        task_id: Hash32,
        dest_tx_hash: Hash32,
        inclusion_proof: Vec<u8>,
    },
}

/// ibc refine output
#[derive(Clone, Debug)]
pub struct IbcRefinedOutput {
    /// is valid
    pub valid: bool,
    /// work item type for accumulate
    pub work_item: IbcWorkItem,
    /// error message if invalid
    pub error: Option<IbcError>,
}

/// refine ibc work item
pub fn refine_ibc(
    work_item: IbcWorkItem,
    clients: &dyn ClientReader,
    current_time: Timestamp,
) -> IbcRefinedOutput {
    match &work_item {
        IbcWorkItem::CreateClient { client_state, consensus_state } => {
            // validate client state
            if client_state.trust_level.0 == 0 || client_state.trust_level.1 == 0 {
                return IbcRefinedOutput {
                    valid: false,
                    work_item,
                    error: Some(IbcError::InvalidStateTransition),
                };
            }

            if client_state.trusting_period == 0 {
                return IbcRefinedOutput {
                    valid: false,
                    work_item,
                    error: Some(IbcError::InvalidStateTransition),
                };
            }

            // validate consensus state
            if consensus_state.root == [0u8; 32] {
                return IbcRefinedOutput {
                    valid: false,
                    work_item,
                    error: Some(IbcError::InvalidStateTransition),
                };
            }

            IbcRefinedOutput {
                valid: true,
                work_item,
                error: None,
            }
        }

        IbcWorkItem::UpdateClient { client_id, header } => {
            // get existing client state
            let client_state = match clients.get_client_state(client_id) {
                Some(cs) => cs,
                None => {
                    return IbcRefinedOutput {
                        valid: false,
                        work_item,
                        error: Some(IbcError::ClientNotFound),
                    };
                }
            };

            // get trusted consensus state
            let consensus_state = match clients.get_consensus_state(client_id, &header.trusted_height) {
                Some(cs) => cs,
                None => {
                    return IbcRefinedOutput {
                        valid: false,
                        work_item,
                        error: Some(IbcError::ConsensusStateNotFound),
                    };
                }
            };

            // verify header
            match tendermint::verify_header(&client_state, &consensus_state, header, current_time) {
                Ok(_) => IbcRefinedOutput {
                    valid: true,
                    work_item,
                    error: None,
                },
                Err(e) => IbcRefinedOutput {
                    valid: false,
                    work_item,
                    error: Some(e),
                },
            }
        }

        IbcWorkItem::RecvPacket { packet, proof, proof_height: _ } => {
            // verify proof
            // TODO: proper proof verification against client state
            if proof.is_empty() {
                return IbcRefinedOutput {
                    valid: false,
                    work_item,
                    error: Some(IbcError::InvalidProof),
                };
            }

            // verify packet data
            if packet.data.is_empty() {
                return IbcRefinedOutput {
                    valid: false,
                    work_item,
                    error: Some(IbcError::InvalidPacketData),
                };
            }

            IbcRefinedOutput {
                valid: true,
                work_item,
                error: None,
            }
        }

        IbcWorkItem::ClaimRelayTask { task_id, executor, signature } => {
            // verify signature: sign(task_id || executor)
            let mut message = Vec::with_capacity(64);
            message.extend_from_slice(task_id);
            message.extend_from_slice(executor);

            let verifying_key = match VerifyingKey::from_bytes(executor) {
                Ok(k) => k,
                Err(_) => {
                    return IbcRefinedOutput {
                        valid: false,
                        work_item,
                        error: Some(IbcError::InvalidSignature),
                    };
                }
            };

            let sig = Signature::from_bytes(signature);
            if verifying_key.verify(&message, &sig).is_err() {
                return IbcRefinedOutput {
                    valid: false,
                    work_item,
                    error: Some(IbcError::InvalidSignature),
                };
            }

            IbcRefinedOutput {
                valid: true,
                work_item,
                error: None,
            }
        }

        IbcWorkItem::ConfirmExecution { task_id: _, dest_tx_hash: _, inclusion_proof } => {
            // TODO: verify inclusion proof on destination chain
            if inclusion_proof.is_empty() {
                return IbcRefinedOutput {
                    valid: false,
                    work_item,
                    error: Some(IbcError::InvalidProof),
                };
            }

            IbcRefinedOutput {
                valid: true,
                work_item,
                error: None,
            }
        }

        // other work items pass through
        _ => IbcRefinedOutput {
            valid: true,
            work_item,
            error: None,
        },
    }
}

/// trait for reading client state
pub trait ClientReader {
    fn get_client_state(&self, client_id: &ClientId) -> Option<ClientState>;
    fn get_consensus_state(&self, client_id: &ClientId, height: &Height) -> Option<ConsensusState>;
}

/// ibc state for accumulate
#[derive(Clone, Debug, Default)]
pub struct IbcState {
    /// next client id counter
    pub next_client_id: u64,
    /// task queue metrics
    pub metrics: TaskQueueMetrics,
}

/// accumulate ibc work item
pub fn accumulate_ibc<S: IbcStorage>(
    storage: &mut S,
    state: &mut IbcState,
    output: IbcRefinedOutput,
    timeslot: u32,
) -> Result<(), IbcError> {
    if !output.valid {
        return Err(output.error.unwrap_or(IbcError::InvalidStateTransition));
    }

    match output.work_item {
        IbcWorkItem::CreateClient { client_state, consensus_state } => {
            // generate client id
            let client_id = ClientId::new(&format!("07-tendermint-{}", state.next_client_id));
            state.next_client_id += 1;

            // store client state
            storage.set_client_state(&client_id, &client_state)?;

            // store consensus state at latest height
            storage.set_consensus_state(&client_id, &client_state.latest_height, &consensus_state)?;
        }

        IbcWorkItem::UpdateClient { client_id, header } => {
            // get current client state
            let mut client_state = storage
                .get_client_state(&client_id)
                .ok_or(IbcError::ClientNotFound)?;

            let consensus_state = storage
                .get_consensus_state(&client_id, &header.trusted_height)
                .ok_or(IbcError::ConsensusStateNotFound)?;

            // verify and get new state
            let current_time = (timeslot as u64) * 6_000_000_000; // assume 6 second slots
            let result = tendermint::verify_header(&client_state, &consensus_state, &header, current_time)?;

            // update client state if height increased
            if let Some(new_client_state) = result.client_state {
                client_state = new_client_state;
                storage.set_client_state(&client_id, &client_state)?;
            }

            // store new consensus state
            let new_height = Height::new(0, header.signed_header.header.height);
            storage.set_consensus_state(&client_id, &new_height, &result.consensus_state)?;
        }

        IbcWorkItem::SendPacket { packet } => {
            // create relay task
            let bounty_calc = BountyCalculator::default();
            let deadline = timeslot + 600; // ~1 hour at 6s slots
            let bounty = bounty_calc.calculate(0, deadline - timeslot);

            let task = RelayTask::new(
                packet,
                RelayTaskType::RecvPacket,
                ChainId::new("jam"),
                ChainId::new("cosmos"),
                vec![],
                Height::default(),
                bounty,
                deadline,
                timeslot,
            );

            storage.set_relay_task(&task)?;
            state.metrics.task_created();
        }

        IbcWorkItem::RecvPacket { packet, .. } => {
            // mark packet as received
            let commitment = packet.commitment();
            storage.set_packet_receipt(&packet.destination_channel, packet.sequence, &commitment)?;
        }

        IbcWorkItem::ClaimRelayTask { task_id, executor, .. } => {
            let mut task = storage
                .get_relay_task(&task_id)
                .ok_or(IbcError::TaskNotFound)?;

            task.claim(executor, timeslot)?;
            storage.set_relay_task(&task)?;
        }

        IbcWorkItem::ConfirmExecution { task_id, .. } => {
            let mut task = storage
                .get_relay_task(&task_id)
                .ok_or(IbcError::TaskNotFound)?;

            task.mark_executed();
            storage.set_relay_task(&task)?;

            // pay bounty to executor
            if let Some(_executor) = task.claimed_by {
                // TODO: call host::transfer to pay bounty
                state.metrics.task_executed(task.bounty);
            }
        }

        _ => {}
    }

    Ok(())
}

/// storage trait for ibc state
pub trait IbcStorage {
    fn get_client_state(&self, client_id: &ClientId) -> Option<ClientState>;
    fn set_client_state(&mut self, client_id: &ClientId, state: &ClientState) -> Result<(), IbcError>;

    fn get_consensus_state(&self, client_id: &ClientId, height: &Height) -> Option<ConsensusState>;
    fn set_consensus_state(&mut self, client_id: &ClientId, height: &Height, state: &ConsensusState) -> Result<(), IbcError>;

    fn get_relay_task(&self, task_id: &Hash32) -> Option<RelayTask>;
    fn set_relay_task(&mut self, task: &RelayTask) -> Result<(), IbcError>;

    fn set_packet_receipt(&mut self, channel: &ChannelId, sequence: u64, commitment: &Hash32) -> Result<(), IbcError>;
}
