//! relay executor
//!
//! main loop for claiming and executing relay tasks

use ed25519_dalek::{Signer, SigningKey};
use tracing::{info, debug, warn, error};
use std::time::Duration;
use std::collections::HashMap;

use crate::cosmos::CosmosClient;
use crate::jam::JamClient;
use crate::tx;
use crate::types::*;

/// chain type for routing
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ChainType {
    /// cosmos sdk chains (cosmoshub, osmosis)
    Cosmos,
    /// penumbra (jmt proofs, shielded)
    Penumbra,
    /// generic tendermint
    Tendermint,
}

impl ChainType {
    /// detect chain type from chain id
    pub fn from_chain_id(chain_id: &str) -> Self {
        if chain_id.starts_with("penumbra") {
            ChainType::Penumbra
        } else if chain_id.contains("cosmoshub") || chain_id.contains("osmosis") {
            ChainType::Cosmos
        } else {
            ChainType::Tendermint
        }
    }

    /// check if this chain requires timestamp quantization
    pub fn requires_timestamp_quantization(&self) -> bool {
        matches!(self, ChainType::Penumbra)
    }

    /// get quantization interval in nanoseconds
    pub fn timestamp_quantum_ns(&self) -> u64 {
        match self {
            ChainType::Penumbra => 60_000_000_000, // 1 minute
            _ => 0, // no quantization
        }
    }
}

/// relay executor
pub struct Executor {
    pub jam_client: JamClient,
    pub cosmos_client: CosmosClient,
    pub keypair: SigningKey,
    pub min_bounty: u64,
    pub dry_run: bool,
    /// additional chain clients for multi-chain routing
    pub chain_clients: HashMap<String, CosmosClient>,
}

impl Executor {
    /// create new executor with single cosmos client
    pub fn new(
        jam_client: JamClient,
        cosmos_client: CosmosClient,
        keypair: SigningKey,
        min_bounty: u64,
        dry_run: bool,
    ) -> Self {
        Self {
            jam_client,
            cosmos_client,
            keypair,
            min_bounty,
            dry_run,
            chain_clients: HashMap::new(),
        }
    }

    /// add additional chain client for multi-chain routing
    pub fn add_chain_client(&mut self, chain_id: String, client: CosmosClient) {
        self.chain_clients.insert(chain_id, client);
    }

    /// get client for destination chain
    fn get_dest_client(&self, chain_id: &str) -> &CosmosClient {
        self.chain_clients.get(chain_id).unwrap_or(&self.cosmos_client)
    }

    /// detect chain type from destination chain
    fn detect_chain_type(&self, chain_id: &str) -> ChainType {
        ChainType::from_chain_id(chain_id)
    }

    /// run main executor loop
    pub async fn run(&mut self, poll_interval: Duration) -> anyhow::Result<()> {
        info!("executor starting main loop");

        let mut last_cosmos_height = self.cosmos_client.get_height().await?;
        info!("starting cosmos height: {}", last_cosmos_height);

        loop {
            if let Err(e) = self.tick(&mut last_cosmos_height).await {
                error!("executor tick failed: {}", e);
            }

            tokio::time::sleep(poll_interval).await;
        }
    }

    /// single executor tick
    async fn tick(&mut self, last_cosmos_height: &mut u64) -> anyhow::Result<()> {
        // check for new packets from cosmos
        let current_height = self.cosmos_client.get_height().await?;

        if current_height > *last_cosmos_height {
            debug!(
                "scanning cosmos blocks {} to {}",
                *last_cosmos_height + 1,
                current_height
            );

            // query for send_packet events
            let packets = self
                .cosmos_client
                .query_send_packets(*last_cosmos_height + 1, current_height)
                .await?;

            for packet_event in packets {
                if let Err(e) = self.handle_packet_event(packet_event).await {
                    warn!("failed to handle packet: {}", e);
                }
            }

            *last_cosmos_height = current_height;
        }

        // check for pending tasks on jam
        let pending_tasks = self.jam_client.get_pending_tasks().await?;

        for task in pending_tasks {
            if task.bounty < self.min_bounty {
                debug!("skipping task {:?}, bounty {} < min {}",
                    hex::encode(&task.id[..8]), task.bounty, self.min_bounty);
                continue;
            }

            if task.status != TaskStatus::Pending {
                continue;
            }

            if let Err(e) = self.process_task(task).await {
                warn!("failed to process task: {}", e);
            }
        }

        Ok(())
    }

    /// handle packet event from cosmos
    async fn handle_packet_event(&mut self, mut event: PacketEvent) -> anyhow::Result<()> {
        info!(
            "detected packet: {}:{} seq {}",
            event.packet.source_port,
            event.packet.source_channel,
            event.packet.sequence
        );

        // fetch proof for packet commitment
        let (proof, proof_height) = self
            .cosmos_client
            .get_packet_commitment_proof(
                &event.packet.source_port,
                &event.packet.source_channel,
                event.packet.sequence,
                event.proof_height.revision_height,
            )
            .await?;

        event.proof = proof;
        event.proof_height = proof_height;

        if self.dry_run {
            info!("dry run: would submit RecvPacket for seq {}", event.packet.sequence);
            return Ok(());
        }

        // submit work item to jam
        let work_item = IbcWorkItem::RecvPacket {
            packet: event.packet.clone(),
            proof_commitment: event.proof,
            proof_height: event.proof_height,
        };

        let hash = self.jam_client.submit_work_item(&work_item).await?;
        info!("submitted RecvPacket, hash: {}", hex::encode(&hash));

        Ok(())
    }

    /// process pending relay task
    async fn process_task(&mut self, task: RelayTask) -> anyhow::Result<()> {
        info!(
            "processing task {:?}, bounty: {}",
            hex::encode(&task.id[..8]),
            task.bounty
        );

        // claim the task first
        let claimed = self.claim_task(&task).await?;
        if !claimed {
            debug!("task already claimed by another executor");
            return Ok(());
        }

        // execute based on task type
        match task.task_type {
            RelayTaskType::RecvPacket => {
                self.execute_recv_packet(&task).await?;
            }
            RelayTaskType::AckPacket => {
                self.execute_ack_packet(&task).await?;
            }
            RelayTaskType::TimeoutPacket => {
                self.execute_timeout_packet(&task).await?;
            }
        }

        Ok(())
    }

    /// claim a relay task
    async fn claim_task(&mut self, task: &RelayTask) -> anyhow::Result<bool> {
        let executor_pubkey = self.keypair.verifying_key().to_bytes();

        // sign the claim message: task_id || executor_pubkey
        let mut message = Vec::with_capacity(64);
        message.extend_from_slice(&task.id);
        message.extend_from_slice(&executor_pubkey);

        let signature = self.keypair.sign(&message);

        if self.dry_run {
            info!("dry run: would claim task {:?}", hex::encode(&task.id[..8]));
            return Ok(true);
        }

        let work_item = IbcWorkItem::ClaimRelayTask {
            task_id: task.id,
            executor: executor_pubkey,
            signature: signature.to_bytes().to_vec(),
        };

        match self.jam_client.submit_work_item(&work_item).await {
            Ok(hash) => {
                info!("claimed task, hash: {}", hex::encode(&hash));
                Ok(true)
            }
            Err(e) => {
                // task might already be claimed
                debug!("claim failed: {}", e);
                Ok(false)
            }
        }
    }

    /// execute recv_packet relay
    async fn execute_recv_packet(&mut self, task: &RelayTask) -> anyhow::Result<()> {
        info!("executing recv_packet for task {:?}", hex::encode(&task.id[..8]));

        // the task should already have the packet and proof from jam
        // we need to relay to the destination cosmos chain

        // for now, the destination is the cosmos chain we're connected to
        // in production, we'd need to route based on task.dest_chain

        // build cosmos tx for MsgRecvPacket
        let tx_bytes = self.build_recv_packet_tx(task)?;

        if self.dry_run {
            info!("dry run: would broadcast recv_packet tx");
            return Ok(());
        }

        // broadcast to cosmos
        let tx_hash = self.cosmos_client.broadcast_tx(&tx_bytes).await?;
        info!("broadcast recv_packet, tx: {}", hex::encode(&tx_hash));

        // wait for inclusion
        let height = self.cosmos_client.wait_for_tx(&tx_hash, 60).await?;
        info!("recv_packet included at height {}", height);

        // get inclusion proof
        let inclusion_proof = self
            .cosmos_client
            .get_tx_inclusion_proof(&tx_hash)
            .await?;

        // confirm execution on jam
        let work_item = IbcWorkItem::ConfirmExecution {
            task_id: task.id,
            dest_tx_hash: tx_hash,
            inclusion_proof,
        };

        let hash = self.jam_client.submit_work_item(&work_item).await?;
        info!("confirmed execution, hash: {}", hex::encode(&hash));

        Ok(())
    }

    /// execute ack_packet relay
    async fn execute_ack_packet(&mut self, task: &RelayTask) -> anyhow::Result<()> {
        info!("executing ack_packet for task {:?}", hex::encode(&task.id[..8]));

        // similar to recv_packet but submits MsgAcknowledgement
        let tx_bytes = self.build_ack_packet_tx(task)?;

        if self.dry_run {
            info!("dry run: would broadcast ack_packet tx");
            return Ok(());
        }

        let tx_hash = self.cosmos_client.broadcast_tx(&tx_bytes).await?;
        info!("broadcast ack_packet, tx: {}", hex::encode(&tx_hash));

        let height = self.cosmos_client.wait_for_tx(&tx_hash, 60).await?;
        info!("ack_packet included at height {}", height);

        let inclusion_proof = self
            .cosmos_client
            .get_tx_inclusion_proof(&tx_hash)
            .await?;

        let work_item = IbcWorkItem::ConfirmExecution {
            task_id: task.id,
            dest_tx_hash: tx_hash,
            inclusion_proof,
        };

        let hash = self.jam_client.submit_work_item(&work_item).await?;
        info!("confirmed execution, hash: {}", hex::encode(&hash));

        Ok(())
    }

    /// execute timeout_packet relay
    async fn execute_timeout_packet(&mut self, task: &RelayTask) -> anyhow::Result<()> {
        info!("executing timeout_packet for task {:?}", hex::encode(&task.id[..8]));

        let tx_bytes = self.build_timeout_packet_tx(task)?;

        if self.dry_run {
            info!("dry run: would broadcast timeout_packet tx");
            return Ok(());
        }

        let tx_hash = self.cosmos_client.broadcast_tx(&tx_bytes).await?;
        info!("broadcast timeout_packet, tx: {}", hex::encode(&tx_hash));

        let height = self.cosmos_client.wait_for_tx(&tx_hash, 60).await?;
        info!("timeout_packet included at height {}", height);

        let inclusion_proof = self
            .cosmos_client
            .get_tx_inclusion_proof(&tx_hash)
            .await?;

        let work_item = IbcWorkItem::ConfirmExecution {
            task_id: task.id,
            dest_tx_hash: tx_hash,
            inclusion_proof,
        };

        let hash = self.jam_client.submit_work_item(&work_item).await?;
        info!("confirmed execution, hash: {}", hex::encode(&hash));

        Ok(())
    }

    /// build cosmos tx for MsgRecvPacket
    fn build_recv_packet_tx(&self, task: &RelayTask) -> anyhow::Result<Vec<u8>> {
        // TODO: derive cosmos address from executor key
        // for now use placeholder - real impl needs secp256k1 key
        let signer = format!("cosmos1{}", hex::encode(&self.keypair.verifying_key().to_bytes()[..20]));

        let msg_bytes = tx::build_recv_packet_msg(task, &signer);
        let tx_bytes = tx::wrap_in_tx_body(tx::type_urls::MSG_RECV_PACKET, &msg_bytes);

        Ok(tx_bytes)
    }

    /// build cosmos tx for MsgAcknowledgement
    fn build_ack_packet_tx(&self, task: &RelayTask) -> anyhow::Result<Vec<u8>> {
        let signer = format!("cosmos1{}", hex::encode(&self.keypair.verifying_key().to_bytes()[..20]));

        // TODO: get acknowledgement from task metadata
        let ack = b"{}"; // placeholder

        let msg_bytes = tx::build_ack_packet_msg(task, ack, &signer);
        let tx_bytes = tx::wrap_in_tx_body(tx::type_urls::MSG_ACKNOWLEDGEMENT, &msg_bytes);

        Ok(tx_bytes)
    }

    /// build cosmos tx for MsgTimeout
    fn build_timeout_packet_tx(&self, task: &RelayTask) -> anyhow::Result<Vec<u8>> {
        let signer = format!("cosmos1{}", hex::encode(&self.keypair.verifying_key().to_bytes()[..20]));

        // next_sequence_recv comes from querying the counterparty
        let next_seq = task.packet.sequence;

        let msg_bytes = tx::build_timeout_packet_msg(task, next_seq, &signer);
        let tx_bytes = tx::wrap_in_tx_body(tx::type_urls::MSG_TIMEOUT, &msg_bytes);

        Ok(tx_bytes)
    }
}
