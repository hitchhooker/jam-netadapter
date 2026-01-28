//! relay executor
//!
//! main loop for claiming and executing relay tasks

use ed25519_dalek::{Signer, SigningKey};
use tracing::{info, debug, warn, error};
use std::time::Duration;

use crate::cosmos::CosmosClient;
use crate::jam::JamClient;
use crate::types::*;

/// relay executor
pub struct Executor {
    pub jam_client: JamClient,
    pub cosmos_client: CosmosClient,
    pub keypair: SigningKey,
    pub min_bounty: u64,
    pub dry_run: bool,
}

impl Executor {
    /// run main executor loop
    pub async fn run(&self, poll_interval: Duration) -> anyhow::Result<()> {
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
    async fn tick(&self, last_cosmos_height: &mut u64) -> anyhow::Result<()> {
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
    async fn handle_packet_event(&self, mut event: PacketEvent) -> anyhow::Result<()> {
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
    async fn process_task(&self, task: RelayTask) -> anyhow::Result<()> {
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
    async fn claim_task(&self, task: &RelayTask) -> anyhow::Result<bool> {
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
    async fn execute_recv_packet(&self, task: &RelayTask) -> anyhow::Result<()> {
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
    async fn execute_ack_packet(&self, task: &RelayTask) -> anyhow::Result<()> {
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
    async fn execute_timeout_packet(&self, task: &RelayTask) -> anyhow::Result<()> {
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
        // cosmos tx structure (simplified - real impl needs protobuf)
        // MsgRecvPacket {
        //   packet: Packet,
        //   proof_commitment: bytes,
        //   proof_height: Height,
        //   signer: string,
        // }

        let mut tx = Vec::new();

        // tx type prefix for MsgRecvPacket
        tx.extend_from_slice(b"/ibc.core.channel.v1.MsgRecvPacket");
        tx.push(0); // separator

        // packet
        encode_packet_for_cosmos(&mut tx, &task.packet);

        // proof
        tx.extend_from_slice(&(task.proof.len() as u32).to_le_bytes());
        tx.extend_from_slice(&task.proof);

        // proof height
        tx.extend_from_slice(&task.proof_height.revision_number.to_le_bytes());
        tx.extend_from_slice(&task.proof_height.revision_height.to_le_bytes());

        // signer would be derived from executor's cosmos key
        // for now just placeholder
        let signer = self.keypair.verifying_key().to_bytes();
        tx.extend_from_slice(&signer);

        Ok(tx)
    }

    /// build cosmos tx for MsgAcknowledgement
    fn build_ack_packet_tx(&self, task: &RelayTask) -> anyhow::Result<Vec<u8>> {
        let mut tx = Vec::new();

        tx.extend_from_slice(b"/ibc.core.channel.v1.MsgAcknowledgement");
        tx.push(0);

        encode_packet_for_cosmos(&mut tx, &task.packet);

        // acknowledgement would come from task metadata
        // placeholder empty ack
        tx.extend_from_slice(&[0u8; 4]);

        tx.extend_from_slice(&(task.proof.len() as u32).to_le_bytes());
        tx.extend_from_slice(&task.proof);

        tx.extend_from_slice(&task.proof_height.revision_number.to_le_bytes());
        tx.extend_from_slice(&task.proof_height.revision_height.to_le_bytes());

        let signer = self.keypair.verifying_key().to_bytes();
        tx.extend_from_slice(&signer);

        Ok(tx)
    }

    /// build cosmos tx for MsgTimeout
    fn build_timeout_packet_tx(&self, task: &RelayTask) -> anyhow::Result<Vec<u8>> {
        let mut tx = Vec::new();

        tx.extend_from_slice(b"/ibc.core.channel.v1.MsgTimeout");
        tx.push(0);

        encode_packet_for_cosmos(&mut tx, &task.packet);

        tx.extend_from_slice(&(task.proof.len() as u32).to_le_bytes());
        tx.extend_from_slice(&task.proof);

        tx.extend_from_slice(&task.proof_height.revision_number.to_le_bytes());
        tx.extend_from_slice(&task.proof_height.revision_height.to_le_bytes());

        // next sequence recv for timeout proofs
        tx.extend_from_slice(&task.packet.sequence.to_le_bytes());

        let signer = self.keypair.verifying_key().to_bytes();
        tx.extend_from_slice(&signer);

        Ok(tx)
    }
}

/// encode packet for cosmos tx
fn encode_packet_for_cosmos(buf: &mut Vec<u8>, packet: &Packet) {
    buf.extend_from_slice(&packet.sequence.to_le_bytes());

    let src_port = packet.source_port.as_bytes();
    buf.extend_from_slice(&(src_port.len() as u32).to_le_bytes());
    buf.extend_from_slice(src_port);

    let src_chan = packet.source_channel.as_bytes();
    buf.extend_from_slice(&(src_chan.len() as u32).to_le_bytes());
    buf.extend_from_slice(src_chan);

    let dst_port = packet.destination_port.as_bytes();
    buf.extend_from_slice(&(dst_port.len() as u32).to_le_bytes());
    buf.extend_from_slice(dst_port);

    let dst_chan = packet.destination_channel.as_bytes();
    buf.extend_from_slice(&(dst_chan.len() as u32).to_le_bytes());
    buf.extend_from_slice(dst_chan);

    buf.extend_from_slice(&(packet.data.len() as u32).to_le_bytes());
    buf.extend_from_slice(&packet.data);

    buf.extend_from_slice(&packet.timeout_height.revision_number.to_le_bytes());
    buf.extend_from_slice(&packet.timeout_height.revision_height.to_le_bytes());
    buf.extend_from_slice(&packet.timeout_timestamp.to_le_bytes());
}
