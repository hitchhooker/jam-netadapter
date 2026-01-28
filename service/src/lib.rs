use ed25519_dalek::VerifyingKey;
use jam_netadapter_common::{
    DnsZone, NetAdapterError, RequestId, ThresholdResponse, WorkerId, ZoneUpdate,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

pub mod ibc;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkItem {
    pub item_type: WorkItemType,
    pub threshold_response: Option<ThresholdResponse>,
    pub zone_updates: Option<ZoneUpdates>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WorkItemType {
    OracleData,
    ZoneUpdate,
    ZoneCreate,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZoneUpdates {
    pub zone: String,
    pub updates: Vec<ZoneUpdate>,
    pub signatures: Vec<jam_netadapter_common::WorkerSignature>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefinedOutput {
    pub valid: bool,
    pub item_type: WorkItemType,
    pub data_hash: [u8; 32],
    pub request_id: Option<RequestId>,
    pub zone: Option<String>,
    pub updates: Option<Vec<ZoneUpdate>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ServiceState {
    pub oracle_data: HashMap<RequestId, OracleEntry>,
    pub zones: HashMap<String, DnsZone>,
    pub last_block: u64,
    pub finalized_block: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OracleEntry {
    pub data: Vec<u8>,
    pub data_hash: [u8; 32],
    pub timestamp: u64,
    pub block_number: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceConfig {
    pub threshold: usize,
    pub finality_blocks: u64,
    pub worker_keys: HashMap<WorkerId, [u8; 32]>,
}

impl Default for ServiceConfig {
    fn default() -> Self {
        Self {
            threshold: 2,
            finality_blocks: 3,
            worker_keys: HashMap::new(),
        }
    }
}

pub fn refine<'a>(
    work_item: &'a WorkItem,
    config: &'a ServiceConfig,
) -> Result<RefinedOutput, NetAdapterError> {
    match work_item.item_type {
        WorkItemType::OracleData => {
            let response = work_item
                .threshold_response
                .as_ref()
                .ok_or(NetAdapterError::Serialization("missing threshold response".into()))?;

            let public_keys: HashMap<WorkerId, VerifyingKey> = config
                .worker_keys
                .iter()
                .filter_map(|(id, bytes)| {
                    VerifyingKey::from_bytes(bytes).ok().map(|pk| (*id, pk))
                })
                .collect();

            if !response.verify(&public_keys, config.threshold) {
                return Err(NetAdapterError::ThresholdNotMet {
                    got: response.signatures.len(),
                    need: config.threshold,
                });
            }

            let mut hasher = Sha256::new();
            hasher.update(&response.data);
            let data_hash: [u8; 32] = hasher.finalize().into();

            Ok(RefinedOutput {
                valid: true,
                item_type: WorkItemType::OracleData,
                data_hash,
                request_id: Some(response.request_id),
                zone: None,
                updates: None,
            })
        }
        WorkItemType::ZoneUpdate => {
            let zone_updates = work_item
                .zone_updates
                .as_ref()
                .ok_or(NetAdapterError::Serialization("missing zone updates".into()))?;

            let public_keys: HashMap<WorkerId, VerifyingKey> = config
                .worker_keys
                .iter()
                .filter_map(|(id, bytes)| {
                    VerifyingKey::from_bytes(bytes).ok().map(|pk| (*id, pk))
                })
                .collect();

            let update_bytes = bincode::serialize(&zone_updates.updates)
                .map_err(|e| NetAdapterError::Serialization(e.to_string()))?;

            let mut valid_sigs = 0;
            for sig in &zone_updates.signatures {
                if let Some(pk) = public_keys.get(&sig.worker_id) {
                    let mut msg = zone_updates.zone.as_bytes().to_vec();
                    msg.extend_from_slice(&update_bytes);
                    msg.extend_from_slice(&sig.timestamp.to_le_bytes());

                    let signature = ed25519_dalek::Signature::from_bytes(&sig.signature);
                    if pk.verify_strict(&msg, &signature).is_ok() {
                        valid_sigs += 1;
                    }
                }
            }

            if valid_sigs < config.threshold {
                return Err(NetAdapterError::ThresholdNotMet {
                    got: valid_sigs,
                    need: config.threshold,
                });
            }

            let mut hasher = Sha256::new();
            hasher.update(&update_bytes);
            let data_hash: [u8; 32] = hasher.finalize().into();

            Ok(RefinedOutput {
                valid: true,
                item_type: WorkItemType::ZoneUpdate,
                data_hash,
                request_id: None,
                zone: Some(zone_updates.zone.clone()),
                updates: Some(zone_updates.updates.clone()),
            })
        }
        WorkItemType::ZoneCreate => {
            let mut hasher = Sha256::new();
            hasher.update(b"zone_create");
            let data_hash: [u8; 32] = hasher.finalize().into();

            Ok(RefinedOutput {
                valid: true,
                item_type: WorkItemType::ZoneCreate,
                data_hash,
                request_id: None,
                zone: None,
                updates: None,
            })
        }
    }
}

pub fn accumulate(
    state: &mut ServiceState,
    refined_outputs: Vec<(RefinedOutput, WorkItem)>,
    block_number: u64,
    config: &ServiceConfig,
) {
    state.last_block = block_number;

    if block_number >= config.finality_blocks {
        state.finalized_block = block_number - config.finality_blocks;
    }

    for (output, work_item) in refined_outputs {
        if !output.valid {
            continue;
        }

        match output.item_type {
            WorkItemType::OracleData => {
                if let (Some(request_id), Some(response)) =
                    (output.request_id, &work_item.threshold_response)
                {
                    state.oracle_data.insert(
                        request_id,
                        OracleEntry {
                            data: response.data.clone(),
                            data_hash: output.data_hash,
                            timestamp: response.timestamp,
                            block_number,
                        },
                    );
                }
            }
            WorkItemType::ZoneUpdate => {
                if let (Some(zone_name), Some(updates)) = (&output.zone, &output.updates) {
                    if let Some(zone) = state.zones.get_mut(zone_name) {
                        for update in updates {
                            apply_zone_update(zone, update);
                        }
                        zone.serial += 1;
                        zone.finalized_block = Some(state.finalized_block);
                    }
                }
            }
            WorkItemType::ZoneCreate => {}
        }
    }
}

fn apply_zone_update(zone: &mut DnsZone, update: &ZoneUpdate) {
    match update {
        ZoneUpdate::AddRecord(record) => {
            zone.records.push(record.clone());
        }
        ZoneUpdate::RemoveRecord { name, record_type } => {
            zone.records
                .retain(|r| !(r.name == *name && r.record_type == *record_type));
        }
        ZoneUpdate::UpdateRecord(record) => {
            if let Some(existing) = zone
                .records
                .iter_mut()
                .find(|r| r.name == record.name && r.record_type == record.record_type)
            {
                *existing = record.clone();
            }
        }
        ZoneUpdate::SetTtl { name, ttl } => {
            for record in &mut zone.records {
                if record.name == *name {
                    record.ttl = Some(*ttl);
                }
            }
        }
    }
}

pub fn query_oracle<'a>(state: &'a ServiceState, request_id: &RequestId) -> Option<&'a OracleEntry> {
    state.oracle_data.get(request_id)
}

pub fn query_zone<'a>(state: &'a ServiceState, zone_name: &str) -> Option<&'a DnsZone> {
    state.zones.get(zone_name)
}

pub fn is_finalized(state: &ServiceState, block_number: u64) -> bool {
    block_number <= state.finalized_block
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use jam_netadapter_common::{WorkerResponse, WorkerSignature};
    use rand::rngs::OsRng;

    fn create_test_config() -> (ServiceConfig, Vec<SigningKey>) {
        let mut config = ServiceConfig::default();
        let mut signing_keys = Vec::new();

        for _ in 0..3 {
            let key = SigningKey::generate(&mut OsRng);
            let worker_id = key.verifying_key().to_bytes();
            config.worker_keys.insert(worker_id, worker_id);
            signing_keys.push(key);
        }

        (config, signing_keys)
    }

    #[test]
    fn test_refine_oracle_data() {
        let (config, signing_keys) = create_test_config();

        let request_id = [1u8; 32];
        let data = b"oracle response data".to_vec();

        let mut signatures = Vec::new();
        for key in &signing_keys {
            let timestamp = 1704067200u64;
            let msg = WorkerResponse::signing_message(&request_id, &data, timestamp);
            let sig = key.sign(&msg);
            signatures.push(WorkerSignature {
                worker_id: key.verifying_key().to_bytes(),
                timestamp,
                signature: sig.to_bytes(),
            });
        }

        let response = ThresholdResponse {
            request_id,
            data: data.clone(),
            timestamp: 1704067200,
            signatures,
        };

        let work_item = WorkItem {
            item_type: WorkItemType::OracleData,
            threshold_response: Some(response),
            zone_updates: None,
        };

        let result = refine(&work_item, &config);
        assert!(result.is_ok());

        let output = result.unwrap();
        assert!(output.valid);
        assert_eq!(output.request_id, Some(request_id));
    }

    #[test]
    fn test_accumulate() {
        let (config, signing_keys) = create_test_config();
        let mut state = ServiceState::default();

        let request_id = [2u8; 32];
        let data = b"test data".to_vec();

        let mut signatures = Vec::new();
        for key in &signing_keys {
            let timestamp = 1704067200u64;
            let msg = WorkerResponse::signing_message(&request_id, &data, timestamp);
            let sig = key.sign(&msg);
            signatures.push(WorkerSignature {
                worker_id: key.verifying_key().to_bytes(),
                timestamp,
                signature: sig.to_bytes(),
            });
        }

        let response = ThresholdResponse {
            request_id,
            data: data.clone(),
            timestamp: 1704067200,
            signatures,
        };

        let work_item = WorkItem {
            item_type: WorkItemType::OracleData,
            threshold_response: Some(response),
            zone_updates: None,
        };

        let output = refine(&work_item, &config).unwrap();
        accumulate(&mut state, vec![(output, work_item)], 5, &config);

        assert!(state.oracle_data.contains_key(&request_id));
        assert_eq!(state.last_block, 5);
        assert_eq!(state.finalized_block, 2);
    }
}
