use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use thiserror::Error;

pub type RequestId = [u8; 32];
pub type WorkerId = [u8; 32];
pub type ZoneOwner = [u8; 32];
pub type UpdateNonce = u64;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum OracleRequest {
    Http { url: String, method: String },
    Dns { name: String, record_type: DnsRecordType },
    Timestamp,
    Feed { feed_id: String },
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum DnsRecordType {
    A,
    AAAA,
    CNAME,
    MX,
    TXT,
    NS,
    SOA,
    SRV,
    PTR,
}

impl OracleRequest {
    pub fn request_id(&self) -> RequestId {
        let encoded = bincode::serialize(self).expect("serialize request");
        let mut hasher = Sha256::new();
        hasher.update(&encoded);
        hasher.finalize().into()
    }
}

#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerResponse {
    pub request_id: RequestId,
    pub worker_id: WorkerId,
    pub data: Vec<u8>,
    pub timestamp: u64,
    #[serde_as(as = "[_; 64]")]
    pub signature: [u8; 64],
}

impl WorkerResponse {
    pub fn signing_message(request_id: &RequestId, data: &[u8], timestamp: u64) -> Vec<u8> {
        let mut msg = Vec::with_capacity(32 + data.len() + 8);
        msg.extend_from_slice(request_id);
        msg.extend_from_slice(data);
        msg.extend_from_slice(&timestamp.to_le_bytes());
        msg
    }

    pub fn verify(&self, public_key: &VerifyingKey) -> bool {
        let msg = Self::signing_message(&self.request_id, &self.data, self.timestamp);
        let sig = Signature::from_bytes(&self.signature);
        public_key.verify_strict(&msg, &sig).is_ok()
    }
}

#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerSignature {
    pub worker_id: WorkerId,
    pub timestamp: u64,
    #[serde_as(as = "[_; 64]")]
    pub signature: [u8; 64],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThresholdResponse {
    pub request_id: RequestId,
    pub data: Vec<u8>,
    pub timestamp: u64,
    pub signatures: Vec<WorkerSignature>,
}

impl ThresholdResponse {
    pub fn verify(&self, public_keys: &HashMap<WorkerId, VerifyingKey>, threshold: usize) -> bool {
        let mut valid_count = 0;
        for sig in &self.signatures {
            if let Some(pk) = public_keys.get(&sig.worker_id) {
                let msg = WorkerResponse::signing_message(&self.request_id, &self.data, sig.timestamp);
                let signature = Signature::from_bytes(&sig.signature);
                if pk.verify_strict(&msg, &signature).is_ok() {
                    valid_count += 1;
                }
            }
        }
        valid_count >= threshold
    }
}

#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsZone {
    pub origin: String,
    pub ttl: u32,
    pub records: Vec<DnsRecord>,
    pub serial: u32,
    pub finalized_block: Option<u64>,
    #[serde_as(as = "Option<[_; 32]>")]
    pub owner: Option<ZoneOwner>,
    pub nonce: UpdateNonce,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ZoneState {
    Optimistic,
    Pending,
    Finalized,
}

#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedZoneUpdate {
    pub zone: String,
    pub updates: Vec<ZoneUpdate>,
    pub expected_serial: u32,
    pub nonce: UpdateNonce,
    pub timestamp: u64,
    #[serde_as(as = "[_; 64]")]
    pub signature: [u8; 64],
}

impl SignedZoneUpdate {
    pub fn signing_message(zone: &str, updates: &[ZoneUpdate], expected_serial: u32, nonce: UpdateNonce, timestamp: u64) -> Vec<u8> {
        let mut msg = Vec::new();
        msg.extend_from_slice(zone.as_bytes());
        msg.extend_from_slice(&bincode::serialize(updates).unwrap_or_default());
        msg.extend_from_slice(&expected_serial.to_le_bytes());
        msg.extend_from_slice(&nonce.to_le_bytes());
        msg.extend_from_slice(&timestamp.to_le_bytes());
        msg
    }

    pub fn verify(&self, public_key: &VerifyingKey) -> bool {
        let msg = Self::signing_message(&self.zone, &self.updates, self.expected_serial, self.nonce, self.timestamp);
        let sig = Signature::from_bytes(&self.signature);
        public_key.verify_strict(&msg, &sig).is_ok()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConflictRecord {
    pub zone: String,
    pub optimistic_serial: u32,
    pub finalized_serial: u32,
    pub rolled_back_updates: Vec<ZoneUpdate>,
    pub block: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsRecord {
    pub name: String,
    pub record_type: DnsRecordType,
    pub ttl: Option<u32>,
    pub data: String,
    pub priority: Option<u16>,
    pub regions: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum GeoRegion {
    Global,
    Continent(String),
    Country(String),
    Custom(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ZoneUpdate {
    AddRecord(DnsRecord),
    RemoveRecord { name: String, record_type: DnsRecordType },
    UpdateRecord(DnsRecord),
    SetTtl { name: String, ttl: u32 },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZoneUpdateRequest {
    pub zone: String,
    pub updates: Vec<ZoneUpdate>,
    pub optimistic: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZoneUpdateResponse {
    pub zone: String,
    pub new_serial: u32,
    pub finalized: bool,
    pub pending_block: Option<u64>,
}

// .alt namespace types (rfc 8244 compliant)

#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AltDomain {
    pub name: String,
    pub namespace: String,
    #[serde_as(as = "[_; 32]")]
    pub owner: [u8; 32],
    pub records: Vec<DnsRecord>,
    pub registered_block: u64,
    pub expires_block: Option<u64>,
    pub nonce: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AltNamespace {
    pub name: String,
    pub admin: Option<[u8; 32]>,
    pub policy: RegistrationPolicy,
    pub domains: Vec<AltDomain>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RegistrationPolicy {
    Open,
    Whitelist { admins: Vec<[u8; 32]> },
    FirstComeFirstServe,
}

#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AltRegistration {
    Register {
        name: String,
        namespace: String,
        #[serde_as(as = "[_; 32]")]
        owner: [u8; 32],
        records: Vec<DnsRecord>,
        #[serde_as(as = "[_; 64]")]
        signature: [u8; 64],
    },
    Transfer {
        name: String,
        namespace: String,
        #[serde_as(as = "[_; 32]")]
        new_owner: [u8; 32],
        #[serde_as(as = "[_; 64]")]
        signature: [u8; 64],
    },
    UpdateRecords {
        name: String,
        namespace: String,
        records: Vec<DnsRecord>,
        nonce: u64,
        #[serde_as(as = "[_; 64]")]
        signature: [u8; 64],
    },
    Renew {
        name: String,
        namespace: String,
        #[serde_as(as = "[_; 64]")]
        signature: [u8; 64],
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolverConfig {
    pub blocklist_root: [u8; 32],
    pub upstream_servers: Vec<String>,
    pub dnssec_enabled: bool,
    pub alt_namespaces: Vec<String>,
    pub version: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlocklistUpdate {
    pub add_domains: Vec<String>,
    pub remove_domains: Vec<String>,
    pub new_root: [u8; 32],
}

#[derive(Debug, Error)]
pub enum NetAdapterError {
    #[error("invalid signature")]
    InvalidSignature,
    #[error("threshold not met: got {got}, need {need}")]
    ThresholdNotMet { got: usize, need: usize },
    #[error("zone not found: {0}")]
    ZoneNotFound(String),
    #[error("record not found")]
    RecordNotFound,
    #[error("serialization error: {0}")]
    Serialization(String),
    #[error("serial mismatch: expected {expected}, got {got}")]
    SerialMismatch { expected: u32, got: u32 },
    #[error("nonce already used: {0}")]
    NonceReplay(UpdateNonce),
    #[error("not zone owner")]
    NotZoneOwner,
    #[error("update rejected: {0}")]
    UpdateRejected(String),
    #[error("conflict detected: optimistic rollback required")]
    ConflictDetected(ConflictRecord),
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use rand::rngs::OsRng;

    #[test]
    fn test_worker_response_sign_verify() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();

        let request = OracleRequest::Timestamp;
        let request_id = request.request_id();
        let data = b"1704067200".to_vec();
        let timestamp = 1704067200u64;

        let msg = WorkerResponse::signing_message(&request_id, &data, timestamp);
        let signature = signing_key.sign(&msg);

        let response = WorkerResponse {
            request_id,
            worker_id: verifying_key.to_bytes(),
            data,
            timestamp,
            signature: signature.to_bytes(),
        };

        assert!(response.verify(&verifying_key));
    }

    #[test]
    fn test_threshold_response() {
        let mut keys = HashMap::new();
        let mut signatures = Vec::new();
        let request_id = [0u8; 32];
        let data = b"test data".to_vec();

        for i in 0..3 {
            let signing_key = SigningKey::generate(&mut OsRng);
            let verifying_key = signing_key.verifying_key();
            let worker_id = verifying_key.to_bytes();
            keys.insert(worker_id, verifying_key);

            let timestamp = 1704067200u64 + i;
            let msg = WorkerResponse::signing_message(&request_id, &data, timestamp);
            let sig = signing_key.sign(&msg);
            signatures.push(WorkerSignature {
                worker_id,
                timestamp,
                signature: sig.to_bytes(),
            });
        }

        let response = ThresholdResponse {
            request_id,
            data,
            timestamp: 1704067201,
            signatures,
        };

        assert!(response.verify(&keys, 2));
        assert!(response.verify(&keys, 3));
        assert!(!response.verify(&keys, 4));
    }
}
