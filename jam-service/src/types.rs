//! jam-netadapter types
//!
//! netadapter is a general oracle + state bridge service.
//! dns/geodns is one application built on top of it.
//!
//! core capabilities:
//! - oracle: fetch and attest external data (http, dns, feeds)
//! - state: store arbitrary key-value data with ownership
//! - namespace: .alt domain resolution from multiple sources

use alloc::vec::Vec;
use crate::codec;

pub type Hash = [u8; 32];
pub type Signature = [u8; 64];
pub type PublicKey = [u8; 32];

// ============================================================================
// work item types - what workers submit
// ============================================================================

#[derive(Clone, Debug)]
pub enum WorkItemType {
    /// oracle data fetch (http, dns, timestamp, feed)
    OracleData = 0,
    /// key-value state update
    StateUpdate = 1,
    /// namespace registration (.alt domains)
    NamespaceOp = 2,
    /// sla monitoring operation
    SlaOp = 3,
    /// private/shielded transaction (zeratul-style)
    PrivateOp = 4,
    /// ibc relay operation (cosmos bridge)
    IbcOp = 5,
}

impl WorkItemType {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::OracleData),
            1 => Some(Self::StateUpdate),
            2 => Some(Self::NamespaceOp),
            3 => Some(Self::SlaOp),
            4 => Some(Self::PrivateOp),
            5 => Some(Self::IbcOp),
            _ => None,
        }
    }
}

// ============================================================================
// oracle types
// ============================================================================

#[derive(Clone, Debug)]
pub struct OracleRequest {
    pub request_type: OracleRequestType,
    pub request_id: Hash,
}

#[derive(Clone, Debug)]
pub enum OracleRequestType {
    Http { url: Vec<u8>, method: u8 },
    Dns { name: Vec<u8>, record_type: u8 },
    Timestamp,
    Feed { feed_id: Vec<u8> },
}

#[derive(Clone, Debug)]
pub struct OracleResponse {
    pub request_id: Hash,
    pub data: Vec<u8>,
    pub timestamp: u64,
    pub signatures: Vec<WorkerSignature>,
}

#[derive(Clone, Debug)]
pub struct WorkerSignature {
    pub worker_id: PublicKey,
    pub timestamp: u64,
    pub signature: Signature,
}

// ============================================================================
// state types - general key-value with ownership
// ============================================================================

#[derive(Clone, Debug)]
pub struct StateEntry {
    pub key: Vec<u8>,
    pub value: Vec<u8>,
    pub owner: Option<PublicKey>,
    pub nonce: u64,
}

#[derive(Clone, Debug)]
pub enum StateOp {
    Set { key: Vec<u8>, value: Vec<u8>, signature: Signature },
    Delete { key: Vec<u8>, signature: Signature },
    Transfer { key: Vec<u8>, new_owner: PublicKey, signature: Signature },
}

// ============================================================================
// namespace types - .alt domains
// ============================================================================

#[derive(Clone, Debug)]
pub struct NamespaceDomain {
    pub name: Vec<u8>,          // e.g. "rotko"
    pub namespace: Vec<u8>,     // e.g. "jam", "dot", "eth"
    pub owner: PublicKey,
    pub records: Vec<DnsRecord>,
    pub registered_slot: u32,
    pub expires_slot: Option<u32>,
    pub nonce: u64,
}

#[derive(Clone, Debug)]
pub struct DnsRecord {
    pub name: Vec<u8>,
    pub record_type: u8,  // A=1, AAAA=28, CNAME=5, TXT=16, MX=15, etc
    pub ttl: u32,
    pub data: Vec<u8>,
    pub priority: Option<u16>,
    pub regions: Option<Vec<Vec<u8>>>,  // geodns regions
}

#[derive(Clone, Debug)]
pub enum NamespaceOp {
    Register {
        name: Vec<u8>,
        namespace: Vec<u8>,
        owner: PublicKey,
        records: Vec<DnsRecord>,
        signature: Signature,
    },
    Update {
        name: Vec<u8>,
        namespace: Vec<u8>,
        records: Vec<DnsRecord>,
        nonce: u64,
        signature: Signature,
    },
    Transfer {
        name: Vec<u8>,
        namespace: Vec<u8>,
        new_owner: PublicKey,
        signature: Signature,
    },
    Renew {
        name: Vec<u8>,
        namespace: Vec<u8>,
        signature: Signature,
    },
}

// ============================================================================
// refine/accumulate argument types
// ============================================================================

pub struct RefineArgs {
    pub core_index: u32,
    pub work_item_index: u32,
    pub service_id: u32,
    pub package_hash: Hash,
}

impl RefineArgs {
    pub fn fetch() -> Self {
        // these come from host context
        Self {
            core_index: 0,      // TODO: fetch from host
            work_item_index: 0,
            service_id: 0,
            package_hash: [0u8; 32],
        }
    }
}

pub struct AccumulateArgs {
    pub timeslot: u32,
    pub service_id: u32,
    pub num_inputs: u64,
}

impl AccumulateArgs {
    pub fn fetch() -> Self {
        Self {
            timeslot: crate::host::current_timeslot(),
            service_id: 0,  // TODO: fetch from host
            num_inputs: 0,
        }
    }
}

// ============================================================================
// accumulate input - operand or transfer
// ============================================================================

#[derive(Clone, Debug)]
pub struct AccumulateInput {
    pub is_transfer: bool,
    pub operand: Option<Operand>,
    pub transfer: Option<Transfer>,
}

#[derive(Clone, Debug)]
pub struct Operand {
    pub package_hash: Hash,
    pub segment_root: Hash,
    pub authorizer_hash: Hash,
    pub payload_hash: Hash,
    pub gas_limit: u64,
    pub digest_output: Vec<u8>,  // refine output
    pub report_output: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct Transfer {
    pub sender: u32,
    pub receiver: u32,
    pub amount: u64,
    pub memo: Vec<u8>,
    pub gas_limit: u64,
}

// ============================================================================
// decoding implementations
// ============================================================================

impl OracleResponse {
    pub fn decode(data: &[u8]) -> Option<(Self, usize)> {
        let mut offset = 0;

        // request_id: 32 bytes
        if data.len() < 32 {
            return None;
        }
        let mut request_id = [0u8; 32];
        request_id.copy_from_slice(&data[0..32]);
        offset += 32;

        // data: length-prefixed
        let (response_data, consumed) = codec::decode_bytes(&data[offset..])?;
        offset += consumed;

        // timestamp: u64
        let (timestamp, consumed) = codec::decode_u64(&data[offset..])?;
        offset += consumed;

        // signatures: list
        let (num_sigs, consumed) = codec::decode_list_len(&data[offset..])?;
        offset += consumed;

        let mut signatures = Vec::with_capacity(num_sigs);
        for _ in 0..num_sigs {
            let (sig, consumed) = WorkerSignature::decode(&data[offset..])?;
            offset += consumed;
            signatures.push(sig);
        }

        Some((
            Self {
                request_id,
                data: response_data.to_vec(),
                timestamp,
                signatures,
            },
            offset,
        ))
    }
}

impl WorkerSignature {
    pub fn decode(data: &[u8]) -> Option<(Self, usize)> {
        if data.len() < 32 + 8 + 64 {
            return None;
        }

        let mut worker_id = [0u8; 32];
        worker_id.copy_from_slice(&data[0..32]);

        let timestamp = u64::from_le_bytes(data[32..40].try_into().ok()?);

        let mut signature = [0u8; 64];
        signature.copy_from_slice(&data[40..104]);

        Some((
            Self {
                worker_id,
                timestamp,
                signature,
            },
            104,
        ))
    }
}

impl AccumulateInput {
    pub fn decode(data: &[u8]) -> Option<(Self, usize)> {
        if data.is_empty() {
            return None;
        }

        let is_transfer = data[0] != 0;
        let mut offset = 1;

        if is_transfer {
            let (transfer, consumed) = Transfer::decode(&data[offset..])?;
            offset += consumed;
            Some((
                Self {
                    is_transfer: true,
                    operand: None,
                    transfer: Some(transfer),
                },
                offset,
            ))
        } else {
            let (operand, consumed) = Operand::decode(&data[offset..])?;
            offset += consumed;
            Some((
                Self {
                    is_transfer: false,
                    operand: Some(operand),
                    transfer: None,
                },
                offset,
            ))
        }
    }
}

impl Operand {
    pub fn decode(data: &[u8]) -> Option<(Self, usize)> {
        let mut offset = 0;

        // 4 x 32-byte hashes
        if data.len() < 128 {
            return None;
        }

        let mut package_hash = [0u8; 32];
        package_hash.copy_from_slice(&data[0..32]);
        let mut segment_root = [0u8; 32];
        segment_root.copy_from_slice(&data[32..64]);
        let mut authorizer_hash = [0u8; 32];
        authorizer_hash.copy_from_slice(&data[64..96]);
        let mut payload_hash = [0u8; 32];
        payload_hash.copy_from_slice(&data[96..128]);
        offset = 128;

        let (gas_limit, consumed) = codec::decode_u64(&data[offset..])?;
        offset += consumed;

        let (digest_output, consumed) = codec::decode_bytes(&data[offset..])?;
        offset += consumed;

        let (report_output, consumed) = codec::decode_bytes(&data[offset..])?;
        offset += consumed;

        Some((
            Self {
                package_hash,
                segment_root,
                authorizer_hash,
                payload_hash,
                gas_limit,
                digest_output: digest_output.to_vec(),
                report_output: report_output.to_vec(),
            },
            offset,
        ))
    }
}

impl Transfer {
    pub fn decode(data: &[u8]) -> Option<(Self, usize)> {
        let mut offset = 0;

        let (sender, consumed) = codec::decode_u32(&data[offset..])?;
        offset += consumed;

        let (receiver, consumed) = codec::decode_u32(&data[offset..])?;
        offset += consumed;

        let (amount, consumed) = codec::decode_u64(&data[offset..])?;
        offset += consumed;

        let (memo, consumed) = codec::decode_bytes(&data[offset..])?;
        offset += consumed;

        let (gas_limit, consumed) = codec::decode_u64(&data[offset..])?;
        offset += consumed;

        Some((
            Self {
                sender,
                receiver,
                amount,
                memo: memo.to_vec(),
                gas_limit,
            },
            offset,
        ))
    }
}
