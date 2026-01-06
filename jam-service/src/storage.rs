//! storage schema for jam-netadapter
//!
//! key prefixes:
//! - 0x00: config (threshold, worker keys, etc)
//! - 0x01: oracle data by request_id
//! - 0x02: state entries by key
//! - 0x03: namespace domains
//! - 0x04: namespace metadata

use alloc::vec::Vec;
use crate::host;
use crate::types::*;
use crate::codec;

// storage key prefixes
pub const PREFIX_CONFIG: u8 = 0x00;
pub const PREFIX_ORACLE: u8 = 0x01;
pub const PREFIX_STATE: u8 = 0x02;
pub const PREFIX_DOMAIN: u8 = 0x03;
pub const PREFIX_NAMESPACE: u8 = 0x04;

// config keys
pub const CONFIG_THRESHOLD: &[u8] = &[PREFIX_CONFIG, 0x01];
pub const CONFIG_FINALITY_SLOTS: &[u8] = &[PREFIX_CONFIG, 0x02];
pub const CONFIG_WORKER_KEYS: &[u8] = &[PREFIX_CONFIG, 0x03];

// ============================================================================
// config operations
// ============================================================================

pub fn get_threshold() -> u32 {
    host::storage_read(CONFIG_THRESHOLD)
        .and_then(|v| codec::decode_u32(&v).map(|(t, _)| t))
        .unwrap_or(2)  // default threshold
}

pub fn set_threshold(threshold: u32) {
    let _ = host::storage_write(CONFIG_THRESHOLD, &codec::encode_u64(threshold as u64));
}

pub fn get_finality_slots() -> u32 {
    host::storage_read(CONFIG_FINALITY_SLOTS)
        .and_then(|v| codec::decode_u32(&v).map(|(t, _)| t))
        .unwrap_or(3)  // default finality
}

pub fn get_worker_keys() -> Vec<PublicKey> {
    host::storage_read(CONFIG_WORKER_KEYS)
        .map(|data| {
            let mut keys = Vec::new();
            let mut offset = 0;

            if let Some((count, consumed)) = codec::decode_list_len(&data) {
                offset += consumed;
                for _ in 0..count {
                    if data.len() >= offset + 32 {
                        let mut key = [0u8; 32];
                        key.copy_from_slice(&data[offset..offset + 32]);
                        keys.push(key);
                        offset += 32;
                    }
                }
            }
            keys
        })
        .unwrap_or_default()
}

// ============================================================================
// oracle data storage
// ============================================================================

fn oracle_key(request_id: &Hash) -> Vec<u8> {
    let mut key = Vec::with_capacity(33);
    key.push(PREFIX_ORACLE);
    key.extend_from_slice(request_id);
    key
}

pub fn get_oracle_data(request_id: &Hash) -> Option<OracleEntry> {
    let key = oracle_key(request_id);
    host::storage_read(&key).and_then(|data| OracleEntry::decode(&data).map(|(e, _)| e))
}

pub fn set_oracle_data(request_id: &Hash, entry: &OracleEntry) {
    let key = oracle_key(request_id);
    let data = entry.encode();
    let _ = host::storage_write(&key, &data);
}

#[derive(Clone, Debug)]
pub struct OracleEntry {
    pub data: Vec<u8>,
    pub data_hash: Hash,
    pub timestamp: u64,
    pub slot: u32,
}

impl OracleEntry {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&codec::encode_bytes(&self.data));
        out.extend_from_slice(&self.data_hash);
        out.extend_from_slice(&self.timestamp.to_le_bytes());
        out.extend_from_slice(&self.slot.to_le_bytes());
        out
    }

    pub fn decode(data: &[u8]) -> Option<(Self, usize)> {
        let mut offset = 0;

        let (entry_data, consumed) = codec::decode_bytes(data)?;
        offset += consumed;

        if data.len() < offset + 32 + 8 + 4 {
            return None;
        }

        let mut data_hash = [0u8; 32];
        data_hash.copy_from_slice(&data[offset..offset + 32]);
        offset += 32;

        let timestamp = u64::from_le_bytes(data[offset..offset + 8].try_into().ok()?);
        offset += 8;

        let slot = u32::from_le_bytes(data[offset..offset + 4].try_into().ok()?);
        offset += 4;

        Some((
            Self {
                data: entry_data.to_vec(),
                data_hash,
                timestamp,
                slot,
            },
            offset,
        ))
    }
}

// ============================================================================
// state entry storage (general key-value)
// ============================================================================

fn state_key(user_key: &[u8]) -> Vec<u8> {
    let mut key = Vec::with_capacity(1 + user_key.len());
    key.push(PREFIX_STATE);
    key.extend_from_slice(user_key);
    key
}

pub fn get_state(user_key: &[u8]) -> Option<StateEntry> {
    let key = state_key(user_key);
    host::storage_read(&key).and_then(|data| StateEntry::decode(&data).map(|(e, _)| e))
}

pub fn set_state(entry: &StateEntry) {
    let key = state_key(&entry.key);
    let data = entry.encode();
    let _ = host::storage_write(&key, &data);
}

pub fn delete_state(user_key: &[u8]) {
    let key = state_key(user_key);
    let _ = host::storage_delete(&key);
}

impl StateEntry {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&codec::encode_bytes(&self.key));
        out.extend_from_slice(&codec::encode_bytes(&self.value));

        // owner: optional pubkey
        if let Some(ref owner) = self.owner {
            out.push(1);
            out.extend_from_slice(owner);
        } else {
            out.push(0);
        }

        out.extend_from_slice(&self.nonce.to_le_bytes());
        out
    }

    pub fn decode(data: &[u8]) -> Option<(Self, usize)> {
        let mut offset = 0;

        let (key, consumed) = codec::decode_bytes(data)?;
        offset += consumed;

        let (value, consumed) = codec::decode_bytes(&data[offset..])?;
        offset += consumed;

        if data.len() <= offset {
            return None;
        }

        let owner = if data[offset] == 1 {
            offset += 1;
            if data.len() < offset + 32 {
                return None;
            }
            let mut pk = [0u8; 32];
            pk.copy_from_slice(&data[offset..offset + 32]);
            offset += 32;
            Some(pk)
        } else {
            offset += 1;
            None
        };

        if data.len() < offset + 8 {
            return None;
        }
        let nonce = u64::from_le_bytes(data[offset..offset + 8].try_into().ok()?);
        offset += 8;

        Some((
            Self {
                key: key.to_vec(),
                value: value.to_vec(),
                owner,
                nonce,
            },
            offset,
        ))
    }
}

// ============================================================================
// namespace domain storage
// ============================================================================

fn domain_key(namespace: &[u8], name: &[u8]) -> Vec<u8> {
    let mut key = Vec::with_capacity(1 + namespace.len() + 1 + name.len());
    key.push(PREFIX_DOMAIN);
    key.extend_from_slice(&codec::encode_bytes(namespace));
    key.extend_from_slice(name);
    key
}

pub fn get_domain(namespace: &[u8], name: &[u8]) -> Option<NamespaceDomain> {
    let key = domain_key(namespace, name);
    host::storage_read(&key).and_then(|data| NamespaceDomain::decode(&data).map(|(d, _)| d))
}

pub fn set_domain(domain: &NamespaceDomain) {
    let key = domain_key(&domain.namespace, &domain.name);
    let data = domain.encode();
    let _ = host::storage_write(&key, &data);
}

pub fn delete_domain(namespace: &[u8], name: &[u8]) {
    let key = domain_key(namespace, name);
    let _ = host::storage_delete(&key);
}

impl NamespaceDomain {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&codec::encode_bytes(&self.name));
        out.extend_from_slice(&codec::encode_bytes(&self.namespace));
        out.extend_from_slice(&self.owner);

        // records
        out.extend_from_slice(&codec::encode_u64(self.records.len() as u64));
        for record in &self.records {
            out.extend_from_slice(&record.encode());
        }

        out.extend_from_slice(&self.registered_slot.to_le_bytes());

        if let Some(expires) = self.expires_slot {
            out.push(1);
            out.extend_from_slice(&expires.to_le_bytes());
        } else {
            out.push(0);
        }

        out.extend_from_slice(&self.nonce.to_le_bytes());
        out
    }

    pub fn decode(data: &[u8]) -> Option<(Self, usize)> {
        let mut offset = 0;

        let (name, consumed) = codec::decode_bytes(data)?;
        offset += consumed;

        let (namespace, consumed) = codec::decode_bytes(&data[offset..])?;
        offset += consumed;

        if data.len() < offset + 32 {
            return None;
        }
        let mut owner = [0u8; 32];
        owner.copy_from_slice(&data[offset..offset + 32]);
        offset += 32;

        let (num_records, consumed) = codec::decode_list_len(&data[offset..])?;
        offset += consumed;

        let mut records = Vec::with_capacity(num_records);
        for _ in 0..num_records {
            let (record, consumed) = DnsRecord::decode(&data[offset..])?;
            offset += consumed;
            records.push(record);
        }

        if data.len() < offset + 4 {
            return None;
        }
        let registered_slot = u32::from_le_bytes(data[offset..offset + 4].try_into().ok()?);
        offset += 4;

        if data.len() <= offset {
            return None;
        }
        let expires_slot = if data[offset] == 1 {
            offset += 1;
            if data.len() < offset + 4 {
                return None;
            }
            let v = u32::from_le_bytes(data[offset..offset + 4].try_into().ok()?);
            offset += 4;
            Some(v)
        } else {
            offset += 1;
            None
        };

        if data.len() < offset + 8 {
            return None;
        }
        let nonce = u64::from_le_bytes(data[offset..offset + 8].try_into().ok()?);
        offset += 8;

        Some((
            Self {
                name: name.to_vec(),
                namespace: namespace.to_vec(),
                owner,
                records,
                registered_slot,
                expires_slot,
                nonce,
            },
            offset,
        ))
    }
}

impl DnsRecord {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&codec::encode_bytes(&self.name));
        out.push(self.record_type);
        out.extend_from_slice(&self.ttl.to_le_bytes());
        out.extend_from_slice(&codec::encode_bytes(&self.data));

        if let Some(prio) = self.priority {
            out.push(1);
            out.extend_from_slice(&prio.to_le_bytes());
        } else {
            out.push(0);
        }

        if let Some(ref regions) = self.regions {
            out.extend_from_slice(&codec::encode_u64(regions.len() as u64));
            for region in regions {
                out.extend_from_slice(&codec::encode_bytes(region));
            }
        } else {
            out.push(0);  // empty list
        }

        out
    }

    pub fn decode(data: &[u8]) -> Option<(Self, usize)> {
        let mut offset = 0;

        let (name, consumed) = codec::decode_bytes(data)?;
        offset += consumed;

        if data.len() <= offset {
            return None;
        }
        let record_type = data[offset];
        offset += 1;

        if data.len() < offset + 4 {
            return None;
        }
        let ttl = u32::from_le_bytes(data[offset..offset + 4].try_into().ok()?);
        offset += 4;

        let (record_data, consumed) = codec::decode_bytes(&data[offset..])?;
        offset += consumed;

        if data.len() <= offset {
            return None;
        }
        let priority = if data[offset] == 1 {
            offset += 1;
            if data.len() < offset + 2 {
                return None;
            }
            let v = u16::from_le_bytes(data[offset..offset + 2].try_into().ok()?);
            offset += 2;
            Some(v)
        } else {
            offset += 1;
            None
        };

        let (num_regions, consumed) = codec::decode_list_len(&data[offset..])?;
        offset += consumed;

        let regions = if num_regions > 0 {
            let mut r = Vec::with_capacity(num_regions);
            for _ in 0..num_regions {
                let (region, consumed) = codec::decode_bytes(&data[offset..])?;
                offset += consumed;
                r.push(region.to_vec());
            }
            Some(r)
        } else {
            None
        };

        Some((
            Self {
                name: name.to_vec(),
                record_type,
                ttl,
                data: record_data.to_vec(),
                priority,
                regions,
            },
            offset,
        ))
    }
}
