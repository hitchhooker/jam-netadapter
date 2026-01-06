//! jam codec - general integer encoding and decoding
//!
//! jam uses a variable-length integer encoding similar to protobuf varints

use alloc::vec::Vec;

/// decode a general integer (variable length)
/// returns (value, bytes_consumed)
pub fn decode_u64(data: &[u8]) -> Option<(u64, usize)> {
    if data.is_empty() {
        return None;
    }

    let first = data[0];

    // single byte: 0-127
    if first < 128 {
        return Some((first as u64, 1));
    }

    // determine length from high bits
    let len = first.leading_ones() as usize;
    if len > 8 || data.len() < len + 1 {
        return None;
    }

    // mask off the length prefix bits
    let mut value = (first & (0xFF >> len)) as u64;

    // read remaining bytes
    for i in 1..=len {
        value = (value << 8) | (data[i] as u64);
    }

    Some((value, len + 1))
}

/// encode a u64 as general integer
pub fn encode_u64(value: u64) -> Vec<u8> {
    if value < 128 {
        return alloc::vec![value as u8];
    }

    // find how many bytes we need
    let bits_needed = 64 - value.leading_zeros();
    let bytes_needed = ((bits_needed + 6) / 8) as usize; // +6 for prefix bits

    let mut result = Vec::with_capacity(bytes_needed + 1);

    // prefix byte with length indicator
    let prefix_bits = bytes_needed;
    let prefix_mask = !((1u8 << (8 - prefix_bits)) - 1);
    let value_bits_in_first = 8 - prefix_bits - 1;
    let first_byte = prefix_mask | ((value >> (bytes_needed * 8 - value_bits_in_first)) as u8 & !prefix_mask);

    result.push(first_byte);

    // remaining bytes
    for i in (0..bytes_needed).rev() {
        result.push((value >> (i * 8)) as u8);
    }

    result
}

/// decode a length-prefixed byte sequence
pub fn decode_bytes<'a>(data: &'a [u8]) -> Option<(&'a [u8], usize)> {
    let (len, consumed) = decode_u64(data)?;
    let total = consumed + len as usize;

    if data.len() < total {
        return None;
    }

    Some((&data[consumed..total], total))
}

/// encode a length-prefixed byte sequence
pub fn encode_bytes(data: &[u8]) -> Vec<u8> {
    let mut result = encode_u64(data.len() as u64);
    result.extend_from_slice(data);
    result
}

/// decode a u32
pub fn decode_u32(data: &[u8]) -> Option<(u32, usize)> {
    decode_u64(data).map(|(v, c)| (v as u32, c))
}

/// decode a list length
pub fn decode_list_len(data: &[u8]) -> Option<(usize, usize)> {
    decode_u64(data).map(|(v, c)| (v as usize, c))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_u64_roundtrip() {
        for v in [0u64, 1, 127, 128, 255, 256, 65535, 1 << 20, u64::MAX] {
            let encoded = encode_u64(v);
            let (decoded, _) = decode_u64(&encoded).unwrap();
            assert_eq!(v, decoded);
        }
    }
}
