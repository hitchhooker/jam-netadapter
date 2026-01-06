//! polkavm host function bindings
//!
//! these are the syscalls to interact with jam runtime
//! using raw u32/u64 for polkavm compatibility

use alloc::vec::Vec;

// fetch discriminators
pub const FETCH_WORK_PAYLOAD: u32 = 13;
pub const FETCH_INPUTS: u32 = 14;

// result codes
pub const ERR_LOW: u64 = u64::MAX - 5;
pub const ERR_NONE: u64 = u64::MAX - 7;

// ============================================================================
// host call imports (polkavm externals) - using u32 for pointers
// ============================================================================

#[polkavm_derive::polkavm_import]
extern "C" {
    /// read from service storage (key_ptr, key_len, out_ptr, out_len) - simplified
    pub fn read(key_ptr: u32, key_len: u32, out_ptr: u32, out_len: u32) -> u64;

    /// write to service storage
    pub fn write(key_ptr: u32, key_len: u32, value_ptr: u32, value_len: u32) -> u64;

    /// get remaining gas
    pub fn gas() -> u64;

    /// get service info
    pub fn info(index: u32, service_id: u32) -> u64;

    /// fetch data - (discriminator << 32 | index, out_ptr, out_len)
    pub fn fetch(disc_and_idx: u64, out_ptr: u32, out_len: u32) -> u64;

    /// allocate memory
    pub fn alloc(size: u32) -> u32;
}

// ============================================================================
// safe wrappers
// ============================================================================

/// read a key from storage, returns None if not found
pub fn storage_read(key: &[u8]) -> Option<Vec<u8>> {
    // first call to get length
    let len = unsafe {
        read(key.as_ptr() as u32, key.len() as u32, 0, 0)
    };

    if len == ERR_NONE || len == 0 {
        return None;
    }

    let mut buf = alloc::vec![0u8; len as usize];
    let actual = unsafe {
        read(key.as_ptr() as u32, key.len() as u32, buf.as_mut_ptr() as u32, len as u32)
    };

    if actual != len {
        return None;
    }

    Some(buf)
}

/// write a key to storage
pub fn storage_write(key: &[u8], value: &[u8]) -> Result<u64, u64> {
    let result = unsafe {
        write(key.as_ptr() as u32, key.len() as u32, value.as_ptr() as u32, value.len() as u32)
    };

    if result >= ERR_LOW {
        Err(result)
    } else {
        Ok(result)
    }
}

/// delete a key from storage (write empty)
pub fn storage_delete(key: &[u8]) -> Result<u64, u64> {
    storage_write(key, &[])
}

/// fetch work payload during refine
pub fn fetch_work_payload(item_index: u32) -> Vec<u8> {
    // pack discriminator and index
    let disc_idx = ((FETCH_WORK_PAYLOAD as u64) << 32) | (item_index as u64);

    // get length first
    let len = unsafe {
        fetch(disc_idx, 0, 0)
    };

    if len == 0 || len >= ERR_LOW {
        return Vec::new();
    }

    let mut buf = alloc::vec![0u8; len as usize];
    unsafe {
        fetch(disc_idx, buf.as_mut_ptr() as u32, len as u32);
    }

    buf
}

/// fetch accumulate inputs
pub fn fetch_inputs() -> Vec<u8> {
    let disc_idx = (FETCH_INPUTS as u64) << 32;

    let len = unsafe {
        fetch(disc_idx, 0, 0)
    };

    if len == 0 || len >= ERR_LOW {
        return Vec::new();
    }

    let mut buf = alloc::vec![0u8; len as usize];
    unsafe {
        fetch(disc_idx, buf.as_mut_ptr() as u32, len as u32);
    }

    buf
}

/// return result from refine phase - trap since we can't return
pub fn return_result(_data: &[u8]) -> ! {
    // in real polkavm this would yield back to host
    // for now we trap
    trap()
}

/// trap/abort execution
pub fn trap() -> ! {
    // polkavm trap instruction
    unsafe {
        core::arch::asm!("unimp", options(noreturn));
    }
}

/// get current gas remaining
#[allow(dead_code)]
pub fn gas_remaining() -> u64 {
    unsafe { gas() }
}

/// get current timeslot
pub fn current_timeslot() -> u32 {
    unsafe { info(1, 0) as u32 }
}
