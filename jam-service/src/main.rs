//! jam-netadapter polkavm service
//!
//! on-chain motor for:
//! - oracle data validation and aggregation
//! - decentralized dns (.alt namespaces)
//! - sla monitoring with distributed probes

#![no_std]
#![no_main]
#![feature(never_type)]
#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(unused_variables)]
#![allow(unused_assignments)]

extern crate alloc;

mod host;
mod codec;
mod types;
mod storage;
mod refine;
mod accumulate;
mod sla;
mod sla_storage;
mod sla_refine;
mod sla_accumulate;
mod privacy;
mod poseidon;
mod privacy_storage;
mod privacy_refine;
mod privacy_accumulate;

use types::*;

// ============================================================================
// polkavm entry points
// ============================================================================

#[polkavm_derive::polkavm_export]
extern "C" fn refine() {
    let args = RefineArgs::fetch();
    refine::handle_refine(&args);
}

#[polkavm_derive::polkavm_export]
extern "C" fn accumulate() {
    let args = AccumulateArgs::fetch();
    accumulate::handle_accumulate(&args);
}

// ============================================================================
// panic handler for no_std
// ============================================================================

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    host::trap()
}

// ============================================================================
// global allocator
// ============================================================================

#[global_allocator]
static ALLOCATOR: BumpAllocator = BumpAllocator::new();

/// simple bump allocator for polkavm
/// services are short-lived so we just bump and never free
struct BumpAllocator {
    // we'll use host memory
}

impl BumpAllocator {
    const fn new() -> Self {
        Self {}
    }
}

unsafe impl core::alloc::GlobalAlloc for BumpAllocator {
    unsafe fn alloc(&self, layout: core::alloc::Layout) -> *mut u8 {
        // align size up to alignment
        let size = (layout.size() + layout.align() - 1) & !(layout.align() - 1);
        let ptr = unsafe { host::alloc(size as u32) };
        ptr as *mut u8
    }

    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: core::alloc::Layout) {
        // bump allocator doesn't free
    }
}
