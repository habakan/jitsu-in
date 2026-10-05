//! parser.wasm, in Rust.
//!
//! Zero imports, no allocator, no unwinding: the module cannot call the host, and the host reads and
//! writes buffers it exports after checking the offsets itself. The convention both modules follow is
//! in ../../docs/module-abi.md, and this module's own ABI is in ../docs/abi.md.
//!
//! This is being ported from the C in ../src, one piece at a time. While that is in progress both
//! are built and `make check-rust-agrees` requires them to produce identical output on every vector
//! and on fuzzed input; the C is the reference until the port is complete.
#![no_std]

use core::panic::PanicInfo;

/// There is nothing to unwind to and nothing to print to. A trap here is what the C's error return
/// would have been, and it cannot be mistaken for success.
#[panic_handler]
fn panic(_: &PanicInfo) -> ! {
    core::arch::wasm32::unreachable()
}

pub mod reader;
pub mod sha256;
pub mod tx;

mod exports;
