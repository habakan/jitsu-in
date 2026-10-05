//! The module's entry points. While the port is in progress these cover only what has been moved
//! across, so that each piece can be compared against the C before the next one starts.
//!
//! Everything is static: this module never allocates, and a host writes into the buffers it exposes
//! here rather than handing it pointers of its own.

use crate::{sha256, tx};

const IN_CAP: usize = 32768;

static mut IN_BUF: [u8; IN_CAP] = [0; IN_CAP];
static mut TX_OUT: TxOut = TxOut::ZERO;

/// What tx::parse found, in a layout a host can read without knowing Rust's.
#[repr(C)]
pub struct TxOut {
    pub version: i32,
    pub locktime: u32,
    pub n_inputs: u32,
    pub n_outputs: u32,
    pub segwit: u32,
    pub txid: [u8; 32],
    pub amounts: [u64; 16],
    pub spk_off: [u32; 16],
    pub spk_len: [u32; 16],
}

impl TxOut {
    const ZERO: TxOut = TxOut {
        version: 0, locktime: 0, n_inputs: 0, n_outputs: 0, segwit: 0,
        txid: [0; 32], amounts: [0; 16], spk_off: [0; 16], spk_len: [0; 16],
    };
}

#[no_mangle]
pub extern "C" fn rs_input() -> *mut u8 {
    (&raw mut IN_BUF) as *mut u8
}

#[no_mangle]
pub extern "C" fn rs_input_cap() -> u32 {
    IN_CAP as u32
}

#[no_mangle]
pub extern "C" fn rs_tx_out() -> *const TxOut {
    &raw const TX_OUT
}

/// Parses the transaction in the input buffer. 1 on success, 0 if it is malformed.
#[no_mangle]
pub extern "C" fn rs_tx_parse(len: u32) -> i32 {
    let len = len as usize;
    if len > IN_CAP {
        return 0;
    }
    // One &mut to each static, taken once. This module is single-threaded by construction: wasm
    // without the threads proposal has no way to call in concurrently
    let raw: &[u8] = unsafe { core::slice::from_raw_parts((&raw const IN_BUF) as *const u8, len) };
    let out: &mut TxOut = unsafe { &mut *(&raw mut TX_OUT) };
    *out = TxOut::ZERO;

    let mut info = tx::Info {
        version: 0, locktime: 0, n_inputs: 0, n_outputs: 0, segwit: false, txid: [0; 32],
    };
    let mut amounts = [0u64; 16];
    let mut spk_off = [0u32; 16];
    let mut spk_len = [0u32; 16];
    let base = raw.as_ptr() as usize;

    let ok = tx::parse(
        raw,
        |_i, _input| true,
        |i, o| {
            let i = i as usize;
            if i < 16 {
                amounts[i] = o.amount;
                spk_off[i] = (o.spk.as_ptr() as usize - base) as u32;
                spk_len[i] = o.spk.len() as u32;
            }
            true
        },
        &mut info,
    );
    if !ok {
        return 0;
    }

    out.version = info.version;
    out.locktime = info.locktime;
    out.n_inputs = info.n_inputs;
    out.n_outputs = info.n_outputs;
    out.segwit = info.segwit as u32;
    out.txid = info.txid;
    out.amounts = amounts;
    out.spk_off = spk_off;
    out.spk_len = spk_len;
    1
}

/// SHA-256 of the input buffer, written back over it. For checking the hash against the C's.
#[no_mangle]
pub extern "C" fn rs_sha256(len: u32) -> i32 {
    let len = len as usize;
    if len > IN_CAP {
        return 0;
    }
    let digest = {
        let raw: &[u8] = unsafe { core::slice::from_raw_parts((&raw const IN_BUF) as *const u8, len) };
        sha256::hash(raw)
    };
    unsafe {
        let buf: &mut [u8] = core::slice::from_raw_parts_mut((&raw mut IN_BUF) as *mut u8, 32);
        buf.copy_from_slice(&digest);
    }
    1
}
