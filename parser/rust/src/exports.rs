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
        |item| match item {
            tx::Item::Input(..) => true,
            tx::Item::Output(i, o) => {
                let i = i as usize;
                if i < 16 {
                    amounts[i] = o.amount;
                    spk_off[i] = (o.spk.as_ptr() as usize - base) as u32;
                    spk_len[i] = o.spk.len() as u32;
                }
                true
            }
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


// --- the real ABI ---
//
// The same names the C exports, so that the existing test suite — 529 vectors, the signature
// insertion cases, the comparison against Bitcoin Core — runs against this module unchanged. A port
// that needed its own tests would be a port whose bugs became its tests.

use crate::plan::{self, Plan, Sig};
use crate::psbt::{self, Parsed, PSBT_MAX, PSBT_OUT_MAX};

static mut PSBT_IN: [u8; PSBT_MAX] = [0; PSBT_MAX];
static mut PSBT_OUT: [u8; PSBT_OUT_MAX] = [0; PSBT_OUT_MAX];
static mut PARSED: Parsed = Parsed::ZERO;
static mut SIGS: [Sig; plan::MAX_INPUTS] = [Sig::ZERO; plan::MAX_INPUTS];
static mut IN_LEN: usize = 0;
static mut IS_PARSED: bool = false;

#[no_mangle]
pub extern "C" fn parser_input() -> *mut u8 {
    (&raw mut PSBT_IN) as *mut u8
}

#[no_mangle]
pub extern "C" fn parser_input_cap() -> u32 {
    PSBT_MAX as u32
}

#[no_mangle]
pub extern "C" fn parser_plan() -> *const Plan {
    unsafe { &raw const (*(&raw const PARSED)).plan }
}

#[no_mangle]
pub extern "C" fn parser_sigs() -> *mut Sig {
    (&raw mut SIGS) as *mut Sig
}

#[no_mangle]
pub extern "C" fn parser_output() -> *mut u8 {
    (&raw mut PSBT_OUT) as *mut u8
}

#[no_mangle]
pub extern "C" fn parser_prevtx_off(i: u32) -> u32 {
    if (i as usize) < plan::MAX_INPUTS {
        unsafe { (*(&raw const PARSED)).prevtx_off[i as usize] }
    } else {
        0
    }
}

#[no_mangle]
pub extern "C" fn parser_prevtx_len(i: u32) -> u32 {
    if (i as usize) < plan::MAX_INPUTS {
        unsafe { (*(&raw const PARSED)).prevtx_len[i as usize] }
    } else {
        0
    }
}

/// Called after the host writes `len` bytes to `parser_input()`. `fp` is the signer's master
/// fingerprint, which is not a secret.
#[no_mangle]
pub extern "C" fn parser_parse(len: u32, fp: u32) -> i32 {
    let len = len as usize;
    unsafe {
        IS_PARSED = false;
        IN_LEN = 0;
    }
    if len > PSBT_MAX {
        return psbt::Err::Limit as i32;
    }
    let base = (&raw const PSBT_IN) as usize;
    let raw: &[u8] = unsafe { core::slice::from_raw_parts(base as *const u8, len) };
    let out: &mut Parsed = unsafe { &mut *(&raw mut PARSED) };
    match psbt::parse(raw, fp, base, out) {
        Ok(()) => {
            unsafe {
                IN_LEN = len;
                IS_PARSED = true;
            }
            0
        }
        Err(e) => e as i32,
    }
}

/// Called after the host writes `n` signatures to `parser_sigs()`. Returns the signed PSBT's length,
/// or a negative error.
#[no_mangle]
pub extern "C" fn parser_finalize(n: u32) -> i32 {
    let n = n as usize;
    let parsed: &Parsed = unsafe { &*(&raw const PARSED) };
    let sigs: &[Sig] = unsafe { &*(&raw const SIGS) };
    let in_len = unsafe { IN_LEN };
    if !unsafe { IS_PARSED } || n > plan::MAX_INPUTS {
        return -(psbt::Err::Sig as i32);
    }

    // Which signature belongs to which input, rejecting a duplicate or one for an input this module
    // never offered to sign
    let mut by_input = [usize::MAX; plan::MAX_INPUTS];
    for k in 0..n {
        let s = &sigs[k];
        let idx = s.input as usize;
        if idx >= parsed.plan.n_inputs as usize || by_input[idx] != usize::MAX {
            return -(psbt::Err::Sig as i32);
        }
        let in_ = &parsed.plan.inputs[idx];
        if in_.key.depth == 0 {
            return -(psbt::Err::Sig as i32);
        }
        let bad = if in_.spk.is_p2wpkh() {
            (s.pubkey[0] != 2 && s.pubkey[0] != 3) || s.sig_len < 9 || s.sig_len > 73
        } else {
            s.pubkey[0] != 0 || (s.sig_len != 64 && s.sig_len != 65)
        };
        if bad {
            return -(psbt::Err::Sig as i32);
        }
        by_input[idx] = k;
    }

    let src: &[u8] = unsafe { core::slice::from_raw_parts((&raw const PSBT_IN) as *const u8, in_len) };
    let dst: &mut [u8] =
        unsafe { core::slice::from_raw_parts_mut((&raw mut PSBT_OUT) as *mut u8, PSBT_OUT_MAX) };

    let mut o = 0usize;
    let mut prev = 0usize;
    for i in 0..parsed.plan.n_inputs as usize {
        let k = by_input[i];
        if k == usize::MAX {
            continue;
        }
        let s = &sigs[k];
        let end = parsed.in_map_end[i];
        dst[o..o + end - prev].copy_from_slice(&src[prev..end]);
        o += end - prev;
        prev = end;
        // Every length here is below 0xfd, so each compact size is a single byte
        if parsed.plan.inputs[i].spk.is_p2wpkh() {
            dst[o] = 34;
            dst[o + 1] = 0x02; // PSBT_IN_PARTIAL_SIG
            o += 2;
            dst[o..o + 33].copy_from_slice(&s.pubkey);
            o += 33;
        } else {
            dst[o] = 1;
            dst[o + 1] = 0x13; // PSBT_IN_TAP_KEY_SIG
            o += 2;
        }
        dst[o] = s.sig_len;
        o += 1;
        let l = s.sig_len as usize;
        dst[o..o + l].copy_from_slice(&s.sig[..l]);
        o += l;
    }
    dst[o..o + in_len - prev].copy_from_slice(&src[prev..in_len]);
    o += in_len - prev;
    o as i32
}
