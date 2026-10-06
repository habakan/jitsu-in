//! The module's entry points: the same seventeen names the C exports, in the same order of use.
//!
//! Keeping the names identical is what let the existing suite — 556 vectors, the UR reference
//! values, the comparison against Bitcoin Core — test this module unchanged. A port that needed its
//! own tests would be a port whose bugs became its tests.
//!
//! Everything is static: this module never allocates, and a host writes into the buffers it exposes
//! here rather than handing it pointers of its own.

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

// --- UR (animated QR) ---
//
// The reassembly buffer is the output buffer, which is free until finalize needs it. The part text
// is written over the input buffer, so a caller parses again before another finalize.

use crate::ur;

static mut DECODER: ur::Decoder = ur::Decoder::new();
static mut ENCODER: ur::Encoder = ur::Encoder::new();
static mut UR_READY: bool = false;

/// Drops decoder state before a new animated QR.
#[no_mangle]
pub extern "C" fn parser_ur_reset() {
    let d: &mut ur::Decoder = unsafe { &mut *(&raw mut DECODER) };
    d.reset((&raw mut PSBT_OUT) as *mut u8, PSBT_OUT_MAX);
    unsafe {
        UR_READY = true;
    }
}

/// Called after the host writes one QR payload to `parser_input()`. Returns the PSBT's length once
/// the UR is complete — with the PSBT now at the start of the input buffer, ready for
/// `parser_parse` — 0 while more parts are needed, or a negative error for a rejected part, which
/// leaves the parts received so far untouched.
#[no_mangle]
pub extern "C" fn parser_ur_receive(len: u32) -> i32 {
    // the part overwrites the parsed PSBT that finalize would splice into
    unsafe {
        IS_PARSED = false;
    }
    if !unsafe { UR_READY } {
        parser_ur_reset();
    }
    let len = len as usize;
    if len > PSBT_MAX {
        return ur::Err::Limit as i32;
    }
    let d: &mut ur::Decoder = unsafe { &mut *(&raw mut DECODER) };
    let part: &mut [u8] =
        unsafe { core::slice::from_raw_parts_mut((&raw mut PSBT_IN) as *mut u8, len) };
    let n = match d.receive(part) {
        Err(e) => return e as i32,
        Ok(0) => return 0,
        Ok(n) => n as usize,
    };
    // Complete: it has to be a PSBT, and it has to be a CBOR byte string
    let ty = &d.ur_type;
    let is_psbt = ty.starts_with(b"crypto-psbt\0") || ty.starts_with(b"psbt\0");
    if !is_psbt {
        return ur::Err::Type as i32;
    }
    let msg: &[u8] = unsafe { core::slice::from_raw_parts(d.message(), n) };
    let (at, psbt_len) = match ur::cbor_bytes(msg) {
        None => return ur::Err::Type as i32,
        Some(v) => v,
    };
    if psbt_len > PSBT_MAX {
        return ur::Err::Limit as i32;
    }
    // The message is in the output buffer and the PSBT has to end up in the input buffer; different
    // allocations, so a copy rather than a move
    unsafe {
        let src = core::slice::from_raw_parts(d.message().add(at), psbt_len);
        let dst = core::slice::from_raw_parts_mut((&raw mut PSBT_IN) as *mut u8, psbt_len);
        dst.copy_from_slice(src);
    }
    psbt_len as i32
}

/// Parts expected in the upper 16 bits, 0 until the first multipart part, and distinct fragments
/// recovered in the lower 16.
#[no_mangle]
pub extern "C" fn parser_ur_progress() -> u32 {
    let d: &ur::Decoder = unsafe { &*(&raw const DECODER) };
    let (expected, received) = d.progress();
    expected << 16 | received
}

/// Encodes the first `len` bytes of `parser_output()` as a crypto-psbt UR with fragments of at most
/// `max_fragment_len` bytes. Returns the number of pure parts, or a negative error.
#[no_mangle]
pub extern "C" fn parser_ur_encode_start(len: u32, max_fragment_len: u32) -> i32 {
    let len = len as usize;
    if len > PSBT_OUT_MAX {
        return ur::Err::Limit as i32;
    }
    unsafe {
        IS_PARSED = false;
    }
    let e: &mut ur::Encoder = unsafe { &mut *(&raw mut ENCODER) };
    match e.start(b"crypto-psbt", (&raw const PSBT_OUT) as *const u8, len, max_fragment_len as usize) {
        Ok(n) => n as i32,
        Err(err) => err as i32,
    }
}

/// Writes the next part over `parser_input()` and returns its length.
#[no_mangle]
pub extern "C" fn parser_ur_encode_next() -> i32 {
    let e: &mut ur::Encoder = unsafe { &mut *(&raw mut ENCODER) };
    let out: &mut [u8] =
        unsafe { core::slice::from_raw_parts_mut((&raw mut PSBT_IN) as *mut u8, PSBT_MAX) };
    match e.next(out) {
        Ok(n) => n as i32,
        Err(err) => err as i32,
    }
}
