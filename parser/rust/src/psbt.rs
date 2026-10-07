//! Turns a PSBT v0 ([BIP174]) into a `Plan`, and inserts the signer's signatures back into the
//! PSBT. Ported from ../src/psbt.c.
//!
//! It holds no keys and has no imports: built for wasm it cannot call a single host function. What
//! it is strict about and what it passes through is in ../docs/abi.md.
//!
//! [BIP174]: https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki

use crate::plan::{self, KeyPath, Plan, Script};
use crate::reader::Reader;
use crate::tx;

pub const PSBT_MAX: usize = 32768;
pub const PSBT_OUT_MAX: usize = PSBT_MAX + plan::MAX_INPUTS * 128;
const MAX_KV: usize = 64;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(i32)]
pub enum Err {
    Magic = 1,
    /// A BIP174 violation: a key or value length, a v2-only field, trailing bytes.
    Format = 2,
    /// The same key twice within one map.
    Duplicate = 3,
    /// No unsigned transaction, a scriptSig or witness where there must be none, a non-canonical
    /// serialization.
    Tx = 4,
    /// PSBT v2, a script longer than the plan holds, a sighash that does not fit in a byte.
    Unsupported = 5,
    /// More inputs or outputs than the plan holds, or a PSBT larger than PSBT_MAX.
    Limit = 6,
    /// An input with no utxo data, or a non_witness_utxo that does not match what it claims.
    Utxo = 7,
    /// Signatures handed to finalize that this module will not insert.
    Sig = 8,
}

pub type Res = Result<(), Err>;

struct Kv<'a> {
    key: &'a [u8],
    val: &'a [u8],
}

/// A derivation that might be ours. `pubkey` is the key of the BIP32_DERIVATION entry, kept so that
/// an existing signature for the same key can be spotted.
#[derive(Clone, Copy)]
struct Cand<'a> {
    found: bool,
    depth: u8,
    path: [u32; plan::MAX_DEPTH],
    pubkey: Option<&'a [u8]>,
}

impl<'a> Cand<'a> {
    const NONE: Cand<'a> = Cand { found: false, depth: 0, path: [0; plan::MAX_DEPTH], pubkey: None };
}

fn le32(b: &[u8]) -> u32 {
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

/// fingerprint(4) then path(4 x n). The first entry with our fingerprint and a depth that fits
/// becomes the candidate; later ones are only validated. False means the *format* is wrong, which
/// is a different thing from "not ours".
fn keypath(v: &[u8], fp: u32, c: &mut Cand) -> bool {
    if v.len() < 4 || (v.len() - 4) % 4 != 0 {
        return false;
    }
    let depth = (v.len() - 4) / 4;
    // The fingerprint's bytes are in display order, compared as a big-endian integer; the path
    // elements are little-endian. BIP32 is inconsistent about this and the asymmetry is real
    let seen = u32::from_be_bytes([v[0], v[1], v[2], v[3]]);
    if c.found || seen != fp || depth > plan::MAX_DEPTH {
        return true;
    }
    c.found = true;
    c.depth = depth as u8;
    for i in 0..depth {
        c.path[i] = le32(&v[4 + 4 * i..]);
    }
    true
}

/// A TAP_BIP32_DERIVATION value: a leaf hash count, those hashes, then a keypath. Only an entry with
/// no leaves is a key-path spend, so one with leaves is validated but never becomes the candidate.
fn tap_keypath(v: &[u8], fp: u32, c: &mut Cand) -> bool {
    let mut r = Reader::new(v);
    let leaves = r.varint();
    if r.err() || leaves > (v.len() - r.pos()) as u64 / 32 {
        return false;
    }
    r.skip(32 * leaves as usize);
    let rest = &v[r.pos()..];
    if leaves != 0 {
        let mut ignore = Cand::NONE;
        keypath(rest, fp, &mut ignore)
    } else {
        keypath(rest, fp, c)
    }
}

/// Reads one PSBT map up to its terminating zero, returning the entries and the offset of that zero
/// — which is where a signature gets inserted later.
fn read_map<'a>(
    r: &mut Reader<'a>,
    kv: &mut [Option<Kv<'a>>; MAX_KV],
) -> Result<(usize, usize), Err> {
    let mut n = 0;
    loop {
        let klen = r.varint() as usize;
        if r.err() {
            return Err(Err::Format);
        }
        if klen == 0 {
            return Ok((n, r.pos() - 1));
        }
        if n == MAX_KV {
            return Err(Err::Limit);
        }
        let key = r.take(klen).ok_or(Err::Format)?;
        let vlen = r.varint() as usize;
        let val = r.take(vlen).ok_or(Err::Format)?;
        if r.err() {
            return Err(Err::Format);
        }
        for e in kv[..n].iter() {
            if let Some(e) = e {
                if e.key == key {
                    return Err(Err::Duplicate);
                }
            }
        }
        kv[n] = Some(Kv { key, val });
        n += 1;
    }
}

/// Everything the parse writes into. Kept apart from the exports so that the logic can be tested
/// without the static buffers.
pub struct Parsed {
    pub plan: Plan,
    pub prevtx_off: [u32; plan::MAX_INPUTS],
    pub prevtx_len: [u32; plan::MAX_INPUTS],
    pub in_map_end: [usize; plan::MAX_INPUTS],
}

impl Parsed {
    pub const ZERO: Parsed = Parsed {
        plan: Plan::ZERO,
        prevtx_off: [0; plan::MAX_INPUTS],
        prevtx_len: [0; plan::MAX_INPUTS],
        in_map_end: [0; plan::MAX_INPUTS],
    };
}

fn parse_global(r: &mut Reader, out: &mut Parsed) -> Res {
    let mut kv: [Option<Kv>; MAX_KV] = [const { None }; MAX_KV];
    let (n, _end) = read_map(r, &mut kv)?;
    let entries = |i: usize| kv[i].as_ref().unwrap();

    // The version is checked before the v2-only keys, so that a v2 PSBT is reported as unsupported
    // rather than malformed
    for i in 0..n {
        let e = entries(i);
        if e.key[0] != 0xfb {
            continue;
        }
        if e.key.len() != 1 || e.val.len() != 4 {
            return Err(Err::Format);
        }
        if le32(e.val) != 0 {
            return Err(Err::Unsupported);
        }
    }

    let mut have_tx = false;
    for i in 0..n {
        let e = entries(i);
        match e.key[0] {
            0x00 => {
                if e.key.len() != 1 {
                    return Err(Err::Format);
                }
                // Both callbacks need the plan and the same flags, and Rust will not hand out two
                // &mut to either; one struct borrowed once is the way to say that
                struct Utx<'p> {
                    plan: &'p mut Plan,
                    too_many: bool,
                    bad_script_sig: bool,
                    bad_spk: bool,
                }
                let mut u = Utx {
                    plan: &mut out.plan,
                    too_many: false,
                    bad_script_sig: false,
                    bad_spk: false,
                };
                let mut info = tx::Info {
                    version: 0, locktime: 0, n_inputs: 0, n_outputs: 0, segwit: false, txid: [0; 32],
                };
                let ok = tx::parse(
                    e.val,
                    |item| match item {
                        tx::Item::Input(i, input) => {
                            if i as usize >= plan::MAX_INPUTS {
                                u.too_many = true;
                                return false;
                            }
                            if input.script_sig_len != 0 {
                                u.bad_script_sig = true;
                            }
                            let slot = &mut u.plan.inputs[i as usize];
                            slot.prev_txid.copy_from_slice(&input.prevout[..32]);
                            slot.prev_vout = le32(&input.prevout[32..]);
                            slot.sequence = input.sequence;
                            true
                        }
                        tx::Item::Output(i, o) => {
                            if i as usize >= plan::MAX_OUTPUTS {
                                u.too_many = true;
                                return false;
                            }
                            let slot = &mut u.plan.outputs[i as usize];
                            slot.amount = o.amount;
                            if !slot.spk.set(o.spk) {
                                u.bad_spk = true;
                                return false;
                            }
                            true
                        }
                    },
                    &mut info,
                );
                if !ok {
                    return Err(if u.too_many {
                        Err::Limit
                    } else if u.bad_spk {
                        Err::Unsupported
                    } else {
                        Err::Tx
                    });
                }
                // The unsigned transaction must be exactly that: no scriptSig, no witness, and it
                // has to pay to something
                if u.bad_script_sig || info.segwit || info.n_outputs == 0 {
                    return Err(Err::Tx);
                }
                out.plan.tx_version = info.version;
                out.plan.locktime = info.locktime;
                out.plan.n_inputs = info.n_inputs as u8;
                out.plan.n_outputs = info.n_outputs as u8;
                have_tx = true;
            }
            0x01 => {
                let mut ignore = Cand::NONE;
                if e.key.len() != 79 || !keypath(e.val, 0, &mut ignore) {
                    return Err(Err::Format);
                }
            }
            0x02..=0x06 => return Err(Err::Format), // PSBT v2 only
            _ => {}
        }
    }
    if have_tx {
        Ok(())
    } else {
        Err(Err::Tx)
    }
}

fn parse_input(r: &mut Reader, idx: usize, fp: u32, in_buf_base: usize, out: &mut Parsed) -> Res {
    let mut kv: [Option<Kv>; MAX_KV] = [const { None }; MAX_KV];
    let (n, end) = read_map(r, &mut kv)?;
    out.in_map_end[idx] = end;
    let entries = |i: usize| kv[i].as_ref().unwrap();

    let mut wu: Option<&[u8]> = None;
    let mut nwu: Option<&[u8]> = None;
    let mut bip32 = Cand::NONE;
    let mut tap = Cand::NONE;
    let mut finalized = false;
    let mut has_tapsig = false;
    let mut has_merkle = false;
    let mut sighash: u32 = 0xffff_ffff;

    for i in 0..n {
        let e = entries(i);
        let klen = e.key.len();
        match e.key[0] {
            0x00 => {
                if klen != 1 {
                    return Err(Err::Format);
                }
                nwu = Some(e.val);
            }
            0x01 => {
                if klen != 1 {
                    return Err(Err::Format);
                }
                wu = Some(e.val);
            }
            0x02 => {
                if klen != 34 && klen != 66 {
                    return Err(Err::Format);
                }
            }
            0x03 => {
                if klen != 1 || e.val.len() != 4 {
                    return Err(Err::Format);
                }
                sighash = le32(e.val);
            }
            0x04 | 0x05 => {
                if klen != 1 {
                    return Err(Err::Format);
                }
            }
            0x06 => {
                // An uncompressed key cannot be used for P2WPKH, so one is validated and discarded
                let mut ignore = Cand::NONE;
                let target = if klen == 34 { &mut bip32 } else { &mut ignore };
                if (klen != 34 && klen != 66) || !keypath(e.val, fp, target) {
                    return Err(Err::Format);
                }
                if bip32.found && bip32.pubkey.is_none() {
                    bip32.pubkey = Some(&e.key[1..]);
                }
            }
            0x07 | 0x08 => {
                if klen != 1 {
                    return Err(Err::Format);
                }
                finalized = true;
            }
            0x0e..=0x12 => return Err(Err::Format), // PSBT v2 only
            0x13 => {
                if klen != 1 || (e.val.len() != 64 && e.val.len() != 65) {
                    return Err(Err::Format);
                }
                has_tapsig = true;
            }
            0x14 => {
                if klen != 65 || (e.val.len() != 64 && e.val.len() != 65) {
                    return Err(Err::Format);
                }
            }
            // A control block is 33 + 32m bytes
            0x15 => {
                if klen < 34 || (klen - 34) % 32 != 0 {
                    return Err(Err::Format);
                }
            }
            0x16 => {
                if klen != 33 || !tap_keypath(e.val, fp, &mut tap) {
                    return Err(Err::Format);
                }
            }
            0x17 => {
                if klen != 1 || e.val.len() != 32 {
                    return Err(Err::Format);
                }
            }
            0x18 => {
                if klen != 1 || e.val.len() != 32 {
                    return Err(Err::Format);
                }
                has_merkle = true;
            }
            _ => {}
        }
    }

    // An input that already carries this key's signature is not one to sign again
    let mut signed_by_cand = false;
    if let Some(pub_) = bip32.pubkey {
        for i in 0..n {
            let e = entries(i);
            if e.key[0] == 0x02 && e.key.len() == 34 && &e.key[1..] == pub_ {
                signed_by_cand = true;
            }
        }
    }

    let in_ = &mut out.plan.inputs[idx];

    if let Some(raw) = nwu {
        // BIP143 commits only to the amount of the input being signed, so the amount has to be
        // checked against the transaction it claims to come from
        let want_vout = in_.prev_vout;
        let mut found = false;
        let mut amount = 0u64;
        let mut spk_ok = true;
        let mut spk = Script::ZERO;
        let mut info = tx::Info {
            version: 0, locktime: 0, n_inputs: 0, n_outputs: 0, segwit: false, txid: [0; 32],
        };
        let ok = tx::parse(
            raw,
            |item| match item {
                tx::Item::Input(..) => true,
                tx::Item::Output(i, o) => {
                    if i != want_vout {
                        return true;
                    }
                    found = true;
                    amount = o.amount;
                    spk_ok = spk.set(o.spk);
                    spk_ok
                }
            },
            &mut info,
        );
        if !ok {
            return Err(Err::Utxo);
        }
        if !found || info.txid != in_.prev_txid {
            return Err(Err::Utxo);
        }
        in_.amount = amount;
        in_.spk = spk;
        // Relative to the input buffer, not an absolute pointer: linking these sources natively
        // once truncated a 64-bit pointer and handed the host a bogus offset
        out.prevtx_off[idx] = (raw.as_ptr() as usize - in_buf_base) as u32;
        out.prevtx_len[idx] = raw.len() as u32;
    }

    if let Some(raw) = wu {
        let mut w = Reader::new(raw);
        let amount = w.le(8);
        let len = w.varint() as usize;
        let spk = w.take(len).unwrap_or(&[]);
        let prev_amount = in_.amount;
        let prev_spk = in_.spk;
        if w.err() || w.pos() != raw.len() {
            return Err(Err::Format);
        }
        if len > plan::MAX_SPK {
            return Err(Err::Unsupported);
        }
        in_.amount = amount;
        in_.spk = Script::ZERO;
        in_.spk.set(spk);
        // Both forms present: they have to agree, or one of them is lying
        if nwu.is_some() && (prev_amount != in_.amount || prev_spk != in_.spk) {
            return Err(Err::Utxo);
        }
    }

    if wu.is_none() && nwu.is_none() {
        return Err(Err::Utxo);
    }
    if sighash != 0xffff_ffff && sighash > 0xff {
        return Err(Err::Unsupported);
    }

    // Only a P2WPKH with our derivation and no signature yet, or a P2TR key-path spend with no
    // script tree and no signature yet, is one this signer will sign
    let chosen = if in_.spk.is_wpkh() && bip32.found && !signed_by_cand {
        in_.sighash_type = if sighash == 0xffff_ffff { 0x01 } else { sighash as u8 };
        Some(bip32)
    } else if in_.spk.is_p2tr() && tap.found && !has_merkle && !has_tapsig {
        in_.sighash_type = if sighash == 0xffff_ffff { 0x00 } else { sighash as u8 };
        Some(tap)
    } else {
        None
    };

    match chosen {
        Some(c) if !finalized => {
            in_.key = KeyPath { depth: c.depth, fingerprint: fp, path: c.path };
        }
        _ => in_.sighash_type = 0,
    }
    Ok(())
}

fn parse_output(r: &mut Reader, idx: usize, fp: u32, out: &mut Parsed) -> Res {
    let mut kv: [Option<Kv>; MAX_KV] = [const { None }; MAX_KV];
    let (n, _end) = read_map(r, &mut kv)?;
    let entries = |i: usize| kv[i].as_ref().unwrap();

    let mut bip32 = Cand::NONE;
    let mut tap = Cand::NONE;
    let mut has_tree = false;

    for i in 0..n {
        let e = entries(i);
        let klen = e.key.len();
        match e.key[0] {
            0x00 | 0x01 => {
                if klen != 1 {
                    return Err(Err::Format);
                }
            }
            0x02 => {
                let mut ignore = Cand::NONE;
                let target = if klen == 34 { &mut bip32 } else { &mut ignore };
                if (klen != 34 && klen != 66) || !keypath(e.val, fp, target) {
                    return Err(Err::Format);
                }
            }
            0x03 | 0x04 => return Err(Err::Format), // PSBT v2 only
            0x05 => {
                if klen != 1 || e.val.len() != 32 {
                    return Err(Err::Format);
                }
            }
            0x06 => {
                if klen != 1 || e.val.is_empty() {
                    return Err(Err::Format);
                }
                has_tree = true;
            }
            0x07 => {
                if klen != 33 || !tap_keypath(e.val, fp, &mut tap) {
                    return Err(Err::Format);
                }
            }
            _ => {}
        }
    }

    let o = &mut out.plan.outputs[idx];
    let chosen = if o.spk.is_wpkh() && bip32.found {
        Some(bip32)
    } else if o.spk.is_p2tr() && tap.found && !has_tree {
        Some(tap)
    } else {
        None
    };
    if let Some(c) = chosen {
        o.key = KeyPath { depth: c.depth, fingerprint: fp, path: c.path };
    }
    Ok(())
}

/// Parses `raw` into `out`. `fp` is the signer's master fingerprint, which is not a secret: only
/// derivations carrying it become key candidates, so the signer never learns a cosigner's paths.
///
/// `in_buf_base` is the address `raw` starts at, used to report the non_witness_utxo offsets
/// relative to the host's buffer rather than as pointers.
pub fn parse(raw: &[u8], fp: u32, in_buf_base: usize, out: &mut Parsed) -> Res {
    const MAGIC: &[u8; 5] = b"psbt\xff";

    *out = Parsed::ZERO;
    if raw.len() > PSBT_MAX {
        return Err(Err::Limit);
    }
    let mut r = Reader::new(raw);
    if raw.len() < 5 || r.take(5) != Some(&MAGIC[..]) {
        return Err(Err::Magic);
    }
    parse_global(&mut r, out)?;
    for i in 0..out.plan.n_inputs as usize {
        parse_input(&mut r, i, fp, in_buf_base, out)?;
    }
    for i in 0..out.plan.n_outputs as usize {
        parse_output(&mut r, i, fp, out)?;
    }
    // Trailing bytes mean this is not the PSBT it claims to be
    if r.pos() != raw.len() {
        return Err(Err::Format);
    }
    out.plan.magic = plan::MAGIC;
    out.plan.version = plan::VERSION;
    Ok(())
}
