//! The minimal transaction parser, ported from ../src/tx.c.
//!
//! It exists to answer one question the PSBT cannot be trusted on: does the previous transaction an
//! input names really pay that amount to that script? BIP143 commits only to the amount of the input
//! being signed, so with two or more inputs the amounts have to be checked against the transactions
//! they claim to come from, or a malicious PSBT can turn the difference into fees.
//!
//! The txid is computed over the transaction *without* its witness, which is why this cannot simply
//! hash the bytes it was handed.

use crate::reader::Reader;
use crate::sha256;

pub struct Input<'a> {
    pub prevout: &'a [u8],
    pub script_sig_len: usize,
    pub sequence: u32,
}

pub struct Output<'a> {
    pub amount: u64,
    pub spk: &'a [u8],
}

pub struct Info {
    pub version: i32,
    pub locktime: u32,
    pub n_inputs: u32,
    pub n_outputs: u32,
    pub segwit: bool,
    pub txid: [u8; 32],
}

/// Walks a serialized transaction, handing each input and output to the callbacks, and fills `info`.
/// Returns false if the bytes are malformed, if a callback refuses, or if anything is left over —
/// trailing bytes mean this is not the transaction it claims to be.
pub fn parse<'a, FI, FO>(
    raw: &'a [u8],
    mut on_input: FI,
    mut on_output: FO,
    info: &mut Info,
) -> bool
where
    FI: FnMut(u32, &Input<'a>) -> bool,
    FO: FnMut(u32, &Output<'a>) -> bool,
{
    let mut r = Reader::new(raw);

    info.version = r.le(4) as i32;
    // The SegWit marker and flag: a zero input count cannot occur in a legacy transaction
    info.segwit = raw.len() >= 6 && raw[4] == 0 && raw[5] == 1;
    if info.segwit {
        r.skip(2);
    }

    let io_start = r.pos();
    let n = r.varint();
    if n == 0 || n > u32::MAX as u64 {
        return false;
    }
    info.n_inputs = n as u32;
    for i in 0..info.n_inputs {
        if r.err() {
            break;
        }
        let prevout = r.take(36).unwrap_or(&[]);
        let script_sig_len = r.varint() as usize;
        r.skip(script_sig_len);
        let sequence = r.le(4) as u32;
        if !r.err() && !on_input(i, &Input { prevout, script_sig_len, sequence }) {
            return false;
        }
    }

    let n = r.varint();
    if n > u32::MAX as u64 {
        return false;
    }
    info.n_outputs = n as u32;
    for i in 0..info.n_outputs {
        if r.err() {
            break;
        }
        let amount = r.le(8);
        let spk_len = r.varint() as usize;
        let spk = r.take(spk_len).unwrap_or(&[]);
        if !r.err() && !on_output(i, &Output { amount, spk }) {
            return false;
        }
    }
    let io_end = r.pos();

    // The witness, skipped rather than read: it is not part of the txid
    if info.segwit {
        for _ in 0..info.n_inputs {
            if r.err() {
                break;
            }
            let mut k = r.varint();
            while k > 0 && !r.err() {
                let l = r.varint() as usize;
                r.skip(l);
                k -= 1;
            }
        }
    }

    info.locktime = r.le(4) as u32;
    if r.err() || r.pos() != raw.len() {
        return false;
    }

    // version, then the inputs and outputs as serialized, then locktime: the legacy form, which is
    // what a txid is over
    let mut h = sha256::Ctx::new();
    h.update(&raw[..4]);
    h.update(&raw[io_start..io_end]);
    h.update(&raw[raw.len() - 4..]);
    info.txid = h.finish_double();
    true
}
