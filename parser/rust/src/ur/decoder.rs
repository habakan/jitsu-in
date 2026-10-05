//! Reassembling a fountain-coded UR, ported from the decoder half of ../src/ur.c.
//!
//! Parts arrive in any order, in either case, with duplicates, and possibly mixed with parts of
//! another message. A mixed part combines several fragments by XOR; once enough is known it reduces
//! to a single fragment, which may in turn reduce others. All of that happens in fixed buffers:
//! `MAX_MIXED` parts at most, sharing `MIXED_POOL` bytes, with the oldest dropped when full.

use super::{bit, clear_bit, codec, set_bit, xor_into, Bits, Err};
use super::{BITS_BYTES, MAX_MIXED, MAX_SEQ_LEN, MIXED_POOL};
use crate::reader::Reader;

#[derive(Clone, Copy)]
struct Mixed {
    bits: Bits,
    /// 0 marks a free slot.
    count: u16,
}

impl Mixed {
    const ZERO: Mixed = Mixed { bits: [0; BITS_BYTES], count: 0 };
}

pub struct Decoder {
    work: *mut u8,
    work_cap: usize,
    pub ur_type: [u8; 32],
    multipart: bool,
    seq_len: usize,
    message_len: usize,
    checksum: u32,
    frag_len: usize,
    slots: usize,
    have: Bits,
    received: u32,
    evict: usize,
    done: i64,
    mixed: [Mixed; MAX_MIXED],
    pool: [u8; MIXED_POOL],
    stack: [u16; MAX_SEQ_LEN],
    sp: usize,
}

impl Decoder {
    pub const fn new() -> Self {
        Decoder {
            work: core::ptr::null_mut(),
            work_cap: 0,
            ur_type: [0; 32],
            multipart: false,
            seq_len: 0,
            message_len: 0,
            checksum: 0,
            frag_len: 0,
            slots: 0,
            have: [0; BITS_BYTES],
            received: 0,
            evict: 0,
            done: 0,
            mixed: [Mixed::ZERO; MAX_MIXED],
            pool: [0; MIXED_POOL],
            stack: [0; MAX_SEQ_LEN],
            sp: 0,
        }
    }

    /// Drops all state and points the decoder at the buffer the message is reassembled in.
    pub fn reset(&mut self, work: *mut u8, work_cap: usize) {
        *self = Decoder::new();
        self.work = work;
        self.work_cap = work_cap;
    }

    pub fn progress(&self) -> (u32, u32) {
        (if self.multipart { self.seq_len as u32 } else { 0 }, self.received)
    }

    pub fn message(&self) -> *const u8 {
        self.work
    }

    fn frag(&self, i: usize) -> &mut [u8] {
        // The work buffer belongs to the caller and outlives every call here
        unsafe { core::slice::from_raw_parts_mut(self.work.add(i * self.frag_len), self.frag_len) }
    }

    fn only_index(&self, bits: &Bits) -> usize {
        (0..self.seq_len).find(|&i| bit(bits, i)).unwrap_or(0)
    }

    /// Records fragment i and queues it, so that the kept mixed parts can drop it.
    fn add_simple(&mut self, i: usize, data: &[u8]) {
        if bit(&self.have, i) {
            return;
        }
        self.frag(i).copy_from_slice(&data[..self.frag_len]);
        set_bit(&mut self.have, i);
        self.received += 1;
        self.stack[self.sp] = i as u16;
        self.sp += 1;
    }

    /// Removes every known fragment from the kept mixed parts. One that reduces to a single
    /// fragment becomes simple, which may cascade.
    fn drain(&mut self) {
        while self.sp > 0 {
            self.sp -= 1;
            let i = self.stack[self.sp] as usize;
            for s in 0..self.slots {
                if self.mixed[s].count == 0 || !bit(&self.mixed[s].bits, i) {
                    continue;
                }
                let frag_len = self.frag_len;
                let at = s * frag_len;
                // The fragment and the slot are different memory; copying the fragment out first
                // keeps the borrow checker satisfied without copying the slot
                let mut tmp = [0u8; super::MAX_FRAGMENT];
                tmp[..frag_len].copy_from_slice(&self.frag(i)[..frag_len]);
                xor_into(&mut self.pool[at..at + frag_len], &tmp[..frag_len]);
                clear_bit(&mut self.mixed[s].bits, i);
                self.mixed[s].count -= 1;
                if self.mixed[s].count == 1 {
                    self.mixed[s].count = 0;
                    let idx = self.only_index(&self.mixed[s].bits);
                    let mut data = [0u8; super::MAX_FRAGMENT];
                    data[..frag_len].copy_from_slice(&self.pool[at..at + frag_len]);
                    self.add_simple(idx, &data[..frag_len]);
                }
            }
        }
    }

    fn add_mixed(&mut self, bits: &mut Bits, mut count: usize, data: &mut [u8]) {
        let frag_len = self.frag_len;
        // Anything already known comes straight out
        for i in 0..self.seq_len {
            if count <= 1 {
                break;
            }
            if !bit(bits, i) || !bit(&self.have, i) {
                continue;
            }
            let mut tmp = [0u8; super::MAX_FRAGMENT];
            tmp[..frag_len].copy_from_slice(&self.frag(i)[..frag_len]);
            xor_into(&mut data[..frag_len], &tmp[..frag_len]);
            clear_bit(bits, i);
            count -= 1;
        }
        // A kept part that is a strict subset of this one comes out too
        for s in 0..self.slots {
            if count <= 1 {
                break;
            }
            if self.mixed[s].count == 0 {
                continue;
            }
            if self.mixed[s].bits == *bits {
                return; // already kept
            }
            if is_strict_subset(&self.mixed[s].bits, bits) {
                let at = s * frag_len;
                let mut tmp = [0u8; super::MAX_FRAGMENT];
                tmp[..frag_len].copy_from_slice(&self.pool[at..at + frag_len]);
                xor_into(&mut data[..frag_len], &tmp[..frag_len]);
                for k in 0..BITS_BYTES {
                    bits[k] &= !self.mixed[s].bits[k];
                }
                count -= self.mixed[s].count as usize;
            }
        }
        if count == 1 {
            let idx = self.only_index(bits);
            self.add_simple(idx, data);
            return;
        }
        if count == 0 || self.slots == 0 {
            return;
        }

        // Keep it, overwriting the oldest when full
        let mut s = self.slots;
        for k in 0..self.slots {
            if self.mixed[k].count == 0 {
                s = k;
                break;
            }
        }
        if s == self.slots {
            s = self.evict % self.slots;
            self.evict += 1;
        }
        self.mixed[s].bits = *bits;
        let at = s * frag_len;
        self.pool[at..at + frag_len].copy_from_slice(&data[..frag_len]);
        self.mixed[s].count = count as u16;

        // An earlier part that contains this one can drop its fragments
        for k in 0..self.slots {
            if k == s || self.mixed[k].count == 0 || !is_strict_subset(bits, &self.mixed[k].bits) {
                continue;
            }
            let kat = k * frag_len;
            let mut tmp = [0u8; super::MAX_FRAGMENT];
            tmp[..frag_len].copy_from_slice(&data[..frag_len]);
            xor_into(&mut self.pool[kat..kat + frag_len], &tmp[..frag_len]);
            for b in 0..BITS_BYTES {
                self.mixed[k].bits[b] &= !bits[b];
            }
            self.mixed[k].count -= count as u16;
            if self.mixed[k].count == 1 {
                self.mixed[k].count = 0;
                let idx = self.only_index(&self.mixed[k].bits);
                let mut d2 = [0u8; super::MAX_FRAGMENT];
                d2[..frag_len].copy_from_slice(&self.pool[kat..kat + frag_len]);
                self.add_simple(idx, &d2[..frag_len]);
            }
        }
    }

    /// Feeds one part, which is lowercased in place. Returns the message length once complete, 0
    /// while more parts are needed, or an error for a rejected part — which leaves the parts
    /// received so far untouched.
    pub fn receive(&mut self, s: &mut [u8]) -> Result<i64, Err> {
        if self.done != 0 {
            return Ok(self.done);
        }
        for c in s.iter_mut() {
            if c.is_ascii_uppercase() {
                *c = c.to_ascii_lowercase();
            }
        }
        let n = s.len();
        if n < 4 || &s[..3] != b"ur:" {
            return Err(Err::Scheme);
        }
        let mut type_len = 0;
        while 3 + type_len < n && s[3 + type_len] != b'/' {
            let c = s[3 + type_len];
            if !(c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-') {
                return Err(Err::Scheme);
            }
            type_len += 1;
        }
        if type_len == 0 || type_len >= 32 || 3 + type_len == n {
            return Err(Err::Scheme);
        }
        // Copied before the bytewords are decoded over the same memory
        let mut ur_type = [0u8; 32];
        ur_type[..type_len].copy_from_slice(&s[3..3 + type_len]);
        if self.ur_type[0] != 0 && self.ur_type != ur_type {
            return Err(Err::Mismatch);
        }
        let rest = 3 + type_len + 1;

        let seq_end = (rest..n).find(|&i| s[i] == b'/').unwrap_or(n);

        // single-part: ur:<type>/<bytewords>
        if seq_end == n {
            let mut body = [0u8; super::MAX_FRAGMENT * 2];
            let letters = n - rest;
            if letters / 2 > body.len() {
                return Err(Err::Limit);
            }
            let len = {
                let (head, tail) = s.split_at_mut(rest);
                let _ = head;
                codec::bytewords_decode(tail, &mut body).ok_or(Err::Bytewords)?
            };
            if len > self.work_cap {
                return Err(Err::Limit);
            }
            self.ur_type = ur_type;
            unsafe {
                core::slice::from_raw_parts_mut(self.work, len).copy_from_slice(&body[..len]);
            }
            self.done = len as i64;
            return Ok(self.done);
        }

        // multipart: ur:<type>/<seq>-<len>/<bytewords of [seq_num, seq_len, message_len, checksum, fragment]>
        let dash = (rest..seq_end).find(|&i| s[i] == b'-').ok_or(Err::Part)?;
        let c_seq_num = parse_uint(&s[rest..dash]).ok_or(Err::Part)?;
        let c_seq_len = parse_uint(&s[dash + 1..seq_end]).ok_or(Err::Part)?;
        if c_seq_num == 0 || c_seq_len == 0 {
            return Err(Err::Part);
        }
        if s[seq_end + 1..].contains(&b'/') {
            return Err(Err::Part);
        }

        let mut body = [0u8; super::MAX_FRAGMENT * 2];
        let len = codec::bytewords_decode(&s[seq_end + 1..], &mut body).ok_or(Err::Bytewords)?;

        let mut r = Reader::new(&body[..len]);
        if r.le(1) != 0x85 {
            return Err(Err::Part);
        }
        let mut f = [0u64; 4];
        for k in 0..4 {
            f[k] = cbor_uint(&mut r, 0);
        }
        let frag_len = cbor_uint(&mut r, 2) as usize;
        let data_at = r.pos();
        r.skip(frag_len);
        if r.err() || r.pos() != len || f.iter().any(|&v| v > 0xffff_ffff) {
            return Err(Err::Part);
        }
        let (seq_num, seq_len, message_len, checksum) =
            (f[0] as u32, f[1] as u32, f[2] as usize, f[3] as u32);
        if seq_num != c_seq_num || seq_len != c_seq_len || seq_num == 0 || frag_len == 0 {
            return Err(Err::Part);
        }
        let seq_len = seq_len as usize;
        if seq_len > MAX_SEQ_LEN || seq_len * frag_len > self.work_cap {
            return Err(Err::Limit);
        }
        // The encoder splits into ceil(message_len / frag_len) fragments; anything else is a lie
        if message_len == 0 || (message_len + frag_len - 1) / frag_len != seq_len {
            return Err(Err::Part);
        }
        if !self.multipart {
            self.ur_type = ur_type;
            self.multipart = true;
            self.seq_len = seq_len;
            self.message_len = message_len;
            self.checksum = checksum;
            self.frag_len = frag_len;
            self.slots = core::cmp::min(MIXED_POOL / frag_len, MAX_MIXED);
        } else if seq_len != self.seq_len
            || message_len != self.message_len
            || checksum != self.checksum
            || frag_len != self.frag_len
        {
            return Err(Err::Mismatch);
        }

        let mut fragment = [0u8; super::MAX_FRAGMENT];
        fragment[..frag_len].copy_from_slice(&body[data_at..data_at + frag_len]);
        let mut bits: Bits = [0; BITS_BYTES];
        let count = codec::choose_fragments(seq_num, seq_len, checksum, &mut bits);
        if count == 1 {
            let idx = self.only_index(&bits);
            self.add_simple(idx, &fragment[..frag_len]);
        } else {
            self.add_mixed(&mut bits, count, &mut fragment[..frag_len]);
        }
        self.drain();

        if (self.received as usize) < self.seq_len {
            return Ok(0);
        }
        let msg = unsafe { core::slice::from_raw_parts(self.work, self.message_len) };
        if codec::crc32(msg) != self.checksum {
            // A message that fails its checksum means some part was wrong; start over rather than
            // keep building on it
            let (work, cap) = (self.work, self.work_cap);
            self.reset(work, cap);
            return Err(Err::Message);
        }
        self.done = self.message_len as i64;
        Ok(self.done)
    }
}

fn is_strict_subset(a: &Bits, b: &Bits) -> bool {
    let mut equal = true;
    for k in 0..BITS_BYTES {
        if a[k] & !b[k] != 0 {
            return false;
        }
        if a[k] != b[k] {
            equal = false;
        }
    }
    !equal
}

fn parse_uint(s: &[u8]) -> Option<u32> {
    if s.is_empty() || s.len() > 10 {
        return None;
    }
    let mut v = 0u64;
    for &c in s {
        if !c.is_ascii_digit() {
            return None;
        }
        v = v * 10 + (c - b'0') as u64;
    }
    if v > 0xffff_ffff {
        return None;
    }
    Some(v as u32)
}

/// A CBOR head of the given major type, returning its argument.
fn cbor_uint(r: &mut Reader, major: u8) -> u64 {
    let head = r.le(1);
    let mut v = head & 31;
    let extra = match v {
        24 => 1,
        25 => 2,
        26 => 4,
        27 => 8,
        _ => 0,
    };
    if (head >> 5) as u8 != major || v > 27 {
        r.fail();
    }
    if extra != 0 {
        v = 0;
        for _ in 0..extra {
            v = v << 8 | r.le(1);
        }
    }
    if r.err() {
        0
    } else {
        v
    }
}

/// The payload of a message that is exactly one CBOR byte string, which is what a crypto-psbt holds.
pub fn cbor_bytes(m: &[u8]) -> Option<(usize, usize)> {
    let mut r = Reader::new(m);
    let v = cbor_uint(&mut r, 2) as usize;
    if r.err() || v != m.len() - r.pos() {
        return None;
    }
    Some((r.pos(), v))
}
