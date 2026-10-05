//! Producing a fountain-coded UR, ported from the encoder half of ../src/ur.c.
//!
//! The message is a CBOR byte string holding the data, and it is never assembled: each fragment is
//! built on the fly from the CBOR head and the caller's bytes, so there is no second copy of the
//! PSBT anywhere. `message_byte` is what makes that work.
//!
//! Parts 1..=seq_len are the pure fragments; later ones are mixed, so a scanner that missed some can
//! still recover the message by watching the loop go round again.

use super::{codec, Bits, Err, BITS_BYTES, MAX_FRAGMENT, MAX_SEQ_LEN};

pub struct Encoder {
    ur_type: [u8; 32],
    type_len: usize,
    data: *const u8,
    data_len: usize,
    head: [u8; 5],
    head_len: usize,
    message_len: usize,
    frag_len: usize,
    seq_len: usize,
    checksum: u32,
    seq_num: u32,
}

/// The fragment length the reference picks: the fewest fragments that stay within `max_len`.
pub fn nominal_fragment_len(message_len: usize, min_len: usize, max_len: usize) -> usize {
    let mut frag_len = message_len;
    let mut count = 1;
    while count <= message_len / min_len {
        frag_len = (message_len + count - 1) / count;
        if frag_len <= max_len {
            break;
        }
        count += 1;
    }
    frag_len
}

/// A minimal CBOR head, as the reference encoder writes it.
fn cbor_head(out: &mut [u8], major: u8, v: u64) -> usize {
    let extra = if v < 24 {
        0
    } else if v < 0x100 {
        1
    } else if v < 0x10000 {
        2
    } else if v < 0x1_0000_0000 {
        4
    } else {
        8
    };
    let low = match extra {
        0 => v as u8,
        1 => 24,
        2 => 25,
        4 => 26,
        _ => 27,
    };
    out[0] = major << 5 | low;
    for k in 0..extra {
        out[1 + k] = (v >> (8 * (extra - 1 - k))) as u8;
    }
    1 + extra
}

impl Encoder {
    pub const fn new() -> Self {
        Encoder {
            ur_type: [0; 32],
            type_len: 0,
            data: core::ptr::null(),
            data_len: 0,
            head: [0; 5],
            head_len: 0,
            message_len: 0,
            frag_len: 0,
            seq_len: 0,
            checksum: 0,
            seq_num: 0,
        }
    }

    pub fn seq_len(&self) -> usize {
        self.seq_len
    }

    /// `data` must stay valid and unchanged until the last part has been written.
    pub fn start(
        &mut self,
        ur_type: &[u8],
        data: *const u8,
        len: usize,
        max_fragment_len: usize,
    ) -> Result<usize, Err> {
        *self = Encoder::new();
        if ur_type.len() >= 32 || max_fragment_len < 10 || max_fragment_len > MAX_FRAGMENT {
            return Err(Err::Limit);
        }
        self.ur_type[..ur_type.len()].copy_from_slice(ur_type);
        self.type_len = ur_type.len();
        self.data = data;
        self.data_len = len;
        self.head_len = cbor_head(&mut self.head, 2, len as u64);
        self.message_len = self.head_len + len;
        self.frag_len = nominal_fragment_len(self.message_len, 10, max_fragment_len);
        self.seq_len = (self.message_len + self.frag_len - 1) / self.frag_len;
        if self.seq_len > MAX_SEQ_LEN {
            return Err(Err::Limit);
        }
        // CRC32 over the message that is never assembled
        let mut c: u32 = 0xffff_ffff;
        for i in 0..self.message_len {
            c ^= self.message_byte(i) as u32;
            for _ in 0..8 {
                c = (c >> 1) ^ (0xedb8_8320 & 0u32.wrapping_sub(c & 1));
            }
        }
        self.checksum = !c;
        Ok(self.seq_len)
    }

    fn message_byte(&self, i: usize) -> u8 {
        if i < self.head_len {
            self.head[i]
        } else if i < self.message_len {
            // The caller's buffer, which start() required to outlive the encoding
            unsafe { *self.data.add(i - self.head_len) }
        } else {
            0
        }
    }

    /// Writes the next part, uppercase for QR alphanumeric mode, and returns its length.
    pub fn next(&mut self, out: &mut [u8]) -> Result<usize, Err> {
        // "UR:" + type + "/" + "<seq>-<len>/" (at most 22) + two letters per byte of the part and
        // its CRC32. A single-part message is no longer than one fragment, so this bounds both
        let need = 3 + self.type_len + 1 + 22 + 2 * (1 + 4 * 5 + 3 + self.frag_len + 4);
        if self.seq_len == 0 || out.len() < need {
            return Err(Err::Limit);
        }
        let mut o = 0;
        out[o..o + 3].copy_from_slice(b"UR:");
        o += 3;
        for k in 0..self.type_len {
            out[o] = self.ur_type[k].to_ascii_uppercase();
            o += 1;
        }
        out[o] = b'/';
        o += 1;

        let mut part = [0u8; 1 + 4 * 5 + 3 + MAX_FRAGMENT];

        if self.seq_len == 1 {
            // The single-part form carries the whole message
            for i in 0..self.message_len {
                part[i] = self.message_byte(i);
            }
            return Ok(o + put_bytewords(&mut out[o..], &part[..self.message_len]));
        }

        self.seq_num += 1;
        let mut bits: Bits = [0; BITS_BYTES];
        codec::choose_fragments(self.seq_num, self.seq_len, self.checksum, &mut bits);

        let mut n = 0;
        part[n] = 0x85; // a CBOR array of five
        n += 1;
        n += cbor_head(&mut part[n..], 0, self.seq_num as u64);
        n += cbor_head(&mut part[n..], 0, self.seq_len as u64);
        n += cbor_head(&mut part[n..], 0, self.message_len as u64);
        n += cbor_head(&mut part[n..], 0, self.checksum as u64);
        n += cbor_head(&mut part[n..], 2, self.frag_len as u64);
        part[n..n + self.frag_len].fill(0);
        for f in 0..self.seq_len {
            if !super::bit(&bits, f) {
                continue;
            }
            for k in 0..self.frag_len {
                part[n + k] ^= self.message_byte(f * self.frag_len + k);
            }
        }
        n += self.frag_len;

        o += put_uint(&mut out[o..], self.seq_num);
        out[o] = b'-';
        o += 1;
        o += put_uint(&mut out[o..], self.seq_len as u32);
        out[o] = b'/';
        o += 1;
        Ok(o + put_bytewords(&mut out[o..], &part[..n]))
    }
}

fn put_uint(out: &mut [u8], mut v: u32) -> usize {
    let mut t = [0u8; 10];
    let mut n = 0;
    loop {
        t[n] = b'0' + (v % 10) as u8;
        n += 1;
        v /= 10;
        if v == 0 {
            break;
        }
    }
    for k in 0..n {
        out[k] = t[n - 1 - k];
    }
    n
}

/// Uppercase minimal Bytewords of `b`, followed by its CRC32.
fn put_bytewords(out: &mut [u8], b: &[u8]) -> usize {
    let c = codec::crc32(b);
    let mut o = 0;
    for i in 0..b.len() + 4 {
        let v = if i < b.len() {
            b[i]
        } else {
            (c >> (8 * (3 - (i - b.len())))) as u8
        };
        let (first, last) = codec::byteword(v);
        out[o] = first.to_ascii_uppercase();
        out[o + 1] = last.to_ascii_uppercase();
        o += 2;
    }
    o
}
