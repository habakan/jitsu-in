//! Reads untrusted bytes. Every length is checked against what remains before anything is read, and
//! errors accumulate rather than being returned at each step — the same shape as the C this replaces
//! (`include/reader.h`), so the two can be compared call for call during the migration.

pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
    err: bool,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Reader { buf, pos: 0, err: false }
    }

    pub fn pos(&self) -> usize {
        self.pos
    }

    pub fn err(&self) -> bool {
        self.err
    }

    pub fn fail(&mut self) {
        self.err = true;
    }

    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    /// Advances past `k` bytes and returns them, or marks the reader failed and returns None. Once
    /// failed it stays failed, so a caller may read a whole structure and check once at the end.
    pub fn take(&mut self, k: usize) -> Option<&'a [u8]> {
        if self.err || k > self.remaining() {
            self.err = true;
            return None;
        }
        let at = self.pos;
        self.pos += k;
        Some(&self.buf[at..at + k])
    }

    /// Skips `k` bytes without returning them.
    pub fn skip(&mut self, k: usize) {
        self.take(k);
    }

    /// A little-endian integer of `k` bytes, at most 8. Zero if the read failed.
    pub fn le(&mut self, k: usize) -> u64 {
        debug_assert!(k <= 8);
        match self.take(k) {
            None => 0,
            Some(b) => b.iter().rev().fold(0u64, |v, &x| (v << 8) | x as u64),
        }
    }

    /// A Bitcoin compact size. Rejects a non-minimal encoding, and a value larger than the bytes
    /// that remain — a length that cannot be satisfied is a malformed message, not a short read.
    pub fn varint(&mut self) -> u64 {
        let mut v = self.le(1);
        if v == 0xfd {
            v = self.le(2);
            if v < 0xfd {
                self.err = true;
            }
        } else if v == 0xfe {
            v = self.le(4);
            if v <= 0xffff {
                self.err = true;
            }
        } else if v == 0xff {
            v = self.le(8);
            if v <= 0xffff_ffff {
                self.err = true;
            }
        }
        if v > self.remaining() as u64 {
            self.err = true;
        }
        if self.err {
            0
        } else {
            v
        }
    }
}
