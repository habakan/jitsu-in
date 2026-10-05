//! SHA-256, ported from ../src/sha256.c.
//!
//! Written out rather than taken from a crate: this is the one hash the parser needs, a dependency
//! here would be a dependency to audit, and the published test vectors make it cheap to be sure of.

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

const IV: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

fn compress(s: &mut [u32; 8], b: &[u8; 64]) {
    let mut w = [0u32; 64];
    for i in 0..16 {
        w[i] = u32::from_be_bytes([b[4 * i], b[4 * i + 1], b[4 * i + 2], b[4 * i + 3]]);
    }
    for i in 16..64 {
        let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
        let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
        // Wrapping on purpose: SHA-256 is defined modulo 2^32, so this is the specification, not a
        // place where overflow-checks should fire
        w[i] = w[i - 16]
            .wrapping_add(s0)
            .wrapping_add(w[i - 7])
            .wrapping_add(s1);
    }
    let [mut a, mut b_, mut c, mut d, mut e, mut f, mut g, mut h] = *s;
    for i in 0..64 {
        let t1 = h
            .wrapping_add(e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25))
            .wrapping_add((e & f) ^ (!e & g))
            .wrapping_add(K[i])
            .wrapping_add(w[i]);
        let t2 = (a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22))
            .wrapping_add((a & b_) ^ (a & c) ^ (b_ & c));
        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b_;
        b_ = a;
        a = t1.wrapping_add(t2);
    }
    for (acc, v) in s.iter_mut().zip([a, b_, c, d, e, f, g, h]) {
        *acc = acc.wrapping_add(v);
    }
}

pub struct Ctx {
    s: [u32; 8],
    buf: [u8; 64],
    len: u64,
}

impl Ctx {
    pub fn new() -> Self {
        Ctx { s: IV, buf: [0; 64], len: 0 }
    }

    pub fn update(&mut self, mut p: &[u8]) {
        let mut used = (self.len % 64) as usize;
        self.len += p.len() as u64;
        if used != 0 {
            let take = core::cmp::min(p.len(), 64 - used);
            self.buf[used..used + take].copy_from_slice(&p[..take]);
            p = &p[take..];
            used += take;
            if used < 64 {
                return;
            }
            let block = self.buf;
            compress(&mut self.s, &block);
        }
        while p.len() >= 64 {
            let mut block = [0u8; 64];
            block.copy_from_slice(&p[..64]);
            compress(&mut self.s, &block);
            p = &p[64..];
        }
        self.buf[..p.len()].copy_from_slice(p);
    }

    pub fn finish(mut self) -> [u8; 32] {
        let used = (self.len % 64) as usize;
        let padlen = if used < 56 { 56 } else { 120 } - used;
        let bits = self.len * 8;
        let mut pad = [0u8; 72];
        pad[0] = 0x80;
        for i in 0..8 {
            pad[padlen + i] = (bits >> (56 - 8 * i)) as u8;
        }
        self.update(&pad[..padlen + 8]);
        let mut out = [0u8; 32];
        for (i, v) in self.s.iter().enumerate() {
            out[4 * i..4 * i + 4].copy_from_slice(&v.to_be_bytes());
        }
        out
    }

    /// SHA-256 of the SHA-256, which is what Bitcoin means by a hash of a transaction or a block.
    pub fn finish_double(self) -> [u8; 32] {
        hash(&self.finish())
    }
}

pub fn hash(p: &[u8]) -> [u8; 32] {
    let mut c = Ctx::new();
    c.update(p);
    c.finish()
}
