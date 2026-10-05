//! Uniform Resources (BCR-2020-005): the animated-QR encoding PSBTs usually arrive in.
//!
//! Ported from ../src/ur.c, which follows the Blockchain Commons reference implementation (bc-ur)
//! closely where the result has to match bit for bit: the Xoshiro256** seeding, the alias sampler,
//! the shuffle, and therefore which fragments each mixed part combines. Those are checked against
//! bc-ur's own test values — 1,174 of them — so a difference anywhere in that chain is caught.
//!
//! Everything is in fixed buffers; nothing allocates.

mod codec;
mod decoder;
mod encoder;

pub use codec::{bytewords_decode, choose_degree, choose_fragments, crc32, shuffle, Rng};
pub use decoder::{cbor_bytes, Decoder};
pub use encoder::{nominal_fragment_len, Encoder};

/// Parts a message may be split into.
pub const MAX_SEQ_LEN: usize = 1024;
/// Mixed parts kept while waiting to be reduced.
pub const MAX_MIXED: usize = 64;
/// Bytes shared by the kept mixed parts.
pub const MIXED_POOL: usize = 16384;
/// The largest fragment the encoder will produce.
pub const MAX_FRAGMENT: usize = 1000;

pub const BITS_BYTES: usize = MAX_SEQ_LEN / 8;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(i32)]
pub enum Err {
    /// Not `ur:<type>/...`.
    Scheme = -1,
    /// Invalid characters, or the trailing CRC32 does not match.
    Bytewords = -2,
    /// Malformed part CBOR or sequence component.
    Part = -3,
    /// The part disagrees with earlier ones: a different type, length or checksum.
    Mismatch = -4,
    /// Beyond the limits above, or beyond the caller's buffer.
    Limit = -5,
    /// The reassembled message fails its CRC32.
    Message = -6,
    /// Complete, but not a PSBT holding a CBOR byte string.
    Type = -7,
}

/// A bitset over fragment indices, sized for MAX_SEQ_LEN. Set comparisons look at the whole thing,
/// so the unused tail has to stay zero.
pub type Bits = [u8; BITS_BYTES];

pub fn bit(b: &Bits, i: usize) -> bool {
    b[i / 8] >> (i % 8) & 1 == 1
}

pub fn set_bit(b: &mut Bits, i: usize) {
    b[i / 8] |= 1 << (i % 8);
}

pub fn clear_bit(b: &mut Bits, i: usize) {
    b[i / 8] &= !(1 << (i % 8));
}

pub fn xor_into(dst: &mut [u8], src: &[u8]) {
    for (d, s) in dst.iter_mut().zip(src) {
        *d ^= *s;
    }
}
