//! The parts whose results have to match the Blockchain Commons reference bit for bit: CRC32, the
//! Xoshiro256** seeding and draws, Bytewords, the alias sampler, the degree distribution and the
//! shuffle. Which fragments a mixed part combines follows from all of them, so a difference
//! anywhere here makes this module unable to talk to any other UR implementation.
//!
//! The arithmetic is deliberately written to wrap where the reference wraps, and the floating-point
//! steps are kept in the same order and the same precision: `next_double` divides by 2^64 and the
//! sampler compares against it, so reordering those would change which fragment is chosen.

use super::{set_bit, Bits, MAX_SEQ_LEN};
use crate::sha256;

/// Four letters per byte value, in value order. Minimal Bytewords uses the first and last letter.
const WORDS: &[u8] = b"ableacidalsoapexaquaarchatomauntawayaxisbackbaldbarnbeltbetabiasbluebodybragbrewbulbbuzzcalmcashcatschef\
cityclawcodecolacookcostcruxcurlcuspcyandarkdatadaysdelidicedietdoordowndrawdropdrumdulldutyeacheasyecho\
edgeepicevenexamexiteyesfactfairfernfigsfilmfishfizzflapflewfluxfoxyfreefrogfuelfundgalagamegeargemsgift\
girlglowgoodgraygrimgurugushgyrohalfhanghardhawkheathelphighhillholyhopehornhutsicedideaidleinchinkyinto\
irisironitemjadejazzjoinjoltjowljudojugsjumpjunkjurykeepkenokeptkeyskickkilnkingkitekiwiknoblamblavalazy\
leaflegsliarlimplionlistlogoloudloveluaulucklungmainmanymathmazememomenumeowmildmintmissmonknailnavyneed\
newsnextnoonnotenumbobeyoboeomitonyxopenovalowlspaidpartpeckplaypluspoempoolposepuffpumapurrquadquizrace\
ramprealredorichroadrockroofrubyruinrunsrustsafesagascarsetssilkskewslotsoapsolosongstubsurfswantacotask\
taxitenttiedtimetinytoiltombtoystriptunatwinuglyundouniturgeuservastveryvetovialvibeviewvisavoidvowswall\
wandwarmwaspwavewaxywebswhatwhenwhizwolfworkyankyawnyellyogayurtzapszerozestzinczonezoom";

pub fn crc32(p: &[u8]) -> u32 {
    let mut c: u32 = 0xffff_ffff;
    for &b in p {
        c ^= b as u32;
        for _ in 0..8 {
            // The reference's branchless form: subtracting the low bit from zero gives the mask
            c = (c >> 1) ^ (0xedb8_8320 & 0u32.wrapping_sub(c & 1));
        }
    }
    !c
}

/// Xoshiro256**, seeded as bc-ur seeds it: SHA-256 of the seed bytes, read as four big-endian words.
pub struct Rng {
    s: [u64; 4],
}

impl Rng {
    pub fn from_seed(seed: &[u8]) -> Self {
        let h = sha256::hash(seed);
        let mut s = [0u64; 4];
        for i in 0..4 {
            let mut v = 0u64;
            for k in 0..8 {
                v = v << 8 | h[8 * i + k] as u64;
            }
            s[i] = v;
        }
        Rng { s }
    }

    pub fn next(&mut self) -> u64 {
        let s = &mut self.s;
        let result = s[1].wrapping_mul(5).rotate_left(7).wrapping_mul(9);
        let t = s[1] << 17;
        s[2] ^= s[0];
        s[3] ^= s[1];
        s[1] ^= s[2];
        s[0] ^= s[3];
        s[2] ^= t;
        s[3] = s[3].rotate_left(45);
        result
    }

    /// Divided by 2^64, as the reference does. The sampler compares against this value, so the
    /// division must stay exactly here.
    pub fn next_double(&mut self) -> f64 {
        self.next() as f64 / 18446744073709551616.0
    }

    pub fn next_int(&mut self, low: u64, high: u64) -> u64 {
        (self.next_double() * (high - low + 1) as f64) as u64 + low
    }
}

/// Minimal Bytewords: two letters per byte, with a trailing CRC32 that is checked and removed.
/// Returns the message length, or None.
///
/// `out` may be the same memory the letters are in: byte i is written only after letters 2i and
/// 2i+1 have been read.
pub fn bytewords_decode(s: &[u8], out: &mut [u8]) -> Option<usize> {
    if s.len() % 2 != 0 {
        return None;
    }
    let len = s.len() / 2;
    if len < 5 || len > out.len() {
        return None;
    }
    for i in 0..len {
        let x = s[2 * i];
        let y = s[2 * i + 1];
        if !x.is_ascii_lowercase() || !y.is_ascii_lowercase() {
            return None;
        }
        out[i] = lookup(x, y)?;
    }
    let len = len - 4;
    let want = u32::from_be_bytes([out[len], out[len + 1], out[len + 2], out[len + 3]]);
    if crc32(&out[..len]) != want {
        return None;
    }
    Some(len)
}

/// The byte whose word starts with `first` and ends with `last`. Searched rather than tabulated: a
/// 676-entry table would be built at run time in a module with no initialiser to build it in, and
/// 256 comparisons on a QR payload is not where the time goes.
fn lookup(first: u8, last: u8) -> Option<u8> {
    for v in 0..256usize {
        if WORDS[4 * v] == first && WORDS[4 * v + 3] == last {
            return Some(v as u8);
        }
    }
    None
}

/// The first and last letter of the word for `v`, which is how minimal Bytewords spells a byte.
pub fn byteword(v: u8) -> (u8, u8) {
    let i = 4 * v as usize;
    (WORDS[i], WORDS[i + 3])
}

/// Vose's alias method, in the form bc-ur implements it — including the reversed index order and
/// the way it finishes, both of which change which index a given pair of draws selects.
///
/// The two stacks share one array, growing from opposite ends: every index is in exactly one of
/// them, so they cannot overlap.
pub struct Sampler {
    probs: [f64; MAX_SEQ_LEN],
    aliases: [i16; MAX_SEQ_LEN],
    n: usize,
}

impl Sampler {
    pub const fn new() -> Self {
        Sampler { probs: [0.0; MAX_SEQ_LEN], aliases: [0; MAX_SEQ_LEN], n: 0 }
    }

    /// Initialises from DEGREE_WEIGHTS, read through a raw pointer so that the weights and this
    /// sampler are not two live borrows of the same static at once.
    fn init_from_static(&mut self, n: usize) {
        let w = (&raw const DEGREE_WEIGHTS) as *const f64;
        self.n = n;
        let mut sum = 0.0f64;
        for i in 0..n {
            sum += unsafe { *w.add(i) };
        }
        for i in 0..n {
            self.probs[i] = unsafe { *w.add(i) } * n as f64 / sum;
        }
        self.build(n);
    }

    pub fn init(&mut self, weights: &[f64]) {
        let n = weights.len();
        self.n = n;
        let sum: f64 = weights.iter().sum();
        for i in 0..n {
            self.probs[i] = weights[i] * n as f64 / sum;
        }
        self.build(n);
    }

    /// Vose's method over `probs`, which init has already filled.
    fn build(&mut self, n: usize) {
        // Also static: the two stacks are 2 KB and this is called from the same single path
        static mut STACK: [i16; MAX_SEQ_LEN] = [0; MAX_SEQ_LEN];
        let stack: &mut [i16] =
            unsafe { core::slice::from_raw_parts_mut((&raw mut STACK) as *mut i16, MAX_SEQ_LEN) };
        let mut ns = 0usize;
        let mut nl = 0usize;
        // Reversed, as in the reference
        for i in (0..n).rev() {
            if self.probs[i] < 1.0 {
                stack[ns] = i as i16;
                ns += 1;
            } else {
                stack[n - 1 - nl] = i as i16;
                nl += 1;
            }
        }
        self.aliases[..n].fill(0);
        while ns > 0 && nl > 0 {
            ns -= 1;
            let a = stack[ns] as usize;
            let g = stack[n - nl] as usize;
            nl -= 1;
            self.aliases[a] = g as i16;
            self.probs[g] += self.probs[a] - 1.0;
            if self.probs[g] < 1.0 {
                stack[ns] = g as i16;
                ns += 1;
            } else {
                stack[n - 1 - nl] = g as i16;
                nl += 1;
            }
        }
        while nl > 0 {
            self.probs[stack[n - nl] as usize] = 1.0;
            nl -= 1;
        }
        while ns > 0 {
            ns -= 1;
            self.probs[stack[ns] as usize] = 1.0;
        }
    }

    pub fn next(&self, r: &mut Rng) -> usize {
        let r1 = r.next_double();
        let r2 = r.next_double();
        let i = (self.n as f64 * r1) as usize;
        if r2 < self.probs[i] {
            i
        } else {
            self.aliases[i] as usize
        }
    }
}

/// How many fragments a mixed part combines: 1/i over i in 1..=seq_len, sampled.
///
/// The working arrays are static, not local. On a microcontroller the linker reserves the deepest
/// stack any path needs, and 1,024 f64 weights plus a sampler is 18 KB of it — which is what pushed
/// the module's linear memory from 3 pages to 18 before these moved here. The C put them in `static`
/// for the same reason.
///
/// This module is single-threaded by construction: wasm without the threads proposal has no way to
/// call in concurrently, so sharing one buffer across calls is safe and there is nothing to lock.
static mut DEGREE_WEIGHTS: [f64; MAX_SEQ_LEN] = [0.0; MAX_SEQ_LEN];
static mut DEGREE_SAMPLER: Sampler = Sampler::new();

pub fn choose_degree(seq_len: usize, r: &mut Rng) -> usize {
    let weights: &mut [f64] =
        unsafe { core::slice::from_raw_parts_mut((&raw mut DEGREE_WEIGHTS) as *mut f64, MAX_SEQ_LEN) };
    for i in 1..=seq_len {
        weights[i - 1] = 1.0 / i as f64;
    }
    let s: &mut Sampler = unsafe { &mut *(&raw mut DEGREE_SAMPLER) };
    s.init_from_static(seq_len);
    s.next(r) + 1
}

/// The reference moves each chosen item from a "remaining" list into the result. Here the result
/// grows at the front of `items` and the remaining ones stay behind it in their original order,
/// which produces the same sequence.
pub fn shuffle(items: &mut [u16], r: &mut Rng) {
    let n = items.len();
    for k in 0..n {
        let i = r.next_int(0, (n - k - 1) as u64) as usize;
        let item = items[k + i];
        items[k..=k + i].rotate_right(1);
        items[k] = item;
    }
}

/// Which fragments part `seq_num` combines, as a bitset. Returns how many.
///
/// A part within the first `seq_len` is a pure fragment, so no randomness is involved; past that
/// the seed is the sequence number and the checksum, which is what makes every implementation agree
/// on the same mixture.
pub fn choose_fragments(seq_num: u32, seq_len: usize, checksum: u32, bits: &mut Bits) -> usize {
    bits.fill(0);
    if seq_num as usize <= seq_len {
        set_bit(bits, seq_num as usize - 1);
        return 1;
    }
    let mut seed = [0u8; 8];
    seed[..4].copy_from_slice(&seq_num.to_be_bytes());
    seed[4..].copy_from_slice(&checksum.to_be_bytes());
    let mut r = Rng::from_seed(&seed);
    let degree = choose_degree(seq_len, &mut r);
    // Static for the same reason as the sampler's arrays: 2 KB of stack the linker would reserve
    static mut IDX: [u16; MAX_SEQ_LEN] = [0; MAX_SEQ_LEN];
    let idx: &mut [u16] =
        unsafe { core::slice::from_raw_parts_mut((&raw mut IDX) as *mut u16, MAX_SEQ_LEN) };
    for i in 0..seq_len {
        idx[i] = i as u16;
    }
    shuffle(&mut idx[..seq_len], &mut r);
    for i in 0..degree {
        set_bit(bits, idx[i] as usize);
    }
    degree
}
