//! The structured form of a transaction that this module hands to a signer, ported from
//! ../include/plan.h.
//!
//! No pointers and no 64-bit-dependent types, so wasm32, rv32 and a 64-bit host all see the same
//! layout. `#[repr(C)]` and the asserts at the bottom keep it that way: a host reads these offsets
//! from the documentation, and nothing here may move without that documentation changing.

pub const MAGIC: u32 = 0x4e4c_5042; // "BPLN"
pub const VERSION: u32 = 2;
pub const MAX_INPUTS: usize = 16;
pub const MAX_OUTPUTS: usize = 16;
pub const MAX_SPK: usize = 83; // the standard OP_RETURN limit; P2TR and P2WSH need 34
pub const MAX_DEPTH: usize = 8;
// sortedmulti of at most three keys: OP_m, 3 x (push + 33), OP_n, OP_CHECKMULTISIG
pub const MAX_WSCRIPT: usize = 105;

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Script {
    pub len: u8,
    pub bytes: [u8; MAX_SPK],
}

impl Script {
    pub const ZERO: Script = Script { len: 0, bytes: [0; MAX_SPK] };

    /// False if it does not fit, which the caller reports as unsupported rather than malformed.
    pub fn set(&mut self, b: &[u8]) -> bool {
        if b.len() > MAX_SPK {
            return false;
        }
        self.bytes = [0; MAX_SPK];
        self.bytes[..b.len()].copy_from_slice(b);
        self.len = b.len() as u8;
        true
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.len as usize]
    }

    /// `0014{20 bytes}`, or `a914{20 bytes}87`: P2WPKH, bare or nested in P2SH. Which script a P2SH
    /// hides is for the signer to establish, by re-deriving the key.
    pub fn is_wpkh(&self) -> bool {
        (self.len == 22 && self.bytes[0] == 0 && self.bytes[1] == 20)
            || (self.len == 23 && self.bytes[0] == 0xa9 && self.bytes[1] == 20 && self.bytes[22] == 0x87)
    }

    /// `5120{32 bytes}`: a witness v1 taproot output.
    pub fn is_p2tr(&self) -> bool {
        self.len == 34 && self.bytes[0] == 0x51 && self.bytes[1] == 32
    }

    /// `0020{32 bytes}`. That the witness script hashes to it, and is a multisig with our key, is
    /// for the signer to establish.
    pub fn is_p2wsh(&self) -> bool {
        self.len == 34 && self.bytes[0] == 0 && self.bytes[1] == 32
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct WScript {
    pub len: u8,
    pub bytes: [u8; MAX_WSCRIPT],
}

impl WScript {
    pub const ZERO: WScript = WScript { len: 0, bytes: [0; MAX_WSCRIPT] };
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct KeyPath {
    pub depth: u8,
    /// The first four bytes of HASH160(master pubkey), read big-endian: 73c5da0a is 0x73c5da0a.
    pub fingerprint: u32,
    pub path: [u32; MAX_DEPTH],
}

impl KeyPath {
    pub const ZERO: KeyPath = KeyPath { depth: 0, fingerprint: 0, path: [0; MAX_DEPTH] };
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Input {
    /// Internal byte order, as serialized — not the reversed form a block explorer shows.
    pub prev_txid: [u8; 32],
    pub prev_vout: u32,
    pub sequence: u32,
    /// From the witness_utxo, or from the non_witness_utxo's output at prev_vout.
    pub amount: u64,
    pub spk: Script,
    /// depth = 0 for an input this signer will not sign.
    pub key: KeyPath,
    pub sighash_type: u8,
}

impl Input {
    pub const ZERO: Input = Input {
        prev_txid: [0; 32], prev_vout: 0, sequence: 0, amount: 0,
        spk: Script::ZERO, key: KeyPath::ZERO, sighash_type: 0,
    };
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Output {
    pub amount: u64,
    pub spk: Script,
    /// A change candidate. It is a claim: the signer re-derives the key to confirm it.
    pub key: KeyPath,
}

impl Output {
    pub const ZERO: Output = Output { amount: 0, spk: Script::ZERO, key: KeyPath::ZERO };
}

#[repr(C)]
pub struct Plan {
    pub magic: u32,
    pub version: u32,
    pub tx_version: i32,
    pub locktime: u32,
    pub n_inputs: u8,
    pub n_outputs: u8,
    pub inputs: [Input; MAX_INPUTS],
    pub outputs: [Output; MAX_OUTPUTS],
    /// A P2WSH input's witness script, only for one to be signed.
    pub wscripts: [WScript; MAX_INPUTS],
}

impl Plan {
    pub const ZERO: Plan = Plan {
        magic: 0, version: 0, tx_version: 0, locktime: 0, n_inputs: 0, n_outputs: 0,
        inputs: [Input::ZERO; MAX_INPUTS], outputs: [Output::ZERO; MAX_OUTPUTS],
        wscripts: [WScript::ZERO; MAX_INPUTS],
    };
}

/// A signature the signer made. The host writes these to the signature buffer and this module
/// inserts them into the PSBT.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Sig {
    pub input: u8,
    /// A compressed pubkey for P2WPKH and P2SH-P2WPKH; `0x00` then the x-only output key for P2TR.
    pub pubkey: [u8; 33],
    pub sig_len: u8,
    /// DER plus the sighash byte for ECDSA; 64 or 65 bytes for Schnorr.
    pub sig: [u8; 73],
}

impl Sig {
    pub const ZERO: Sig = Sig { input: 0, pubkey: [0; 33], sig_len: 0, sig: [0; 73] };
}

// The layout a host reads by offset. These are the same assertions ../include/plan.h makes, and a
// change that breaks one is a change to the documented ABI
const _: () = assert!(core::mem::size_of::<Sig>() == 108);
const _: () = assert!(core::mem::size_of::<Input>() == 176);
const _: () = assert!(core::mem::size_of::<Output>() == 136);
const _: () = assert!(core::mem::offset_of!(Plan, inputs) == 24);
const _: () = assert!(core::mem::offset_of!(Plan, wscripts) == 5016);
const _: () = assert!(core::mem::size_of::<Plan>() == 6712);
