# Driving parser.wasm from your language

Everything a host needs to call `parser.wasm`: the exported functions, the layout of the struct it
hands back, the error codes, what it accepts, and what you are still responsible for.
If you are integrating this module, this is the only document you need.

The module has **zero imports**
and does not use WASI, so any runtime that can execute WebAssembly works: WAMR on a microcontroller,
V8 or JavaScriptCore in a browser, wasmtime, wasmi, Chicory (JVM), WasmKit (Swift), WasmEdge.

This file describes ABI **version 1** (`plan_t.version`). Sizes and offsets below are asserted at
compile time in `include/plan.h` and are stable for a given version.

## The module

```
imports   none
memory    exported as "memory", 3 pages (196,608 bytes), not growable
globals   __data_end, __heap_base (both 136064; the module never allocates)
```

All buffers are static. The exported accessors return **offsets into the linear memory**,
not host pointers. A host must bounds-check every offset and length against the memory size
before reading or writing — the module is untrusted from the host's point of view.

## Exported functions

| Export | Signature | Meaning |
|---|---|---|
| `parser_input` | `() -> i32` | Offset of the input buffer. PSBT bytes, UR text, and the UR encoder's output all go here |
| `parser_input_cap` | `() -> i32` | Capacity of that buffer (32,768) |
| `parser_parse` | `(len: i32, fingerprint: i32) -> i32` | Parse the PSBT in the input buffer. `0` on success, else a positive `P_ERR_*` |
| `parser_plan` | `() -> i32` | Offset of the `plan_t` filled by `parser_parse` |
| `parser_prevtx_off` | `(i: i32) -> i32` | Offset **within the input buffer** of input `i`'s `non_witness_utxo` |
| `parser_prevtx_len` | `(i: i32) -> i32` | Its length, or `0` if the input has none |
| `parser_sigs` | `() -> i32` | Offset of an array of 16 `plan_sig_t` the host fills in |
| `parser_finalize` | `(n: i32) -> i32` | Insert the first `n` signatures. Returns the signed PSBT length, or `-P_ERR_SIG` |
| `parser_output` | `() -> i32` | Offset of the signed PSBT written by `parser_finalize` |
| `parser_ur_reset` | `() -> ()` | Drop decoder state before a new animated QR |
| `parser_ur_receive` | `(len: i32) -> i32` | Feed one UR part from the input buffer. `>0`: PSBT length, now in the input buffer. `0`: more parts needed. `<0`: `UR_ERR_*` |
| `parser_ur_progress` | `() -> i32` | Parts received so far (for a progress display only) |
| `parser_ur_encode_start` | `(len: i32, max_fragment_len: i32) -> i32` | Begin encoding the signed PSBT in the output buffer. Returns `seq_len`, or a negative `UR_ERR_*` |
| `parser_ur_encode_next` | `() -> i32` | Write the next part as uppercase text into the input buffer. Returns its length, or a negative `UR_ERR_*` |

`fingerprint` is the signer's master fingerprint — the first 4 bytes of `HASH160(master pubkey)`
read big-endian, so `73c5da0a` is passed as `0x73c5da0a`. It is not a secret. Only [BIP32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki) derivations
carrying this fingerprint become key candidates in the plan.

## Flow

### Signing

```
write PSBT into parser_input()
parser_parse(len, fingerprint)        -> 0
read parser_plan()                    -> show it to the user, derive keys, sign
write signatures into parser_sigs()
parser_finalize(n)                    -> signed length
read parser_output()
```

### Animated QR in

```
parser_ur_reset()
for each QR payload:
    write the text into parser_input()
    rc = parser_ur_receive(len)
    rc > 0 -> the PSBT is now in parser_input(), length rc; continue with parser_parse
```

### Animated QR out

```
seq_len = parser_ur_encode_start(signed_len, 100)   // fragment size tuned for the display
loop:
    n = parser_ur_encode_next()
    render parser_input()[0..n] as a QR
```

Parts are a fountain code ([BCR-2020-005](https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2020-005-ur.md)): the first `seq_len` parts are the pure fragments and the
rest are mixed. A receiver that only understands pure parts can still finish if the sender loops
over the first `seq_len`. Calling `parser_ur_encode_start` again restarts the sequence.

## A minimal host, start to finish

Node, no dependencies. Every other host is this shape: write bytes where the module tells you,
call a function, read a struct back at a documented offset.

```js
import { readFileSync } from "fs";

const w = new WebAssembly.Instance(
  new WebAssembly.Module(readFileSync("parser.wasm")), {}).exports;
const u8 = new Uint8Array(w.memory.buffer);
const dv = new DataView(w.memory.buffer);

// 1. write the PSBT where the module expects it
const psbt = readFileSync("tx.psbt");
if (psbt.length > w.parser_input_cap()) throw new Error("too large");
u8.set(psbt, w.parser_input());

// 2. parse, passing the signer's master fingerprint
const rc = w.parser_parse(psbt.length, 0x73c5da0a);
if (rc !== 0) throw new Error("P_ERR " + rc);

// 3. read the plan. Offsets are in this document; never hard-code the buffer address
const plan = w.parser_plan();
if (dv.getUint32(plan, true) !== 0x4e4c5042) throw new Error("bad magic");  // "BPLN"
if (dv.getUint32(plan + 4, true) !== 1) throw new Error("unknown ABI version");

const nIn = u8[plan + 16], nOut = u8[plan + 17];
let totalIn = 0n, totalOut = 0n;
for (let i = 0; i < nIn; i++) totalIn += dv.getBigUint64(plan + 24 + i * 176 + 40, true);
for (let i = 0; i < nOut; i++) {
  const o = plan + 2840 + i * 136;
  const amount = dv.getBigUint64(o, true);
  const spkLen = u8[o + 8];
  const spk = u8.slice(o + 9, o + 9 + spkLen);
  const mine = u8[o + 92] !== 0;   // key.depth: a *claim* that this output is yours
  totalOut += amount;
  console.log(i, Number(amount) / 1e8, Buffer.from(spk).toString("hex"), mine ? "(claimed yours)" : "");
}
// The fee is yours to compute. The module does not tell you one
console.log("fee", Number(totalIn - totalOut) / 1e8);
```

`mine` above is deliberately named as a claim. Deriving the key and checking that it really produces
that scriptPubKey is the host's job — see [What the host must still do](#what-the-host-must-still-do).

Host libraries for other languages, each runnable with `make run`, are in
[`hosts/`](../hosts): Kotlin on Chicory, Swift on WasmKit.

## Memory map (version 1, informative)

Offsets are what the accessors return today. **Do not hard-code them**; call the accessors.

| Buffer | Offset | Size |
|---|---:|---:|
| input | 17,744 | 32,768 |
| plan | 50,512 | 5,016 |
| sigs | 55,536 | 1,728 (16 × 108) |
| output | 57,264 | 34,816 |

## `plan_t`

The parser's whole output. No pointers and no `long`, so wasm32, rv32 and 64-bit hosts share one layout.

```c
#define PLAN_MAGIC       0x4e4c5042u /* "BPLN" */
#define PLAN_VERSION     1
#define PLAN_MAX_INPUTS  16
#define PLAN_MAX_OUTPUTS 16
#define PLAN_MAX_SPK     83
#define PLAN_MAX_DEPTH   8

typedef struct { uint8_t len; uint8_t bytes[83]; } plan_script_t;          /* 84 */

typedef struct {
    uint8_t  depth;         /* 0 = this is not ours */
    uint32_t fingerprint;
    uint32_t path[8];       /* hardened steps keep the high bit set */
} plan_keypath_t;                                                          /* 40 */

typedef struct {
    uint8_t  prev_txid[32]; /* internal byte order, as serialized */
    uint32_t prev_vout;
    uint32_t sequence;
    uint64_t amount;        /* from witness_utxo */
    plan_script_t spk;      /* from witness_utxo */
    plan_keypath_t key;     /* depth = 0 for inputs not to be signed */
    uint8_t  sighash_type;
} plan_input_t;                                                            /* 176 */

typedef struct {
    uint64_t amount;
    plan_script_t spk;
    plan_keypath_t key;     /* change candidate; the signer re-derives to confirm */
} plan_output_t;                                                           /* 136 */

typedef struct {
    uint32_t magic, version;
    int32_t  tx_version;
    uint32_t locktime;
    uint8_t  n_inputs, n_outputs;
    plan_input_t  inputs[16];
    plan_output_t outputs[16];
} plan_t;                                                                  /* 5016 */
```

Field offsets a non-C host needs:

| | offset | |
|---|---:|---|
| `plan_t.magic` | 0 | u32, must be `0x4e4c5042` |
| `plan_t.version` | 4 | u32, must be 1 |
| `plan_t.tx_version` | 8 | i32 |
| `plan_t.locktime` | 12 | u32 |
| `plan_t.n_inputs` | 16 | u8 |
| `plan_t.n_outputs` | 17 | u8 |
| `plan_t.inputs` | 24 | stride 176 |
| `plan_t.outputs` | 2,840 | stride 136 |
| `plan_input_t.amount` | 40 | u64 little-endian |
| `plan_input_t.spk` | 48 | 1 byte length + 83 bytes |
| `plan_input_t.key` | 132 | |
| `plan_output_t.amount` | 0 | |
| `plan_output_t.spk` | 8 | |
| `plan_output_t.key` | 92 | |
| `plan_keypath_t.depth` | 0 | |
| `plan_keypath_t.fingerprint` | 4 | u32 |
| `plan_keypath_t.path` | 8 | 8 × u32 |

All integers are little-endian, as in the WebAssembly linear memory.

A host **must** check `magic == 0x4e4c5042` and `version == 1` before trusting the rest.

## `plan_sig_t`

```c
typedef struct {
    uint8_t input;      /* index into plan.inputs */
    uint8_t pubkey[33]; /* compressed pubkey for P2WPKH and P2SH-P2WPKH; 0x00 + x-only output key for P2TR */
    uint8_t sig_len;
    uint8_t sig[73];    /* DER + sighash byte for ECDSA; 64 or 65 bytes for Schnorr */
} plan_sig_t;           /* 108 */
```

## Error codes

`parser_parse` returns `0` or a positive value:

| | | |
|---:|---|---|
| 0 | `P_OK` | |
| 1 | `P_ERR_MAGIC` | not a PSBT |
| 2 | `P_ERR_FORMAT` | [BIP174](https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki) violation: key/value lengths, v2-only fields, trailing bytes |
| 3 | `P_ERR_DUPLICATE` | duplicate key within a map |
| 4 | `P_ERR_TX` | no unsigned tx, scriptSig or witness present, non-canonical serialization |
| 5 | `P_ERR_UNSUPPORTED` | PSBT v2, script longer than 83 bytes, sighash that does not fit in a byte |
| 6 | `P_ERR_LIMIT` | more than 16 inputs or outputs, PSBT larger than 32,768 bytes |
| 7 | `P_ERR_UTXO` | input without utxo data, `non_witness_utxo` txid or output mismatch |
| 8 | `P_ERR_SIG` | invalid signatures passed to `parser_finalize` (returned negated) |

The UR functions return negative values:

| | | |
|---:|---|---|
| −1 | `UR_ERR_SCHEME` | not `ur:<type>/...` |
| −2 | `UR_ERR_BYTEWORDS` | invalid characters or CRC32 |
| −3 | `UR_ERR_PART` | malformed part CBOR or sequence component |
| −4 | `UR_ERR_MISMATCH` | part disagrees with earlier parts |
| −5 | `UR_ERR_LIMIT` | beyond the decoder's limits or the caller's buffer |
| −6 | `UR_ERR_MESSAGE` | reassembled message fails its CRC32 |
| −7 | `UR_ERR_TYPE` | complete, but not a PSBT |

## Where the rules come from

[BIP174](https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki) defines the serialization only — it says nothing about how a parsed transaction
should be represented, so `plan_t` is this project's own shape. What BIP174 *does* define is the
**Signer role**, and several checks below exist because it requires them:

> The Signer must only use the UTXOs provided in the PSBT to produce signatures for inputs.

> Before signing a non-witness input, the Signer must verify that the TXID of the non-witness UTXO
> matches the TXID specified in the unsigned transaction.

> Before signing a witness input, the Signer must verify that the witnessScript (if provided) matches
> the hash specified in the UTXO or the redeemScript, and the redeemScript (if provided) matches the
> hash in the UTXO.

This module does the first two: a `non_witness_utxo` whose txid or output does not match the unsigned
transaction is rejected with `P_ERR_UTXO`, and amounts come only from the PSBT's own UTXO data.
The third falls to the signer. The only `redeemScript` in scope is BIP49's P2SH-P2WPKH, and this
module does not read it: it passes a P2SH input's derivation through, and `signer.wasm` derives the
redeem script from its own key and refuses the input unless its hash is the UTXO's. `witnessScript`
inputs remain out of scope.

BIP174 also says "The Signer may choose to fail to sign a segwit input if a non-witness UTXO is not
provided." The host decides that, not this module; the reference host requires one when a SegWit v0
input is signed alongside others, because that is the input amount it would otherwise have to take
on trust.

## What is accepted

- PSBT v0 only ([BIP174](https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki)). v2 is rejected with `P_ERR_UNSUPPORTED`
- At most 16 inputs and 16 outputs, 32,768 bytes total
- Every input needs `witness_utxo` or `non_witness_utxo`; when both are present the `non_witness_utxo`
  must hash to `prev_txid` and its output must match the `witness_utxo`
- scriptPubKey at most 83 bytes
- The unsigned transaction must be canonical and carry no scriptSig or witness

## What the host must still do

The parser is untrusted. It shapes bytes into a struct; it does not decide anything.

- **Bounds-check** every offset and length against the exported memory
- **Check `magic` and `version`**
- **Re-derive keys.** `plan_keypath_t` is a claim. The signer derives the key itself and compares the
  resulting scriptPubKey with `spk` before treating an input as its own or an output as change
- **Compute the fee itself** from the amounts it has verified, and show it
- **Bind display to signature.** The reference implementation hashes the reviewed plan and requires the
  same hash at signing time, so what the user approved is what gets signed

## Versioning

`plan_t.version` is `1`. Adding a field, changing a size, or changing a meaning bumps it.
A host that sees an unknown version must refuse rather than guess.
Export names and error numbers are part of the ABI and do not change within a version.

## Reproducing the binary

`parser.wasm` is reproducible: wasi-sdk 34.0 and binaryen 132, pinned by hash. macOS arm64 and
Linux x86_64 produce the same `a6766d13e1eb2e79fe036658ab5d3a6b60609e7b83d8bd3309dbed0eee156356`.

## Fuzzing

```sh
make check-fuzz     # short deterministic run
make fuzz-psbt      # run until stopped
make fuzz-ur
```

Two harnesses cover everything an attacker controls: `tests/fuzz_psbt.c` feeds arbitrary bytes to
`parser_parse` and then checks the invariants a host relies on (magic, version, counts, script
lengths, derivation depth, and that `parser_prevtx_off/len` stay inside the input buffer), and
`tests/fuzz_ur.c` feeds arbitrary UR parts, one per line, the way an animated QR arrives.

Needs a clang with libFuzzer. Apple's does not ship it; Homebrew's `llvm` does, and the Makefile
links with `lld` because Apple's linker rejects its objects.
