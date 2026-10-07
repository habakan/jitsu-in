# parser.wasm

A PSBT v0 ([BIP174](https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki)) parser, with animated-QR (UR) decoding and encoding, that compiles to a ~16 KB WebAssembly module with
**no imports and no keys**.
It turns an untrusted PSBT into a fixed-layout *plan* (`include/plan.h`) that a signer can check and sign,
and inserts the signer's signatures back into the PSBT.

> **Status: experimental.** Not audited. Do not use with real funds.

## Why

In an air-gapped hardware signer, the PSBT parser is the most complex code that reads attacker-controlled input.
This module is meant to run inside a WebAssembly sandbox (e.g. WAMR on a microcontroller) while the keys, sighash
computation and signing stay in native code outside the sandbox:

- The module has **zero imports**. It cannot call the host, draw on the screen, read keys or produce randomness.
  The host only reads and writes buffers the module exports, after bounds-checking the addresses.
- It never sees private keys. If a malicious PSBT compromises the parser, it still cannot reach the keys.
- The signer derives what it shows and what it signs from the **same** plan. A compromised parser can make the
  signer sign what it displays, but not display one transaction and sign another.

The signer is still responsible for checking the plan (key ownership, change detection, fees, and the SegWit v0
fee attack via `non_witness_utxo`); see [the ABI](docs/abi.md) for the full list of what a host must do.

## Releases

Each release carries a `SHA256SUMS`, a detached PGP signature over it, and a GitHub build
provenance attestation — and the build is reproducible, so you can skip all three and check the
bytes yourself. See [docs/releases.md](docs/releases.md).

## Animated QR (UR)

PSBTs usually arrive as animated QR codes in the [Uniform Resources](https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2020-005-ur.md)
format (`ur:crypto-psbt/...` or `ur:psbt/...`). The module reassembles them itself, so the fountain decoding of
untrusted QR payloads also stays inside the sandbox:

```
parser_ur_reset()
parser_ur_receive(len) -> PSBT length once complete (the PSBT is then in the input buffer for parser_parse),
                          0 while more parts are needed, or a negative UR_ERR_* (include/ur.h)
parser_ur_progress()   -> parts expected (upper 16 bits) and fragments recovered (lower 16 bits)
```

The signed PSBT goes back the same way:

```
parser_ur_encode_start(len, max_fragment_len) -> number of pure parts (len is what parser_finalize() returned)
parser_ur_encode_next()                       -> length of the next part, written to the input buffer
```

Parts are uppercase (QR alphanumeric mode) `ur:crypto-psbt` parts. After the pure parts come mixed ones, so a
device can loop them and a scanner that missed some still recovers the PSBT. The encoder builds each fragment on
the fly from the output buffer, without a second copy of the message.

Parts may arrive in any order, in either case, with duplicates, and mixed with parts of another message (those are
rejected without disturbing the rest). Limits: 1024 parts per message, and up to 64 mixed parts (16 KB) kept while
waiting to be reduced; the oldest is dropped when full. The PRNG, alias sampler and shuffle that decide which
fragments a mixed part combines match the Blockchain Commons reference implementation bit for bit.

## Interface

```
parser_input()        -> address of the 32 KB input buffer
parser_parse(len, fp) -> 0 or an error code (include/psbt_parser.h)
parser_plan()         -> address of plan_t
parser_prevtx_off(i)  -> offset/length of input i's non_witness_utxo inside the input buffer
parser_prevtx_len(i)
parser_sigs()         -> address of plan_sig_t[16] for the host to fill
parser_finalize(n)    -> length of the signed PSBT, or a negative error
parser_output()       -> address of the signed PSBT
```

`fp` is the signer's master key fingerprint (not a secret). Only derivation paths with this fingerprint become
key candidates, so the signer never learns about cosigners' paths.

`plan_t` has no pointers or `long`s, and its size and offsets are pinned with `_Static_assert`, so wasm32,
RV32 and 64-bit hosts share the same layout.

## What it checks

Strict for the fields it interprets: duplicate keys, key/value lengths per type, PSBT v2-only fields,
scriptSig/witness in the unsigned transaction, `non_witness_utxo` txid and its consistency with `witness_utxo`,
trailing bytes, and the limits below.

Fields it does not interpret (MuSig2, script-path details, proprietary) are passed through untouched.
It does not check that public keys are on the curve: the signer is expected to derive its own keys instead of
trusting the PSBT.

It never marks these inputs as signable: finalized inputs, inputs that already carry the candidate key's signature, and P2TR inputs with
a script tree (only [BIP86](https://github.com/bitcoin/bips/blob/master/bip-0086.mediawiki) key-path spends are supported).

Limits: PSBT up to 32 KB, 16 inputs, 16 outputs, scriptPubKey up to 83 bytes, derivation depth up to 8.

## Build and test

Requires clang with the wasm32 target, wasi-libc, compiler-rt builtins for wasm32, Node and Python 3.
For the WAMR interpreter check, run `make wamr-deps && make check-wamr` from the repository root.
With Homebrew: `brew install llvm lld wasi-libc wasi-runtimes node cmake`.

```
make          # build/parser.wasm and its SHA-256
make test
```

This uses whatever clang you have, which is fine for development but will not reproduce a release
byte for byte. To do that, use the pinned toolchain — see [docs/releases.md](docs/releases.md).

The UR building blocks are first checked natively (with ASan / UBSan) against the expected values of the
[bc-ur](https://github.com/BlockchainCommons/bc-ur) test suite (`tests/bc-ur-test.cpp`, extracted by
`tools/gen_ur_ref_vectors.py`): CRC32, Bytewords, the Xoshiro256** sequences, 500 sampler draws, shuffles,
200 degree choices, fragment choices, and the single-part and 20-part example URs. On a sequence with a dropped
part in reverse order, the decoder needs the same number of parts (16) as the reference decoder.

The same JavaScript vector suite runs `build/parser.wasm` under Node/V8 and WAMR's classic interpreter.

- the module has no imports;
- Bitcoin Core's `test/functional/data/rpc_psbt.json`: no traps; every invalid vector is rejected except 15 whose
  only defect is in MuSig2 fields this parser does not interpret; valid vectors are accepted or rejected only as
  PSBT v2 (unsupported), missing UTXO data, or a transaction with no inputs;
- PSBTs built with [embit](https://github.com/diybitcoinhardware/embit) (P2WPKH, P2SH-P2WPKH, P2TR, mixed, a
  foreign input):
  every plan field matches the values the PSBT was built from, and a different fingerprint selects no keys;
- signature insertion: the signed PSBT parses with embit, the transaction is unchanged, the signatures are in the
  right inputs, and invalid signature lists are rejected;
- UR: the same PSBTs encoded as `crypto-psbt` and `psbt` URs by [@ngraveio/bc-ur](https://github.com/ngraveio/bc-ur)
  (`tests/ur_vectors.json`, from `tools/gen_ur_vectors.cjs`) reassemble to the original bytes with every third pure
  part dropped, and then parse;
- UR encoding: the module encodes each of those PSBTs part for part identically to the reference encoder, and its
  parts decode back to the PSBT. Natively, it reproduces bc-ur's 20-part and single-part example URs character for
  character.

## License

MIT. See [LICENSE](../LICENSE) and [NOTICE](../NOTICE) for the bundled test data.

## Fuzzing

`make check-fuzz` runs both harnesses for a fixed number of iterations; `make fuzz-psbt` and
`make fuzz-ur` run until stopped. See [docs/abi.md](docs/abi.md).
