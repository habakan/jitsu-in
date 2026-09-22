# wasm-psbt-parser

A PSBT v0 (BIP174) parser that compiles to a ~7 KB WebAssembly module with **no imports and no keys**.
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
fee attack via `non_witness_utxo`). A reference signer lives in
[baremetal-wasm-signer](https://github.com/habakan/baremetal-wasm-signer) (currently private).

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
a script tree (only BIP86 key-path spends are supported).

Limits: PSBT up to 32 KB, 16 inputs, 16 outputs, scriptPubKey up to 83 bytes, derivation depth up to 8.

## Build and test

Requires clang with the wasm32 target, wasi-libc and compiler-rt builtins for wasm32, and [uv](https://docs.astral.sh/uv/)
for the tests. With Homebrew: `brew install llvm lld wasi-libc wasi-runtimes uv`.

```
make          # build/parser.wasm and its SHA-256
make test
```

The tests run `build/parser.wasm` itself under wasmtime:

- the module has no imports;
- Bitcoin Core's `test/functional/data/rpc_psbt.json`: no traps; every invalid vector is rejected except 15 whose
  only defect is in MuSig2 fields this parser does not interpret; valid vectors are accepted or rejected only as
  PSBT v2 (unsupported), missing UTXO data, or a transaction with no inputs;
- PSBTs built with [embit](https://github.com/diybitcoinhardware/embit) (P2WPKH, P2TR, mixed, a foreign input):
  every plan field matches the values the PSBT was built from, and a different fingerprint selects no keys;
- signature insertion: the signed PSBT parses with embit, the transaction is unchanged, the signatures are in the
  right inputs, and invalid signature lists are rejected.

## License

MIT. See [LICENSE](LICENSE) and [NOTICE](NOTICE) for the bundled test data.
