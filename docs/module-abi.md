# The module convention

Five WebAssembly modules in this repository share one shape. This page is what a host author needs
before reading any single module's own documentation.

The thing that makes these modules worth sharing is not that they are portable — compiling Bitcoin
logic to wasm is not scarce. It is that each one can be checked rather than trusted: no imports, a
memory that cannot grow, a pinned feature set, bytes that rebuild to the same hash, and in the
parser's case answers that match Bitcoin Core's. A review of one of these modules carries over to
every platform that loads it, which is the point of the picture in the README.

## The rules

**One prefix per module, and no two modules share a name.** The prefix matches what the module is:
`parser_`, `signer_`, `prim_`, `addr_`, `qr_`.

This was not true until 2026-10-04: `signer.wasm` and `bitcoin-signer.wasm` both exported
`signer_in`, `signer_init` and `signer_seed_from_mnemonic` with different meanings, so a host loading
both could not tell them apart by name.

**Buffers are reached through accessor functions, never exported as memory offsets.**

| | |
|---|---|
| `<mod>_input` | the buffer the host writes into |
| `<mod>_input_cap` | how many bytes that buffer holds, so a host can bounds-check first |
| `<mod>_output` | the buffer the host reads from |
| a role name | a buffer with one specific job: `parser_plan`, `signer_sigs`, `parser_prevtx_off` |

A module that genuinely has one combined scratch area says so: `prim_io` is a fixed layout of
seckey, message, aux and result, and calling it an input or an output would be a lie.

**Operations are `<mod>_<verb>`.** There is no single return convention, because three different
kinds of thing are being reported, and pretending otherwise would mean a host checking the wrong
sense somewhere. Each module states which of these each function uses:

| | |
|---|---|
| a predicate | `1` on success, `0` on failure, for something that can only fail one way |
| an error code | `0` on success, a positive module-specific code otherwise |
| a count | the number produced, or the negated error code |

Writing the first host library for `signer.wasm` is what found that `signer_xpub` had been returning
`1` for success while `signer_review` next to it returned `0`. It now returns an error code like its
neighbours. A convention nobody has driven from another language is a guess.

**Every module has zero imports.** No clock, no randomness, no filesystem, no network, nothing to
polyfill. A host that needs randomness passes it in through a buffer. This is checked in CI
(`make check-wasm`), not merely intended.

**Memory does not grow.** Built with `--no-growable-memory`, so a module cannot take more of the
host's memory than it declared.

**The feature set is pinned to [Lime1](https://github.com/WebAssembly/tool-conventions/blob/main/Lime.md)**
and enforced at link time, so a dependency cannot quietly widen what a runtime has to support.

**The set of exports is pinned** for the parser (`tools/parser.exports`, compared in CI). Growing it
by accident is how a module starts offering more than it documents.

## The modules

| module | prefix | what it does | spec | host libraries |
|---|---|---|---|---|
| `parser.wasm` | `parser_` | UR reassembly, PSBT parsing, building the Plan, taking signatures back, UR encoding | [abi.md](../components/parser/docs/abi.md) | JS, Kotlin, Swift |
| `signer.wasm` | `signer_` | keys, derivation, re-checking a Plan, the display model, signing, xpub export | [abi.md](../components/signer/docs/abi.md) | JS, Kotlin, Swift |
| `bitcoin-signer.wasm` | `prim_` | the signing primitives on their own; what the RV32 benchmark exercises | none | none |
| `address.wasm` | `addr_` | a scriptPubKey to an address string | none | none |
| `qr.wasm` | `qr_` | QR decoding (quirc), for the browser | none | none |

**`parser.wasm` is finished as a part**: a specification, three host libraries, 529 vectors,
fuzzing, its own CI and a signed release. **`signer.wasm` now matches it** — a specification, host
libraries for JavaScript, Kotlin and Swift, and 74 checks of its own — which satisfies the first of
the conditions in [design.md](design.md) §16 for giving it a repository of its own.

An Android app built on the Kotlin host is in [../apps/android](../apps/android). Its signatures are
byte-identical to the native implementation's, which is the first evidence that these modules are
usable by someone other than this repository's own applications. What building it found is in its
README: the ABI itself needed no Android-specific anything, and the two problems were both packaging.

Three hosts matter more than three times one host: `make check-hosts-agree` runs all of them over
the same PSBT and requires their output to match byte for byte. A single host's tests pass just as happily when the
library and its expectations are wrong together, which is what caught `signer_xpub` returning the
opposite sense from its neighbours.

The remaining three are built and tested through the applications that use them, not on their own
terms, and a third party should not expect to drive them from this page alone.

## Driving one

The shape is always the same. From JavaScript, with `parser.wasm`:

```js
const { instance } = await WebAssembly.instantiate(bytes, {});   // no imports to supply
const e = instance.exports;
const mem = new Uint8Array(e.memory.buffer);

if (psbt.length > e.parser_input_cap()) throw new RangeError("too large");
mem.set(psbt, e.parser_input());
const rc = e.parser_parse(psbt.length, fingerprint);
if (rc !== 0) throw new Error(`refused: ${rc}`);
// then read the plan at e.parser_plan()
```

A host must check every offset and length the module hands back against the bounds of the linear
memory before copying. The three host libraries do this, and so does the device
(`wasm_runtime_validate_app_addr` in `apps/device/runtime/host-abi`).
