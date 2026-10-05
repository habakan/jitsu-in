# The module convention

<sup>[日本語](ja/module-abi.md)</sup>

Both WebAssembly modules in this repository share one shape. This page is what a host author needs
before reading either module's own documentation.

What makes them worth sharing is not that they are portable — compiling Bitcoin logic to wasm is not
scarce. It is that each one can be **checked rather than trusted**, and a review of one carries over
to every platform that loads it.

## What the modules guarantee

Every one of these is enforced by a check that runs in CI, named beside it. A host may rely on them,
and anyone is welcome to hold their own modules to the same list.

| | what it means | checked by |
|---|---|---|
| **No imports** | The module cannot call out. No clock, no filesystem, no network, no allocator — there is no host function to supply, so `instantiate(bytes, {})` is the whole interface | `make check-wasm` |
| **Memory cannot grow** | The linear memory declares a maximum equal to its minimum, so a malformed input cannot make the module consume the host's memory | `make check-wasm` |
| **No mutable global is exported** | The host cannot reach in and rewrite internal state between calls | `make check-wasm` |
| **A pinned feature set** | The module validates against [Lime1](https://github.com/WebAssembly/tool-conventions/blob/main/Lime.md) — WebAssembly 1.0 plus five standardised features — so it loads on constrained runtimes and cannot silently start needing more | `make check-wasm` |
| **A fixed-layout answer** | What comes back is a struct at a known offset with asserted field offsets, not a serialisation format the host has to parse | `make check-layout` |
| **The bytes rebuild to the same hash** | Building with the pinned toolchain gives the hashes in [checksums.txt](../checksums.txt), so the module a host loads can be tied back to this source | `make check-repro` |
| **Independent hosts agree** | Three host libraries, written separately, must produce byte-identical output over the same input | `make check-hosts-agree` |
| **An outside oracle agrees** | The parser's answers are compared against Bitcoin Core rather than against a second implementation by the same author | `make check-core-diff` |

The first four are properties of the module alone, and a reviewer can confirm them from the `.wasm`
file without building anything. The last four are properties of how it is developed.

None of this is specific to Bitcoin. A module that reads attacker-chosen bytes in any domain can be
held to the same list, and the point of writing it out is that it can be checked against rather than
taken on description.

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
| `parser.wasm` | `parser_` | UR reassembly, PSBT parsing, building the Plan, taking signatures back, UR encoding | [abi.md](../parser/docs/abi.md) | JS, Kotlin, Swift |
| `signer.wasm` | `signer_` | keys, derivation, re-checking a Plan, the display model, signing, xpub export | [abi.md](../signer/docs/abi.md) | JS, Kotlin, Swift |

**`parser.wasm` is finished as a part**: a specification, three host libraries, 529 vectors,
fuzzing, its own CI and a signed release. **`signer.wasm` now matches it** — a specification, host
libraries for JavaScript, Kotlin and Swift, and 74 checks of its own — which is what it needed to stand on its own.

An Android app built on the Kotlin host is in the bare-metal repository (`apps/android`). Its signatures are
byte-identical to the native implementation's, which is the first evidence that these modules are
usable by someone other than this repository's own applications. What building it found is in its
README: the ABI itself needed no Android-specific anything, and the two problems were both packaging.

Three hosts matter more than three times one host: `make check-hosts-agree` runs all of them over
the same PSBT and requires their output to match byte for byte. A single host's tests pass just as happily when the
library and its expectations are wrong together, which is what caught `signer_xpub` returning the
opposite sense from its neighbours.

Three further modules are built from these sources by the bare-metal repository rather than here —
the signing primitives on their own, a scriptPubKey-to-address module, and a QR decoder. They are
tested through the applications that use them, not on their own terms, and a third party should not
expect to drive them from this page.

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
(`wasm_runtime_validate_app_addr`, in the bare-metal repository).
