# Why it is shaped this way

<sup>[日本語](ja/rationale.md)</sup>

The README says what this is and how to use it. This says why those choices were made.
What is where is in [../ARCHITECTURE.md](../ARCHITECTURE.md); where it has been run is in
[everywhere.md](everywhere.md).

## Why two modules

The parser is the most complex code in a signer that reads bytes an attacker chose. Isolating it
means that compromising it does not reach the key: it is not in the same module, and the module it
is in cannot call anything.

What stops a compromised parser lying about the transaction is not the sandbox but the plan. The
signer re-derives every key itself, decides for itself what is change, computes the fee itself, and
builds every string it displays from the plan's bytes. **It then refuses to sign anything but the
plan it was shown**, by requiring the SHA-256 to match. So a malicious parser can make the signer
sign what it displayed, but it cannot display one transaction and sign another.

## What this is for

Bitcoin lets users verify the rules and transactions for themselves. Signing software is harder to
inspect: it handles the keys and decides what to sign, and few users can review all of its code.

**jitsu-in aims to make a signer easier to verify in two ways.**

**No host imports; pinned build tools.** Both modules have zero imports. The build uses no package
manager, and the toolchain is pinned by version and hash. `parser.wasm` is 15,570 bytes, built from
four C files.

> Pinning makes builds reproducible and identifies the dependencies. It does not make an unaudited
> dependency safe; those dependencies still need review.

**The same module across platforms.** The same wasm file runs on a microcontroller with no OS, in a
browser, on Android and on iOS. Running it in several runtimes checks whether they produce the same
output. A fix to the shared module applies wherever that version is used; runtime and host bugs still
need their own fixes.

The [platform diagram](everywhere.md) lists where the modules have run and what those runs checked.

## What you can check

| | |
|---|---|
| **no imports** | neither module can call a host function — no clock, no network, no syscalls. Verified in CI, not merely intended |
| **memory cannot grow** | built with `--no-growable-memory`, so neither can take more of the host's memory than it declared |
| **a pinned feature set** | [Lime1](https://github.com/WebAssembly/tool-conventions/blob/main/Lime.md), enforced at link time, so a dependency cannot quietly widen what a runtime must support |
| **reproducible** | macOS arm64 and Linux x86_64 give the same bytes from a toolchain pinned by version and by hash |
| **the same answers as Bitcoin Core** | 37 PSBTs agree on the parse, and 8 signatures are byte-identical, ECDSA and Schnorr alike |
| **three host libraries that agree** | JavaScript, Kotlin and Swift, required to produce identical output byte for byte |
| **no package manager** | no npm, no Gradle, no pip. The one Python left is a vector expander with no dependencies; everything else is C, JavaScript, Kotlin or Swift with its tools pinned by hash |

## What is tested

| | |
|---|---|
| the parser | 529 PSBT vectors including Bitcoin Core's own `rpc_psbt.json`, 1,174 UR checks against Blockchain Commons' reference values, continuous fuzzing, a pinned set of exports |
| the signer | 74 checks across three host libraries, with the signatures required to equal what the native implementation produced, byte for byte |
| both | the shape of the output (`make check-wasm`), and that every structure offset in both specifications and all three host libraries equals what C says it is (`make check-layout`) |

Signing is deterministic — ECDSA grinds for a low R as Bitcoin Core does, and Schnorr passes a zero
`aux_rand` — so "the same signature" means identical bytes, not merely another valid one. That is
what lets a browser reproduce a hardware signer's output exactly. **It also has to be revisited
before multisig**, where [BIP340](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki)
says deterministic nonces are unsafe.
