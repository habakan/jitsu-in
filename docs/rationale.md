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

Bitcoin's own position is that you should not have to trust anyone — you should be able to check. A
signer is where that is hardest to live up to: it is the one piece that must be trusted absolutely,
and almost nobody can read the whole of one.

**This exists to lower the cost of verifying a signer**, by two means.

**Fewer dependencies, so the supply chain is cheaper to check.** Both modules have zero imports,
pull in no package manager, and are built by a toolchain pinned by version and by hash. The whole of
`parser.wasm` is 15,570 bytes from four C files.

> This lowers the **cost of checking**, not the risk. A dependency you did not audit is no safer for
> being pinned; it is only easier to find out what you are running. Pretending otherwise would be
> the opposite of the point.

**More platforms, so the same program is verified more times.** One module, byte for byte, runs on a
microcontroller with no OS, in a browser, on Android and on iOS. Every platform that loads it is
another set of eyes on the same bytes, and a bug found on one is a bug fixed for all of them — which
is only true because the code is shared rather than reimplemented per platform.

That is what the "runs anywhere" picture is for. Not that portability is convenient: that
**verification accumulates** instead of starting over on each device.

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
