<h1><img src="docs/bitcoin.svg" width="26" align="top" alt=""> jitsu-in</h1>

> **jitsu-in** — 実印, the registered seal that makes a signature binding in Japan. Not a 認印, the
> everyday stamp you keep in a drawer. The two modules here are named for the two halves of using
> one: 照合 (*shougou*), checking the document against what it claims to be, and 実印 itself, the
> mark that commits you.

**Two WebAssembly modules that split a Bitcoin signer in half.** One reads the untrusted
transaction and holds no keys; the other holds the keys and reads nothing else. Both have **zero
imports**: no clock, no filesystem, no network, nothing to call.

> **Status: experimental, and not audited.** Do not put real funds through it. What a review would
> need to cover is in [docs/module-abi.md](docs/module-abi.md); the signer's own limits are in
> [signer/docs/abi.md](signer/docs/abi.md).

| | bytes | imports | what it does |
|---|---:|---:|---|
| [`parser.wasm`](parser/README.md) | 15,570 | **0** | animated QR (UR) reassembly, PSBT v0 parsing, building a fixed-layout plan, taking signatures back, UR encoding |
| [`signer.wasm`](signer/docs/abi.md) | 56,522 | **0** | keys, BIP32 derivation, re-checking that plan, building what to display, sighash, signing, xpub export |

<img src="docs/everywhere.svg" alt="The same bytes run everywhere: jitsu-in at the centre, six places it has been run" width="940">

Where these have been run, and what the figure does not claim, is in
[docs/everywhere.md](docs/everywhere.md).

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

## Host libraries

No native build in any of them: no JNI, no NDK, no `.so` or XCFramework per architecture.

| | runtime | |
|---|---|---|
| JavaScript / browser / Node | the engine you already have | [parser](parser/hosts/js) · [signer](signer/hosts/js) |
| Kotlin / JVM / **Android** | [Chicory](https://github.com/dylibso/chicory), pure Java | [parser](parser/hosts/kotlin) · [signer](signer/hosts/kotlin) |
| Swift / macOS / **iOS** | [WasmKit](https://github.com/swiftwasm/WasmKit), pure Swift | [parser](parser/hosts/swift) · [signer](signer/hosts/swift) |

The JavaScript libraries ship as plain `.mjs` — importable from Node, a browser or a CDN with no
build step, so what you run is what you can read — with a `.d.mts` beside each for TypeScript. They
are type-checked in place with JSDoc (`make check-types`), and the committed `.d.mts` has to be
current or that check fails.

Each library bounds-checks every offset the module hands back, and each can refuse a module whose
SHA-256 is not the build you expected — which for a module that holds a key is the difference
between running your signer and running someone else's.

## Building and testing

```sh
make deps     # libsecp256k1 at its pinned commit
make          # build/parser.wasm and build/signer.wasm
make test     # the vectors, the host libraries, the layout, the shape of the output
```

Needs clang with the wasm32 target, a wasi-libc sysroot, and Node. With Homebrew:
`brew install llvm lld wasi-libc wasi-runtimes node`.

One test runs `parser.wasm` under [wasmtime](https://wasmtime.dev/) and so wants
[uv](https://docs.astral.sh/uv/) as well; nothing else here needs Python, and nothing needs a second
Bitcoin library. Where an independent opinion is required, it comes from **Bitcoin Core itself**
(`make check-core-diff`, which needs `bitcoind`).

That uses whatever clang you have, which is fine for development but will not reproduce a release
byte for byte. For that, use the pinned toolchain — see
[parser/docs/releases.md](parser/docs/releases.md).

The JVM and Swift host libraries need `kotlinc` and Swift 6.3 or newer:

```sh
make check-signer-kotlin check-signer-swift
make check-hosts-agree       # and require all of them to produce the same bytes
```

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

## Where things are

```
parser/
  c/           the C implementation — what the device ships
  rust/        the Rust implementation — same plan, same tests, measured in BENCHMARK.md
  docs/abi.md  how to drive the module
  hosts/       JavaScript, Kotlin, Swift
  tests/       vectors, the UR reference values, fuzzing
  BENCHMARK.md what the two cost, and why the device takes the C
signer/        signer.wasm: sources, its ABI, three host libraries, golden signatures
docs/
  module-abi.md   the convention both modules follow, and what a host must do
tools/         checking the shape of the output, the layout, and fetching the pinned toolchain
```

**The parser exists twice.** Both are built, and `make check-rust-plan` requires them to return the
same 5,016-byte plan for every vector and for 20,000 mutated PSBTs. That is not only a migration
state: two independent implementations held to the same specification is worth more than either
alone, and it has already found a gap in the vectors that neither one's own tests would have.

`make` builds the C; `make PARSER_IMPL=rust` builds the Rust; `make which-parser` says which one
`build/parser.wasm` currently is. The device takes the C because WAMR's interpreter charges for every
bounds check — the parse costs 3.5x the instructions — and because the Rust AOT wants more pool than
the RP2350 has. [parser/BENCHMARK.md](parser/BENCHMARK.md) has the measurements.

A reference implementation on bare metal — an RP2350 with no operating system, running the same
`parser.wasm` byte for byte — uses these as a submodule.

## Scope

Single-signature P2WPKH ([BIP84](https://github.com/bitcoin/bips/blob/master/bip-0084.mediawiki))
and P2TR key path ([BIP86](https://github.com/bitcoin/bips/blob/master/bip-0086.mediawiki)),
`SIGHASH_ALL` and Taproot's `SIGHASH_DEFAULT`. No multisig, no script trees, no legacy P2PKH
signing.

## Licence

MIT, except where [NOTICE](NOTICE) says otherwise.
