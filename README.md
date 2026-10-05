# wasm-bitcoin-signer

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

## Why two modules

The parser is the most complex code in a signer that reads bytes an attacker chose. Isolating it
means that compromising it does not reach the key: it is not in the same module, and the module it
is in cannot call anything.

What stops a compromised parser lying about the transaction is not the sandbox but the plan. The
signer re-derives every key itself, decides for itself what is change, computes the fee itself, and
builds every string it displays from the plan's bytes. **It then refuses to sign anything but the
plan it was shown**, by requiring the SHA-256 to match. So a malicious parser can make the signer
sign what it displayed, but it cannot display one transaction and sign another.

## Why this is worth sharing

Compiling Bitcoin logic to wasm is not scarce; libwally and BDK do it too. What is scarce is being
able to **check rather than trust**:

| | |
|---|---|
| **no imports** | neither module can call a host function. Verified in CI, not merely intended |
| **memory cannot grow** | built with `--no-growable-memory`, so neither can take more of the host's memory than it declared |
| **a pinned feature set** | [Lime1](https://github.com/WebAssembly/tool-conventions/blob/main/Lime.md), enforced at link time, so a dependency cannot quietly widen what a runtime must support |
| **reproducible** | macOS arm64 and Linux x86_64 give the same bytes from a toolchain pinned by version and by hash |
| **the same answers as Bitcoin Core** | 37 PSBTs agree on the parse, and 8 signatures are byte-identical, ECDSA and Schnorr alike |
| **three host libraries that agree** | JavaScript, Kotlin and Swift, required to produce identical output byte for byte |

That combination is what makes the "runs anywhere" picture mean something. It is not about
portability being convenient — it is that **a review of one of these modules carries over to every
platform that loads it**. The audit amortizes; that is the point.

## Host libraries

No native build in any of them: no JNI, no NDK, no `.so` or XCFramework per architecture.

| | runtime | |
|---|---|---|
| JavaScript / browser / Node | the engine you already have | [parser](parser/hosts/js) · [signer](signer/hosts/js) |
| Kotlin / JVM / **Android** | [Chicory](https://github.com/dylibso/chicory), pure Java | [parser](parser/hosts/kotlin) · [signer](signer/hosts/kotlin) |
| Swift / macOS / **iOS** | [WasmKit](https://github.com/swiftwasm/WasmKit), pure Swift | [parser](parser/hosts/swift) · [signer](signer/hosts/swift) |

Each one bounds-checks every offset the module hands back, and each can refuse a module whose
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
parser/        parser.wasm: sources, its ABI, three host libraries, vectors, fuzzing
signer/        signer.wasm: sources, its ABI, three host libraries, golden signatures
docs/
  module-abi.md   the convention both modules follow, and what a host must do
tools/         checking the shape of the output, the layout, and fetching the pinned toolchain
```

A reference implementation on bare metal — an RP2350 with no operating system, running the same
`parser.wasm` byte for byte — uses these as a submodule.

## Scope

Single-signature P2WPKH ([BIP84](https://github.com/bitcoin/bips/blob/master/bip-0084.mediawiki))
and P2TR key path ([BIP86](https://github.com/bitcoin/bips/blob/master/bip-0086.mediawiki)),
`SIGHASH_ALL` and Taproot's `SIGHASH_DEFAULT`. No multisig, no script trees, no legacy P2PKH
signing.

## Licence

MIT, except where [NOTICE](NOTICE) says otherwise.
