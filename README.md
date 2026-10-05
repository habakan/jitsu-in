<h1><img src="docs/bitcoin.svg" width="26" align="top" alt=""> jitsu-in</h1>

<sup>[日本語](docs/ja/README.md)</sup>

**jitsu-in is the signing logic a Bitcoin signer needs, pulled out into WebAssembly modules.**
Being WebAssembly means every platform runs signing logic built from the same source, and each
module runs sandboxed with only what it needs: one reads the untrusted transaction and holds no
keys, the other holds the keys and reads nothing else.

> **Status: experimental, and not audited.** Be careful before putting real funds through it. What
> it handles is in [Scope](#scope); the signer's own limits are in
> [signer/docs/abi.md](signer/docs/abi.md).

<sub>**jitsu-in** — 実印, the registered seal that makes a signature binding in Japan, not the 認印
you keep in a drawer. The two modules are the two halves of using one: 照合, checking the document
against what it claims to be, and 実印 itself, the mark that commits you.</sub>

| | bytes | imports | what it does |
|---|---:|---:|---|
| [`parser.wasm`](parser/README.md) | 15,570 | **0** | animated QR (UR) reassembly, PSBT v0 parsing, building a fixed-layout plan, taking signatures back, UR encoding |
| [`signer.wasm`](signer/docs/abi.md) | 56,522 | **0** | keys, BIP32 derivation, re-checking that plan, building what to display, sighash, signing, xpub export |

<img src="docs/everywhere.svg" alt="The same bytes run everywhere: jitsu-in at the centre, six places it has been run" width="940">

Where these have been run, and what the figure does not claim, is in
[docs/everywhere.md](docs/everywhere.md).

## Using it

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

Why it is shaped this way is in [docs/rationale.md](docs/rationale.md); what is where is in [ARCHITECTURE.md](ARCHITECTURE.md).

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

## Scope

Single-signature P2WPKH ([BIP84](https://github.com/bitcoin/bips/blob/master/bip-0084.mediawiki))
and P2TR key path ([BIP86](https://github.com/bitcoin/bips/blob/master/bip-0086.mediawiki)),
`SIGHASH_ALL` and Taproot's `SIGHASH_DEFAULT`. No multisig, no script trees, no legacy P2PKH
signing.

## Licence

MIT, except where [NOTICE](NOTICE) says otherwise.
