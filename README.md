<h1>jitsu-in</h1>

<sup>[日本語](docs/ja/README.md)</sup>

**jitsu-in provides WebAssembly modules for Bitcoin transaction signing.** `parser.wasm` reads
an untrusted PSBT and builds a fixed-layout plan. `signer.wasm` checks that plan, prepares transaction
details for review, and signs the transaction. The parser has no keys; the signer does not read the PSBT.

> **Status: experimental, and not audited.** Be careful before putting real funds through it. What
> it handles is in [Scope](#scope); the signer's own limits are in
> [signer/docs/abi.md](signer/docs/abi.md).

<sub>**jitsu-in** — 実印, the registered seal that makes a signature binding in Japan, not the 認印
you keep in a drawer. The two modules are the two halves of using one: 照合, checking the document
against what it claims to be, and 実印 itself, the mark that commits you.</sub>

| | bytes | imports | what it does |
|---|---:|---:|---|
| [`parser.wasm`](parser/README.md) | 15,632 | **0** | animated QR (UR) reassembly, PSBT v0 parsing, building a fixed-layout plan, taking signatures back, UR encoding |
| [`signer.wasm`](signer/docs/abi.md) | 77,520 | **0** | keys, SeedQR, BIP32 derivation, re-checking that plan, building what to display, sighash, signing, BIP137 messages, xpub export |

<img src="docs/everywhere.svg" alt="The same bytes run everywhere: jitsu-in at the centre, six places it has been run" width="940">

The tested runtimes and the limits of those tests are in [docs/everywhere.md](docs/everywhere.md).

## Using it

No native build in any of them: no JNI, no NDK, no `.so` or XCFramework per architecture.

The [browser viewer](examples/viewer) combines the parser host with a single-file PSBT and UR review
page. It holds no keys and is not a signing device.

| | runtime | |
|---|---|---|
| JavaScript / browser / Node | the engine you already have | [parser](parser/hosts/js) · [signer](signer/hosts/js) |
| Kotlin / JVM / **Android** | [Chicory](https://github.com/dylibso/chicory), pure Java | [parser](parser/hosts/kotlin) · [signer](signer/hosts/kotlin) |
| Swift / macOS / **iOS** | [WasmKit](https://github.com/swiftwasm/WasmKit), pure Swift | [parser](parser/hosts/swift) · [signer](signer/hosts/swift) |

The JavaScript libraries ship as plain `.mjs` — importable from Node, a browser or a CDN with no
build step, so what you run is what you can read — with a `.d.mts` beside each for TypeScript. They
are type-checked in place with JSDoc (`make check-types`), and the committed `.d.mts` has to be
current or that check fails.

The JavaScript, Kotlin and Swift host libraries check offsets returned by the modules and can pin
each module's SHA-256. A host configured with that hash can refuse a different build before it runs.

See [the design rationale](docs/rationale.md) and [the repository map](ARCHITECTURE.md).

## Building and testing

```sh
make deps     # libsecp256k1 at its pinned commit
make          # build/parser.wasm and build/signer.wasm
make test     # the vectors, the host libraries, the layout
make check-wasm   # the shape of the output (needs wasm-tools)
make check-c-format check-c-tidy
```

`make wamr-deps && make check-wamr` runs the parser vectors and the signer's JavaScript tests in WAMR
too, with the same test suites as Node/V8, and requires the signer's output to match V8's byte for
byte. WAMR 2.4.5 is pinned for this check.

`make format-c` applies the C formatting rules. Formatting and the parser's static analysis use the
clang-format and clang-tidy shipped with the pinned wasi-sdk toolchain in CI.

Needs clang with the wasm32 target, a wasi-libc sysroot, and Node. With Homebrew:
`brew install llvm lld wasi-libc wasi-runtimes node cmake`.

Both modules' tests run under Node/V8 and WAMR's classic interpreter. Where an independent opinion is
required, it comes from **Bitcoin Core itself** (`make check-core-diff`, which needs `bitcoind`).

That uses whatever clang you have, which is fine for development but will not reproduce a release
byte for byte. For that, use the pinned toolchain — see
[parser/docs/releases.md](parser/docs/releases.md).

The JVM and Swift host libraries need `kotlinc` and Swift 6.3 or newer:

```sh
make check-signer-kotlin check-signer-swift
make check-hosts-agree       # and require all of them to produce the same bytes
```

## Scope

Single-signature P2WPKH ([BIP84](https://github.com/bitcoin/bips/blob/master/bip-0084.mediawiki)),
P2SH-P2WPKH ([BIP49](https://github.com/bitcoin/bips/blob/master/bip-0049.mediawiki))
and P2TR key path ([BIP86](https://github.com/bitcoin/bips/blob/master/bip-0086.mediawiki)),
`SIGHASH_ALL` and Taproot's `SIGHASH_DEFAULT`. No multisig, no script trees, no legacy P2PKH
signing.

## Licence

MIT, except where [NOTICE](NOTICE) says otherwise.
