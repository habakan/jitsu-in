# signer.wasm in Swift

A host for `signer.wasm` that runs on macOS and iOS. It uses
[WasmKit](https://github.com/swiftwasm/WasmKit), a WebAssembly runtime written in Swift: **no C
interop and no native build step.** The module has zero imports and does not use WASI, so nothing
else is needed.

The ABI is in [../../docs/abi.md](../../docs/abi.md). What is specific to holding a key is under
"What a host must not do" there, and this library enforces what it can.

## Which Swift

WasmKit 0.3.1 onwards declares `swift-tools-version: 6.3`, so **this needs Swift 6.3 or newer**. On
an older Swift it fails to resolve rather than to compile:

```
error: 'wasmkit': package 'wasmkit' @ 0.4.1 is using Swift tools version 6.3.0
       but the installed version is 6.1.0
```

The versions are pinned exactly rather than with `from:`. A range keeps working wherever `.build` is
already populated while failing for anyone starting fresh — which is exactly how this went unnoticed
in the parser's Swift host until someone tried a clean checkout.

## Testing

```sh
make check    # 25 checks, against the signatures the native signer produced
```

## Using it

```swift
import WasmSigner

// Pin the hash. A module that holds a key is the last place to accept whatever bytes arrived.
let signer = try Signer(signerWasm: signerWasm, sha256: "6f05069b…")
try signer.initialise(testnet: false)

// A mutable array, not a String: a Swift String cannot be cleared, and this one is zeroed for you
var mnemonic = [UInt8](mnemonicText.utf8)
var passphrase: [UInt8] = []
try signer.seedFromMnemonic(&mnemonic, passphrase: &passphrase)
print(signer.fingerprint)                    // "73c5da0a"

try signer.setPlan(plan).setPrevTxs(prevTxs) // plan comes from parser.wasm, verbatim

let review = try signer.review()             // re-derives the keys and checks the plan
let display = try signer.display()            // what to put in front of the person approving
for o in display.outputs {
    print("\(o.amount) sats to \(o.text) (\(o.owner))")
}
print("fee \(display.fee)")

// Only after someone has actually approved what display() returned
let signatures = try signer.sign()            // one review permits one signing
signer.unload()                               // zeroes the key; do not wait until you remember
```

Hand each `Signature.raw` to `parser.wasm`'s signature buffer and call `parser_finalize()`.

## On iOS

WasmKit is a Swift package, so this is a package dependency and nothing more — no XCFramework, no
bitcode, no per-architecture build. The module's bytes ship in the app bundle, and pinning its
SHA-256 means a replaced resource is refused rather than run.

`seedFromMnemonic` takes `inout [UInt8]` so it can be cleared. A `String` from a `TextField` cannot
be, so copy out of it into a mutable array and clear that; the array you pass is zeroed here.

## Agreeing with the other hosts

`make -C ../../../.. check-hosts-agree` runs the JavaScript, Kotlin and Swift libraries over the same
PSBT and requires their output to match byte for byte. Three independent hosts reading the same
module is what catches one of them reading the layout wrong — a single host's tests pass just as
happily when the library and its expectations are wrong together.
