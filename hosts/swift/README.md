# Swift host

Runs on [WasmKit](https://github.com/swiftwasm/WasmKit), a WebAssembly runtime written in Swift —
**no C interop and no native build step**, which is what you want inside an iOS app.
The module has zero imports and does not use WASI, so nothing else is needed.

```swift
import WasmPsbtParser

let parser = try Parser(parserWasm: parserWasmBytes)      // once
let plan = try parser.parse(psbt, fingerprint: 0x73c5da0a) // per transaction

print("\(plan.inputs.count) in / \(plan.outputs.count) out, fee \(plan.fee)")
for out in plan.outputs {
    print(out.amount, out.key.map { "claimed as \($0)" } ?? "")
}
```

Add it to your own package:

```swift
.package(path: "../wasm-psbt-parser/hosts/swift")   // or a URL once this is tagged
```

## What you get

`plan.inputs[i]` — `prevTxid`, `prevVout`, `sequence`, `amount` (`UInt64`, satoshis), `spk`,
`key`, `sighashType`, and `prevtx` (the `non_witness_utxo`, or `nil`).

`plan.outputs[i]` — `amount`, `spk`, `key`.

`key` is a `KeyOrigin?` — BIP380's name for this. It prints as `73c5da0a/84h/0h/0h/0/0`.
**It is a claim**: the module read it out of the PSBT. Derive the key yourself and check it produces
`spk` before you call an output change, or an input yours. `plan.fee` is `totalIn - totalOut`, and
those amounts are claims too until each input's `prevtx` is checked against its `prevTxid`.

Anything the module rejects throws a `ParserError` that prints as `P_ERR_MAGIC`, `UR_ERR_BYTEWORDS`
and so on. `ParserError.outOfBounds` means the module returned an offset outside its own memory —
that would mean it is not the module you think it is.

## Running it

```sh
make run      # prints the plan for a test PSBT
make check    # 66 checks, mirroring hosts/js/test.mjs and hosts/kotlin/Test.kt
```

## Toolchain

WasmKit 0.3.0 and later need a Swift 6.3 toolchain or newer; the one bundled with Xcode may be
older. [swiftly](https://github.com/swiftlang/swiftly) installs one into your home directory
without touching Xcode:

```sh
brew install swiftly && swiftly init --assume-yes --skip-install && swiftly install 6.4.0
export PATH="$HOME/.swiftly/bin:$PATH"
```

Verified with Swift 6.4 and WasmKit 0.4.1 on macOS 15.
