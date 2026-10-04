# Swift + WasmKit

[WasmKit](https://github.com/swiftwasm/WasmKit) is a WebAssembly runtime written in Swift,
so this runs with no C interop and no native build step — which is what an iOS app would want.

```sh
make run
```

Point it elsewhere with `make run WASM=... PSBT=... FP=...`.

## The code

The full example is [`Sources/PlanDump/main.swift`](Sources/PlanDump/main.swift); this is its core:

```swift
let module = try parseWasm(bytes: [UInt8](Data(contentsOf: URL(fileURLWithPath: wasmPath))))
let instance = try module.instantiate(store: Store(engine: Engine()))
guard case let .memory(memory) = instance.export("memory") else { fatalError("no memory") }

func call(_ name: String, _ a: [Value] = []) throws -> Int32 {
    guard case let .function(f) = instance.export(name) else { fatalError("missing \(name)") }
    guard case let .i32(v) = try f.invoke(a).first! else { fatalError("not i32") }
    return Int32(bitPattern: v)
}

// Every read goes through here so the offset and length are checked against the memory size
func bytes(_ offset: Int, _ count: Int) -> [UInt8] {
    precondition(offset >= 0 && count >= 0 && offset + count <= memory.data.count)
    return Array(memory.data[offset ..< offset + count])
}

// Write the PSBT where the module expects it, then parse
let psbt = try [UInt8](Data(contentsOf: URL(fileURLWithPath: psbtPath)))
let input = Int(try call("parser_input"))
memory.withUnsafeMutableBufferPointer(offset: UInt(input), count: psbt.count) {
    $0.copyBytes(from: psbt)
}
let rc = try call("parser_parse", [.i32(UInt32(psbt.count)), .i32(fingerprint)])
guard rc == 0 else { fatalError("P_ERR \(rc)") }

// Read the plan it produced. Offsets come from docs/abi.md
let plan = Int(try call("parser_plan"))
let nOut = Int(bytes(plan + 17, 1)[0])
```

Verified with Swift 6.4 and WasmKit 0.4.1 on macOS 15.

## Toolchain

WasmKit 0.3.0 and later need a Swift 6.3 toolchain or newer; the one bundled with Xcode may be
older. [swiftly](https://github.com/swiftlang/swiftly) installs one into your home directory
without touching Xcode:

```sh
brew install swiftly && swiftly init --assume-yes --skip-install && swiftly install 6.4.0
export PATH="$HOME/.swiftly/bin:$PATH"
```

The target uses `swiftLanguageMode(.v5)` because top-level code is main-actor isolated under
Swift 6 and this example is a plain script.
