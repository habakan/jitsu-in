# Swift + WasmKit

[WasmKit](https://github.com/swiftwasm/WasmKit) is a WebAssembly runtime written in Swift,
so this runs with no C interop and no native build step — which is what an iOS app would want.

```sh
make run
```

Point it elsewhere with `make run WASM=... PSBT=... FP=...`.

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
