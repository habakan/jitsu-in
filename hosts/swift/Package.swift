// swift-tools-version:6.0
import PackageDescription

// Reads parser.wasm with WasmKit, a WebAssembly runtime written in Swift.
// No native toolchain and no WASI: the module has zero imports.
let package = Package(
    name: "PlanDump",
    platforms: [.macOS(.v15)],
    dependencies: [
        .package(url: "https://github.com/swiftwasm/WasmKit.git", from: "0.4.1"),
    ],
    targets: [
        .executableTarget(
            name: "PlanDump",
            dependencies: [.product(name: "WasmKit", package: "WasmKit")],
            // Top-level code is main-actor isolated under Swift 6; this example is a plain script.
            swiftSettings: [.swiftLanguageMode(.v5)]
        ),
    ]
)
