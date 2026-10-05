// swift-tools-version:6.0
import PackageDescription

// WasmSigner is the library; SignerCheck is its tests.
let package = Package(
    name: "WasmSigner",
    platforms: [.macOS(.v15), .iOS(.v18)],
    products: [
        .library(name: "WasmSigner", targets: ["WasmSigner"]),
    ],
    dependencies: [
        // Exact, not "from": WasmKit 0.3.1 onwards declares swift-tools-version 6.3, so this needs
        // Swift 6.3 or newer to resolve at all. A "from:" range picks one of those and then fails
        // on a fresh checkout while still working wherever .build is already populated — which is
        // how this went unnoticed in the parser's host until 2026-10-04
        .package(url: "https://github.com/swiftwasm/WasmKit.git", exact: "0.4.1"),
        // Only for SHA-256 when checking the module's digest. CryptoKit is Apple-only
        .package(url: "https://github.com/apple/swift-crypto.git", exact: "3.15.1"),
    ],
    targets: [
        .target(
            name: "WasmSigner",
            dependencies: [
                .product(name: "WasmKit", package: "WasmKit"),
                .product(name: "Crypto", package: "swift-crypto"),
            ],
            swiftSettings: [.swiftLanguageMode(.v5)]
        ),
        .executableTarget(name: "SignerCheck", dependencies: ["WasmSigner"],
                          swiftSettings: [.swiftLanguageMode(.v5)]),
    ]
)
