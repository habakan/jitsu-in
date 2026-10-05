// swift-tools-version:6.0
import PackageDescription

// WasmPsbtParser is the library; PlanDump and ParserCheck are the demo and the tests.
let package = Package(
    name: "WasmPsbtParser",
    platforms: [.macOS(.v15), .iOS(.v18)],
    products: [
        .library(name: "WasmPsbtParser", targets: ["WasmPsbtParser"]),
    ],
    dependencies: [
        // Exact, not "from": WasmKit 0.3.1 onwards declares swift-tools-version 6.3, so this needs
        // Swift 6.3 or newer to resolve at all. A "from:" range picks one of those and then fails on
        // a fresh checkout while still working wherever .build is already populated, which is how
        // this went unnoticed here until 2026-10-04
        .package(url: "https://github.com/swiftwasm/WasmKit.git", exact: "0.4.1"),
        // Only for SHA-256 when checking the module's digest. CryptoKit is Apple-only
        .package(url: "https://github.com/apple/swift-crypto.git", exact: "3.15.1"),
    ],
    targets: [
        .target(
            name: "WasmPsbtParser",
            dependencies: [
                .product(name: "WasmKit", package: "WasmKit"),
                .product(name: "Crypto", package: "swift-crypto"),
            ],
            swiftSettings: [.swiftLanguageMode(.v5)]
        ),
        .executableTarget(name: "PlanDump", dependencies: ["WasmPsbtParser"],
                          swiftSettings: [.swiftLanguageMode(.v5)]),
        .executableTarget(name: "ParserCheck", dependencies: ["WasmPsbtParser"],
                          swiftSettings: [.swiftLanguageMode(.v5)]),
    ]
)
