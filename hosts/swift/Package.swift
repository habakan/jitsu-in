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
        .package(url: "https://github.com/swiftwasm/WasmKit.git", from: "0.4.1"),
    ],
    targets: [
        .target(
            name: "WasmPsbtParser",
            dependencies: [.product(name: "WasmKit", package: "WasmKit")],
            swiftSettings: [.swiftLanguageMode(.v5)]
        ),
        .executableTarget(name: "PlanDump", dependencies: ["WasmPsbtParser"],
                          swiftSettings: [.swiftLanguageMode(.v5)]),
        .executableTarget(name: "ParserCheck", dependencies: ["WasmPsbtParser"],
                          swiftSettings: [.swiftLanguageMode(.v5)]),
    ]
)
