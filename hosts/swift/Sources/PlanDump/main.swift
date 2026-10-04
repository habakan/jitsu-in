// Prints the plan for a PSBT, using the WasmPsbtParser library in this package.
//   make run
import Foundation
import WasmPsbtParser

let args = CommandLine.arguments
guard args.count >= 3 else {
    FileHandle.standardError.write("usage: PlanDump parser.wasm file.psbt [fingerprint]\n".data(using: .utf8)!)
    exit(2)
}
let fingerprint = UInt32(args.count > 3 ? args[3] : "73c5da0a", radix: 16) ?? 0

let parser = try Parser(parserWasm: [UInt8](Data(contentsOf: URL(fileURLWithPath: args[1]))))
let plan = try parser.parse([UInt8](Data(contentsOf: URL(fileURLWithPath: args[2]))), fingerprint: fingerprint)

func btc(_ sats: UInt64) -> String { String(format: "%.8f", Double(sats) / 100_000_000) }
func hex(_ b: [UInt8]) -> String { b.map { String(format: "%02x", $0) }.joined() }

print("version \(plan.txVersion)  locktime \(plan.locktime)  \(plan.inputs.count) in / \(plan.outputs.count) out")
for (i, x) in plan.inputs.enumerated() {
    print("  in  \(i)  \(btc(x.amount))  \(hex(x.spk))  \(x.key.map(String.init(describing:)) ?? "-")")
}
for (i, x) in plan.outputs.enumerated() {
    let mine = x.key.map { "  (change candidate: \($0))" } ?? ""
    print("  out \(i)  \(btc(x.amount))  \(hex(x.spk))\(mine)")
}
// The fee is computed from amounts that are claims until each prevtx is checked
print("  fee     \(btc(plan.fee))")
