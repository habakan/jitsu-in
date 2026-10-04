// Drives parser.wasm from Swift with WasmKit, to show that the ABI needs nothing but a
// WebAssembly runtime: no imports, no WASI, no native toolchain.
//
//   swift run PlanDump ../../build/parser.wasm ../../build/vectors/own_p2wpkh_1in.psbt 73c5da0a
//
// See ../../docs/abi.md. The host must bounds-check, check magic/version, and re-derive keys;
// this example only reads what the parser produced.
import Foundation
import WasmKit

let args = CommandLine.arguments
guard args.count >= 3 else {
    FileHandle.standardError.write("usage: PlanDump parser.wasm file.psbt [fingerprint]\n".data(using: .utf8)!)
    exit(2)
}
let fingerprint = UInt32(args.count > 3 ? args[3] : "73c5da0a", radix: 16) ?? 0

// MARK: - plan_t, as documented in docs/abi.md (ABI version 1)
let PLAN_MAGIC: UInt32 = 0x4e4c_5042  // "BPLN"
let INPUTS_OFF = 24, INPUT_SIZE = 176, OUTPUTS_OFF = 2840, OUTPUT_SIZE = 136
let IN_AMOUNT = 40, IN_SPK = 48, IN_KEY = 132
let OUT_AMOUNT = 0, OUT_SPK = 8, OUT_KEY = 92
let KEY_DEPTH = 0, KEY_FP = 4, KEY_PATH = 8

let module = try parseWasm(bytes: [UInt8](Data(contentsOf: URL(fileURLWithPath: args[1]))))
let engine = Engine()
let store = Store(engine: engine)
let instance = try module.instantiate(store: store)

guard case let .memory(memory) = instance.export("memory") else { fatalError("no memory export") }
func call(_ name: String, _ a: [Value] = []) throws -> Int32 {
    guard case let .function(f) = instance.export(name) else { fatalError("missing export \(name)") }
    guard case let .i32(v) = try f.invoke(a).first! else { fatalError("\(name) returned non-i32") }
    return Int32(bitPattern: v)
}

/// Every read goes through here so the offset and length are checked against the memory size.
func bytes(_ offset: Int, _ count: Int) -> [UInt8] {
    let total = memory.data.count
    precondition(offset >= 0 && count >= 0 && offset + count <= total, "out of bounds \(offset)+\(count)")
    return Array(memory.data[offset ..< offset + count])
}
func u32(_ o: Int) -> UInt32 { bytes(o, 4).withUnsafeBytes { $0.loadUnaligned(as: UInt32.self) } }
func u64(_ o: Int) -> UInt64 { bytes(o, 8).withUnsafeBytes { $0.loadUnaligned(as: UInt64.self) } }

// MARK: - parse
let psbt = try [UInt8](Data(contentsOf: URL(fileURLWithPath: args[2])))
let inputOff = Int(try call("parser_input"))
let cap = Int(try call("parser_input_cap"))
guard psbt.count <= cap else { fatalError("PSBT larger than \(cap)") }
memory.withUnsafeMutableBufferPointer(offset: UInt(inputOff), count: psbt.count) {
    $0.copyBytes(from: psbt)
}

let rc = try call("parser_parse", [.i32(UInt32(psbt.count)), .i32(fingerprint)])
guard rc == 0 else { fatalError("parser_parse failed: P_ERR \(rc)") }

let plan = Int(try call("parser_plan"))
guard u32(plan) == PLAN_MAGIC, u32(plan + 4) == 1 else { fatalError("bad magic or unknown ABI version") }

// MARK: - print
func btc(_ sats: UInt64) -> String { String(format: "%.8f", Double(sats) / 100_000_000) }
func hex(_ b: [UInt8]) -> String { b.map { String(format: "%02x", $0) }.joined() }
func path(_ o: Int) -> String {
    let depth = Int(bytes(o + KEY_DEPTH, 1)[0])
    if depth == 0 { return "-" }
    let steps = (0 ..< depth).map { i -> String in
        let v = u32(o + KEY_PATH + i * 4)
        return v & 0x8000_0000 != 0 ? "\(v & 0x7fff_ffff)h" : "\(v)"
    }
    return String(format: "%08x", u32(o + KEY_FP)) + "/" + steps.joined(separator: "/")
}
func spk(_ o: Int) -> String { hex(bytes(o + 1, Int(bytes(o, 1)[0]))) }

let nIn = Int(bytes(plan + 16, 1)[0]), nOut = Int(bytes(plan + 17, 1)[0])
print("version \(Int32(bitPattern: u32(plan + 8)))  locktime \(u32(plan + 12))  \(nIn) in / \(nOut) out")

var totalIn: UInt64 = 0, totalOut: UInt64 = 0
for i in 0 ..< nIn {
    let o = plan + INPUTS_OFF + i * INPUT_SIZE
    totalIn += u64(o + IN_AMOUNT)
    print("  in  \(i)  \(btc(u64(o + IN_AMOUNT)))  \(spk(o + IN_SPK))  \(path(o + IN_KEY))")
}
for i in 0 ..< nOut {
    let o = plan + OUTPUTS_OFF + i * OUTPUT_SIZE
    totalOut += u64(o + OUT_AMOUNT)
    let mine = bytes(o + OUT_KEY + KEY_DEPTH, 1)[0] != 0 ? "  (change candidate: \(path(o + OUT_KEY)))" : ""
    print("  out \(i)  \(btc(u64(o + OUT_AMOUNT)))  \(spk(o + OUT_SPK))\(mine)")
}
// The host computes the fee itself rather than trusting a field from the parser.
print("  fee     \(btc(totalIn - totalOut))")
