// Tests the host, not the parser: the module itself is covered by the 529 vectors in tools/run_tests.py.
// Mirrors hosts/js/test.mjs and hosts/kotlin/Test.kt, so a host that behaves differently shows up here.
import Foundation
import WasmPsbtParser

let args = CommandLine.arguments
let wasmPath = args.count > 1 ? args[1] : "../../build/parser.wasm"
let vectorDir = args.count > 2 ? args[2] : "../../build/vectors"
let parserWasm = [UInt8](try Data(contentsOf: URL(fileURLWithPath: wasmPath)))
let fp: UInt32 = 0x73c5_da0a

var checks = 0, failures = 0
func check(_ cond: Bool, _ what: String) {
    checks += 1
    if !cond { failures += 1; print("FAIL \(what)") }
}
func throwsError(_ want: String, _ what: String, _ body: () throws -> Void) {
    checks += 1
    do { try body(); failures += 1; print("FAIL \(what): did not throw") }
    catch { if !"\(error)".contains(want) { failures += 1; print("FAIL \(what): \(error)") } }
}
func load(_ name: String) throws -> [UInt8] {
    [UInt8](try Data(contentsOf: URL(fileURLWithPath: "\(vectorDir)/\(name)")))
}

let names = try FileManager.default.contentsOfDirectory(atPath: vectorDir).sorted()

// the hand-made vectors parse, and the shape is sane
let own = names.filter { $0.hasPrefix("own_") && $0.hasSuffix(".psbt") }
check(own.count >= 4, "\(own.count) hand-made vectors")
for name in own {
    let plan = try Parser(parserWasm: parserWasm).parse(try load(name), fingerprint: fp)
    check(!plan.inputs.isEmpty && !plan.outputs.isEmpty, "\(name): has inputs and outputs")
    check(plan.fee > 0 && plan.fee < 1_000_000, "\(name): fee \(plan.fee) is plausible")
    check(plan.totalIn - plan.totalOut == plan.fee, "\(name): fee is in minus out")
    for i in plan.inputs {
        check(i.prevTxid.count == 32, "\(name): txid is 32 bytes")
        check(!i.spk.isEmpty && i.spk.count <= 83, "\(name): input spk length")
        check(i.prevtx == nil || i.prevtx!.count > 60, "\(name): prevtx looks like a transaction")
    }
    for o in plan.outputs { check(!o.spk.isEmpty && o.spk.count <= 83, "\(name): output spk length") }
}

// what Bitcoin Core marks invalid is rejected, as a ParserError and not a crash
let invalid = names.filter { $0.hasPrefix("rpc_invalid") && $0.hasSuffix(".psbt") }
check(invalid.count > 50, "\(invalid.count) invalid vectors")
var rejected = 0
for name in invalid {
    do { _ = try Parser(parserWasm: parserWasm).parse(try load(name), fingerprint: fp) }
    catch is ParserError { rejected += 1 }
    catch { failures += 1; print("FAIL \(name): \(error)") }
}
checks += 1
if Double(rejected) < Double(invalid.count) * 0.8 {
    failures += 1; print("FAIL only \(rejected)/\(invalid.count) rejected")
}

// a derivation prints the way a human reads it, and matches the other hosts
do {
    let plan = try Parser(parserWasm: parserWasm).parse(try load("own_p2wpkh_1in.psbt"), fingerprint: fp)
    check("\(plan.inputs[0].key!)" == "73c5da0a/84h/0h/0h/0/0", "keypath prints as \(plan.inputs[0].key!)")
    check(plan.inputs[0].key!.fingerprint == fp, "fingerprint is kept as a number")
}

// a fingerprint that matches nothing claims nothing
do {
    let plan = try Parser(parserWasm: parserWasm).parse(try load("own_p2wpkh_1in.psbt"), fingerprint: 0)
    check(plan.inputs.allSatisfy { $0.key == nil }, "a fingerprint that matches nothing claims nothing")
}

// errors arrive as names, not numbers
do {
    let p = try Parser(parserWasm: parserWasm)
    throwsError("P_ERR_MAGIC", "not a PSBT") { _ = try p.parse([1, 2, 3, 4, 5], fingerprint: 0) }
    throwsError("does not fit", "too large for the buffer") {
        _ = try p.parse([UInt8](repeating: 0, count: p.inputCapacity + 1), fingerprint: 0)
    }
    throwsError("UR_ERR_SCHEME", "not a UR") { _ = try p.urReceive("not a ur") }
}

// UR: encode what finalize produced, feed the parts back, get the same bytes
do {
    let enc = try Parser(parserWasm: parserWasm)
    _ = try enc.parse(try load("own_mixed_nwu.psbt"), fingerprint: fp)
    let out = try enc.finalize([])              // no signatures: re-serializes into the output buffer
    check(out.count > 100, "finalize produced \(out.count) bytes")

    let seq = try enc.urEncode(psbtLen: out.count, fragmentLen: 100)
    check(seq.seqLen > 1, "splits into \(seq.seqLen) parts")

    let dec = try Parser(parserWasm: parserWasm)
    try dec.urReset()
    var got: [UInt8]? = nil
    var n = 0
    while got == nil && n < seq.seqLen * 3 { got = try dec.urReceive(try seq.next()); n += 1 }
    check(got != nil, "reassembles")
    check(got == out, "round trip is byte identical")
}

print("\(checks - failures)/\(checks) checks passed")
exit(failures != 0 ? 1 : 0)
