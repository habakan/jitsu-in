// Drives signer.wasm through the host library and checks the result against what the native side
// produced. The signatures are deterministic, so "the same" means byte-identical, not merely valid.
//
//   swift run SignerCheck <signer.wasm> <parser.wasm> <psbt> <natively-signed-psbt>
//   swift run SignerCheck --dump <signer.wasm> <parser.wasm> <psbt>
import Foundation
import WasmKit
import WasmSigner

let planSize = 5016
var pass = 0, fail = 0

func check<T: Equatable>(_ what: String, _ got: T, _ want: T) {
    if got == want { pass += 1 } else { fail += 1; print("FAIL \(what)\n  got  \(got)\n  want \(want)") }
}
func ok(_ what: String, _ cond: Bool) {
    if cond { pass += 1 } else { fail += 1; print("FAIL \(what)") }
}
func hex(_ b: [UInt8]) -> String { b.map { String(format: "%02x", $0) }.joined() }

/// parser.wasm turns the PSBT into a plan; signer.wasm is what is being tested here.
func planFor(_ parserWasm: [UInt8], _ psbt: [UInt8], _ fingerprint: UInt32) throws
    -> ([UInt8], [[UInt8]?]) {
    let module = try parseWasm(bytes: parserWasm)
    let inst = try module.instantiate(store: Store(engine: Engine()))
    guard case let .memory(mem) = inst.export("memory") else { fatalError("no memory") }
    func call(_ n: String, _ a: [Value] = []) throws -> Int32 {
        guard case let .function(f) = inst.export(n) else { fatalError("\(n) missing") }
        guard let v = try f.invoke(a).first, case let .i32(x) = v else { return 0 }
        return Int32(bitPattern: x)
    }
    func read(_ o: Int, _ n: Int) -> [UInt8] {
        mem.withUnsafeMutableBufferPointer(offset: UInt(o), count: n) {
            Array($0.bindMemory(to: UInt8.self))
        }
    }
    let inputAt = Int(try call("parser_input"))
    mem.withUnsafeMutableBufferPointer(offset: UInt(inputAt), count: psbt.count) {
        $0.copyBytes(from: psbt)
    }
    let rc = try call("parser_parse", [.i32(UInt32(psbt.count)), .i32(fingerprint)])
    guard rc == 0 else { fatalError("the parser refused the PSBT: \(rc)") }
    let plan = read(Int(try call("parser_plan")), planSize)
    let nIn = Int(plan[16])
    var prev: [[UInt8]?] = []
    for i in 0 ..< nIn {
        let len = Int(try call("parser_prevtx_len", [.i32(UInt32(i))]))
        if len == 0 { prev.append(nil); continue }
        prev.append(read(inputAt + Int(try call("parser_prevtx_off", [.i32(UInt32(i))])), len))
    }
    return (plan, prev)
}

var args = Array(CommandLine.arguments.dropFirst())
let dumpOnly = args.first == "--dump"
if dumpOnly { args.removeFirst() }

let signerWasm = [UInt8](try Data(contentsOf: URL(fileURLWithPath: args[0])))
let parserWasm = [UInt8](try Data(contentsOf: URL(fileURLWithPath: args[1])))
let psbt = [UInt8](try Data(contentsOf: URL(fileURLWithPath: args[2])))
let mnemonicText = String(repeating: "abandon ", count: 11) + "about"
let fp: UInt32 = 0x73c5_da0a

func freshSigner() throws -> Signer {
    let s = try Signer(signerWasm: signerWasm)
    try s.initialise()
    var mn = [UInt8](mnemonicText.utf8), pass: [UInt8] = []
    try s.seedFromMnemonic(&mn, passphrase: &pass)
    return s
}

let (plan, prevTxs) = try planFor(parserWasm, psbt, fp)

if dumpOnly {
    let s = try freshSigner()
    try s.setPlan(plan).setPrevTxs(prevTxs)
    _ = try s.review()
    let d = try s.display()
    print("fingerprint \(s.fingerprint)")
    print("fee \(d.fee) spend \(d.spend)")
    let owner = ["EXTERNAL", "CHANGE", "SELF"], kind = ["ADDRESS", "OP_RETURN", "SCRIPT"]
    for o in d.outputs {
        print("out \(o.amount) \(owner[Int(o.owner.rawValue)]) \(kind[Int(o.textKind.rawValue)]) \(o.text)")
    }
    for sig in try s.sign() { print("sig \(sig.input) \(hex(sig.sig))") }
    var rolls = [UInt8](String(repeating: "3", count: 99).utf8)
    print("dice \(String(decoding: try s.mnemonicFromDice(&rolls), as: UTF8.self))")
    var abandon = [UInt8](mnemonicText.utf8)
    print("seedqr \(String(decoding: try s.seedQRFromMnemonic(&abandon), as: UTF8.self))")
    s.unload()
    var qr: [UInt8] = [0x5b, 0xbd, 0x9d, 0x71, 0xa8, 0xec, 0x79, 0x90, 0x83, 0x1a, 0xff, 0x35, 0x9d, 0x42, 0x65, 0x45]
    var none: [UInt8] = []
    print("seedqr fingerprint \(try s.initialise().seedFromSeedQR(&qr, passphrase: &none).fingerprint)")
    s.unload()
    exit(0)
}

let nativelySigned = [UInt8](try Data(contentsOf: URL(fileURLWithPath: args[3])))

// --- a module that is not the expected build is refused
do {
    _ = try Signer(signerWasm: signerWasm, sha256: String(repeating: "00", count: 32))
    ok("a wrong sha256 is refused", false)
} catch {
    ok("a wrong sha256 is refused", "\(error)".contains("not the expected build"))
}

let s = try Signer(signerWasm: signerWasm)
try s.initialise()
check("fingerprint before a seed", s.fingerprint, "00000000")
var mn = [UInt8](mnemonicText.utf8), pw: [UInt8] = []
try s.seedFromMnemonic(&mn, passphrase: &pw)
check("fingerprint from the BIP39 test vector", s.fingerprint, "73c5da0a")
ok("the mnemonic array was cleared", mn.allSatisfy { $0 == 0 })

// --- a full round, compared against the native signer's output
try s.setPlan(plan).setPrevTxs(prevTxs)
let r = try s.review()
ok("review says it will sign something", r.nSign > 0)
check("fee is total in minus total out", r.fee, r.totalIn - r.totalOut)

let d = try s.display()
check("the fee review and display agree", d.fee, r.fee)
ok("every output has text", d.outputs.allSatisfy { !$0.text.isEmpty })
ok("an address is shown as an address", d.outputs.contains {
    $0.textKind == .address && ($0.text.hasPrefix("bc1") || $0.text.hasPrefix("tb1"))
})
ok("change is marked as change", d.outputs.contains { $0.owner == .change })
check("spend excludes our own outputs", d.spend,
      d.outputs.filter { $0.owner == .external }.reduce(UInt64(0)) { $0 + $1.amount })

let sigs = try s.sign()
check("one signature per input review chose", sigs.count, r.nSign)

// The native host wrote these; deterministic signing means they have to match to the byte
let nativeHex = hex(nativelySigned)
for sig in sigs {
    ok("input \(sig.input): the signature appears in the natively signed PSBT",
       nativeHex.contains(hex(sig.sig)))
}
ok("ECDSA carries its sighash byte", sigs.contains { $0.sig.count >= 70 && $0.sig[0] == 0x30 })
ok("Schnorr is 64 bytes", sigs.contains { $0.sig.count == 64 })

// --- one approval permits one signing, and no more
do {
    _ = try s.sign()
    ok("a second sign without reviewing again is refused", false)
} catch {
    ok("a second sign without reviewing again is refused",
       "\(error)".contains("one approval permits one signing"))
}

// --- reviewing the same plan again and signing gives the same bytes
_ = try s.review()
check("signing the same plan again is byte-identical", hex(try s.sign()[0].sig), hex(sigs[0].sig))

// --- xpub, against BIP84's published vector
let x = try s.xpub()
ok("the descriptor names the account", x.descriptor.hasPrefix("wpkh([73c5da0a/84h/0h/0h]"))
ok("the descriptor covers receive and change", x.descriptor.contains("<0;1>/*"))
ok("the xpub is an xpub", x.xpub.hasPrefix("xpub"))

// --- signing without a review is refused
do {
    let s2 = try freshSigner()
    try s2.setPlan(plan).setPrevTxs(prevTxs)
    _ = try s2.sign()
    ok("signing without review is refused", false)
} catch {
    ok("signing without review is refused", "\(error)".contains("review() has to pass first"))
}

// --- a plan of the wrong size never reaches the module
do {
    try s.setPlan([UInt8](repeating: 0, count: 100))
    ok("a plan of the wrong size is refused", false)
} catch {
    ok("a plan of the wrong size is refused", "\(error)".contains("does not fit"))
}

// --- an oversized mnemonic is rejected before anything is written
do {
    var big = [UInt8](repeating: 0x78, count: 600), none: [UInt8] = []
    try s.seedFromMnemonic(&big, passphrase: &none)
    ok("an oversized mnemonic is refused", false)
} catch {
    ok("an oversized mnemonic is refused", "\(error)".contains("does not fit"))
}

// --- making a new mnemonic, from entropy and from dice, against BIP39's and the dice vectors
do {
    let g = try Signer(signerWasm: signerWasm)
    try g.initialise()
    var ent: [UInt8] = [0x9e, 0x88, 0x5d, 0x95, 0x2a, 0xd3, 0x62, 0xca, 0xeb, 0x4e, 0xfe, 0x34, 0xa8, 0xe9, 0x1b, 0xd2]
    var mn = try g.mnemonicFromEntropy(&ent)
    check("BIP39's 9e885d95... vector", String(decoding: mn, as: UTF8.self), "ozone drill grab fiber curtain grace pudding thank cruise elder eight picnic")
    ok("the entropy passed in is zeroed", ent.allSatisfy { $0 == 0 })
    var none: [UInt8] = []
    check("the generated words load", try g.seedFromMnemonic(&mn, passphrase: &none).fingerprint.count, 8)
    var rolls = [UInt8](String(repeating: "1", count: 50).utf8)
    check("50 dice rolls", String(decoding: try g.mnemonicFromDice(&rolls, words: 12), as: UTF8.self), "diet glad hat rural panther lawsuit act drop gallery urge where fit")
    do {
        var short = [UInt8](String(repeating: "1", count: 98).utf8)
        _ = try g.mnemonicFromDice(&short)
        ok("98 rolls for 24 words are refused", false)
    } catch {
        ok("98 rolls for 24 words are refused", "\(error)" == "mnemonic_from_dice failed")
    }
    g.unload()
}

// --- making a SeedQR from the words, against the published vector 4, and reading it back
do {
    let q = try Signer(signerWasm: signerWasm)
    try q.initialise()
    var words = [UInt8]("forum undo fragile fade shy sign arrest garment culture tube off merit".utf8)
    check("Standard SeedQR digits", String(decoding: try q.seedQRFromMnemonic(&words), as: UTF8.self), "073318950739065415961602009907670428187212261116")
    ok("the words passed in are zeroed", words.allSatisfy { $0 == 0 })
    var again = [UInt8]("forum undo fragile fade shy sign arrest garment culture tube off merit".utf8), none: [UInt8] = []
    var compact = try q.seedQRFromMnemonic(&again, compact: true)
    check("CompactSeedQR bytes", hex(compact), "5bbd9d71a8ec7990831aff359d426545")
    var typed = [UInt8]("forum undo fragile fade shy sign arrest garment culture tube off merit".utf8)
    let want = try q.seedFromMnemonic(&typed, passphrase: &none).fingerprint
    check("the CompactSeedQR made here loads the same key",
          try q.initialise().seedFromSeedQR(&compact, passphrase: &none).fingerprint, want)
    q.unload()
}

// --- a mnemonic whose BIP39 checksum fails, or that is not English, loads nothing
for (what, bad) in [("a bad checksum", String(repeating: "abandon ", count: 11) + "abandon"),
                    ("a double space", mnemonicText.replacingOccurrences(of: "abandon abandon", with: "abandon  abandon")),
                    ("capitals", "A" + mnemonicText.dropFirst())] {
    let b = try Signer(signerWasm: signerWasm)
    try b.initialise()
    var w = [UInt8](bad.utf8), none: [UInt8] = []
    do {
        try b.seedFromMnemonic(&w, passphrase: &none)
        ok("a mnemonic with \(what) is refused", false)
    } catch {
        ok("a mnemonic with \(what) is refused", "\(error)".contains("seed_from_mnemonic failed") && b.fingerprint == "00000000")
    }
}

// --- SeedQR, against the published vector 4: the fingerprint has to equal the one from typing the words
do {
    let words = "forum undo fragile fade shy sign arrest garment culture tube off merit"
    let digits = "073318950739065415961602009907670428187212261116"
    let compact: [UInt8] = [0x5b, 0xbd, 0x9d, 0x71, 0xa8, 0xec, 0x79, 0x90, 0x83, 0x1a, 0xff, 0x35, 0x9d, 0x42, 0x65, 0x45]
    let q = try Signer(signerWasm: signerWasm)
    func typed(_ p: String) throws -> String {
        var w = [UInt8](words.utf8), pw = [UInt8](p.utf8)
        return try q.initialise().seedFromMnemonic(&w, passphrase: &pw).fingerprint
    }
    func scanned(_ payload: [UInt8], _ p: String = "") throws -> String {
        var b = payload, pw = [UInt8](p.utf8)
        return try q.initialise().seedFromSeedQR(&b, passphrase: &pw).fingerprint
    }
    let want = try typed(""), wantPass = try typed("TREZOR")
    var qr = [UInt8](digits.utf8), none: [UInt8] = []
    check("SeedQR digits give the typed words' fingerprint",
          try q.initialise().seedFromSeedQR(&qr, passphrase: &none).fingerprint, want)
    ok("the SeedQR payload is zeroed", qr.allSatisfy { $0 == 0 })
    check("CompactSeedQR gives the same", try scanned(compact), want)
    check("SeedQR with a passphrase", try scanned([UInt8](digits.utf8), "TREZOR"), wantPass)
    for (what, bad) in [("a bad checksum", String(digits.dropLast()) + "7"), ("47 digits", String(digits.dropFirst())),
                        ("a non-digit", "x" + digits.dropFirst())] {
        q.unload()
        do {
            _ = try scanned([UInt8](bad.utf8))
            ok("SeedQR with \(what) is refused", false)
        } catch {
            ok("SeedQR with \(what) is refused", "\(error)".contains("seed_from_seedqr failed") && q.fingerprint == "00000000")
        }
    }
    do {
        var big = [UInt8](repeating: 0, count: 400), pw = [UInt8](repeating: 0x78, count: 200)
        try q.seedFromSeedQR(&big, passphrase: &pw)
        ok("an oversized SeedQR is refused", false)
    } catch {
        ok("an oversized SeedQR is refused", "\(error)".contains("does not fit"))
    }
    q.unload()
}

// --- unload clears the key
s.unload()
try s.initialise()
check("fingerprint after unload", s.fingerprint, "00000000")

print("\(pass)/\(pass + fail) checks passed")
exit(fail > 0 ? 1 : 0)
