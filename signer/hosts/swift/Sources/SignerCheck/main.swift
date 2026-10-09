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
    let found = try s.findAddress("bc1p3qkhfews2uk44qtvauqyr2ttdsw7svhkl9nkm9s9c3x4ax5h60wqwruhk7", count: 20)!
    print("found \(found.chain) \(found.index)")
    print("desc \(try s.xpub(purpose: 86, account: 1).descriptor)")
    var rolls = [UInt8](String(repeating: "3", count: 99).utf8)
    print("dice \(String(decoding: try s.mnemonicFromDice(&rolls), as: UTF8.self))")
    var abandon = [UInt8](mnemonicText.utf8)
    print("seedqr \(String(decoding: try s.seedQRFromMnemonic(&abandon), as: UTF8.self))")
    print("bip85 \(String(decoding: try s.bip85Mnemonic(words: 24, index: 3), as: UTF8.self))")
    let shown = try s.messageReview([UInt8]("dump\n".utf8), purpose: 49, chain: 1, index: 2)
    print("message \(shown.address) \(shown.text) \(Data(try s.messageSign()).base64EncodedString())")
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
let tr = try s.xpub(purpose: 86)
check("BIP86's account 0", tr.xpub, "xpub6BgBgsespWvERF3LHQu6CnqdvfEvtMcQjYrcRzx53QJjSxarj2afYWcLteoGVky7D3UKDP9QyrLprQ3VCECoY49yfdDEHGCtMMj92pReUsQ")
check("the tr() descriptor", tr.descriptor, "tr([73c5da0a/86h/0h/0h]\(tr.xpub)/<0;1>/*)")
check("the BIP49 descriptor", String(try s.xpub(purpose: 49).descriptor.prefix(32)), "sh(wpkh([73c5da0a/49h/0h/0h]xpub")
let a1 = try s.xpub(account: 1)
check("account 1, as the JavaScript host derives it independently", a1.xpub, "xpub6CatWdiZiodmYVtWLtEQsAg1H9ooS1bmsJUBwQ83FE1Fyk386FWcyicJgEZv3quZSJKA5dh5Lo2PbubMGxCfZtRthV6ST2qquL9w3HSzcUn")
ok("account 1 is named", a1.descriptor.hasPrefix("wpkh([73c5da0a/84h/0h/1h]xpub"))
do {
    _ = try s.xpub(account: 0x8000_0000)
    ok("xpub for a hardened account is refused", false)
} catch {
    ok("xpub for a hardened account is refused", "\(error)" == "xpub: FORMAT")
}
do {
    _ = try s.xpub(purpose: 44)
    ok("xpub for BIP44 is refused", false)
} catch {
    ok("xpub for BIP44 is refused", "\(error)".contains("xpub: FORMAT"))
}

// --- which of our addresses an address is, against BIP84's and BIP86's vectors. A count of 20,
// because WasmKit interprets every derivation and 1000 of them take minutes
func find(_ a: String) throws -> AddressPath? { try s.findAddress(a, count: 20) }
check("BIP84 0/1", try find("bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g"), AddressPath(chain: 0, index: 1))
check("BIP86 change 1/0", try find("bc1p3qkhfews2uk44qtvauqyr2ttdsw7svhkl9nkm9s9c3x4ax5h60wqwruhk7"),
      AddressPath(chain: 1, index: 0))
check("a BIP21 URI in upper case", try find("bitcoin:BC1QNJG0JD8228AQ7EGYZACY8CYS3KNF9XVRERKF9G?amount=0.1"),
      AddressPath(chain: 0, index: 1))
check("not ours", try find("bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3"), nil)
do {
    _ = try find("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2")
    ok("findAddress refuses base58", false)
} catch {
    ok("findAddress refuses base58", "\(error)" == "findAddress: FORMAT")
}

// --- BIP137: the signature Core's signmessagewithprivkey gives, with the P2WPKH header (check-core-diff)
do {
    let shown = try s.messageReview([UInt8]("This is an example of a signed message.".utf8))
    check("the message's address", shown.address, "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu")
    ok("the message is shown as it is", !shown.isHex && shown.text == "This is an example of a signed message.")
    check("the BIP137 signature", Data(try s.messageSign()).base64EncodedString(), "KLRN6BWUkHM2/ac9gTTx/izIth+Q8dyI1m6T8UJX061hEXMnFtDTlKJ/IYgwVCzr1zoF6zlAVzmBa/yEc7Dfi0s=")
    ok("a newline is shown in hex", try s.messageReview([UInt8]("a\nb".utf8)).text == "610a62")
    do {
        _ = try s.messageSign()
        _ = try s.messageSign()
        ok("one review permits one message signature", false)
    } catch {
        ok("one review permits one message signature", "\(error)" == "messageSign: NOT_REVIEWED")
    }
}

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
    do {
        var short = [UInt8](repeating: 0, count: 15)
        _ = try g.mnemonicFromEntropy(&short)
        ok("15 bytes of entropy are refused", false)
    } catch {
        ok("15 bytes of entropy are refused", "\(error)" == "mnemonic_from_entropy failed")
    }
    var kept = [UInt8](String(repeating: "1", count: 99).utf8)
    do {
        _ = try g.mnemonicFromDice(&kept, words: 18)
        ok("18 words from dice is refused", false)
    } catch {
        ok("18 words from dice is refused, and the rolls are kept to retry", kept[0] == 0x31)
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
    do {
        var bad = [UInt8]((String(repeating: "abandon ", count: 11) + "abandon").utf8)
        _ = try q.seedQRFromMnemonic(&bad)
        ok("a SeedQR of a bad mnemonic is refused", false)
    } catch {
        ok("a SeedQR of a bad mnemonic is refused", "\(error)" == "seedqr_from_mnemonic failed")
    }
    q.unload()
}

// --- BIP85: the child the JavaScript host checks against its own derivation
do {
    let b = try freshSigner()
    check("BIP85 12 words, index 0", String(decoding: try b.bip85Mnemonic(words: 12), as: UTF8.self), "prosper short ramp prepare exchange stove life snack client enough purpose fold")
    do {
        _ = try b.bip85Mnemonic(words: 15)
        ok("BIP85 with 15 words is refused", false)
    } catch {
        ok("BIP85 with 15 words is refused", "\(error)" == "bip85_mnemonic failed")
    }
    b.unload()
    do {
        _ = try b.initialise().bip85Mnemonic()
        ok("BIP85 with no seed says so", false)
    } catch {
        ok("BIP85 with no seed says so", "\(error)" == "no seed is loaded")
    }
}

// --- what a keyboard adds loads the same wallet; a bad checksum, or a word not in the list, loads nothing
do {
    let b = try Signer(signerWasm: signerWasm)
    try b.initialise()
    var w = [UInt8](("  " + mnemonicText.uppercased() + "\n").utf8), none: [UInt8] = []
    check("whitespace and capitals load the same wallet", try b.seedFromMnemonic(&w, passphrase: &none).fingerprint,
          "73c5da0a")
}
for (what, bad) in [("a bad checksum", String(repeating: "abandon ", count: 11) + "abandon"),
                    ("a word not in the list", mnemonicText.replacingOccurrences(of: "about", with: "abaut"))] {
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
