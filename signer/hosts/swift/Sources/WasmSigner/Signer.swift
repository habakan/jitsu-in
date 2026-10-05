// A host for signer.wasm in Swift, including iOS.
//
// This module holds a key, which makes the host's behaviour part of the security of the whole in a
// way it is not for parser.wasm. The rules are in ../../docs/abi.md under "What a host must not do";
// the ones this file can enforce, it does.
//
// Runs on WasmKit, a WebAssembly runtime written in Swift: no C interop and no native build step.
// The module has zero imports and does not use WASI, so nothing else is needed.
import Foundation
import Crypto
import WasmKit

// What the host decodes. components/signer/tests/layout.c prints these from the structs themselves
// and `make check-layout` fails if this table drifts from them.
private enum L {
    static let planSize = 5016, planNInputs = 16, planNOutputs = 17

    static let rvSize = 64
    static let rvTotalIn = 0, rvTotalOut = 8, rvFee = 16
    static let rvOwner = 24, rvWillSign = 40, rvNSign = 56

    static let dpSize = 2968
    static let dpFee = 0, dpSpend = 8, dpNOutputs = 16, dpOutputs = 24
    static let dpOutSize = 184
    static let dpOutAmount = 0, dpOutOwner = 8, dpOutTextKind = 9
    static let dpOutText = 10, dpOutTextCap = 167

    static let sigSize = 108
    static let sigInput = 0, sigPubkey = 1, sigLen = 34, sigSig = 35

    static let maxInputs = 16, maxOutputs = 16
    static let xpubMax = 120, descMax = 180
}

private let coreErr = [
    "OK", "FORMAT", "NO_SEED", "NOT_OURS", "NOTHING_TO_SIGN", "SIGHASH", "SCRIPT",
    "PREVTX_MISSING", "PREVTX_MISMATCH", "FEE", "NOT_REVIEWED", "CRYPTO",
]

public enum SignerError: Error, CustomStringConvertible {
    /// The module refused, at the named stage.
    case refused(stage: String, code: Int32)
    /// The module returned an offset outside its own memory. It is not the module you think it is.
    case outOfBounds(offset: Int, count: Int)
    /// Not a signer.wasm, or it speaks an ABI this host does not.
    case unexpectedModule(String)
    /// More bytes than the module's buffer takes.
    case tooLarge(size: Int, capacity: Int)
    /// sign() before review() passed. One approval permits one signing.
    case notReviewed

    public var description: String {
        switch self {
        case .refused(let s, let c):
            return "\(s): " + (coreErr.indices.contains(Int(c)) ? coreErr[Int(c)] : "unknown(\(c))")
        case .outOfBounds(let o, let n):
            return "the module returned an offset outside its memory: \(o)+\(n)"
        case .unexpectedModule(let s): return s
        case .tooLarge(let s, let c): return "\(s) bytes does not fit in \(c)"
        case .notReviewed: return "review() has to pass first; one approval permits one signing"
        }
    }
}

/// Who an output belongs to. `change` and `self_` are only ever set after the module re-derived the
/// key and confirmed it produces that script.
public enum Owner: UInt8 { case external = 0, change = 1, self_ = 2 }

/// What the text of a display output actually is.
public enum TextKind: UInt8 { case address = 0, opReturn = 1, script = 2 }

public struct Review {
    public let totalIn: UInt64
    public let totalOut: UInt64
    public let fee: UInt64
    public let nSign: Int
    public let owner: [Owner]
    public let willSign: [Bool]
}

public struct DisplayOutput {
    public let amount: UInt64
    public let owner: Owner
    public let textKind: TextKind
    public let text: String
}

/// `spend` is the total of external outputs; ours and change are excluded.
public struct Display {
    public let fee: UInt64
    public let spend: UInt64
    public let outputs: [DisplayOutput]
}

/// Hand `raw` to parser.wasm's signature buffer; `sig` and `pubkey` are for showing or checking.
public struct Signature {
    public let input: UInt8
    public let pubkey: [UInt8]
    public let sig: [UInt8]
    public let raw: [UInt8]
}

public struct AccountKey {
    public let xpub: String
    public let descriptor: String
}

public final class Signer {
    private let instance: Instance
    private let memory: Memory
    private var reviewed = false

    /// `sha256` refuses any module that is not the build you expected. For a module that will hold a
    /// key, pinning it is the difference between running your signer and running someone else's.
    public init(signerWasm: [UInt8], sha256: String? = nil) throws {
        if let want = sha256 {
            let got = SHA256.hash(data: Data(signerWasm)).map { String(format: "%02x", $0) }.joined()
            guard got == want.lowercased() else {
                throw SignerError.unexpectedModule("signer.wasm is not the expected build: \(got)")
            }
        }
        let module = try WasmKit.parseWasm(bytes: signerWasm)
        guard module.imports.isEmpty else {
            let names = module.imports.map { "\($0.module).\($0.name)" }.joined(separator: ", ")
            throw SignerError.unexpectedModule("signer.wasm must have no imports, found: \(names)")
        }
        instance = try module.instantiate(store: Store(engine: Engine()))
        guard case let .memory(m) = instance.export("memory") else {
            throw SignerError.unexpectedModule("not a signer.wasm module: no memory export")
        }
        memory = m
        for name in ["signer_init", "signer_plan", "signer_review", "signer_sign"] {
            guard case .function = instance.export(name) else {
                throw SignerError.unexpectedModule("not a signer.wasm module: \(name) missing")
            }
        }
    }

    private func call(_ name: String, _ args: [Value] = []) throws -> Int32 {
        guard case let .function(f) = instance.export(name) else {
            throw SignerError.unexpectedModule("\(name) missing")
        }
        guard let first = try f.invoke(args).first, case let .i32(v) = first else { return 0 }
        return Int32(bitPattern: v)
    }

    /// Everything reads through here, so an offset outside the module's memory cannot be followed.
    private func bytes(_ offset: Int, _ count: Int) throws -> [UInt8] {
        let size = Int(memory.type.min) * 65536
        guard offset >= 0, count >= 0, offset + count <= size else {
            throw SignerError.outOfBounds(offset: offset, count: count)
        }
        return memory.withUnsafeMutableBufferPointer(offset: UInt(offset), count: count) {
            Array($0.bindMemory(to: UInt8.self))
        }
    }
    private func write(_ data: [UInt8], at offset: Int) throws {
        let size = Int(memory.type.min) * 65536
        guard offset >= 0, offset + data.count <= size else {
            throw SignerError.outOfBounds(offset: offset, count: data.count)
        }
        memory.withUnsafeMutableBufferPointer(offset: UInt(offset), count: data.count) {
            $0.copyBytes(from: data)
        }
    }
    private func u8(_ o: Int) throws -> UInt8 { try bytes(o, 1)[0] }
    private func u64(_ o: Int) throws -> UInt64 {
        try bytes(o, 8).withUnsafeBytes { $0.loadUnaligned(as: UInt64.self) }
    }
    private func cstr(_ o: Int, _ cap: Int) throws -> String {
        let raw = try bytes(o, cap)
        let n = raw.firstIndex(of: 0) ?? raw.count
        return String(decoding: raw[0 ..< n], as: UTF8.self)
    }

    /// How many bytes the input buffer takes.
    public var inputCapacity: Int { (try? Int(call("signer_input_cap"))) ?? 0 }

    /// The master fingerprint, or "00000000" when no key is loaded.
    public var fingerprint: String {
        String(format: "%08x", UInt32(bitPattern: (try? call("signer_fingerprint")) ?? 0))
    }

    /// Call once, before anything else. `testnet` covers signet too.
    @discardableResult
    public func initialise(testnet: Bool = false) throws -> Signer {
        guard try call("signer_init", [.i32(testnet ? 1 : 0)]) == 1 else {
            throw SignerError.unexpectedModule("init failed")
        }
        reviewed = false
        return self
    }

    /// Derives the key from a BIP39 mnemonic. PBKDF2 2048 rounds, about half a second.
    ///
    /// Takes bytes rather than a String on purpose: a Swift String cannot be cleared, and the array
    /// you pass is zeroed here. On iOS, read from the field into a mutable buffer and clear that.
    @discardableResult
    public func seedFromMnemonic(_ mnemonic: inout [UInt8], passphrase: inout [UInt8]) throws -> Signer {
        let cap = inputCapacity
        guard mnemonic.count + passphrase.count <= cap else {
            throw SignerError.tooLarge(size: mnemonic.count + passphrase.count, capacity: cap)
        }
        let at = Int(try call("signer_input"))
        try write(mnemonic, at: at)
        try write(passphrase, at: at + mnemonic.count)
        let rc = try call("signer_seed_from_mnemonic",
                          [.i32(UInt32(mnemonic.count)), .i32(UInt32(passphrase.count))])
        for i in mnemonic.indices { mnemonic[i] = 0 }
        for i in passphrase.indices { passphrase[i] = 0 }
        guard rc == 1 else { throw SignerError.unexpectedModule("seed_from_mnemonic failed") }
        return self
    }

    /// For a seed you already have. 64 bytes.
    @discardableResult
    public func loadSeed(_ seed: [UInt8]) throws -> Signer {
        guard seed.count == 64 else { throw SignerError.tooLarge(size: seed.count, capacity: 64) }
        try write(seed, at: Int(try call("signer_input")))
        guard try call("signer_load_seed") == 1 else {
            throw SignerError.unexpectedModule("load_seed failed")
        }
        return self
    }

    /// Zeroes the key and everything derived from it. Call it when you are done, not when you
    /// remember to.
    public func unload() {
        _ = try? call("signer_unload")
        reviewed = false
    }

    /// The plan parser.wasm produced, copied in verbatim. This invalidates any review.
    @discardableResult
    public func setPlan(_ plan: [UInt8]) throws -> Signer {
        guard plan.count == L.planSize else {
            throw SignerError.tooLarge(size: plan.count, capacity: L.planSize)
        }
        try write(plan, at: Int(try call("signer_plan")))
        reviewed = false
        return self
    }

    /// The non_witness_utxo for each input, in the plan's order. nil for an input that had none.
    @discardableResult
    public func setPrevTxs(_ prevTxs: [[UInt8]?]) throws -> Signer {
        let base = Int(try call("signer_prevtx"))
        var used = 0
        for i in 0 ..< L.maxInputs {
            let raw = i < prevTxs.count ? prevTxs[i] : nil
            guard let raw, !raw.isEmpty else {
                _ = try call("signer_set_prevtx", [.i32(UInt32(i)), .i32(0), .i32(0)])
                continue
            }
            try write(raw, at: base + used)
            guard try call("signer_set_prevtx",
                           [.i32(UInt32(i)), .i32(UInt32(used)), .i32(UInt32(raw.count))]) == 1 else {
                throw SignerError.tooLarge(size: raw.count, capacity: 32768 - used)
            }
            used += raw.count
        }
        return self
    }

    /// Re-derives the keys and checks the plan against them. Nothing is signed until this passes.
    public func review() throws -> Review {
        let rc = try call("signer_review")
        guard rc == 0 else { throw SignerError.refused(stage: "review", code: rc) }
        reviewed = true
        let at = Int(try call("signer_review_output"))
        return Review(
            totalIn: try u64(at + L.rvTotalIn),
            totalOut: try u64(at + L.rvTotalOut),
            fee: try u64(at + L.rvFee),
            nSign: Int(try u8(at + L.rvNSign)),
            owner: try (0 ..< L.maxOutputs).map { Owner(rawValue: try u8(at + L.rvOwner + $0)) ?? .external },
            willSign: try (0 ..< L.maxInputs).map { try u8(at + L.rvWillSign + $0) != 0 }
        )
    }

    /// What to put in front of the person approving. Every string here was built inside the module
    /// from the plan's bytes, so it cannot be a string the PSBT chose.
    public func display() throws -> Display {
        let rc = try call("signer_display")
        guard rc == 0 else { throw SignerError.refused(stage: "display", code: rc) }
        let at = Int(try call("signer_display_output"))
        let n = Int(try u8(at + L.dpNOutputs))
        return Display(
            fee: try u64(at + L.dpFee),
            spend: try u64(at + L.dpSpend),
            outputs: try (0 ..< n).map { i in
                let o = at + L.dpOutputs + i * L.dpOutSize
                return DisplayOutput(
                    amount: try u64(o + L.dpOutAmount),
                    owner: Owner(rawValue: try u8(o + L.dpOutOwner)) ?? .external,
                    textKind: TextKind(rawValue: try u8(o + L.dpOutTextKind)) ?? .script,
                    text: try cstr(o + L.dpOutText, L.dpOutTextCap)
                )
            }
        )
    }

    /// Signs, and only the plan review() was shown.
    ///
    /// One review permits exactly one signing: the module clears its own approval afterwards, so a
    /// second call without reviewing again is refused. One approval, one signature.
    public func sign() throws -> [Signature] {
        guard reviewed else { throw SignerError.notReviewed }
        let rc = try call("signer_sign")
        reviewed = false
        guard rc >= 0 else { throw SignerError.refused(stage: "sign", code: -rc) }
        let base = Int(try call("signer_sigs"))
        return try (0 ..< Int(rc)).map { i in
            let at = base + i * L.sigSize
            return Signature(
                input: try u8(at + L.sigInput),
                pubkey: try bytes(at + L.sigPubkey, 33),
                sig: try bytes(at + L.sigSig, Int(try u8(at + L.sigLen))),
                raw: try bytes(at, L.sigSize)
            )
        }
    }

    /// The account xpub and an output descriptor, for making a watch-only wallet elsewhere.
    public func xpub() throws -> AccountKey {
        let rc = try call("signer_xpub")
        guard rc == 0 else { throw SignerError.refused(stage: "xpub", code: rc) }
        return AccountKey(
            xpub: try cstr(Int(try call("signer_xpub_output")), L.xpubMax),
            descriptor: try cstr(Int(try call("signer_desc_output")), L.descMax)
        )
    }
}
