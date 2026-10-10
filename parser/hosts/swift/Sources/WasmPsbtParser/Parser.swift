// A host for parser.wasm in Swift, including iOS. Hides the linear memory, the offsets and the
// error codes, so using the module is `parse(psbt, fingerprint:)` and you get a value back.
//
// Runs on WasmKit, a WebAssembly runtime written in Swift: no C interop and no native build step.
// The module has zero imports and does not use WASI, so nothing else is needed.
//
// Every read is bounds-checked: the module tells the host where things are, and a host must never
// take that on trust. See ../../docs/abi.md.
import Foundation
import Crypto
import WasmKit

private let magicValue: UInt32 = 0x4e4c_5042   // "BPLN"
private let abiVersion: UInt32 = 2

// Layout of plan_t, from docs/abi.md. Kept in one place so a version bump touches one table.
private enum L {
    static let magic = 0, version = 4, txVersion = 8, locktime = 12, nInputs = 16, nOutputs = 17
    static let inputs = 24, inputSize = 176, outputs = 2840, outputSize = 136
    static let planSize = 6712
    static let inPrevTxid = 0, inPrevVout = 32, inSequence = 36
    static let inAmount = 40, inSpk = 48, inKey = 132, inSighash = 172
    static let outAmount = 0, outSpk = 8, outKey = 92
    static let keyDepth = 0, keyFingerprint = 4, keyPath = 8
    static let sigSize = 108, maxInputs = 16
}

private let pErr = ["OK", "MAGIC", "FORMAT", "DUPLICATE", "TX", "UNSUPPORTED", "LIMIT", "UTXO", "SIG"]
private let urErr = ["", "SCHEME", "BYTEWORDS", "PART", "MISMATCH", "LIMIT", "MESSAGE", "TYPE"]

public enum ParserError: Error, CustomStringConvertible {
    /// The module rejected the PSBT.
    case parse(code: Int32)
    /// The module rejected a UR part.
    case ur(code: Int32)
    /// The module returned an offset outside its own memory. It is not the module you think it is.
    case outOfBounds(offset: Int, count: Int)
    /// The module is not a parser.wasm, or speaks an ABI this host does not.
    case unexpectedModule(String)
    /// More bytes than the module's input buffer takes.
    case tooLarge(size: Int, capacity: Int)
    /// A signature that does not fit the module's fixed-size slot.
    case badSignature(String)
    /// No successfully parsed plan is available.
    case planUnavailable

    public var description: String {
        switch self {
        case .parse(let c): return "P_ERR_" + (pErr.indices.contains(Int(c)) ? pErr[Int(c)] : "\(c)")
        case .ur(let c): return "UR_ERR_" + (urErr.indices.contains(Int(-c)) ? urErr[Int(-c)] : "\(c)")
        case .outOfBounds(let o, let n): return "the module returned an offset outside its memory: \(o)+\(n)"
        case .unexpectedModule(let s): return s
        case .tooLarge(let s, let c): return "\(s) bytes does not fit in \(c)"
        case .badSignature(let s): return s
        case .planUnavailable: return "parse() must succeed before rawPlan()"
        }
    }
}

/// A BIP32 derivation the module read out of the PSBT — BIP380 calls this key origin information.
/// It is a *claim*: derive the key yourself and check it produces the scriptPubKey before treating
/// an input as yours or an output as change.
public struct KeyOrigin: CustomStringConvertible {
    public let fingerprint: UInt32
    public let path: [UInt32]

    public var description: String {
        let steps = path.map { $0 & 0x8000_0000 != 0 ? "\($0 & 0x7fff_ffff)h" : "\($0)" }
        return ([String(format: "%08x", fingerprint)] + steps).joined(separator: "/")
    }
}

public struct PlanInput {
    public let prevTxid: [UInt8], prevVout: UInt32, sequence: UInt32
    public let amount: UInt64, spk: [UInt8], key: KeyOrigin?, sighashType: UInt8
    /// The previous transaction, if the PSBT carried one. Checking it against `prevTxid` is the only
    /// way to know `amount` is real.
    public let prevtx: [UInt8]?
}

public struct PlanOutput {
    public let amount: UInt64, spk: [UInt8], key: KeyOrigin?
}

/// What the module read out of the PSBT. Every field is a claim until the host checks it.
public struct Plan {
    public let txVersion: Int32, locktime: UInt32
    public let inputs: [PlanInput], outputs: [PlanOutput]

    public var totalIn: UInt64 { inputs.reduce(0) { $0 + $1.amount } }
    public var totalOut: UInt64 { outputs.reduce(0) { $0 + $1.amount } }
    /// Derived from amounts that are claims until each input's prevtx is checked.
    public var fee: UInt64 { totalIn - totalOut }
}

/// A signature for `finalize`.
public struct Signature {
    public let input: UInt8, pubkey: [UInt8], sig: [UInt8]
    public init(input: UInt8, pubkey: [UInt8], sig: [UInt8]) {
        self.input = input; self.pubkey = pubkey; self.sig = sig
    }
}

public struct UrEncoder {
    public let seqLen: Int
    let nextPart: () throws -> String
    /// The next QR payload. Keep calling it; after `seqLen` parts it produces mixed parts.
    public func next() throws -> String { try nextPart() }
}

public final class Parser {
    private let instance: Instance
    private let memory: Memory
    private var planAvailable = false

    /// - Parameters:
    ///   - parserWasm: the contents of parser.wasm
    ///   - sha256: when given, the module must hash to exactly this, or it is refused. Take the
    ///     value from the project's `checksums.txt` or a release's `SHA256SUMS`.
    public init(parserWasm: [UInt8], sha256: String? = nil) throws {
        // A hash in a file nobody checks is documentation. Checking it here makes it a gate.
        if let want = sha256 {
            let got = SHA256.hash(data: Data(parserWasm)).map { String(format: "%02x", $0) }.joined()
            guard got == want.lowercased() else {
                throw ParserError.unexpectedModule("parser.wasm is not the expected build: \(got) != \(want.lowercased())")
            }
        }
        let module = try parseWasm(bytes: parserWasm)
        instance = try module.instantiate(store: Store(engine: Engine()))
        guard case let .memory(m) = instance.export("memory") else {
            throw ParserError.unexpectedModule("not a parser.wasm module: no memory export")
        }
        memory = m
        for name in ["parser_input", "parser_input_cap", "parser_parse", "parser_plan"] {
            guard case .function = instance.export(name) else {
                throw ParserError.unexpectedModule("not a parser.wasm module: \(name) missing")
            }
        }
    }

    @discardableResult
    private func call(_ name: String, _ args: [Value] = []) throws -> Int32 {
        guard case let .function(f) = instance.export(name) else {
            throw ParserError.unexpectedModule("\(name) missing")
        }
        guard let first = try f.invoke(args).first, case let .i32(v) = first else { return 0 }
        return Int32(bitPattern: v)
    }

    /// Everything reads through here, so a bad offset cannot be followed.
    private func bytes(_ offset: Int, _ count: Int) throws -> [UInt8] {
        let size = Int(memory.type.min) * 65536
        guard offset >= 0, count >= 0, offset + count <= size else {
            throw ParserError.outOfBounds(offset: offset, count: count)
        }
        return memory.withUnsafeMutableBufferPointer(offset: UInt(offset), count: count) {
            Array($0.bindMemory(to: UInt8.self))
        }
    }
    private func u8(_ o: Int) throws -> UInt8 { try bytes(o, 1)[0] }
    private func u32(_ o: Int) throws -> UInt32 { try bytes(o, 4).withUnsafeBytes { $0.loadUnaligned(as: UInt32.self) } }
    private func i32(_ o: Int) throws -> Int32 { try bytes(o, 4).withUnsafeBytes { $0.loadUnaligned(as: Int32.self) } }
    private func u64(_ o: Int) throws -> UInt64 { try bytes(o, 8).withUnsafeBytes { $0.loadUnaligned(as: UInt64.self) } }
    private func script(_ o: Int) throws -> [UInt8] { try bytes(o + 1, Int(try u8(o))) }
    private func key(_ o: Int) throws -> KeyOrigin? {
        let depth = Int(try u8(o + L.keyDepth))
        if depth == 0 { return nil }          // depth 0: the module found no derivation
        return KeyOrigin(fingerprint: try u32(o + L.keyFingerprint),
                         path: try (0 ..< depth).map { try u32(o + L.keyPath + $0 * 4) })
    }

    /// How many bytes the input buffer takes.
    public var inputCapacity: Int { (try? Int(call("parser_input_cap"))) ?? 0 }

    private func writeInput(_ data: [UInt8]) throws {
        let cap = inputCapacity
        guard data.count <= cap else { throw ParserError.tooLarge(size: data.count, capacity: cap) }
        let off = Int(try call("parser_input"))
        _ = try bytes(off, data.count)        // bounds-check before writing
        memory.withUnsafeMutableBufferPointer(offset: UInt(off), count: data.count) {
            $0.copyBytes(from: data)
        }
    }

    /// Parse a PSBT.
    /// - Parameter fingerprint: master fingerprint, big-endian (0x73c5da0a). Not a secret.
    public func parse(_ psbt: [UInt8], fingerprint: UInt32) throws -> Plan {
        planAvailable = false
        try writeInput(psbt)
        let rc = try call("parser_parse", [.i32(UInt32(psbt.count)), .i32(fingerprint)])
        if rc != 0 { throw ParserError.parse(code: rc) }
        let plan = try readPlan()
        planAvailable = true
        return plan
    }

    /// Copy the current ABI-v1 plan_t bytes for a matching signer.wasm module.
    public func rawPlan() throws -> [UInt8] {
        guard planAvailable else { throw ParserError.planUnavailable }
        return try bytes(Int(call("parser_plan")), L.planSize)
    }

    private func readPlan() throws -> Plan {
        let p = Int(try call("parser_plan"))
        guard try u32(p + L.magic) == magicValue else {
            throw ParserError.unexpectedModule("plan_t magic mismatch")
        }
        let version = try u32(p + L.version)
        guard version == abiVersion else {
            throw ParserError.unexpectedModule("plan_t version \(version), this host speaks \(abiVersion)")
        }

        var inputs: [PlanInput] = []
        for i in 0 ..< Int(try u8(p + L.nInputs)) {
            let o = p + L.inputs + i * L.inputSize
            let len = Int(try call("parser_prevtx_len", [.i32(UInt32(i))]))
            let prevtx = len > 0
                ? try bytes(Int(try call("parser_input")) + Int(try call("parser_prevtx_off", [.i32(UInt32(i))])), len)
                : nil
            inputs.append(PlanInput(
                prevTxid: try bytes(o + L.inPrevTxid, 32), prevVout: try u32(o + L.inPrevVout),
                sequence: try u32(o + L.inSequence), amount: try u64(o + L.inAmount),
                spk: try script(o + L.inSpk), key: try key(o + L.inKey),
                sighashType: try u8(o + L.inSighash), prevtx: prevtx))
        }
        var outputs: [PlanOutput] = []
        for i in 0 ..< Int(try u8(p + L.nOutputs)) {
            let o = p + L.outputs + i * L.outputSize
            outputs.append(PlanOutput(amount: try u64(o + L.outAmount), spk: try script(o + L.outSpk),
                                      key: try key(o + L.outKey)))
        }
        return Plan(txVersion: try i32(p + L.txVersion), locktime: try u32(p + L.locktime),
                    inputs: inputs, outputs: outputs)
    }

    // MARK: animated QR (UR)

    /// Drop decoder state before a new animated QR.
    public func urReset() throws { try call("parser_ur_reset") }

    /// Feed one UR part. Returns the PSBT once the message is complete, otherwise nil.
    public func urReceive(_ part: String) throws -> [UInt8]? {
        planAvailable = false
        let raw = Array(part.utf8)
        try writeInput(raw)
        let rc = try call("parser_ur_receive", [.i32(UInt32(raw.count))])
        if rc < 0 { throw ParserError.ur(code: rc) }
        if rc == 0 { return nil }
        return try bytes(Int(try call("parser_input")), Int(rc))
    }

    /// Parts received so far. For a progress display only.
    public var urProgress: Int { (try? Int(call("parser_ur_progress"))) ?? 0 }

    /// Encode the PSBT currently in the output buffer (what `finalize` produced) as QR payloads.
    public func urEncode(psbtLen: Int, fragmentLen: Int = 100) throws -> UrEncoder {
        planAvailable = false
        let seqLen = try call("parser_ur_encode_start", [.i32(UInt32(psbtLen)), .i32(UInt32(fragmentLen))])
        if seqLen < 0 { throw ParserError.ur(code: seqLen) }
        return UrEncoder(seqLen: Int(seqLen)) { [self] in
            let n = try call("parser_ur_encode_next")
            if n < 0 { throw ParserError.ur(code: n) }
            return String(decoding: try bytes(Int(try call("parser_input")), Int(n)), as: UTF8.self)
        }
    }

    /// Insert signatures and return the signed PSBT.
    public func finalize(_ sigs: [Signature]) throws -> [UInt8] {
        guard sigs.count <= L.maxInputs else {
            throw ParserError.badSignature("\(sigs.count) signatures, a plan has at most \(L.maxInputs) inputs")
        }
        for s in sigs where Int(s.input) >= L.maxInputs || s.pubkey.count != 33 || s.sig.count > 73 {
            throw ParserError.badSignature(
                "input \(s.input): a signature slot takes a 33-byte pubkey and at most 73 bytes of signature")
        }
        let base = Int(try call("parser_sigs"))
        _ = try bytes(base, L.sigSize * L.maxInputs)
        memory.withUnsafeMutableBufferPointer(offset: UInt(base), count: L.sigSize * L.maxInputs) {
            for i in 0 ..< $0.count { $0[i] = 0 }
        }
        for (i, s) in sigs.enumerated() {
            let o = base + i * L.sigSize
            var record = [UInt8](repeating: 0, count: L.sigSize)
            record[0] = s.input
            record.replaceSubrange(1 ..< 1 + s.pubkey.count, with: s.pubkey)
            record[34] = UInt8(s.sig.count)
            record.replaceSubrange(35 ..< 35 + s.sig.count, with: s.sig)
            memory.withUnsafeMutableBufferPointer(offset: UInt(o), count: L.sigSize) {
                $0.copyBytes(from: record)
            }
        }
        let len = try call("parser_finalize", [.i32(UInt32(sigs.count))])
        if len < 0 { throw ParserError.parse(code: -len) }
        return try bytes(Int(try call("parser_output")), Int(len))
    }
}
