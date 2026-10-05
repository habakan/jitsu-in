// A host for parser.wasm on the JVM, including Android. Hides the linear memory, the offsets and the
// error codes, so using the module is `parse(psbt, fingerprint)` and you get an object back.
//
// Runs on Chicory, a WebAssembly runtime written in pure Java: no JNI, no NDK, no .so per ABI.
// The module has zero imports and does not use WASI, so nothing else is needed.
//
// Every read is bounds-checked: the module tells the host where things are, and a host must never
// take that on trust. See ../../docs/abi.md.
package wasmpsbt

import com.dylibso.chicory.runtime.Instance
import com.dylibso.chicory.wasm.Parser as WasmParser

private const val MAGIC = 0x4e4c5042           // "BPLN"
private const val ABI_VERSION = 1

// Layout of plan_t, from docs/abi.md. Kept in one place so a version bump touches one table.
private object L {
    const val MAGIC_OFF = 0; const val VERSION = 4; const val TX_VERSION = 8; const val LOCKTIME = 12
    const val N_INPUTS = 16; const val N_OUTPUTS = 17
    const val INPUTS = 24; const val INPUT_SIZE = 176
    const val OUTPUTS = 2840; const val OUTPUT_SIZE = 136
    const val IN_PREV_TXID = 0; const val IN_PREV_VOUT = 32; const val IN_SEQUENCE = 36
    const val IN_AMOUNT = 40; const val IN_SPK = 48; const val IN_KEY = 132; const val IN_SIGHASH = 172
    const val OUT_AMOUNT = 0; const val OUT_SPK = 8; const val OUT_KEY = 92
    const val KEY_DEPTH = 0; const val KEY_FINGERPRINT = 4; const val KEY_PATH = 8
    const val SIG_SIZE = 108; const val MAX_INPUTS = 16
}

private val P_ERR = arrayOf("OK", "MAGIC", "FORMAT", "DUPLICATE", "TX", "UNSUPPORTED", "LIMIT", "UTXO", "SIG")
private val UR_ERR = arrayOf("", "SCHEME", "BYTEWORDS", "PART", "MISMATCH", "LIMIT", "MESSAGE", "TYPE")

class ParserException(val code: Int, kind: String = "P_ERR") : Exception(
    if (kind == "P_ERR") "P_ERR_" + (P_ERR.getOrNull(code) ?: code)
    else "UR_ERR_" + (UR_ERR.getOrNull(-code) ?: code)
)

/**
 * A BIP32 derivation the module read out of the PSBT — BIP380 calls this key origin information.
 * It is a *claim*: derive the key yourself and check that it produces the scriptPubKey before
 * treating an input as yours or an output as change.
 */
class KeyOrigin(val fingerprint: Int, val path: IntArray) {
    override fun toString(): String {
        val fp = "%08x".format(fingerprint)
        return (listOf(fp) + path.map { if (it < 0) "${it and 0x7fffffff}h" else "$it" }).joinToString("/")
    }
}

class PlanInput(
    val prevTxid: ByteArray, val prevVout: Int, val sequence: Int,
    val amount: Long, val spk: ByteArray, val key: KeyOrigin?, val sighashType: Int,
    /** The previous transaction, if the PSBT carried one. Checking it against [prevTxid] is the only
     *  way to know [amount] is real. */
    val prevtx: ByteArray?,
)

class PlanOutput(val amount: Long, val spk: ByteArray, val key: KeyOrigin?)

/** What the module read out of the PSBT. Every field is a claim until the host checks it. */
class Plan(val txVersion: Int, val locktime: Int, val inputs: List<PlanInput>, val outputs: List<PlanOutput>) {
    val totalIn: Long get() = inputs.sumOf { it.amount }
    val totalOut: Long get() = outputs.sumOf { it.amount }
    /** Derived from amounts that are claims until each input's prevtx is checked. */
    val fee: Long get() = totalIn - totalOut
}

/** A signature for [finalize]. */
class Signature(val input: Int, val pubkey: ByteArray, val sig: ByteArray)

class UrEncoder internal constructor(val seqLen: Int, private val next: () -> String) {
    /** The next QR payload. Keep calling it; after [seqLen] parts it produces mixed parts. */
    fun next(): String = next.invoke()
}

/**
 * @param parserWasm the contents of parser.wasm
 * @param sha256 when given, the module must hash to exactly this, or it is refused. Take the value
 *   from the project's `checksums.txt` or a release's `SHA256SUMS`.
 */
class Parser(parserWasm: ByteArray, sha256: String? = null) {
    init {
        // A hash in a file nobody checks is documentation. Checking it here makes it a gate.
        if (sha256 != null) {
            val got = java.security.MessageDigest.getInstance("SHA-256").digest(parserWasm)
                .joinToString("") { "%02x".format(it) }
            require(got == sha256.lowercase()) {
                "parser.wasm is not the expected build: $got != ${sha256.lowercase()}"
            }
        }
    }

    private val instance = Instance.builder(WasmParser.parse(parserWasm)).build()
    private val memory = instance.memory()
    private val limit = memory.pages() * 65536

    init {
        for (n in listOf("parser_input", "parser_input_cap", "parser_parse", "parser_plan"))
            requireNotNull(instance.export(n)) { "not a parser.wasm module: $n missing" }
    }

    // Some exports return nothing (parser_ur_reset), and Chicory hands back null for those
    private fun call(name: String, vararg a: Long): Int =
        instance.export(name).apply(*a)?.firstOrNull()?.toInt() ?: 0

    /** Everything reads through here, so a bad offset cannot be followed. */
    private fun bytes(off: Int, n: Int): ByteArray {
        if (off < 0 || n < 0 || off.toLong() + n > limit)
            throw IndexOutOfBoundsException("the module returned an offset outside its memory: $off+$n")
        return memory.readBytes(off, n)
    }
    private fun u8(off: Int): Int = bytes(off, 1)[0].toInt() and 0xff
    private fun i32(off: Int): Int = bytes(off, 4).let { b ->
        (0..3).fold(0) { acc, i -> acc or ((b[i].toInt() and 0xff) shl (8 * i)) }
    }
    private fun i64(off: Int): Long = bytes(off, 8).let { b ->
        (0..7).fold(0L) { acc, i -> acc or ((b[i].toLong() and 0xffL) shl (8 * i)) }
    }
    private fun script(off: Int): ByteArray = bytes(off + 1, u8(off))
    private fun key(off: Int): KeyOrigin? {
        val depth = u8(off + L.KEY_DEPTH)
        if (depth == 0) return null                 // depth 0: the module found no derivation
        return KeyOrigin(i32(off + L.KEY_FINGERPRINT), IntArray(depth) { i32(off + L.KEY_PATH + it * 4) })
    }

    /** How many bytes the input buffer takes. */
    val inputCapacity: Int get() = call("parser_input_cap")

    private fun writeInput(data: ByteArray) {
        require(data.size <= inputCapacity) { "${data.size} bytes does not fit in $inputCapacity" }
        memory.write(call("parser_input"), data)
    }

    /**
     * Parse a PSBT.
     * @param fingerprint master fingerprint, big-endian (0x73c5da0a). Not a secret.
     */
    fun parse(psbt: ByteArray, fingerprint: Int): Plan {
        writeInput(psbt)
        val rc = call("parser_parse", psbt.size.toLong(), fingerprint.toLong() and 0xffffffffL)
        if (rc != 0) throw ParserException(rc)
        return readPlan()
    }

    private fun readPlan(): Plan {
        val p = call("parser_plan")
        if (i32(p + L.MAGIC_OFF) != MAGIC) throw IllegalStateException("plan_t magic mismatch")
        val version = i32(p + L.VERSION)
        if (version != ABI_VERSION) throw IllegalStateException("plan_t version $version, this host speaks $ABI_VERSION")

        val inputs = (0 until u8(p + L.N_INPUTS)).map { i ->
            val o = p + L.INPUTS + i * L.INPUT_SIZE
            val len = call("parser_prevtx_len", i.toLong())
            PlanInput(
                prevTxid = bytes(o + L.IN_PREV_TXID, 32),
                prevVout = i32(o + L.IN_PREV_VOUT),
                sequence = i32(o + L.IN_SEQUENCE),
                amount = i64(o + L.IN_AMOUNT),
                spk = script(o + L.IN_SPK),
                key = key(o + L.IN_KEY),
                sighashType = u8(o + L.IN_SIGHASH),
                prevtx = if (len > 0) bytes(call("parser_input") + call("parser_prevtx_off", i.toLong()), len) else null,
            )
        }
        val outputs = (0 until u8(p + L.N_OUTPUTS)).map { i ->
            val o = p + L.OUTPUTS + i * L.OUTPUT_SIZE
            PlanOutput(i64(o + L.OUT_AMOUNT), script(o + L.OUT_SPK), key(o + L.OUT_KEY))
        }
        return Plan(i32(p + L.TX_VERSION), i32(p + L.LOCKTIME), inputs, outputs)
    }

    // --- animated QR (UR) ---

    /** Drop decoder state before a new animated QR. */
    fun urReset() { call("parser_ur_reset") }

    /** Feed one UR part. Returns the PSBT once the message is complete, otherwise null. */
    fun urReceive(part: String): ByteArray? {
        val raw = part.toByteArray()
        writeInput(raw)
        val rc = call("parser_ur_receive", raw.size.toLong())
        if (rc < 0) throw ParserException(rc, "UR_ERR")
        return if (rc == 0) null else bytes(call("parser_input"), rc)
    }

    /** Parts received so far. For a progress display only. */
    val urProgress: Int get() = call("parser_ur_progress")

    /** Encode the PSBT currently in the output buffer (what [finalize] produced) as QR payloads. */
    fun urEncode(psbtLen: Int, fragmentLen: Int = 100): UrEncoder {
        val seqLen = call("parser_ur_encode_start", psbtLen.toLong(), fragmentLen.toLong())
        if (seqLen < 0) throw ParserException(seqLen, "UR_ERR")
        return UrEncoder(seqLen) {
            val n = call("parser_ur_encode_next")
            if (n < 0) throw ParserException(n, "UR_ERR")
            String(bytes(call("parser_input"), n))
        }
    }

    /** Insert signatures and return the signed PSBT. */
    fun finalize(sigs: List<Signature>): ByteArray {
        val base = call("parser_sigs")
        memory.write(base, ByteArray(L.SIG_SIZE * L.MAX_INPUTS))
        sigs.forEachIndexed { i, s ->
            val o = base + i * L.SIG_SIZE
            memory.write(o, byteArrayOf(s.input.toByte()))
            memory.write(o + 1, s.pubkey)
            memory.write(o + 34, byteArrayOf(s.sig.size.toByte()))
            memory.write(o + 35, s.sig)
        }
        val len = call("parser_finalize", sigs.size.toLong())
        if (len < 0) throw ParserException(-len)
        return bytes(call("parser_output"), len)
    }
}
