// A host for signer.wasm on the JVM, including Android.
//
// This module holds a key, which makes the host's behaviour part of the security of the whole in a
// way it is not for parser.wasm. The rules are in ../../docs/abi.md under "What a host must not do";
// the ones this file can enforce, it does.
//
// Runs on Chicory, a WebAssembly runtime written in pure Java: no JNI, no NDK, no .so per ABI. The
// module has zero imports and does not use WASI, so nothing else is needed.
package wasmsigner

import com.dylibso.chicory.runtime.Instance
import com.dylibso.chicory.wasm.Parser as WasmParser

// Layout of what the host decodes. components/signer/tests/layout.c prints these from the structs
// themselves and `make check-layout` fails if this table drifts from them.
private object L {
    const val PLAN_SIZE = 5016
    const val PLAN_N_INPUTS = 16
    const val PLAN_N_OUTPUTS = 17

    const val RV_SIZE = 64
    const val RV_TOTAL_IN = 0; const val RV_TOTAL_OUT = 8; const val RV_FEE = 16
    const val RV_OWNER = 24; const val RV_WILL_SIGN = 40; const val RV_N_SIGN = 56

    const val DP_SIZE = 2968
    const val DP_FEE = 0; const val DP_SPEND = 8; const val DP_N_OUTPUTS = 16; const val DP_OUTPUTS = 24
    const val DP_OUT_SIZE = 184
    const val DP_OUT_AMOUNT = 0; const val DP_OUT_OWNER = 8; const val DP_OUT_TEXT_KIND = 9
    const val DP_OUT_TEXT = 10; const val DP_OUT_TEXT_CAP = 167

    const val SIG_SIZE = 108
    const val SIG_INPUT = 0; const val SIG_PUBKEY = 1; const val SIG_LEN = 34; const val SIG_SIG = 35

    const val MAX_INPUTS = 16; const val MAX_OUTPUTS = 16
    const val XPUB_MAX = 120; const val DESC_MAX = 180
}

private val CORE_ERR = arrayOf(
    "OK", "FORMAT", "NO_SEED", "NOT_OURS", "NOTHING_TO_SIGN", "SIGHASH", "SCRIPT",
    "PREVTX_MISSING", "PREVTX_MISMATCH", "FEE", "NOT_REVIEWED", "CRYPTO",
)

class SignerException(val stage: String, val code: Int) : Exception(
    "$stage: ${CORE_ERR.getOrElse(code) { "unknown($code)" }}"
)

/** Who an output belongs to. CHANGE and SELF are only ever set after the module re-derived the key
 *  and confirmed it produces that script. */
enum class Owner { EXTERNAL, CHANGE, SELF }

/** What the text of a display output actually is. */
enum class TextKind { ADDRESS, OP_RETURN, SCRIPT }

class Review(
    val totalIn: Long,
    val totalOut: Long,
    val fee: Long,
    val nSign: Int,
    val owner: List<Owner>,
    val willSign: List<Boolean>,
)

class DisplayOutput(val amount: Long, val owner: Owner, val textKind: TextKind, val text: String)

/** `spend` is the total of external outputs; ours and change are excluded. */
class Display(val fee: Long, val spend: Long, val outputs: List<DisplayOutput>)

/** Hand `raw` to parser.wasm's signature buffer; `sig` and `pubkey` are for showing or checking. */
class Signature(val input: Int, val pubkey: ByteArray, val sig: ByteArray, val raw: ByteArray)

class AccountKey(val xpub: String, val descriptor: String)

class Signer(signerWasm: ByteArray, sha256: String? = null) {
    init {
        // A module that will hold a key is the last place to accept whatever bytes arrived
        if (sha256 != null) {
            val got = java.security.MessageDigest.getInstance("SHA-256").digest(signerWasm)
                .joinToString("") { "%02x".format(it) }
            require(got == sha256.lowercase()) {
                "signer.wasm is not the expected build: $got != ${sha256.lowercase()}"
            }
        }
    }

    private val instance = Instance.builder(WasmParser.parse(signerWasm)).build()
    private val memory = instance.memory()
    private val limit = memory.pages() * 65536
    private var reviewed = false

    init {
        for (n in listOf("signer_init", "signer_plan", "signer_review", "signer_sign"))
            requireNotNull(instance.export(n)) { "not a signer.wasm module: $n missing" }
    }

    // Chicory hands back null for an export that returns nothing (signer_unload)
    private fun call(name: String, vararg a: Long): Int =
        instance.export(name).apply(*a)?.firstOrNull()?.toInt() ?: 0

    /** Everything reads through here, so an offset outside the module's memory cannot be followed. */
    private fun bytes(off: Int, n: Int): ByteArray {
        if (off < 0 || n < 0 || off.toLong() + n > limit)
            throw IndexOutOfBoundsException("the module returned an offset outside its memory: $off+$n")
        return memory.readBytes(off, n)
    }
    private fun u8(off: Int): Int = bytes(off, 1)[0].toInt() and 0xff
    private fun i64(off: Int): Long = bytes(off, 8).let { b ->
        (0..7).fold(0L) { acc, i -> acc or ((b[i].toLong() and 0xffL) shl (8 * i)) }
    }
    private fun cstr(off: Int, cap: Int): String {
        val raw = bytes(off, cap)
        val n = raw.indexOf(0).let { if (it < 0) raw.size else it }
        return String(raw, 0, n, Charsets.UTF_8)
    }

    /** How many bytes the input buffer takes. */
    val inputCapacity: Int get() = call("signer_input_cap")

    /** The master fingerprint, or "00000000" when no key is loaded. */
    val fingerprint: String get() = "%08x".format(call("signer_fingerprint"))

    /** Call once, before anything else. `testnet` covers signet too. */
    fun init(testnet: Boolean = false): Signer {
        require(call("signer_init", if (testnet) 1L else 0L) == 1) { "init failed" }
        reviewed = false
        return this
    }

    /**
     * Derives the key from a BIP39 mnemonic. PBKDF2 2048 rounds, about half a second.
     *
     * Takes CharArray rather than String on purpose: a String cannot be cleared, and this one is
     * zeroed before returning. The caller still owns whatever it built the CharArray from.
     */
    fun seedFromMnemonic(mnemonic: CharArray, passphrase: CharArray = charArrayOf()): Signer {
        val mn = String(mnemonic).toByteArray(Charsets.UTF_8)
        val pass = String(passphrase).toByteArray(Charsets.UTF_8)
        try {
            require(mn.size + pass.size <= inputCapacity) {
                "${mn.size + pass.size} bytes of mnemonic and passphrase does not fit in $inputCapacity"
            }
            val at = call("signer_input")
            memory.write(at, mn)
            memory.write(at + mn.size, pass)
            require(call("signer_seed_from_mnemonic", mn.size.toLong(), pass.size.toLong()) == 1) {
                "seed_from_mnemonic failed"
            }
        } finally {
            mn.fill(0); pass.fill(0)
        }
        return this
    }

    /** For a seed you already have. 64 bytes. */
    fun loadSeed(seed: ByteArray): Signer {
        require(seed.size == 64) { "a seed is 64 bytes, got ${seed.size}" }
        memory.write(call("signer_input"), seed)
        require(call("signer_load_seed") == 1) { "load_seed failed" }
        return this
    }

    /** Zeroes the key and everything derived from it. Call it when you are done, not when you
     *  remember to. */
    fun unload() {
        call("signer_unload")
        reviewed = false
    }

    /** The plan parser.wasm produced, copied in verbatim. This invalidates any review. */
    fun setPlan(plan: ByteArray): Signer {
        require(plan.size == L.PLAN_SIZE) { "a plan is ${L.PLAN_SIZE} bytes, got ${plan.size}" }
        memory.write(call("signer_plan"), plan)
        reviewed = false
        return this
    }

    /** The non_witness_utxo for each input, in the plan's order. null for an input that had none. */
    fun setPrevTxs(prevTxs: List<ByteArray?>): Signer {
        val base = call("signer_prevtx")
        var used = 0
        for (i in 0 until L.MAX_INPUTS) {
            val raw = prevTxs.getOrNull(i)
            if (raw == null || raw.isEmpty()) {
                call("signer_set_prevtx", i.toLong(), 0L, 0L)
                continue
            }
            memory.write(base + used, raw)
            require(call("signer_set_prevtx", i.toLong(), used.toLong(), raw.size.toLong()) == 1) {
                "prevtx $i does not fit"
            }
            used += raw.size
        }
        return this
    }

    /** Re-derives the keys and checks the plan against them. Nothing is signed until this passes. */
    fun review(): Review {
        val rc = call("signer_review")
        if (rc != 0) throw SignerException("review", rc)
        reviewed = true
        val at = call("signer_review_output")
        return Review(
            totalIn = i64(at + L.RV_TOTAL_IN),
            totalOut = i64(at + L.RV_TOTAL_OUT),
            fee = i64(at + L.RV_FEE),
            nSign = u8(at + L.RV_N_SIGN),
            owner = (0 until L.MAX_OUTPUTS).map { Owner.entries[u8(at + L.RV_OWNER + it)] },
            willSign = (0 until L.MAX_INPUTS).map { u8(at + L.RV_WILL_SIGN + it) != 0 },
        )
    }

    /** What to put in front of the person approving. Every string here was built inside the module
     *  from the plan's bytes, so it cannot be a string the PSBT chose. */
    fun display(): Display {
        val rc = call("signer_display")
        if (rc != 0) throw SignerException("display", rc)
        val at = call("signer_display_output")
        val n = u8(at + L.DP_N_OUTPUTS)
        return Display(
            fee = i64(at + L.DP_FEE),
            spend = i64(at + L.DP_SPEND),
            outputs = (0 until n).map { i ->
                val o = at + L.DP_OUTPUTS + i * L.DP_OUT_SIZE
                DisplayOutput(
                    amount = i64(o + L.DP_OUT_AMOUNT),
                    owner = Owner.entries[u8(o + L.DP_OUT_OWNER)],
                    textKind = TextKind.entries[u8(o + L.DP_OUT_TEXT_KIND)],
                    text = cstr(o + L.DP_OUT_TEXT, L.DP_OUT_TEXT_CAP),
                )
            },
        )
    }

    /**
     * Signs, and only the plan review() was shown.
     *
     * One review permits exactly one signing: the module clears its own approval afterwards, so a
     * second call without reviewing again is refused. One approval, one signature.
     */
    fun sign(): List<Signature> {
        check(reviewed) { "review() has to pass first; one approval permits one signing" }
        val rc = call("signer_sign")
        reviewed = false
        if (rc < 0) throw SignerException("sign", -rc)
        val base = call("signer_sigs")
        return (0 until rc).map { i ->
            val at = base + i * L.SIG_SIZE
            Signature(
                input = u8(at + L.SIG_INPUT),
                pubkey = bytes(at + L.SIG_PUBKEY, 33),
                sig = bytes(at + L.SIG_SIG, u8(at + L.SIG_LEN)),
                raw = bytes(at, L.SIG_SIZE),
            )
        }
    }

    /** The account xpub and an output descriptor, for making a watch-only wallet elsewhere. */
    fun xpub(): AccountKey {
        val rc = call("signer_xpub")
        if (rc != 0) throw SignerException("xpub", rc)
        return AccountKey(
            xpub = cstr(call("signer_xpub_output"), L.XPUB_MAX),
            descriptor = cstr(call("signer_desc_output"), L.DESC_MAX),
        )
    }
}
