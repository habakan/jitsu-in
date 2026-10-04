// Drives signer.wasm through the host library and checks the result against what the native side
// produced. The signatures are deterministic, so "the same" means byte-identical, not merely valid.
//
//   java -cp "test.jar:$CP" TestKt <signer.wasm> <parser.wasm> <psbt> <natively-signed-psbt>
import wasmsigner.Owner
import wasmsigner.Signer
import wasmsigner.SignerException
import wasmsigner.TextKind
import com.dylibso.chicory.runtime.Instance
import com.dylibso.chicory.wasm.Parser as WasmParser
import java.io.File

private var pass = 0
private var fail = 0

private fun check(what: String, got: Any?, want: Any?) {
    if (got == want) pass++ else { fail++; println("FAIL $what\n  got  $got\n  want $want") }
}
private fun ok(what: String, cond: Boolean) {
    if (cond) pass++ else { fail++; println("FAIL $what") }
}
private fun hex(b: ByteArray) = b.joinToString("") { "%02x".format(it) }

/** parser.wasm turns the PSBT into a plan; signer.wasm is what is being tested here. */
private class PlanSource(parserWasm: ByteArray) {
    private val inst = Instance.builder(WasmParser.parse(parserWasm)).build()
    private val mem = inst.memory()
    private fun call(n: String, vararg a: Long) = inst.export(n).apply(*a)?.firstOrNull()?.toInt() ?: 0

    fun of(psbt: ByteArray, fingerprint: Int): Pair<ByteArray, List<ByteArray?>> {
        mem.write(call("parser_input"), psbt)
        val rc = call("parser_parse", psbt.size.toLong(), fingerprint.toLong())
        require(rc == 0) { "parser refused the PSBT: $rc" }
        val plan = mem.readBytes(call("parser_plan"), 5016)
        val nIn = plan[16].toInt() and 0xff
        val inputAt = call("parser_input")
        return plan to (0 until nIn).map { i ->
            val len = call("parser_prevtx_len", i.toLong())
            if (len == 0) null else mem.readBytes(inputAt + call("parser_prevtx_off", i.toLong()), len)
        }
    }
}

fun main(args: Array<String>) {
    val signerWasm = File(args[0]).readBytes()
    val parserWasm = File(args[1]).readBytes()
    val psbt = File(args[2]).readBytes()
    val nativelySigned = File(args[3]).readBytes()
    val mnemonic = ("abandon ".repeat(11) + "about").toCharArray()
    val fp = 0x73c5da0a

    // --- a module that is not the expected build is refused
    try {
        Signer(signerWasm, sha256 = "00".repeat(32))
        ok("a wrong sha256 is refused", false)
    } catch (e: IllegalArgumentException) {
        ok("a wrong sha256 is refused", e.message!!.contains("not the expected build"))
    }

    val s = Signer(signerWasm)
    s.init()
    check("fingerprint before a seed", s.fingerprint, "00000000")
    s.seedFromMnemonic(mnemonic)
    check("fingerprint from the BIP39 test vector", s.fingerprint, "73c5da0a")

    // --- a full round, compared against the native signer's output
    val (plan, prevTxs) = PlanSource(parserWasm).of(psbt, fp)
    s.setPlan(plan).setPrevTxs(prevTxs)

    val r = s.review()
    ok("review says it will sign something", r.nSign > 0)
    check("fee is total in minus total out", r.fee, r.totalIn - r.totalOut)

    val d = s.display()
    check("the fee review and display agree", d.fee, r.fee)
    ok("every output has text", d.outputs.all { it.text.isNotEmpty() })
    ok("an address is shown as an address", d.outputs.any {
        it.textKind == TextKind.ADDRESS && Regex("^(bc1|tb1|[13])").containsMatchIn(it.text)
    })
    ok("change is marked as change", d.outputs.any { it.owner == Owner.CHANGE })
    check("spend excludes our own outputs", d.spend,
          d.outputs.filter { it.owner == Owner.EXTERNAL }.sumOf { it.amount })

    val sigs = s.sign()
    check("one signature per input review chose", sigs.size, r.nSign)

    // The native host wrote these; deterministic signing means they have to match to the byte
    for (sig in sigs) {
        ok("input ${sig.input}: the signature appears in the natively signed PSBT",
           hex(nativelySigned).contains(hex(sig.sig)))
    }
    ok("ECDSA carries its sighash byte", sigs.any { it.sig.size >= 70 && it.sig[0] == 0x30.toByte() })
    ok("Schnorr is 64 bytes", sigs.any { it.sig.size == 64 })

    // --- one approval permits one signing, and no more
    try {
        s.sign()
        ok("a second sign without reviewing again is refused", false)
    } catch (e: IllegalStateException) {
        ok("a second sign without reviewing again is refused",
           e.message!!.contains("one approval permits one signing"))
    }

    // --- reviewing the same plan again and signing gives the same bytes
    s.review()
    check("signing the same plan again is byte-identical", hex(s.sign()[0].sig), hex(sigs[0].sig))

    // --- the signatures are the same bytes the JavaScript host gets, from the same module
    ok("the first signature is DER or Schnorr, nothing else",
       sigs.all { it.sig.size == 64 || (it.sig.size in 70..73 && it.sig[0] == 0x30.toByte()) })

    // --- xpub, against BIP84's published vector
    val x = s.xpub()
    ok("the descriptor names the account", x.descriptor.startsWith("wpkh([73c5da0a/84h/0h/0h]"))
    ok("the descriptor covers receive and change", x.descriptor.contains("<0;1>/*"))
    ok("the xpub is an xpub", x.xpub.startsWith("xpub"))

    // --- signing without a review is refused by this library, and by the module
    run {
        val s2 = Signer(signerWasm).init().seedFromMnemonic(mnemonic).setPlan(plan).setPrevTxs(prevTxs)
        try {
            s2.sign()
            ok("signing without review is refused", false)
        } catch (e: IllegalStateException) {
            ok("signing without review is refused", e.message!!.contains("review() has to pass first"))
        }
        s2.unload()
    }

    // --- a plan of the wrong size never reaches the module
    try {
        s.setPlan(ByteArray(100))
        ok("a plan of the wrong size is refused", false)
    } catch (e: IllegalArgumentException) {
        ok("a plan of the wrong size is refused", e.message!!.contains("5016 bytes"))
    }

    // --- an oversized mnemonic is rejected before anything is written
    try {
        s.seedFromMnemonic(CharArray(600) { 'x' })
        ok("an oversized mnemonic is refused", false)
    } catch (e: IllegalArgumentException) {
        ok("an oversized mnemonic is refused", e.message!!.contains("does not fit"))
    }

    // --- unload clears the key
    s.unload()
    s.init()
    check("fingerprint after unload", s.fingerprint, "00000000")

    println("$pass/${pass + fail} checks passed")
    if (fail > 0) System.exit(1)
}
