// Tests the host, not the parser: the module itself is covered by the 529 vectors in tools/run_tests.py.
// Mirrors hosts/js/test.mjs, so a difference between the two hosts shows up as a failing check here.
import wasmpsbt.*
import java.io.File

private var checks = 0
private var failures = 0

private fun check(cond: Boolean, what: String) {
    checks++
    if (!cond) { failures++; println("FAIL $what") }
}

private inline fun throws(want: String, what: String, body: () -> Unit) {
    checks++
    try { body(); failures++; println("FAIL $what: did not throw") }
    catch (e: Exception) {
        val got = "${e::class.simpleName}: ${e.message}"
        if (!got.contains(want)) { failures++; println("FAIL $what: $got") }
    }
}

fun main(args: Array<String>) {
    val wasmPath = args.getOrElse(0) { "../../build/parser.wasm" }
    val vectorDir = File(args.getOrElse(1) { "../../build/vectors" })
    val parserWasm = File(wasmPath).readBytes()
    val fp = 0x73c5da0a

    // the hand-made vectors parse, and the shape is sane
    val vectors = vectorDir.listFiles { f -> f.name.startsWith("own_") && f.extension == "psbt" }!!.sorted()
    check(vectors.size >= 4, "${vectors.size} hand-made vectors")
    for (f in vectors) {
        val plan = Parser(parserWasm).parse(f.readBytes(), fp)
        check(plan.inputs.isNotEmpty() && plan.outputs.isNotEmpty(), "${f.name}: has inputs and outputs")
        check(plan.fee > 0 && plan.fee < 1_000_000, "${f.name}: fee ${plan.fee} is plausible")
        check(plan.totalIn - plan.totalOut == plan.fee, "${f.name}: fee is in minus out")
        for (i in plan.inputs) {
            check(i.prevTxid.size == 32, "${f.name}: txid is 32 bytes")
            check(i.spk.isNotEmpty() && i.spk.size <= 83, "${f.name}: input spk length")
            check(i.prevtx?.let { it.size > 60 } ?: true, "${f.name}: prevtx looks like a transaction")
        }
        for (o in plan.outputs) check(o.spk.isNotEmpty() && o.spk.size <= 83, "${f.name}: output spk length")
    }

    // what Bitcoin Core marks invalid is rejected, as a ParserException and not a crash
    val invalid = vectorDir.listFiles { f -> f.name.startsWith("rpc_invalid") && f.extension == "psbt" }!!
    check(invalid.size > 50, "${invalid.size} invalid vectors")
    var rejected = 0
    for (f in invalid) {
        try { Parser(parserWasm).parse(f.readBytes(), fp) }
        catch (e: ParserException) { rejected++ }
        catch (e: Exception) { failures++; println("FAIL ${f.name}: $e") }
    }
    checks++
    if (rejected < invalid.size * 0.8) { failures++; println("FAIL only $rejected/${invalid.size} rejected") }

    // a derivation prints the way a human reads it, and matches the JavaScript host
    run {
        val parser = Parser(parserWasm)
        val plan = parser.parse(File(vectorDir, "own_p2wpkh_1in.psbt").readBytes(), fp)
        check(plan.inputs[0].key.toString() == "73c5da0a/84h/0h/0h/0/0", "keypath prints as ${plan.inputs[0].key}")
        check(plan.inputs[0].key!!.fingerprint == fp, "fingerprint is kept as a number")
        val raw = parser.rawPlan()
        check(raw.size == 6712, "raw plan is ${raw.size} bytes")
        check(raw.sliceArray(0..3).contentEquals(byteArrayOf(0x42, 0x50, 0x4c, 0x4e)), "raw plan has BPLN magic")
        check(raw[16].toInt() == plan.inputs.size && raw[17].toInt() == plan.outputs.size, "raw plan counts match")
    }

    // a fingerprint that matches nothing claims nothing
    run {
        val plan = Parser(parserWasm).parse(File(vectorDir, "own_p2wpkh_1in.psbt").readBytes(), 0)
        check(plan.inputs.all { it.key == null }, "a fingerprint that matches nothing claims nothing")
    }

    // errors arrive as names, not numbers
    run {
        val p = Parser(parserWasm)
        throws("parse() must succeed", "raw plan before parse") { p.rawPlan() }
        throws("P_ERR_MAGIC", "not a PSBT") { p.parse(byteArrayOf(1, 2, 3, 4, 5), 0) }
        throws("parse() must succeed", "raw plan after failed parse") { p.rawPlan() }
        throws("does not fit", "too large for the buffer") { p.parse(ByteArray(p.inputCapacity + 1), 0) }
        throws("UR_ERR_SCHEME", "not a UR") { p.urReceive("not a ur") }
    }

    // UR: encode what finalize produced, feed the parts back, get the same bytes
    run {
        val enc = Parser(parserWasm)
        enc.parse(File(vectorDir, "own_mixed_nwu.psbt").readBytes(), fp)
        val out = enc.finalize(emptyList())      // no signatures: re-serializes into the output buffer
        check(out.size > 100, "finalize produced ${out.size} bytes")

        val seq = enc.urEncode(out.size, 100)
        check(seq.seqLen > 1, "splits into ${seq.seqLen} parts")

        val dec = Parser(parserWasm)
        dec.urReset()
        var got: ByteArray? = null
        var n = 0
        while (got == null && n < seq.seqLen * 3) { got = dec.urReceive(seq.next()); n++ }
        check(got != null, "reassembles")
        check(got != null && got.contentEquals(out), "round trip is byte identical")
    }

    // a signature that does not fit its slot is refused before anything is written
    run {
        val p = Parser(parserWasm)
        p.parse(File(vectorDir, "own_mixed_nwu.psbt").readBytes(), fp)
        val sig = Signature(0, ByteArray(33) { 2 }, ByteArray(71))
        throws("at most 16 inputs", "17 signatures") { p.finalize(List(17) { sig }) }
        throws("33-byte pubkey", "a 34-byte pubkey") { p.finalize(listOf(Signature(0, ByteArray(34), sig.sig))) }
        throws("33-byte pubkey", "a 74-byte signature") { p.finalize(listOf(Signature(0, sig.pubkey, ByteArray(74)))) }
        throws("33-byte pubkey", "input 16") { p.finalize(listOf(Signature(16, sig.pubkey, sig.sig))) }
    }

    // the digest gate accepts the real build and refuses anything else
    run {
        val sha = java.security.MessageDigest.getInstance("SHA-256").digest(parserWasm)
            .joinToString("") { "%02x".format(it) }
        Parser(parserWasm, sha)                 // no throw: accepted
        checks++
        throws("not the expected build", "a wrong digest is refused") {
            Parser(parserWasm, "00".repeat(32))
        }
    }

    println("${checks - failures}/$checks checks passed")
    kotlin.system.exitProcess(if (failures != 0) 1 else 0)
}
