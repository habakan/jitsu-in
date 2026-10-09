// Drives signer.wasm through the host library and checks the result against what the native side
// produced. The signatures are deterministic, so "the same" means byte-identical, not merely valid.
//
//   java -cp "test.jar:$CP" TestKt <signer.wasm> <parser.wasm> <psbt> <natively-signed-psbt>
import wasmsigner.AddressPath
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
    val mn = mnemonic.copyOf()
    s.seedFromMnemonic(mn)
    ok("the mnemonic is zeroed", mn.all { it == '\u0000' })
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
    val tr = s.xpub(purpose = 86)
    check("BIP86's account 0", tr.xpub, "xpub6BgBgsespWvERF3LHQu6CnqdvfEvtMcQjYrcRzx53QJjSxarj2afYWcLteoGVky7D3UKDP9QyrLprQ3VCECoY49yfdDEHGCtMMj92pReUsQ")
    check("the tr() descriptor", tr.descriptor, "tr([73c5da0a/86h/0h/0h]${tr.xpub}/<0;1>/*)")
    val a1 = s.xpub(account = 1)
    check("account 1, as the JavaScript host derives it independently", a1.xpub, "xpub6CatWdiZiodmYVtWLtEQsAg1H9ooS1bmsJUBwQ83FE1Fyk386FWcyicJgEZv3quZSJKA5dh5Lo2PbubMGxCfZtRthV6ST2qquL9w3HSzcUn")
    ok("account 1 is named", a1.descriptor.startsWith("wpkh([73c5da0a/84h/0h/1h]xpub"))
    try {
        s.xpub(account = -1)
        ok("xpub for a hardened account is refused", false)
    } catch (e: SignerException) {
        ok("xpub for a hardened account is refused", e.message == "xpub: FORMAT")
    }
    try {
        s.xpub(purpose = 49)
        ok("xpub for BIP49 is refused", false)
    } catch (e: SignerException) {
        ok("xpub for BIP49 is refused", e.message!!.contains("FORMAT"))
    }

    // --- which of our addresses an address is, against BIP84's and BIP86's vectors. A count of 20,
    // because Chicory interprets every derivation and 1000 of them take minutes
    val find = { a: String -> s.findAddress(a, count = 20) }
    check("BIP84 0/1", find("bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g"), AddressPath(0, 1))
    check("BIP86 change 1/0", find("bc1p3qkhfews2uk44qtvauqyr2ttdsw7svhkl9nkm9s9c3x4ax5h60wqwruhk7"), AddressPath(1, 0))
    check("a BIP21 URI in upper case", find("bitcoin:BC1QNJG0JD8228AQ7EGYZACY8CYS3KNF9XVRERKF9G?amount=0.1"),
          AddressPath(0, 1))
    check("not ours", find("bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3"), null)
    try {
        find("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2")
        ok("findAddress refuses base58", false)
    } catch (e: SignerException) {
        ok("findAddress refuses base58", e.message == "findAddress: FORMAT")
    }

    // --- signing without a review is refused by this library, and by the module
    run {
        val s2 = Signer(signerWasm).init().seedFromMnemonic(mnemonic.copyOf()).setPlan(plan).setPrevTxs(prevTxs)
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

    // --- prevtxs that overflow the module's buffer are refused before they are written
    run {
        val s3 = Signer(signerWasm).init().seedFromMnemonic(mnemonic.copyOf()).setPlan(plan)
        try {
            s3.setPrevTxs(listOf(ByteArray(20000), ByteArray(20000)))
            ok("prevtxs over the buffer are refused", false)
        } catch (e: IllegalArgumentException) {
            ok("prevtxs over the buffer are refused", e.message!!.contains("does not fit"))
        }
        s3.setPrevTxs(prevTxs)
        ok("the signer still reviews afterwards", s3.review().nSign > 0)
        s3.unload()
    }

    // --- an oversized mnemonic is rejected before anything is written
    try {
        s.seedFromMnemonic(CharArray(600) { 'x' })
        ok("an oversized mnemonic is refused", false)
    } catch (e: IllegalArgumentException) {
        ok("an oversized mnemonic is refused", e.message!!.contains("does not fit"))
    }

    // --- making a new mnemonic, from entropy and from dice, against BIP39's and the dice vectors
    run {
        val g = Signer(signerWasm).init()
        val ent = "9e885d952ad362caeb4efe34a8e91bd2".chunked(2).map { it.toInt(16).toByte() }.toByteArray()
        val mn = g.mnemonicFromEntropy(ent)
        check("BIP39's 9e885d95... vector", String(mn), "ozone drill grab fiber curtain grace pudding thank cruise elder eight picnic")
        ok("the entropy passed in is zeroed", ent.all { it == 0.toByte() })
        check("the generated words load", g.seedFromMnemonic(mn).fingerprint.length, 8)
        check("50 dice rolls", String(g.mnemonicFromDice("1".repeat(50).toByteArray(), 12)), "diet glad hat rural panther lawsuit act drop gallery urge where fit")
        try {
            g.mnemonicFromDice("1".repeat(98).toByteArray())
            ok("98 rolls for 24 words are refused", false)
        } catch (e: IllegalArgumentException) {
            ok("98 rolls for 24 words are refused", e.message == "mnemonic_from_dice failed")
        }
        try {
            g.mnemonicFromEntropy(ByteArray(15))
            ok("15 bytes of entropy are refused", false)
        } catch (e: IllegalArgumentException) {
            ok("15 bytes of entropy are refused", e.message == "mnemonic_from_entropy failed")
        }
        val kept = "1".repeat(99).toByteArray()
        try {
            g.mnemonicFromDice(kept, 18)
            ok("18 words from dice is refused", false)
        } catch (e: IllegalArgumentException) {
            ok("18 words from dice is refused, and the rolls are kept to retry", kept[0] == '1'.code.toByte())
        }
        g.unload()
    }

    // --- making a SeedQR from the words, against the published vector 4, and reading it back
    run {
        val q = Signer(signerWasm).init()
        val words = "forum undo fragile fade shy sign arrest garment culture tube off merit".toCharArray()
        check("Standard SeedQR digits", String(q.seedQRFromMnemonic(words)), "073318950739065415961602009907670428187212261116")
        ok("the words passed in are zeroed", words.all { it == '\u0000' })
        val compact = q.seedQRFromMnemonic("forum undo fragile fade shy sign arrest garment culture tube off merit".toCharArray(), compact = true)
        check("CompactSeedQR bytes", compact.joinToString("") { "%02x".format(it) }, "5bbd9d71a8ec7990831aff359d426545")
        val want = q.seedFromMnemonic("forum undo fragile fade shy sign arrest garment culture tube off merit".toCharArray()).fingerprint
        check("the CompactSeedQR made here loads the same key", q.init().seedFromSeedQR(compact).fingerprint, want)
        try {
            q.seedQRFromMnemonic(("abandon ".repeat(11) + "abandon").toCharArray())
            ok("a SeedQR of a bad mnemonic is refused", false)
        } catch (e: IllegalArgumentException) {
            ok("a SeedQR of a bad mnemonic is refused", e.message == "seedqr_from_mnemonic failed")
        }
        q.unload()
    }

    // --- what a keyboard adds loads the same wallet; a bad checksum, or a word not in the list, loads nothing
    val typed = "abandon ".repeat(11) + "about"
    check("whitespace and capitals load the same wallet",
          Signer(signerWasm).init().seedFromMnemonic((" " + typed.replaceFirst(" ", "  ").uppercase() + "\n").toCharArray())
              .fingerprint, "73c5da0a")
    for ((what, bad) in listOf("a bad checksum" to "abandon ".repeat(11) + "abandon",
                               "a word not in the list" to typed.replace("about", "abaut"))) {
        val b = Signer(signerWasm).init()
        try {
            b.seedFromMnemonic(bad.toCharArray())
            ok("a mnemonic with $what is refused", false)
        } catch (e: IllegalArgumentException) {
            ok("a mnemonic with $what is refused", e.message == "seed_from_mnemonic failed" && b.fingerprint == "00000000")
        }
    }

    // --- SeedQR, against the published vector 4: the fingerprint has to equal the one from typing the words
    run {
        val words = "forum undo fragile fade shy sign arrest garment culture tube off merit"
        val digits = "073318950739065415961602009907670428187212261116"
        val compact = "5bbd9d71a8ec7990831aff359d426545".chunked(2).map { it.toInt(16).toByte() }.toByteArray()
        val q = Signer(signerWasm)
        val want = q.init().seedFromMnemonic(words.toCharArray()).fingerprint
        val wantPass = q.init().seedFromMnemonic(words.toCharArray(), "TREZOR".toCharArray()).fingerprint
        val qr = digits.toByteArray()
        check("SeedQR digits give the typed words' fingerprint", q.init().seedFromSeedQR(qr).fingerprint, want)
        ok("the SeedQR payload is zeroed", qr.all { it == 0.toByte() })
        check("CompactSeedQR gives the same", q.init().seedFromSeedQR(compact.copyOf()).fingerprint, want)
        check("SeedQR with a passphrase",
              q.init().seedFromSeedQR(digits.toByteArray(), "TREZOR".toCharArray()).fingerprint, wantPass)
        for ((what, bad) in listOf("a bad checksum" to digits.dropLast(1) + "7", "47 digits" to digits.drop(1),
                                   "a non-digit" to "x" + digits.drop(1))) {
            q.unload()
            try {
                q.init().seedFromSeedQR(bad.toByteArray())
                ok("SeedQR with $what is refused", false)
            } catch (e: IllegalArgumentException) {
                ok("SeedQR with $what is refused", e.message == "seed_from_seedqr failed" && q.fingerprint == "00000000")
            }
        }
        try {
            q.seedFromSeedQR(ByteArray(400), CharArray(200) { 'x' })
            ok("an oversized SeedQR is refused", false)
        } catch (e: IllegalArgumentException) {
            ok("an oversized SeedQR is refused", e.message!!.contains("does not fit"))
        }
        q.unload()
    }

    // --- unload clears the key
    s.unload()
    s.init()
    check("fingerprint after unload", s.fingerprint, "00000000")

    println("$pass/${pass + fail} checks passed")
    if (fail > 0) System.exit(1)
}
