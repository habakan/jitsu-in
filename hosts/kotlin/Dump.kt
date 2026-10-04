// Prints the signatures as hex, so the JavaScript host's output and this one can be compared
// directly. Two independent hosts driving the same module must produce the same bytes; if they do
// not, one of them is reading the layout wrong.
import wasmsigner.Signer
import com.dylibso.chicory.runtime.Instance
import com.dylibso.chicory.wasm.Parser as WasmParser
import java.io.File

fun main(args: Array<String>) {
    val signerWasm = File(args[0]).readBytes()
    val parserWasm = File(args[1]).readBytes()
    val psbt = File(args[2]).readBytes()

    val p = Instance.builder(WasmParser.parse(parserWasm)).build()
    val mem = p.memory()
    fun call(n: String, vararg a: Long) = p.export(n).apply(*a)?.firstOrNull()?.toInt() ?: 0
    mem.write(call("parser_input"), psbt)
    require(call("parser_parse", psbt.size.toLong(), 0x73c5da0aL) == 0)
    val plan = mem.readBytes(call("parser_plan"), 5016)
    val nIn = plan[16].toInt() and 0xff
    val inputAt = call("parser_input")
    val prev = (0 until nIn).map { i ->
        val len = call("parser_prevtx_len", i.toLong())
        if (len == 0) null else mem.readBytes(inputAt + call("parser_prevtx_off", i.toLong()), len)
    }

    val s = Signer(signerWasm).init()
    s.seedFromMnemonic(("abandon ".repeat(11) + "about").toCharArray())
    s.setPlan(plan).setPrevTxs(prev)
    s.review()
    val d = s.display()
    println("fingerprint ${s.fingerprint}")
    println("fee ${d.fee} spend ${d.spend}")
    for (o in d.outputs) println("out ${o.amount} ${o.owner} ${o.textKind} ${o.text}")
    for (sig in s.sign()) println("sig ${sig.input} ${sig.sig.joinToString("") { "%02x".format(it) }}")
    s.unload()
}
