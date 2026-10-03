// Drives parser.wasm from Kotlin with Chicory, a WebAssembly runtime written in pure Java.
// No JNI and no native toolchain: the module has zero imports and does not use WASI.
//
//   kotlinc PlanDump.kt -cp "lib/*" -include-runtime -d plandump.jar
//   java -cp "plandump.jar:lib/*" PlanDumpKt ../../build/parser.wasm file.psbt 73c5da0a
//
// See ../../docs/abi.md. The host must bounds-check, check magic/version and re-derive keys;
// this example only prints what the parser produced.
import com.dylibso.chicory.runtime.Instance
import com.dylibso.chicory.wasm.Parser
import java.io.File

// plan_t, as documented in docs/abi.md (ABI version 1)
const val PLAN_MAGIC = 0x4e4c5042
const val INPUTS_OFF = 24; const val INPUT_SIZE = 176
const val OUTPUTS_OFF = 2840; const val OUTPUT_SIZE = 136
const val IN_AMOUNT = 40; const val IN_SPK = 48; const val IN_KEY = 132
const val OUT_AMOUNT = 0; const val OUT_SPK = 8; const val OUT_KEY = 92
const val KEY_DEPTH = 0; const val KEY_FP = 4; const val KEY_PATH = 8

fun main(args: Array<String>) {
    if (args.size < 2) {
        System.err.println("usage: PlanDump parser.wasm file.psbt [fingerprint]")
        kotlin.system.exitProcess(2)
    }
    val fingerprint = (if (args.size > 2) args[2] else "73c5da0a").toLong(16).toInt()

    val instance = Instance.builder(Parser.parse(File(args[0]))).build()
    val memory = instance.memory()
    val limit = memory.pages() * 65536

    fun call(name: String, vararg a: Long): Int = instance.export(name).apply(*a)[0].toInt()

    // Every read goes through here so the offset and length are checked against the memory size.
    fun bytes(off: Int, n: Int): ByteArray {
        require(off >= 0 && n >= 0 && off + n <= limit) { "out of bounds $off+$n" }
        return memory.readBytes(off, n)
    }
    fun u32(off: Int): Int = bytes(off, 4).let {
        (it[0].toInt() and 255) or ((it[1].toInt() and 255) shl 8) or
            ((it[2].toInt() and 255) shl 16) or ((it[3].toInt() and 255) shl 24)
    }
    fun u64(off: Int): Long = bytes(off, 8).let { b ->
        (0..7).fold(0L) { acc, i -> acc or ((b[i].toLong() and 255L) shl (8 * i)) }
    }

    val psbt = File(args[1]).readBytes()
    val input = call("parser_input")
    val cap = call("parser_input_cap")
    require(psbt.size <= cap) { "PSBT larger than $cap" }
    memory.write(input, psbt)

    val rc = call("parser_parse", psbt.size.toLong(), fingerprint.toLong())
    require(rc == 0) { "parser_parse failed: P_ERR $rc" }

    val plan = call("parser_plan")
    require(u32(plan) == PLAN_MAGIC && u32(plan + 4) == 1) { "bad magic or unknown ABI version" }

    fun btc(sats: Long) = String.format("%d.%08d", sats / 100_000_000, sats % 100_000_000)
    fun hex(b: ByteArray) = b.joinToString("") { "%02x".format(it) }
    fun path(off: Int): String {
        val depth = bytes(off + KEY_DEPTH, 1)[0].toInt()
        if (depth == 0) return "-"
        val steps = (0 until depth).joinToString("/") {
            val v = u32(off + KEY_PATH + it * 4)
            if (v < 0) "${v and 0x7fffffff}h" else "$v"
        }
        return "%08x".format(u32(off + KEY_FP)) + "/" + steps
    }
    fun spk(off: Int) = hex(bytes(off + 1, bytes(off, 1)[0].toInt()))

    val nIn = bytes(plan + 16, 1)[0].toInt()
    val nOut = bytes(plan + 17, 1)[0].toInt()
    println("version ${u32(plan + 8)}  locktime ${u32(plan + 12)}  $nIn in / $nOut out")

    var totalIn = 0L
    var totalOut = 0L
    for (i in 0 until nIn) {
        val o = plan + INPUTS_OFF + i * INPUT_SIZE
        totalIn += u64(o + IN_AMOUNT)
        println("  in  $i  ${btc(u64(o + IN_AMOUNT))}  ${spk(o + IN_SPK)}  ${path(o + IN_KEY)}")
    }
    for (i in 0 until nOut) {
        val o = plan + OUTPUTS_OFF + i * OUTPUT_SIZE
        totalOut += u64(o + OUT_AMOUNT)
        val mine = if (bytes(o + OUT_KEY + KEY_DEPTH, 1)[0].toInt() != 0)
            "  (change candidate: ${path(o + OUT_KEY)})" else ""
        println("  out $i  ${btc(u64(o + OUT_AMOUNT))}  ${spk(o + OUT_SPK)}$mine")
    }
    // The host computes the fee itself rather than trusting a field from the parser.
    println("  fee     ${btc(totalIn - totalOut)}")
}
