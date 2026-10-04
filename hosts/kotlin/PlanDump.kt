// Prints the plan for a PSBT, using the host library next to this file.
//   make run
import wasmpsbt.Parser
import java.io.File

fun main(args: Array<String>) {
    if (args.size < 2) {
        System.err.println("usage: PlanDump parser.wasm file.psbt [fingerprint]")
        kotlin.system.exitProcess(2)
    }
    val fingerprint = (if (args.size > 2) args[2] else "73c5da0a").toLong(16).toInt()
    val parser = Parser(File(args[0]).readBytes())
    val plan = parser.parse(File(args[1]).readBytes(), fingerprint)

    fun btc(sats: Long) = "%d.%08d".format(sats / 100_000_000, sats % 100_000_000)
    fun hex(b: ByteArray) = b.joinToString("") { "%02x".format(it) }

    println("version ${plan.txVersion}  locktime ${plan.locktime}  " +
            "${plan.inputs.size} in / ${plan.outputs.size} out")
    plan.inputs.forEachIndexed { i, x ->
        println("  in  $i  ${btc(x.amount)}  ${hex(x.spk)}  ${x.key ?: "-"}")
    }
    plan.outputs.forEachIndexed { i, x ->
        val mine = x.key?.let { "  (change candidate: $it)" } ?: ""
        println("  out $i  ${btc(x.amount)}  ${hex(x.spk)}$mine")
    }
    // The fee is computed from amounts that are claims until each prevtx is checked
    println("  fee     ${btc(plan.fee)}")
}
