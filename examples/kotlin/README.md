# Kotlin + Chicory

[Chicory](https://github.com/dylibso/chicory) is a WebAssembly runtime written in pure Java,
so this runs on any JVM with no JNI and no native build step.

```sh
make run
```

That fetches the two Chicory jars (checking their SHA-256), compiles `PlanDump.kt`, and prints the
plan for a test PSBT. Point it elsewhere with `make run WASM=... PSBT=... FP=...`.

## The code

Loading the module and reading the plan is about twenty lines. The full example is
[`PlanDump.kt`](PlanDump.kt); this is its core:

```kotlin
val instance = Instance.builder(Parser.parse(File(wasmPath))).build()
val memory = instance.memory()
val limit = memory.pages() * 65536

fun call(name: String, vararg a: Long): Int = instance.export(name).apply(*a)[0].toInt()

// Every read goes through here so the offset and length are checked against the memory size
fun bytes(off: Int, n: Int): ByteArray {
    require(off >= 0 && n >= 0 && off + n <= limit) { "out of bounds $off+$n" }
    return memory.readBytes(off, n)
}

// Write the PSBT where the module expects it, then parse
val psbt = File(psbtPath).readBytes()
require(psbt.size <= call("parser_input_cap"))
memory.write(call("parser_input"), psbt)
require(call("parser_parse", psbt.size.toLong(), fingerprint.toLong()) == 0)

// Read the plan it produced. Offsets come from docs/abi.md
val plan = call("parser_plan")
require(u32(plan) == 0x4e4c5042 && u32(plan + 4) == 1)   // "BPLN", ABI version 1
val nIn = bytes(plan + 16, 1)[0].toInt()
val nOut = bytes(plan + 17, 1)[0].toInt()
val firstOutputAmount = u64(plan + 2840 + 0)             // outputs[0].amount
```

There is no generated binding and no code generation step: the offsets are read straight from
[the ABI](../../docs/abi.md).

Needs `kotlinc` and a JDK; verified with Kotlin 2.4.20, OpenJDK 27 and Chicory 1.4.0. The output
matches the C host and the browser host byte for byte.

There is no Gradle setup on purpose: it would mean committing `gradle-wrapper.jar`, and a binary
blob is not something this repository should ask you to trust.
