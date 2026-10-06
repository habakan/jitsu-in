# Kotlin host

Runs on [Chicory](https://github.com/dylibso/chicory), a WebAssembly runtime written in pure Java —
**no JNI, no NDK, and no `.so` per ABI**, which is what makes it the easy choice on Android.
The module has zero imports and does not use WASI, so nothing else is needed.

```kotlin
import wasmpsbt.Parser

val parser = Parser(File("parser.wasm").readBytes())        // once
val plan = parser.parse(psbt, 0x73c5da0a)                   // per transaction

println("${plan.inputs.size} in / ${plan.outputs.size} out, fee ${plan.fee}")
for (out in plan.outputs) {
    println("${out.amount}  ${out.key?.let { "claimed as $it" } ?: ""}")
}
```

On Android the module is an asset: `Parser(assets.open("parser.wasm").readBytes())`.

## What you get

`plan.inputs[i]` — `prevTxid`, `prevVout`, `sequence`, `amount` (`Long`, satoshis), `spk`,
`key`, `sighashType`, and `prevtx` (the `non_witness_utxo`, or `null`).

`plan.outputs[i]` — `amount`, `spk`, `key`.

`key` is a `KeyOrigin?` — BIP380's name for this. It prints as `73c5da0a/84h/0h/0h/0/0`. **It is a claim**: the module read it
out of the PSBT. Derive the key yourself and check that it produces `spk` before you call an output
change, or an input yours. `plan.fee` is `totalIn - totalOut`, and those amounts are claims too
until each input's `prevtx` is checked against its `prevTxid`.

Anything the module rejects throws a `ParserException` with a readable message (`P_ERR_MAGIC`,
`P_ERR_LIMIT`, `UR_ERR_BYTEWORDS`, …). An offset outside the module's memory throws
`IndexOutOfBoundsException` — that would mean the module is not the one you think it is.

## Checking you have the right module

```kotlin
val parser = Parser(File("parser.wasm").readBytes(), sha256 = "7c89bf15…")
```

The module is refused unless it hashes to exactly that. Take the value from the project's
`checksums.txt` or a release's `SHA256SUMS`. A hash written in a file nobody checks is documentation; passing it here makes it a gate.

## Running it

```sh
make run      # prints the plan for a test PSBT
make check    # mirrors hosts/js/test.mjs
```

Both fetch the Chicory jars and verify their SHA-256 first. Needs `kotlinc` and a JDK; verified with
Kotlin 2.4.20, OpenJDK 27 and Chicory 1.4.0.

There is no Gradle setup on purpose: it would mean committing `gradle-wrapper.jar`, and a binary
blob is not something this repository should ask you to trust. Copy `Parser.kt` into your own
project — it is one file with one dependency.
