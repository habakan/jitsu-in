# signer.wasm on the JVM

A host for `signer.wasm` that runs anywhere a JVM does, Android included. It uses
[Chicory](https://github.com/dylibso/chicory), a WebAssembly runtime written in pure Java: **no JNI,
no NDK, no `.so` per ABI.** The module has zero imports and does not use WASI, so nothing else is
needed.

The ABI is in [../../docs/abi.md](../../docs/abi.md). What is specific to holding a key is under
"What a host must not do" there, and this library enforces what it can.

## Building and testing

```sh
make check    # 25 checks, against the signatures the native signer produced
```

Chicory comes from Maven Central and its hash is checked. There is no Gradle on purpose: that would
mean committing `gradle-wrapper.jar`, and a binary blob is not something this repository should ask
you to trust.

## Using it

```kotlin
import wasmsigner.Signer

// Pin the hash. A module that holds a key is the last place to accept whatever bytes arrived.
val signer = Signer(signerWasm, sha256 = "6f05069b…").init(testnet = false)

// CharArray, not String: a String cannot be cleared, and this one is zeroed for you
signer.seedFromMnemonic(mnemonic)
println(signer.fingerprint)                 // "73c5da0a"

signer.setPlan(plan).setPrevTxs(prevTxs)    // plan comes from parser.wasm, verbatim

val review = signer.review()                // re-derives the keys and checks the plan
val display = signer.display()              // what to put in front of the person approving
for (o in display.outputs) {
    println("${o.amount} sats to ${o.text} (${o.owner})")
}
println("fee ${display.fee}")

// Only after someone has actually approved what display() returned
val signatures = signer.sign()              // one review permits one signing
signer.unload()                             // zeroes the key; do not wait until you remember
```

Hand each `Signature.raw` to `parser.wasm`'s signature buffer and call `parser_finalize()`.

## On Android

Chicory is a plain JAR, so this is a library dependency and nothing more — no native build, no ABI
splits, no NDK. The module's bytes can ship as an asset, and pinning its SHA-256 means an asset
swapped out for another is refused rather than run.

`seedFromMnemonic` takes a `CharArray` so it can be cleared. Android's `EditText` hands you an
`Editable`; copy out of it and clear it, rather than taking `.toString()`.

## Agreeing with the JavaScript host

`make -C ../../../.. check-hosts-agree` runs this library and the JavaScript one over the same PSBT
and requires their output to match byte for byte. Two independent hosts reading the same module is
the only thing that catches one of them reading the layout wrong — a single host's tests pass just
as happily when both the library and its expectations are wrong together.
