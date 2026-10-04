# Kotlin + Chicory

[Chicory](https://github.com/dylibso/chicory) is a WebAssembly runtime written in pure Java,
so this runs on any JVM with no JNI and no native build step.

```sh
make run
```

That fetches the two Chicory jars (checking their SHA-256), compiles `PlanDump.kt`, and prints the
plan for a test PSBT. Point it elsewhere with `make run WASM=... PSBT=... FP=...`.

Needs `kotlinc` and a JDK; verified with Kotlin 2.4.20, OpenJDK 27 and Chicory 1.4.0. The output
matches the C host and the browser host byte for byte.

There is no Gradle setup on purpose: it would mean committing `gradle-wrapper.jar`, and a binary
blob is not something this repository should ask you to trust.
