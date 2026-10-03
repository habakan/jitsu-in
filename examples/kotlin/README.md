# Kotlin + Chicory

[Chicory](https://github.com/dylibso/chicory) is a WebAssembly runtime written in pure Java,
so this runs on any JVM with no JNI and no native build step.

```sh
# jars (once)
mkdir -p lib
for a in runtime wasm; do
  curl -sLO "https://repo1.maven.org/maven2/com/dylibso/chicory/$a/1.4.0/$a-1.4.0.jar"
  mv "$a-1.4.0.jar" lib/
done

kotlinc PlanDump.kt -cp "lib/runtime-1.4.0.jar:lib/wasm-1.4.0.jar" -include-runtime -d plandump.jar
java -cp "plandump.jar:lib/runtime-1.4.0.jar:lib/wasm-1.4.0.jar" PlanDumpKt \
  ../../build/parser.wasm ../../build/vectors/own_p2wpkh_1in.psbt 73c5da0a
```

Verified with OpenJDK 27, Kotlin 2.4.20 and Chicory 1.4.0. The output matches the C host and the
browser host byte for byte.
