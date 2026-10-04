# Hosts

A host library for `parser.wasm` in each environment, so you do not write the glue yourself.
Each one hides the linear memory, the offsets and the error codes, and bounds-checks every read —
the thing [the ABI](../docs/abi.md) says a host must do and that is easy to forget.

| | Runtime | |
|---|---|---|
| [js](js) | the browser's own, or Node | No dependencies. Works from `file://` |
| [kotlin](kotlin) | [Chicory](https://github.com/dylibso/chicory) | Pure Java: no JNI, no NDK. The easy path on Android |
| [swift](swift) | [WasmKit](https://github.com/swiftwasm/WasmKit) | Pure Swift |

Each directory has the library, a `make run` demo and `make check` tests. The tests mirror each
other, so a host that behaves differently from the others shows up as a failing check.

Adding a language? Copy the shape: one table of offsets, one checked accessor that everything reads
through, and typed objects out.

**These hosts verify nothing.** They hand you what the module read out of the PSBT. Deriving keys,
checking the previous transactions and computing the fee you show the user remain yours — see
[What the host must still do](../docs/abi.md#what-the-host-must-still-do).
