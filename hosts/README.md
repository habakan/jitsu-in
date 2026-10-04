# Hosts

Ready-made hosts for `parser.wasm`, so you do not have to write the glue yourself.
Each one hides the linear memory, the offsets and the error codes, and bounds-checks every read —
the thing [the ABI](../docs/abi.md) says a host must do and that is easy to forget.

| | Status |
|---|---|
| [js](js) | Reference host. No dependencies, works in Node and in a browser |
| Kotlin / Swift | [`examples/`](../examples) show the same thing inline; a library is not packaged yet |

If you are adding a host for another language, the JavaScript one is the shape to copy: one checked
accessor that everything reads through, one table of offsets, and typed objects out.

**These hosts do not verify anything.** They hand you what the module read out of the PSBT.
Deriving keys, checking the previous transactions and computing the fee you show the user remain
yours — see [What the host must still do](../docs/abi.md#what-the-host-must-still-do).
