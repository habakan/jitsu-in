# Host examples

Each example loads `parser.wasm`, feeds it a PSBT and prints the plan. They exist to show that
[the ABI](../docs/abi.md) needs nothing but a WebAssembly runtime: **zero imports, no WASI,
no native toolchain**.

All of them print the same thing for the same input, which is the point:

```
version 2  locktime 0  1 in / 2 out
  in  0  0.00100000  0014c0ce…  73c5da0a/84h/0h/0h/0/0
  out 0  0.00060000  0014a5a7…
  out 1  0.00039000  00143e34…  (change candidate: 73c5da0a/84h/0h/0h/1/0)
  fee     0.00001000
```

| | Runtime | Notes |
|---|---|---|
| [kotlin](kotlin) | [Chicory](https://github.com/dylibso/chicory) 1.4.0 | Pure Java, no JNI |
| [swift](swift) | [WasmKit](https://github.com/swiftwasm/WasmKit) | Pure Swift. Needs a recent toolchain (see its README) |

The reference host in C lives in [`tests/`](../tests) and in the signer repository; the browser
host is `web/viewer.html` there.

## What these examples deliberately do not do

They print what the parser produced. **A real host must do more**, as [the ABI](../docs/abi.md)
spells out: bounds-check every offset, check `magic` and `version`, re-derive keys instead of
trusting `plan_keypath_t`, compute the fee itself, and bind what was displayed to what gets signed.
