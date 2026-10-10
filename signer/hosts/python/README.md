# signer.wasm from Python

A host for `signer.wasm` and `parser.wasm` on [WAMR](https://github.com/bytecodealliance/wasm-micro-runtime)'s
classic interpreter, the one jitsu-in-pico runs. The bindings are plain `ctypes`: the only native piece is
`libiwasm`, so a Linux image such as SeedSigner OS needs that one shared library and nothing compiled
against Python.

Status: a proof of concept for driving these modules from a SeedSigner fork. It covers the signer's whole
ABI; the parser is driven through its raw exports in `dump.py`, without a host library of its own yet.

The ABI is in [../../docs/abi.md](../../docs/abi.md). Secrets are passed as `bytearray`, because a `str`
or `bytes` cannot be cleared, and each one is zeroed before the call returns.

## Testing

```sh
make wamr-deps
make check-python   # dump.py on WAMR must print exactly what dump.mjs prints on V8
python3 signer/hosts/python/bench.py build/signer.wasm build/parser.wasm parser/build/vectors/own_mixed_nwu.psbt
```

`JITSU_IN_LIBIWASM` points at `libiwasm.so` (or `.dylib`) when it is not on the loader's path.

## Using it

```python
from jitsu_in import Signer

signer = Signer(signer_wasm, sha256="…").init(testnet=False)
try:
    signer.seed_from_mnemonic(bytearray(mnemonic_bytes))  # zeroed for you
    signer.set_plan(plan).set_prevtxs(prevtxs)
    signer.review()
    shown = signer.display()  # put this in front of the person approving
    sigs = signer.sign()      # hand each sig["raw"] to parser.wasm
finally:
    signer.unload()
```
