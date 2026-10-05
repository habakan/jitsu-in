# Golden signatures

`own_mixed_nwu.signed` is the signed PSBT the **native** implementation produced for
`own_mixed_nwu.psbt` — the same C core that runs on the RP2350, compiled for the host rather than to
wasm. The host libraries' tests require their signatures to appear in it, byte for byte.

That comparison is only meaningful because signing here is deterministic: ECDSA grinds for a low R as
Bitcoin Core does and Schnorr passes a zero `aux_rand`, so one key over one plan has exactly one
answer. A signature that differs is a bug, not a different-but-valid signature.

It is committed rather than generated because producing it needs a WAMR host and a native build of
the core, which belong to the device repository. Regenerate it there with:

```sh
make check-psbt            # writes build/psbt/own_mixed_nwu.signed
```

The same bytes are also required to equal Bitcoin Core's own output, which that repository checks
with `make check-core-diff` against a real `bitcoind`.
