# The vectors we built ourselves

These five PSBTs exercise the cases Bitcoin Core's own `rpc_psbt.json` does not: inputs that belong
to a known key, P2TR alongside P2WPKH, a foreign input, and a `non_witness_utxo` present or missing.
Each `.psbt` has a `.json` beside it holding the plan the parser is expected to produce.

They are **committed rather than generated**, because generating them needs a Bitcoin library to
build a PSBT with — and a library that builds the expectation is a library whose bugs become the
expectation. Committing them fixes the corpus, so a change in a dependency cannot quietly change
what is being tested.

The seed is BIP39's published all-zero test vector (`abandon` x11 + `about`), fingerprint
`73c5da0a`. There is nothing secret here.

| | |
|---|---|
| `own_p2wpkh_1in` | one P2WPKH input, paying out plus change |
| `own_p2wpkh_2in_nwu` | two P2WPKH inputs, both with their previous transaction |
| `own_p2tr_2in` | two P2TR key-path inputs |
| `own_mixed_nwu` | P2WPKH and P2TR in one transaction |
| `own_with_foreign_input` | one input ours, one someone else's |

## Regenerating them

`tools/gen_vectors.py` still builds them, with [embit](https://github.com/diybitcoinhardware/embit)
as an independent implementation. It is not part of `make test`; run it only to add a case or to
change one deliberately:

```sh
uv run tools/gen_vectors.py tests/rpc_psbt.json tests/vectors
```

Then read the diff before committing it. A change here changes what every test believes.

## What checks them

That these PSBTs mean what the `.json` says is checked twice, and the second time is the one that
matters: `../../tools/check_against_core.mjs` asks **Bitcoin Core** to decode the same files and
requires its answer to match, and requires the signatures `signer.wasm` produces over them to equal
Core's byte for byte.
