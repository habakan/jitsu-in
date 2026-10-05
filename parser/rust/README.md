# parser.wasm, in Rust

The parser is being moved from C to Rust. The C in `../src` is the reference until that is finished,
and `make check-rust-agrees` requires the two to give identical answers on every vector and on
50,000 fuzzed inputs. **A port checked only against its own tests is a port whose bugs become its
tests**, which is why the comparison exists rather than a second set of expectations.

## Why

The parser is the only code here that reads bytes an attacker chose. What Rust removes is the class
of bug that lives exactly there: the `prevtx_off` defect found on 2026-10-03 was a pointer truncated
to 32 bits, which the type system makes unwritable. Bounds and integer handling stop being things a
reviewer has to check by eye.

What Rust does **not** remove is a fee computed wrongly, change identified wrongly, or BIP174 read
wrongly — and that is most of what the 529 vectors, the fuzzing and the comparison against Bitcoin
Core are guarding. The move is worth making, and it is not a substitute for any of those.

## What it costs, measured

Ported `reader.h` and `tx.c` both ways and compared, with the same flags and the same work
(2026-10-05):

| | raw | after `wasm-opt -Oz` | code | imports | dependencies |
|---|---:|---:|---:|---:|---:|
| Rust, `no_std` | 1,278 | 1,067 | 899 | **0** | **0** |
| C | 1,454 | 1,221 | 925 | **0** | — |

Rust came out smaller, which was not the expectation. `panic = "abort"` with
`core::arch::wasm32::unreachable()` leaves no unwinding machinery, and nothing pulls in `core`'s
formatting.

The one place C is clearly ahead is **pinning the toolchain**: wasi-sdk is two tarballs checked by
hash, where Rust is `rustup` with a `rust-toolchain.toml`. The version is pinned; the bytes are not
pinned as tightly.

## How the port is run

- `overflow-checks = true` stays on in release. This reads untrusted input, and a length that wraps
  is the kind of bug the move is for
- No dependencies. `Cargo.lock` holds this crate and nothing else — fewer things to audit before you
  can say what you are running
- Each piece is ported, then compared, then the next one starts. Nothing is deleted from `../src`
  until the whole of `parser.wasm` is Rust and the existing 529 vectors, 1,174 UR checks and the
  Bitcoin Core comparison all pass against it unchanged
- Those tests drive the module by its exported names, so **they do not need porting**: a Rust module
  with the same 17 exports is tested by exactly the suite the C is

## Moved across so far

| | |
|---|---|
| `include/reader.h` | `src/reader.rs` — bounds-checked reads, compact size |
| `include/plan.h` | `src/plan.rs` — the same `#[repr(C)]` layout, with the same offset assertions |
| `src/sha256.c` | `src/sha256.rs` |
| `src/tx.c` | `src/tx.rs` — the minimal transaction parser and the txid |
| `src/psbt.c` | `src/psbt.rs` — the PSBT parse, and signature insertion |

Still C: `src/ur.c` (526 lines), the animated-QR reassembly and encoding.

## What is checked, and what it found

| | |
|---|---|
| `make check-rust-suite` | the C's own suite, against the Rust module: **257 checks**, including Bitcoin Core's `rpc_psbt.json` with the same accept/reject counts |
| `make check-rust-plan` | the whole 5,016-byte plan, the prevtx offsets and what `finalize` produces, over every vector at three fingerprints and 20,000 mutated PSBTs: **29,524 comparisons** |
| `make check-rust-shape` | no imports, and inside Lime1 |

Comparing the plan *whole* rather than field by field is deliberate: a field the check does not know
about cannot hide a difference.

**The comparison found a gap in the vectors, not in the port.** Removing `!has_tree` from the
output's change test — so a taproot output with a script tree would wrongly be offered as change —
changed nothing, because no committed vector had an output that was both ours and carried a tree.
`own_p2tr_change_with_tree.psbt` is that case, and with it the break is caught. The vector count went
from 529 to 556.

## One thing Rust made explicit

`tx::parse` takes a single visitor over an `Item` enum, where the C took two function pointers and a
`void *`. Two `FnMut` closures that both touch the same state each want unique access to it, and the
borrow checker refuses. The C had the same aliasing — both callbacks wrote to the same `plan` — and
simply did not say so. The shape is the same; which of the two the compiler checks is not.
