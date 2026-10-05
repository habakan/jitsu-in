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

The port is complete, so this is the whole module both ways, with the same flags (2026-10-05):

| | wasm (flash) | linear memory | `__heap_base` | imports | dependencies |
|---|---:|---:|---:|---:|---:|
| C | **15,570** | 196,608 (3 pages) | 136,064 | 0 | — |
| Rust, `no_std` | **20,542** | 196,608 (3 pages) | 174,608 | 0 | **0** |

**The linear memory is the same, and that is the number that matters on a microcontroller.** The
module's bytes cost 5 KB more of flash, out of 4 MB, and the interpreter's writable copy of it costs
5 KB more of RAM, out of 162 KB free.

Getting there took two corrections, both of which inflated an earlier measurement by a long way:

- **Cargo's default wasm stack is 1 MB.** Without `-zstack-size` the linear memory came to 18 pages
  against the C's 3 — it would not have fitted on the device at all. `.cargo/config.toml` sets it to
  48 KB, which is what this needs; 32 KB is not enough, because Rust passes `Parsed` (the 5,016-byte
  plan plus its side tables) by value where the C passed a pointer
- **The working arrays belonged in `static`, not on the stack.** The sampler's 1,024 weights, its
  aliases and the shuffle's index array are 22 KB, and the linker reserves the deepest stack any path
  needs. The C had them in `static` for exactly this reason

Neither was visible from measuring a slice. An earlier comparison of `reader.h` and `tx.c` alone had
Rust *smaller* — 1,067 bytes against 1,221 — and that reversed once `psbt.c` and `ur.c` came across.
**Measuring part of it predicted the wrong sign for the whole.**

Where the 5 KB goes is `core`'s bounds-checked slicing and the panic paths that `overflow-checks` and
indexing produce: each is a branch and a trap the C did not have, because the C checked by hand and
the reviewer had to believe it. That is the trade, stated plainly — **5 KB for not having to believe
it**. Turning `overflow-checks` off would reduce it, and that is the protection the move was for, so
it stays on.

The one place C is clearly ahead on the terms this project cares about is **pinning the toolchain**:
wasi-sdk is two tarballs checked by hash, where Rust is `rustup` with a `rust-toolchain.toml`. The
version is pinned; the bytes are not pinned as tightly.

## Not decided, and not measured

- **Neither module has been run on the hardware or under QEMU.** The instruction counts are unknown,
  so nothing here says anything about speed. The device repository can measure both on the same
  footing (`make check-qemu-psbt`), and that is the next thing worth knowing
- The 48 KB stack is larger than the C's 16 KB. The device gives its native side 32 KB, and whether
  those interact has not been checked
- The signer stays C: it links libsecp256k1, which is C. Only the parser is in question
- Which one becomes the shipped module is open. Keeping both is not only a migration cost: two
  independent implementations held to the same plan catch what neither one's own tests would, and
  this one already has (see [../../docs/rationale.md](../../docs/rationale.md))

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

## Moved across

| C | Rust | |
|---|---|---|
| `include/reader.h` | `src/reader.rs` | bounds-checked reads, compact size |
| `include/plan.h` | `src/plan.rs` | the same `#[repr(C)]` layout, with the same offset assertions |
| `src/sha256.c` | `src/sha256.rs` | |
| `src/tx.c` | `src/tx.rs` | the minimal transaction parser and the txid |
| `src/psbt.c` | `src/psbt.rs` | the PSBT parse, and signature insertion |
| `src/ur.c` | `src/ur/` | `codec.rs`, `decoder.rs`, `encoder.rs` |

**All of it.** The C in `../src` is still the reference and still built, and the two are compared on
every commit until it is retired.

## What is checked, and what it found

| | |
|---|---|
| `make check-rust-suite` | the C's own suite, against the Rust module: **556 checks**, including the 1,174 UR reference values and Bitcoin Core's `rpc_psbt.json` with the same accept/reject counts |
| `make check-rust-plan` | the whole plan, the prevtx offsets and what `finalize` produces, over every vector at three fingerprints and 20,000 mutated PSBTs: **29,455 comparisons** |
| `make check-rust-shape` | no imports, and inside Lime1 |
| `make check-core-diff` | the same agreement with a real `bitcoind` that the C has |

Comparing the plan *whole* rather than field by field is deliberate: a field the check does not know
about cannot hide a difference.

**The comparison found a gap in the vectors, not in the port.** Removing `!has_tree` from the
output's change test — so a taproot output with a script tree would wrongly be offered as change —
changed nothing, because no committed vector had an output that was both ours and carried a tree.
`own_p2tr_change_with_tree.psbt` is that case, and with it the break is caught. The vector count
went from 529 to 556.

## Two things Rust made explicit

`tx::parse` takes a single visitor over an `Item` enum, where the C took two function pointers and a
`void *`. Two `FnMut` closures that both touch the same state each want unique access to it, and the
borrow checker refuses. The C had the same aliasing — both callbacks wrote to the same `plan` — and
simply did not say so. The shape is the same; which of the two the compiler checks is not.

The UR decoder XORs a fragment into a kept mixed part, and in the C those were a pointer into the
caller's buffer and a pointer into the pool. In Rust they are two borrows of `self`, which is
refused, so the fragment is copied to the stack first. **That copy is real cost the C did not pay**,
and it is in the 5.4 KB above.
