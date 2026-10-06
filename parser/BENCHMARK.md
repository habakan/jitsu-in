# C and Rust, measured

Both implementations of `parser.wasm` return the same plan for every vector and for 29,412 mutated
inputs. This is what differs: size, memory, and instructions on the target the device actually uses.

Measured 2026-10-05 under QEMU on RV32 (`qemu-system-riscv32 -icount shift=0`), which counts retired
instructions rather than wall-clock time, with WAMR built the way the device builds it. The PSBT is
`own_mixed_nwu` (two inputs, three outputs, P2WPKH and P2TR mixed) arriving as a 19-part UR.

## What the module is

| | wasm (flash) | linear memory | `__heap_base` | imports |
|---|---:|---:|---:|---:|
| C | 15,570 | 196,608 (3 pages) | 136,064 | 0 |
| Rust | 20,542 | 196,608 (3 pages) | 174,608 | 0 |

The linear memory is the same. Flash costs 5 KB more out of 4 MB.

## Instructions, on the interpreter the device runs

| | C | Rust | |
|---|---:|---:|---:|
| UR reassembly, all 19 parts | 22,170,459 | 82,566,272 | 3.72x |
| UR, worst single part | 4,323,404 | 8,068,291 | 1.91x |
| **PSBT parse** | **24,867,976** | **86,063,551** | **3.46x** |
| signature insertion | 42,660 | 69,203 | 1.62x |
| UR encode and QR, 10 parts | 237,825,663 | 244,812,874 | 1.03x |
| WAMR pool high-water | 152,792 | 192,952 | 1.26x |

At 150 MHz, taking one instruction per cycle, the parse goes from **166 ms to 574 ms**. A full round
is about 806 ms today, so it becomes roughly 1.2 s.

The pool matters as much: the device gives WAMR 160 KB, and Rust wants 193 KB.

## The same, compiled ahead of time

| | C AOT | Rust AOT | |
|---|---:|---:|---:|
| UR reassembly, all 19 parts | 833,059 | 2,120,265 | 2.55x |
| **PSBT parse** | **986,691** | **2,326,928** | **2.36x** |
| the .aot itself | 50,372 | 86,116 | 1.71x |
| WAMR pool high-water | 196,808 | **268,192** | 1.36x |

AOT makes the parse 25x faster for the C and 37x for the Rust — 6.6 ms and 15.5 ms at 150 MHz. It is
not free: AOT code has to be expanded into RAM (executing it in place measured seven times slower on
the hardware), it puts `wamrc` and LLVM in the TCB, and a full round only improved by 8% when this
was tried with the C, because the time is in the native checking, signing and the seed.

**Rust AOT needs 268 KB of pool, and the device has 162 KB free.** It does not fit.

## What this means

| | parse | pool | fits on the device |
|---|---:|---:|---|
| **C, interpreter** | 166 ms | 153 KB | **yes — what ships** |
| C, AOT | 6.6 ms | 197 KB | yes, at +44 KB of RAM and LLVM in the TCB |
| Rust, interpreter | 574 ms | 193 KB | only by raising the pool from 160 KB; and it is slow |
| Rust, AOT | 15.5 ms | 268 KB | **no** |

So the device keeps the C. Not because of flash — the two are within 5 KB — but because the
interpreter charges for every bounds check, and because the pool has a ceiling.

Where the cost comes from is not mysterious: the C calls `rd_take` once and then reads through a raw
pointer, where Rust checks each slice access. On an interpreter every one of those checks is dispatched
instructions, so the ratio shows up directly in the count.

## And yet the Rust is not wasted

Nothing here is an argument for deleting it:

- **In a browser, on Android and on iOS none of these numbers matter.** 574 ms on an interpreter is
  15 ms on a JIT, and the hosts there have memory to spare
- **Two independent implementations required to return the same plan is worth more than either
  alone.** `make check-rust-plan` demands exactly that, and it has already found a gap in the
  vectors that neither implementation's own tests would have
- Where Rust's safety earns its keep is on untrusted input, which is all this module reads. That the
  device cannot afford it is a fact about WAMR's interpreter, not about whether the safety is worth
  having

The measurement that would change this conclusion is a faster interpreter, or the bounds checks
getting cheaper. Both are upstream of this repository.

## Reproducing it

```sh
make check-rust-suite PARSER_IMPL=rust   # the whole suite against either one
```

The QEMU measurements come from the device repository, which has the RV32 toolchain and the host that
drives the module (`make check-qemu-psbt`, with `PARSER_AOT=1` for the AOT rows).
