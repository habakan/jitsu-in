# Architecture

<sup>[日本語](docs/ja/ARCHITECTURE.md)</sup>

What this is and how to use it is in [README.md](README.md); why it is shaped this way is in
[docs/rationale.md](docs/rationale.md).

*The device* in these pages is the RP2350 hardware signer these modules were first written for. It is
a separate project and is not public.

## Where things are

```
parser/
  c/           the C implementation — what the device ships
  rust/        the Rust implementation — same plan, same tests, measured in BENCHMARK.md
  docs/abi.md  how to drive the module
  hosts/       JavaScript, Kotlin, Swift
  tests/       vectors, the UR reference values, fuzzing
  BENCHMARK.md what the two cost, and why the device takes the C
signer/        signer.wasm: sources, its ABI, three host libraries, golden signatures
docs/
  module-abi.md   the convention both modules follow, and what a host must do
tools/         checking the shape of the output, the layout, and fetching the pinned toolchain
```

The parser has C and Rust implementations. Both are built, and `make check-rust-plan` requires them
to return the same 6,712-byte plan for every vector and for 20,000 mutated PSBTs. Comparing the two
implementations has also exposed a gap that neither implementation's tests found on their own.

`make` builds the C; `make PARSER_IMPL=rust` builds the Rust; `make which-parser` says which one
`build/parser.wasm` currently is. The device takes the C because WAMR's interpreter charges for every
bounds check — the parse costs 3.5x the instructions — and because the Rust AOT wants more pool than
the RP2350 has. [parser/BENCHMARK.md](parser/BENCHMARK.md) has the measurements.

The bare-metal reference implementation runs the same `parser.wasm` on an RP2350 without an
operating system. It uses this repository as a submodule.
