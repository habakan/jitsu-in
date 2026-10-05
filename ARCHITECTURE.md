# Architecture

<sup>[日本語](docs/ja/ARCHITECTURE.md)</sup>

What this is and how to use it is in [README.md](README.md); why it is shaped this way is in
[docs/rationale.md](docs/rationale.md).

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

**The parser exists twice.** Both are built, and `make check-rust-plan` requires them to return the
same 5,016-byte plan for every vector and for 20,000 mutated PSBTs. That is not only a migration
state: two independent implementations held to the same specification is worth more than either
alone, and it has already found a gap in the vectors that neither one's own tests would have.

`make` builds the C; `make PARSER_IMPL=rust` builds the Rust; `make which-parser` says which one
`build/parser.wasm` currently is. The device takes the C because WAMR's interpreter charges for every
bounds check — the parse costs 3.5x the instructions — and because the Rust AOT wants more pool than
the RP2350 has. [parser/BENCHMARK.md](parser/BENCHMARK.md) has the measurements.

A reference implementation on bare metal — an RP2350 with no operating system, running the same
`parser.wasm` byte for byte — uses these as a submodule.
