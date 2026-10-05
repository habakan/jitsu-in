# 構成

何であるかと使い方は [README.ja.md](README.ja.md)、
なぜそうしたかは [docs/rationale.ja.md](docs/rationale.ja.md)。

## どこに何があるか

```
parser/
  c/           C 実装 ── 実機が積むもの
  rust/        Rust 実装 ── 同じ plan、同じテスト。測定は BENCHMARK.md
  docs/abi.md  モジュールの駆動方法
  hosts/       JavaScript、Kotlin、Swift
  tests/       ベクタ、UR の参照値、ファジング
  BENCHMARK.md 両者の代償と、実機が C を取る理由
signer/        signer.wasm: ソース、ABI、3つのホストライブラリ、golden 署名
docs/
  module-abi.md   両モジュールが従う規約と、ホストがやるべきこと
tools/         出力の形とレイアウトの検査、版を固定したツールチェーンの取得
```

**解析器は2つある。** どちらもビルドされ、`make check-rust-plan` が
「全ベクタと2万件の変異 PSBT に対して同じ 5,016 byte の plan を返すこと」を要求する。
これは移行中の状態というだけではない。**同じ仕様に縛られた2つの独立実装は、どちらか一方より価値がある** ──
実際、どちらの自前テストでも見つからなかったベクタの穴を見つけている。

`make` が C、`make PARSER_IMPL=rust` が Rust、`make which-parser` が
`build/parser.wasm` がどちらなのかを答える。実機が C を取るのは、WAMR のインタプリタが
境界検査ごとに課金するため（解析の命令数が3.5倍）と、Rust の AOT が RP2350 の持たない量の
プールを要求するためである。測定は [parser/BENCHMARK.md](parser/BENCHMARK.md)。

ベアメタルの参照実装 ── OS を持たない RP2350 で、同じ `parser.wasm` をバイト単位で同一のまま
動かすもの ── がこれを submodule として使っている。
