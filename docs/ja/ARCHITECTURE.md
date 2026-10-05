# 構成

何であるかと使い方は [README.md](README.md)、
なぜそうしたかは [rationale.md](rationale.md)。

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

C と Rust の解析器をどちらもビルドします。`make check-rust-plan` は、全ベクタと2万件の変異 PSBT に対して
両方が同じ 5,016 byte の plan を返すことを確認します。2つの実装を比較したことで、個別のテストでは
見つからなかったベクタの不足も判明しました。

`make` が C、`make PARSER_IMPL=rust` が Rust、`make which-parser` が
`build/parser.wasm` がどちらなのかを答える。実機が C を取るのは、WAMR のインタプリタが
境界検査ごとに課金するため（解析の命令数が3.5倍）と、Rust の AOT が RP2350 の持たない量の
プールを要求するためである。測定は [parser/BENCHMARK.md](../../parser/BENCHMARK.md)。

ベアメタルの参照実装は、OS のない RP2350 で同じ `parser.wasm` をそのまま動かします。
このリポジトリを submodule として使っています。
