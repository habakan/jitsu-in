<h1><img src="docs/bitcoin.svg" width="26" align="top" alt=""> jitsu-in</h1>

jitsu-inは**Bitcoin の署名機として必要な機能を抽出した WebAssembly モジュール群**です。
WebAssemblyにすることによって、どのプラットフォームでも同一のコードから生成された署名ロジックを利用できることと、各モジュールで必要な情報のみをサンドボックス環境で実行できるようにします。

> **状態: このプロジェクトはまだ実験的で、監査を受けていません。** 本物の資金を利用する場合は
> 十分注意してください。扱える範囲は[対応範囲](#対応範囲)、署名側の制約は
> [signer/docs/abi.md](signer/docs/abi.md) にあります。

<img src="docs/everywhere.svg" alt="同じバイト列がどこでも動く。中央が jitsu-in、周囲が実際に動かした6箇所" width="940">

どこで動かしたか、この図が主張していないことは [docs/everywhere.md](docs/everywhere.md)。

| | byte | import | 何をするか |
|---|---:|---:|---|
| [`parser.wasm`](parser/README.md) | 15,570 | **0** | アニメーション QR（UR）の復元、PSBT v0 の解析、固定長 plan の生成、署名の差し込み、UR の符号化 |
| [`signer.wasm`](signer/docs/abi.md) | 56,522 | **0** | 鍵、BIP32 導出、plan の再検証、表示内容の組み立て、sighash、署名、xpub 出力 |


## 利用方法
本リポジトリで作成されたwasmモジュールをベースにいずれのプラットフォームでも署名機を作成することができます。

| | ランタイム | |
|---|---|---|
| JavaScript / ブラウザ / Node | すでに手元にあるエンジン | [parser](parser/hosts/js) · [signer](signer/hosts/js) |
| Kotlin / JVM / **Android** | [Chicory](https://github.com/dylibso/chicory)、純 Java | [parser](parser/hosts/kotlin) · [signer](signer/hosts/kotlin) |
| Swift / macOS / **iOS** | [WasmKit](https://github.com/swiftwasm/WasmKit)、純 Swift | [parser](parser/hosts/swift) · [signer](signer/hosts/swift) |

どれもネイティブビルドを必要としない。JNI も NDK も、アーキテクチャごとの `.so` や
XCFramework もない。JavaScript のライブラリは素の `.mjs` で、ビルドなしで `import` できる
（TypeScript 用の `.d.mts` も隣にある）。

どのホストもモジュールが返したオフセットを必ず範囲検査し、SHA-256 が期待したビルドでない
モジュールを拒否できる。鍵を持つモジュールにとってこれは、**自分の署名器を動かすのか
他人の署名器を動かすのか** の違いである。

設計の背景は [docs/rationale.md](docs/rationale.md)、構成は [ARCHITECTURE.md](ARCHITECTURE.md)。

## ビルドとテスト

```sh
make deps     # libsecp256k1 を固定した commit で取得
make          # build/parser.wasm と build/signer.wasm
make test     # ベクタ、ホストライブラリ、レイアウト、出力の形
```

wasm32 ターゲットの clang、wasi-libc の sysroot、Node が必要。
Homebrew なら `brew install llvm lld wasi-libc wasi-runtimes node`。

`parser.wasm` を [wasmtime](https://wasmtime.dev/) で動かすテストが1つあるので
[uv](https://docs.astral.sh/uv/) も要る。それ以外に Python は不要で、
第二の Bitcoin ライブラリも要らない。独立した意見が必要なところは
**Bitcoin Core 自身**から取る（`make check-core-diff`、`bitcoind` が必要）。

これは手元の clang を使うので開発には十分だが、**リリースをバイト単位で再現はしない**。
再現には版を固定したツールチェーンを使う ── [parser/docs/releases.md](parser/docs/releases.md)。

JVM と Swift のホストは `kotlinc` と Swift 6.3 以降を要する。

```sh
make check-signer-kotlin check-signer-swift
make check-hosts-agree       # そして全部が同じバイト列を出すことを要求する
```


## 対応範囲

単署名の P2WPKH（[BIP84](https://github.com/bitcoin/bips/blob/master/bip-0084.mediawiki)）と
P2TR の key path（[BIP86](https://github.com/bitcoin/bips/blob/master/bip-0086.mediawiki)）、
`SIGHASH_ALL` と Taproot の `SIGHASH_DEFAULT`。マルチシグ、スクリプトツリー、
レガシー P2PKH の署名は扱わない。

## ライセンス

MIT。[NOTICE](NOTICE) に記載のあるものを除く。
