<h1>jitsu-in</h1>

<sup>[English](../../README.md)</sup>

jitsu-in は Bitcoin の署名に使う処理を WebAssembly モジュールとして提供します。
`parser.wasm` は未信頼の PSBT を読み、固定レイアウトの plan を作ります。`signer.wasm` は plan を検証し、
レビュー用の取引情報を作り、取引に署名します。parser は鍵を持たず、signer は PSBT を読みません。

> **状態: このプロジェクトはまだ実験的で、監査を受けていません。** 本物の資金を利用する場合は
> 十分注意してください。扱える範囲は[対応範囲](#対応範囲)、署名側の制約は
> [signer/docs/abi.md](../../signer/docs/abi.md) にあります。

<img src="../everywhere.svg" alt="同じバイト列がどこでも動く。中央が jitsu-in、周囲が実際に動かした6箇所" width="940">

実行した環境と、各環境で確認した範囲は [docs/everywhere.md](../everywhere.md) に記載しています。

| | byte | import | 何をするか |
|---|---:|---:|---|
| [`parser.wasm`](../../parser/README.md) | 15,632 | **0** | アニメーション QR（UR）の復元、PSBT v0 の解析、固定長 plan の生成、署名の差し込み、UR の符号化 |
| [`signer.wasm`](../../signer/docs/abi.md) | 74,631 | **0** | 鍵、SeedQR、BIP32 導出、plan の再検証、表示内容の組み立て、sighash、署名、xpub 出力 |


## 利用方法

[ブラウザビューア](../../examples/viewer)は、parser のホストと、PSBT と UR を確認する1ファイルのページを組み合わせたものです。
鍵を持たず、署名用の端末でもありません。

| | ランタイム | |
|---|---|---|
| JavaScript / ブラウザ / Node | すでに手元にあるエンジン | [parser](../../parser/hosts/js) · [signer](../../signer/hosts/js) |
| Kotlin / JVM / **Android** | [Chicory](https://github.com/dylibso/chicory)、純 Java | [parser](../../parser/hosts/kotlin) · [signer](../../signer/hosts/kotlin) |
| Swift / macOS / **iOS** | [WasmKit](https://github.com/swiftwasm/WasmKit)、純 Swift | [parser](../../parser/hosts/swift) · [signer](../../signer/hosts/swift) |

どのホストもネイティブビルドを必要としません。JNI や NDK、アーキテクチャごとの `.so` や
XCFramework も不要です。JavaScript のライブラリは素の `.mjs` で、ビルドせずに `import` できます
（TypeScript 用の `.d.mts` も隣にあります）。

JavaScript、Kotlin、Swift のホストライブラリは、モジュールが返すオフセットを範囲検査し、
モジュールの SHA-256 を固定できます。設定したハッシュと異なるビルドは実行前に拒否できます。

設計理由は [docs/rationale.md](rationale.md)、リポジトリの構成は [ARCHITECTURE.md](ARCHITECTURE.md) にあります。

## ビルドとテスト

```sh
make deps     # 固定した commit の libsecp256k1 を取得します
make          # build/parser.wasm と build/signer.wasm をビルドします
make test     # ベクタ、ホストライブラリ、レイアウトを検査します
make check-wasm   # 出力の形を検査します（wasm-tools が必要）
make check-c-format check-c-tidy
```

`make format-c` は C の書式を整えます。CI では固定した wasi-sdk に含まれる clang-format と clang-tidy を使います。

wasm32 ターゲットの clang、wasi-libc の sysroot、Node が必要です。
Homebrew では `brew install llvm lld wasi-libc wasi-runtimes node cmake` でインストールできます。

`make wamr-deps && make check-wamr` で parser のベクタテストと signer の JavaScript テストを WAMR 2.4.5 でも実行し、signer の出力が V8 とバイト単位で一致することを確認します。
Node/V8 と同じ JavaScript テストを使います。独立した照合には**Bitcoin Core 自身**を使います
（`make check-core-diff`。実行には `bitcoind` が必要です）。

通常のビルドでは手元の clang を使います。開発には使えますが、**リリースをバイト単位で再現するものではありません**。
再現にはバージョンを固定したツールチェーンを使います。詳しくは[リリース手順](../../parser/docs/releases.md)をご覧ください。

JVM と Swift のホストには `kotlinc` と Swift 6.3 以降が必要です。

```sh
make check-signer-kotlin check-signer-swift
make check-hosts-agree       # すべてのホストで出力が同じバイト列になることを確認します
```


## 対応範囲

単署名の P2WPKH（[BIP84](https://github.com/bitcoin/bips/blob/master/bip-0084.mediawiki)）、
P2SH-P2WPKH（[BIP49](https://github.com/bitcoin/bips/blob/master/bip-0049.mediawiki)）、
P2TR の key path（[BIP86](https://github.com/bitcoin/bips/blob/master/bip-0086.mediawiki)）、
`SIGHASH_ALL` と Taproot の `SIGHASH_DEFAULT` に対応しています。マルチシグ、スクリプトツリー、
レガシー P2PKH の署名は扱いません。

## ライセンス

ライセンスは MIT です。ただし、[NOTICE](../../NOTICE) に記載したものは除きます。
