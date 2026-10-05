# jitsu-in

> **jitsu-in ── 実印。** 署名に拘束力を与える、登録された印。引き出しに入れておく認印ではない。
> ここにある2つのモジュールは、実印を使う行為の2つの半分から名を取っている ──
> **照合**（書面が主張どおりのものか突き合わせる）と、**実印**そのもの（こちらを縛る印）。

**Bitcoin の署名器を2つに割った WebAssembly モジュール。** 一方は信頼できない取引を読み、鍵を持たない。
もう一方は鍵を持ち、それ以外を読まない。どちらも **import が 0 個** ── 時計もファイルシステムも
ネットワークも、呼べるものが何もない。

> **状態: 実験的。監査を受けていない。** 本物の資金を通さないこと。レビューが必要な範囲は
> [docs/module-abi.md](docs/module-abi.md)、署名側の制約は
> [signer/docs/abi.md](signer/docs/abi.md) にある。

| | byte | import | 何をするか |
|---|---:|---:|---|
| [`parser.wasm`](parser/README.md) | 15,570 | **0** | アニメーション QR（UR）の復元、PSBT v0 の解析、固定長 plan の生成、署名の差し込み、UR の符号化 |
| [`signer.wasm`](signer/docs/abi.md) | 56,522 | **0** | 鍵、BIP32 導出、plan の再検証、表示内容の組み立て、sighash、署名、xpub 出力 |

<img src="docs/everywhere.svg" alt="同じバイト列がどこでも動く。中央が jitsu-in、周囲が実際に動かした6箇所" width="940">

どこで動かしたか、この図が主張していないことは [docs/everywhere.md](docs/everywhere.md)。

## なぜ2つに分けるのか

署名器の中で、攻撃者が選んだバイト列を読む最も複雑なコードが解析器である。そこを隔離すると、
解析器を乗っ取っても鍵には届かない。同じモジュールに無く、そのモジュールは何も呼べないからだ。

**乗っ取られた解析器が取引について嘘をつくのを止めているのは、サンドボックスではなく plan である。**
署名側は鍵をすべて自分で再導出し、お釣りかどうかを自分で判定し、手数料を自分で計算し、表示する
文字列をすべて plan のバイト列から組み立てる。そして **見せた plan 以外には署名しない** ──
SHA-256 の一致を要求することで。だから悪意ある解析器は「表示したものに署名させる」ことはできても、
「ある取引を表示して別の取引に署名させる」ことはできない。

## 何のためにあるのか

Bitcoin の立場は「誰も信じなくてよい、自分で確かめられるべきだ」である。署名器はそれを最も
守りにくい場所だ。絶対に信頼しなければならない唯一の部品であり、その全体を読める人はほとんどいない。

**これは署名器を検証するコストを下げるためにある。** 手段は2つ。

**依存を減らし、サプライチェーンを確かめやすくする。** どちらのモジュールも import が 0 個で、
パッケージマネージャを引き込まず、版とハッシュを固定したツールチェーンでビルドされる。
`parser.wasm` 全体が C 4ファイル、15,570 byte である。

> これが下げるのは**確かめるコスト**であって、リスクではない。監査していない依存は、版を固定しても
> 安全にはならない。**何を動かしているのか分かりやすくなるだけ**である。そこを混同するのは
> この取り組みの趣旨に反する。

**プラットフォームを増やし、同じプログラムが検証される回数を増やす。** 1つのモジュールが
バイト単位で同一のまま、OS の無いマイコンで、ブラウザで、Android で、iOS で動く。
それを読み込むプラットフォームが増えるほど、同じバイト列に向けられた目が増える。
そして**あるプラットフォームで見つかった不具合は、全部のプラットフォームで直った不具合になる** ──
これはコードがプラットフォームごとの再実装ではなく共有されているからこそ成り立つ。

「どこでも動く」という図はそのためにある。移植が便利だという話ではない。
**検証が各デバイスでやり直しにならず、積み上がる**という話である。

## 何を確かめられるのか

| | |
|---|---|
| **import が無い** | どちらのモジュールもホスト関数を呼べない。時計もネットワークもシステムコールも無い。意図ではなく CI で検証している |
| **メモリが伸びない** | `--no-growable-memory` でビルドしてあり、宣言した以上のホストメモリを取れない |
| **要求する機能を固定** | [Lime1](https://github.com/WebAssembly/tool-conventions/blob/main/Lime.md)。リンク時の関門なので、依存が黙って要求ランタイムを広げられない |
| **再現可能** | 版とハッシュを固定したツールチェーンで、macOS arm64 と Linux x86_64 が同じバイト列を出す |
| **Bitcoin Core と同じ答え** | 解析で 37 件が一致し、署名 8 本がバイト単位で一致（ECDSA も Schnorr も） |
| **3つのホストが一致** | JavaScript、Kotlin、Swift。出力がバイト単位で同一であることを要求している |
| **パッケージマネージャを使わない** | npm も Gradle も pip も無い。残っている Python 1本は依存ゼロのベクタ展開器。他は C / JavaScript / Kotlin / Swift で、道具はハッシュで固定してある |

## ホストライブラリ

どれもネイティブビルドを必要としない。JNI も NDK も、アーキテクチャごとの `.so` や XCFramework もない。

| | ランタイム | |
|---|---|---|
| JavaScript / ブラウザ / Node | すでに手元にあるエンジン | [parser](parser/hosts/js) · [signer](signer/hosts/js) |
| Kotlin / JVM / **Android** | [Chicory](https://github.com/dylibso/chicory)、純 Java | [parser](parser/hosts/kotlin) · [signer](signer/hosts/kotlin) |
| Swift / macOS / **iOS** | [WasmKit](https://github.com/swiftwasm/WasmKit)、純 Swift | [parser](parser/hosts/swift) · [signer](signer/hosts/swift) |

JavaScript のライブラリは素の `.mjs` で配る。Node でもブラウザでも CDN からでもビルドなしで
`import` できる ── **読んだものが動く** ── そして TypeScript 用に `.d.mts` を隣に置いてある。
型は JSDoc でその場に書き、`make check-types` が検査する。同梱の `.d.mts` が古ければ落ちる。

どのホストもモジュールが返したオフセットを必ず範囲検査し、SHA-256 が期待したビルドでない
モジュールを拒否できる。鍵を持つモジュールにとってこれは、**自分の署名器を動かすのか
他人の署名器を動かすのか** の違いである。

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

## 何を検査しているか

| | |
|---|---|
| 解析器 | Bitcoin Core 自身の `rpc_psbt.json` を含む PSBT ベクタ 529 件、Blockchain Commons の参照値に対する UR の検査 1,174 件、継続ファジング、輸出集合の固定 |
| 署名器 | 3つのホストライブラリにわたる 74 項目。署名がネイティブ実装の出力とバイト単位で一致することを要求 |
| 両方 | 出力の形（`make check-wasm`）と、2つの仕様書および3つのホストライブラリに書かれた構造体オフセットが C の言う値と一致すること（`make check-layout`） |

署名は決定論的である ── ECDSA は Bitcoin Core と同じく low-R grinding を行い、Schnorr は
`aux_rand` に 0 を渡す。だから「同じ署名」とは、有効な別の署名ではなく **同一のバイト列** を意味する。
これがブラウザでハードウェア署名器の出力を正確に再現できる理由である。
**同時にこれはマルチシグの前に見直さなければならない。**
[BIP340](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki) は、
マルチシグで決定論的 nonce は危険だと述べている。

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

## 対応範囲

単署名の P2WPKH（[BIP84](https://github.com/bitcoin/bips/blob/master/bip-0084.mediawiki)）と
P2TR の key path（[BIP86](https://github.com/bitcoin/bips/blob/master/bip-0086.mediawiki)）、
`SIGHASH_ALL` と Taproot の `SIGHASH_DEFAULT`。マルチシグ、スクリプトツリー、
レガシー P2PKH の署名は扱わない。

## ライセンス

MIT。[NOTICE](NOTICE) に記載のあるものを除く。
