# /// script
# dependencies = []
# ///
"""配る .wasm が、公開して差し支えない形になっているかを検査する。
利用者が「中身を信じなくても確かめられる」性質を、こちらでも常に確かめておくため。

使い方: uv run tools/check_wasm.py build/parser.wasm ...

見るもの:
  import が無い           ホスト関数を呼べない。時計もネットワークも触れない
  メモリに上限がある       memory.grow でホストのメモリを食えない
  可変 global を輸出しない  ホストから内部状態を書き換えられない
  table を輸出しない       間接呼び出しの表を差し替えられない
  start 関数が無い         読み込んだだけで何も動かない
  未知の custom 節が無い    余計なものが混ざっていない
"""
import subprocess
import sys

ALLOWED_CUSTOM = {"target_features", "producers"}

# wasm-tools validate の既定は「phase 4 以降の提案を全部有効」で、help が自ら
# "relatively bleeding edge" と書いている。MCU の WAMR で動かすものの検査としては逆向きなので、
# 要求する機能をモジュールごとに固定して、知らないうちに広がらないようにする。
# -mutable-global を入れているのは、可変 global の import/export だけを対象にする提案だから。
# これで「可変 global を輸出していない」が spec レベルの検査になる
# Lime1 でビルドしているので、要求するのは WebAssembly 1.0 + phase-5 の狭い集合で足りる。
# floats と saturating-float-to-int は ur.c の fountain code のサンプラが f64 を使うため
BASE_FEATURES = "-all,floats,saturating-float-to-int,bulk-memory-opt,-mutable-global"
EXTRA_FEATURES = {
    # 署名側は secp256k1 由来で sign-extension を使う
    "signer.wasm": ",sign-extension",
}


def wat(path):
    r = subprocess.run(["wasm-tools", "print", path], capture_output=True, text=True)
    if r.returncode:
        sys.exit(f"wasm-tools print が失敗: {r.stderr.strip()}")
    return r.stdout


def check(path):
    features = BASE_FEATURES + EXTRA_FEATURES.get(path.rsplit("/", 1)[-1], "")
    r = subprocess.run(["wasm-tools", "validate", f"--features={features}", path],
                       capture_output=True, text=True)
    bad = [] if r.returncode == 0 else [f"検証に失敗（{features}）: {r.stderr.strip().splitlines()[0]}"]
    text = wat(path)

    # import
    imports = [l for l in text.splitlines() if l.strip().startswith("(import ")]
    if imports:
        bad.append(f"import が {len(imports)} 個ある: {imports[0].strip()[:60]}")

    # メモリの上限。(memory (;0;) 3 3) のように min max と並ぶ
    mem = [l.strip() for l in text.splitlines() if l.strip().startswith("(memory ")]
    for m in mem:
        nums = [w for w in m.replace(")", " ").split() if w.isdigit()]
        if len(nums) < 2:
            bad.append(f"メモリに上限が無い（伸長できる）: {m}")

    # 可変 global の輸出
    mutable = {i for i, l in enumerate(
        [l for l in text.splitlines() if l.strip().startswith("(global ")]) if "(mut " in l}
    for l in text.splitlines():
        s = l.strip()
        if s.startswith("(export ") and "(global " in s:
            idx = int(s.split("(global ")[1].split(")")[0])
            if idx in mutable:
                bad.append(f"可変 global を輸出している: {s[:60]}")

    # table / memory の輸出、start 関数
    for l in text.splitlines():
        s = l.strip()
        if s.startswith("(export ") and "(table " in s:
            bad.append(f"table を輸出している: {s[:60]}")
        if s.startswith("(start "):
            bad.append(f"start 関数がある: {s[:60]}")

    # custom 節
    for l in text.splitlines():
        s = l.strip()
        if s.startswith("(@custom "):
            name = s.split('"')[1] if '"' in s else "?"
            if name not in ALLOWED_CUSTOM:
                bad.append(f"見覚えのない custom 節: {name}")
    return bad, text


failed = 0
for path in sys.argv[1:]:
    bad, text = check(path)
    mem = next((l.strip() for l in text.splitlines() if l.strip().startswith("(memory ")), "?")
    exports = sum(1 for l in text.splitlines() if l.strip().startswith("(export "))
    print(f"{path}: {mem}  輸出 {exports} 個")
    for b in bad:
        print(f"  × {b}")
        failed += 1
    if not bad:
        print("  import 無し / メモリ上限あり / 可変 global も table も輸出せず / start 無し")
sys.exit(1 if failed else 0)
