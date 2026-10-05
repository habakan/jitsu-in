#!/usr/bin/env python3
"""Checks that a .wasm we are about to ship has the shape it claims.

The properties that let a user check rather than trust are worth checking continuously on our side
too, so that none of them can quietly stop being true.

Usage: uv run tools/check_wasm.py build/parser.wasm ...

What it looks at:
  no imports              it cannot call a host function: no clock, no network
  memory has a maximum    it cannot eat the host's memory through memory.grow
  no mutable global export the host cannot reach in and rewrite internal state
  no table export         the indirect call table cannot be swapped out
  no start function       loading it does not run anything
  no unfamiliar custom sections  nothing extra came along
"""
import subprocess
import sys

ALLOWED_CUSTOM = {"target_features", "producers"}

# wasm-tools validate defaults to enabling every proposal from phase 4 on, and its own help calls
# that "relatively bleeding edge". For something that has to run on WAMR on an MCU that is the wrong
# direction, so the features each module may require are pinned here and cannot widen unnoticed.
# -mutable-global is in the list because that proposal covers exactly the import and export of a
# mutable global, which turns "exports no mutable global" into a check at the spec level.
# Built with Lime1, so WebAssembly 1.0 plus a narrow phase-5 set is all that is needed. floats and
# saturating-float-to-int are there because the fountain code sampler in ur.c uses f64
BASE_FEATURES = "-all,floats,saturating-float-to-int,bulk-memory-opt,-mutable-global"
EXTRA_FEATURES = {
    # The signer needs sign-extension, which comes in with secp256k1
    "signer.wasm": ",sign-extension",
}


def wat(path):
    r = subprocess.run(["wasm-tools", "print", path], capture_output=True, text=True)
    if r.returncode:
        sys.exit(f"wasm-tools print failed: {r.stderr.strip()}")
    return r.stdout


def check(path):
    features = BASE_FEATURES + EXTRA_FEATURES.get(path.rsplit("/", 1)[-1], "")
    r = subprocess.run(["wasm-tools", "validate", f"--features={features}", path],
                       capture_output=True, text=True)
    bad = [] if r.returncode == 0 else [f"did not validate ({features}): {r.stderr.strip().splitlines()[0]}"]
    text = wat(path)

    # import
    imports = [l for l in text.splitlines() if l.strip().startswith("(import ")]
    if imports:
        bad.append(f"has {len(imports)} import(s): {imports[0].strip()[:60]}")

    # The memory maximum, printed as min then max: (memory (;0;) 3 3)
    mem = [l.strip() for l in text.splitlines() if l.strip().startswith("(memory ")]
    for m in mem:
        nums = [w for w in m.replace(")", " ").split() if w.isdigit()]
        if len(nums) < 2:
            bad.append(f"memory has no maximum, so it can grow: {m}")

    # Exported mutable globals
    mutable = {i for i, l in enumerate(
        [l for l in text.splitlines() if l.strip().startswith("(global ")]) if "(mut " in l}
    for l in text.splitlines():
        s = l.strip()
        if s.startswith("(export ") and "(global " in s:
            idx = int(s.split("(global ")[1].split(")")[0])
            if idx in mutable:
                bad.append(f"exports a mutable global: {s[:60]}")

    # Exported tables and memories, and a start function
    for l in text.splitlines():
        s = l.strip()
        if s.startswith("(export ") and "(table " in s:
            bad.append(f"exports a table: {s[:60]}")
        if s.startswith("(start "):
            bad.append(f"has a start function: {s[:60]}")

    # Custom sections
    for l in text.splitlines():
        s = l.strip()
        if s.startswith("(@custom "):
            name = s.split('"')[1] if '"' in s else "?"
            if name not in ALLOWED_CUSTOM:
                bad.append(f"unfamiliar custom section: {name}")
    return bad, text


failed = 0
for path in sys.argv[1:]:
    bad, text = check(path)
    mem = next((l.strip() for l in text.splitlines() if l.strip().startswith("(memory ")), "?")
    exports = sum(1 for l in text.splitlines() if l.strip().startswith("(export "))
    print(f"{path}: {mem}  {exports} export(s)")
    for b in bad:
        print(f"  × {b}")
        failed += 1
    if not bad:
        print("  no imports / memory is capped / no mutable global or table exported / no start")
sys.exit(1 if failed else 0)
