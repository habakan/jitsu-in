#!/usr/bin/env python3
"""Expands Bitcoin Core's rpc_psbt.json into one .psbt per case.

Only a base64 decode: the corpus is Core's, and nothing here invents a transaction. The vectors that
*are* ours (own_*) are committed under tests/vectors instead, so that no Bitcoin library is needed to
produce them — see tests/vectors/README.md.
"""
import base64
import json
import shutil
import sys
from pathlib import Path


def main():
    if len(sys.argv) != 4:
        sys.exit("usage: expand_rpc_vectors.py rpc_psbt.json COMMITTED_DIR OUT_DIR")
    rpc, committed, out = Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3])

    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)

    # The vectors we built ourselves, committed rather than generated
    n_own = 0
    for f in sorted(committed.glob("own_*")):
        shutil.copy(f, out / f.name)
        n_own += 1 if f.suffix == ".psbt" else 0

    cases = json.loads(rpc.read_text())
    n_rpc = 0
    for kind in ("invalid", "invalid_with_msg", "valid"):
        for i, case in enumerate(cases.get(kind, [])):
            b64 = case[0] if isinstance(case, list) else case
            try:
                raw = base64.b64decode(b64, validate=True)
            except Exception:
                continue           # two cases in Core's file have corrupt base64
            # The kind is kept in the name, and the index is the one in the JSON array: run_tests.py
            # looks the expected message back up by both
            (out / f"rpc_{kind}_{i:02d}.psbt").write_bytes(raw)
            n_rpc += 1

    print(f"{n_own} committed vectors, {n_rpc} expanded from rpc_psbt.json")


if __name__ == "__main__":
    main()
