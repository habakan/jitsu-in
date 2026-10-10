"""Times each stage on this machine, for comparing a Pi Zero against jitsu-in-pico's figures.

  python3 bench.py <signer.wasm> <parser.wasm> <psbt>
"""

import sys
import time
from pathlib import Path

from jitsu_in import Instance, Signer
from jitsu_in.signer import PLAN_N_INPUTS, PLAN_SIZE


def stage(name, f):
    t = time.perf_counter()
    r = f()
    print(f"{name:<24} {(time.perf_counter() - t) * 1000:8.1f} ms")
    return r


signer_path, parser_path, psbt_path = sys.argv[1:4]
psbt = Path(psbt_path).read_bytes()
P = stage("load parser.wasm", lambda: Instance(Path(parser_path).read_bytes()))
S = stage("load signer.wasm", lambda: Signer(Path(signer_path).read_bytes()).init())
P.memory[P.parser_input():P.parser_input() + len(psbt)] = psbt
if stage("parse PSBT", lambda: P.parser_parse(len(psbt), 0x73C5DA0A)) != 0:
    sys.exit("the parser refused the PSBT")
plan = bytes(P.memory[P.parser_plan():P.parser_plan() + PLAN_SIZE])
prevtxs = []
for i in range(plan[PLAN_N_INPUTS]):
    n, at = P.parser_prevtx_len(i), P.parser_input() + P.parser_prevtx_off(i)
    prevtxs.append(bytes(P.memory[at:at + n]) if n else None)
stage("BIP39 seed (PBKDF2)", lambda: S.seed_from_mnemonic(bytearray(("abandon " * 11 + "about").encode())))
S.set_plan(plan).set_prevtxs(prevtxs)
stage("review + display", lambda: (S.review(), S.display()))
sigs = stage("sign", S.sign)
print(f"{len(sigs)} signatures")
S.unload()
