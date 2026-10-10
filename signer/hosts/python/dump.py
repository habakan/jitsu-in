"""Prints what the module reported, in the same lines as signer/hosts/js/dump.mjs, so that the two
hosts can be diffed byte for byte.

  python3 dump.py <signer.wasm> <parser.wasm> <psbt>
"""

import base64
import sys
from pathlib import Path

from jitsu_in import Instance, Signer
from jitsu_in.signer import OWNER, PLAN_N_INPUTS, PLAN_SIZE, TEXT_KIND

signer_path, parser_path, psbt_path = sys.argv[1:4]
MNEMONIC = "abandon " * 11 + "about"

P = Instance(Path(parser_path).read_bytes())
psbt = Path(psbt_path).read_bytes()
P.memory[P.parser_input():P.parser_input() + len(psbt)] = psbt
if P.parser_parse(len(psbt), 0x73C5DA0A) != 0:
    sys.exit("the parser refused the PSBT")
plan = bytes(P.memory[P.parser_plan():P.parser_plan() + PLAN_SIZE])
prevtxs = []
for i in range(plan[PLAN_N_INPUTS]):
    n, at = P.parser_prevtx_len(i), P.parser_input() + P.parser_prevtx_off(i)
    prevtxs.append(bytes(P.memory[at:at + n]) if n else None)

S = Signer(Path(signer_path).read_bytes())
S.init().seed_from_mnemonic(bytearray(MNEMONIC.encode())).set_plan(plan).set_prevtxs(prevtxs)
S.review()
d = S.display()
print(f"fingerprint {S.fingerprint}")
print(f"fee {d['fee']} spend {d['spend']}")
for o in d["outputs"]:
    print(f"out {o['amount']} {OWNER[o['owner']]} {TEXT_KIND[o['text_kind']]} {o['text']}")
for s in S.sign():
    print(f"sig {s['input']} {s['sig'].hex()}")
chain, index = S.find_address("bc1p3qkhfews2uk44qtvauqyr2ttdsw7svhkl9nkm9s9c3x4ax5h60wqwruhk7", count=20)
print(f"found {chain} {index}")
print(f"desc {S.xpub(purpose=86, account=1)['descriptor']}")
print(f"dice {S.mnemonic_from_dice(bytearray(b'3' * 99)).decode()}")
print(f"seedqr {S.seedqr_from_mnemonic(bytearray(MNEMONIC.encode())).decode()}")
print(f"bip85 {S.bip85_mnemonic(words=24, index=3).decode()}")
shown = S.message_review(b"dump\n", purpose=49, chain=1, index=2)
print(f"message {shown['address']} {shown['text']} {base64.b64encode(S.message_sign()).decode()}")
S.unload()
S.init().seed_from_seedqr(bytearray.fromhex("5bbd9d71a8ec7990831aff359d426545"))
print(f"seedqr fingerprint {S.fingerprint}")
S.unload()
