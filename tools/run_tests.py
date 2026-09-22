# /// script
# dependencies = ["wasmtime", "embit"]
# ///
"""Tests build/parser.wasm itself under wasmtime.
1) no imports  2) Bitcoin Core's rpc_psbt.json  3) plans match expectations  4) signature insertion and failures"""
import glob, json, os, re, struct, sys
import wasmtime
from embit import ec
from embit.psbt import PSBT
from embit.transaction import Transaction

WASM, VEC, RPC = sys.argv[1], sys.argv[2], sys.argv[3]
P_OK, P_ERR_TX, P_ERR_UNSUPPORTED, P_ERR_UTXO = 0, 4, 5, 7
# The defect in invalid_with_msg[15] is the value length of PSBT_IN_MUSIG2_PARTIAL_SIG (0x1c); its message omits musig2
MUSIG2_BY_FIELD = {15}
engine = wasmtime.Engine()
module = wasmtime.Module.from_file(engine, WASM)
checks, failures = 0, []


def check(cond, msg):
    global checks
    checks += 1
    if not cond:
        failures.append(msg)


class Parser:
    def __init__(self):
        self.store = wasmtime.Store(engine)
        self.ex = wasmtime.Instance(self.store, module, []).exports(self.store)
        self.mem = self.ex["memory"]

    def call(self, name, *args):
        return self.ex[name](self.store, *args)

    def parse(self, raw, fp):
        self.mem.write(self.store, raw, self.call("parser_input"))
        return self.call("parser_parse", len(raw), fp)

    def read(self, addr, n):
        return bytes(self.mem.read(self.store, addr, addr + n))

    def plan(self):
        b = self.read(self.call("parser_plan"), 5016)
        magic, version, txv, locktime, n_in, n_out = struct.unpack_from("<IIiIBB", b, 0)

        def keypath(off):
            depth, fp = b[off], struct.unpack_from("<I", b, off + 4)[0]
            path = list(struct.unpack_from("<8I", b, off + 8))
            return None if depth == 0 else {"fingerprint": fp, "path": path[:depth]}

        ins = []
        for i in range(n_in):
            o = 24 + 176 * i
            vout, seq, amount = struct.unpack_from("<IIQ", b, o + 32)
            ins.append({"prev_txid": b[o:o + 32].hex(), "prev_vout": vout, "sequence": seq, "amount": amount,
                        "spk": b[o + 49:o + 49 + b[o + 48]].hex(), "key": keypath(o + 132), "sighash_type": b[o + 172]})
        outs = []
        for i in range(n_out):
            o = 24 + 176 * 16 + 136 * i
            outs.append({"amount": struct.unpack_from("<Q", b, o)[0], "spk": b[o + 9:o + 9 + b[o + 8]].hex(),
                         "key": keypath(o + 92)})
        return {"magic": magic, "version": version, "tx_version": txv, "locktime": locktime, "inputs": ins,
                "outputs": outs}

    def prevtx(self, i):
        n = self.call("parser_prevtx_len", i)
        return self.read(self.call("parser_prevtx_off", i), n) if n else b""

    def finalize(self, sigs):
        buf = b"".join(bytes([i]) + pub.ljust(33, b"\0") + bytes([len(sig)]) + sig.ljust(73, b"\0")
                       for i, pub, sig in sigs)
        if buf:
            self.mem.write(self.store, buf, self.call("parser_sigs"))
        n = self.call("parser_finalize", len(sigs))
        return n, (self.read(self.call("parser_output"), n) if n > 0 else b"")


# 1) no imports
check(len(module.imports) == 0, f"imports: {[i.name for i in module.imports]}")

# 2) Bitcoin Core's rpc_psbt.json
vectors = json.load(open(RPC))
counts = {}
for path in sorted(glob.glob(os.path.join(VEC, "rpc_*.psbt"))):
    kind, i = re.match(r".*/rpc_(\w+?)_(\d+)\.psbt", path).groups()
    i = int(i)
    try:
        rc = Parser().parse(open(path, "rb").read(), 0)
    except wasmtime.Trap as e:
        check(False, f"{kind}[{i}] trapped: {e}")
        continue
    counts[(kind, rc == P_OK)] = counts.get((kind, rc == P_OK), 0) + 1
    if kind.startswith("invalid") and rc == P_OK:
        msg = vectors["invalid_with_msg"][i][1] if kind == "invalid_with_msg" else ""
        check("musig2" in msg.lower() or (kind == "invalid_with_msg" and i in MUSIG2_BY_FIELD),
              f"{kind}[{i}] accepted")
    if kind == "valid":
        check(rc in (P_OK, P_ERR_UNSUPPORTED, P_ERR_UTXO, P_ERR_TX), f"valid[{i}] rejected rc={rc}")

# 3) plans match expectations, 4) signature insertion
for path in sorted(glob.glob(os.path.join(VEC, "own_*.psbt"))):
    name = os.path.basename(path)[:-5]
    raw = open(path, "rb").read()
    exp = json.load(open(path[:-5] + ".json"))
    p = Parser()
    check(p.parse(raw, exp["fingerprint"]) == P_OK, f"{name}: parse")
    plan = p.plan()
    check(plan["tx_version"] == exp["tx_version"] and plan["locktime"] == exp["locktime"], f"{name}: header")
    check(len(plan["inputs"]) == len(exp["inputs"]) and len(plan["outputs"]) == len(exp["outputs"]), f"{name}: counts")
    for i, (got, want) in enumerate(zip(plan["inputs"], exp["inputs"])):
        for k in ("prev_txid", "prev_vout", "sequence", "amount", "spk", "key", "sighash_type"):
            check(got[k] == want[k], f"{name}: input {i} {k}: {got[k]} != {want[k]}")
        prev = p.prevtx(i)
        check(bool(prev) == want["has_prevtx"], f"{name}: input {i} prevtx presence")
        if prev:
            check(bytes(reversed(Transaction.parse(prev).txid())).hex() == want["prev_txid"], f"{name}: prevtx txid")
    for i, (got, want) in enumerate(zip(plan["outputs"], exp["outputs"])):
        for k in ("amount", "spk", "key"):
            check(got[k] == want[k], f"{name}: output {i} {k}: {got[k]} != {want[k]}")

    # a different fingerprint selects no key candidates
    other = Parser()
    check(other.parse(raw, exp["fingerprint"] ^ 1) == P_OK and all(
        x["key"] is None for x in other.plan()["inputs"] + other.plan()["outputs"]), f"{name}: foreign fingerprint")

    sigs = []
    for i, want in enumerate(exp["inputs"]):
        if want["key"] is None:
            continue
        if want["spk"].startswith("5120"):
            sig = bytes([0xab]) * 64 + (bytes([want["sighash_type"]]) if want["sighash_type"] else b"")
            sigs.append((i, b"\0" + bytes.fromhex(want["spk"])[2:], sig))
        else:
            sigs.append((i, bytes.fromhex(exp["pubkeys"][i]), bytes([0x30, 0x44]) + bytes([0x5a]) * 68 + b"\x01"))
    n, out = p.finalize(sigs)
    inserted = sum(2 + 33 + 1 + len(s) if pub[0] else 2 + 1 + len(s) for _, pub, s in sigs)
    check(n == len(raw) + inserted, f"{name}: finalize length {n}")
    signed, orig = PSBT.parse(out), PSBT.parse(raw)
    check(signed.tx.serialize() == orig.tx.serialize(), f"{name}: tx unchanged")
    for i, pub, sig in sigs:
        got = signed.inputs[i].unknown.get(b"\x13") if pub[0] == 0 else \
            signed.inputs[i].partial_sigs.get(ec.PublicKey.parse(pub))
        check(got == sig, f"{name}: input {i} signature inserted")

    # failures: sig for a foreign input, the same input twice, too many sigs, bad pubkey prefix
    unsigned = [i for i, w in enumerate(exp["inputs"]) if w["key"] is None]
    if unsigned:
        check(p.finalize([(unsigned[0], b"\x02" * 33, b"\x30" * 71)])[0] < 0, f"{name}: sig for foreign input")
    check(p.finalize(sigs[:1] * 2)[0] < 0, f"{name}: duplicate input")
    check(p.finalize(sigs[:1] * 17)[0] < 0, f"{name}: too many sigs")
    i0, pub0, sig0 = sigs[0]
    check(p.finalize([(i0, b"\x05" + pub0[1:], sig0)])[0] < 0, f"{name}: bad pubkey prefix")

check(Parser().finalize([])[0] < 0, "finalize before parse")

print("rpc_psbt.json:", {f"{k}/{'accepted' if ok else 'rejected'}": v for (k, ok), v in sorted(counts.items())})
for f in failures:
    print("FAIL", f)
print(f"{checks - len(failures)}/{checks} checks passed")
sys.exit(1 if failures else 0)
