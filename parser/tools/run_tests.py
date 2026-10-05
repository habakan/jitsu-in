# /// script
# dependencies = ["wasmtime", "embit"]
# ///
"""Tests build/parser.wasm itself under wasmtime.
1) no imports  2) Bitcoin Core's rpc_psbt.json  3) plans match expectations  4) signature insertion and failures
5) animated-QR (UR) reassembly of the same PSBTs, encoded by the reference encoder
6) UR encoding of the output, part for part against the reference encoder, and back through the decoder"""
import glob, json, os, re, struct, sys
import wasmtime
from embit import ec
from embit.psbt import PSBT
from embit.transaction import Transaction

WASM, VEC, RPC, URV = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
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
        # The offset is relative to parser_input(), so add the base
        n = self.call("parser_prevtx_len", i)
        return self.read(self.call("parser_input") + self.call("parser_prevtx_off", i), n) if n else b""

    def ur(self, part):
        raw = part.encode()
        self.mem.write(self.store, raw, self.call("parser_input"))
        return self.call("parser_ur_receive", len(raw))

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

# 5) UR: drop every third pure part so mixed parts have to fill the gaps
UR_ERR_MISMATCH, UR_ERR_TYPE = -4, -7
ur = json.load(open(URV))
for v in ur["vectors"]:
    name = f"{v['name']} {v['type']}/{v['fragment_len']}"
    psbt = bytes.fromhex(v["psbt_hex"])
    exp = json.load(open(os.path.join(VEC, v["name"] + ".json")))
    p = Parser()
    p.call("parser_ur_reset")
    rc, fed = 0, 0
    for part in v["parts"]:
        m = re.match(r"UR:[A-Z-]+/(\d+)-\d+/", part)
        if m and int(m.group(1)) <= v["seq_len"] and int(m.group(1)) % 3 == 0:
            continue
        rc = p.ur(part)
        fed += 1
        if rc:
            break
        progress = p.call("parser_ur_progress")
        check(progress >> 16 == v["seq_len"], f"{name}: progress {progress >> 16} != {v['seq_len']}")
    check(rc == len(psbt) and p.read(p.call("parser_input"), rc) == psbt, f"{name}: reassembled (rc={rc}, {fed} parts)")
    check(p.call("parser_parse", rc, exp["fingerprint"]) == P_OK if rc > 0 else False, f"{name}: parses")

# 6) encoding: parser_finalize() with no signatures returns the PSBT unchanged, which the reference encoded too
for v in [v for v in ur["vectors"] if v["type"] == "crypto-psbt"]:
    name = f"encode {v['name']}/{v['fragment_len']}"
    psbt = bytes.fromhex(v["psbt_hex"])
    exp = json.load(open(os.path.join(VEC, v["name"] + ".json")))
    p = Parser()
    check(p.parse(psbt, exp["fingerprint"]) == P_OK, f"{name}: parse")
    n, out = p.finalize([])
    check(n == len(psbt) and out == psbt, f"{name}: finalize without signatures")
    if v["fragment_len"] > 1000:  # UR_MAX_FRAGMENT; the single-part form is checked natively against bc-ur
        check(p.call("parser_ur_encode_start", n, v["fragment_len"]) == -5, f"{name}: fragment limit")
        continue
    check(p.call("parser_ur_encode_start", n, v["fragment_len"]) == v["seq_len"], f"{name}: seq_len")
    ours = []
    for _ in range(v["seq_len"] * 3 + 2):
        k = p.call("parser_ur_encode_next")
        ours.append(p.read(p.call("parser_input"), k).decode())
    if v["seq_len"] == 1:
        check(ours[0] == v["parts"][0], f"{name}: single part")
    else:
        by_seq = {int(re.match(r"UR:[A-Z-]+/(\d+)-", x).group(1)): x for x in ours}
        for ref in v["parts"]:
            seq = int(re.match(r"UR:[A-Z-]+/(\d+)-", ref).group(1))
            check(by_seq.get(seq) == ref, f"{name}: part {seq}")
    d = Parser()
    d.call("parser_ur_reset")
    rc = 0
    for part in ours[1::2] + ours[0::2]:  # odd parts first, pure ones dropped at first
        rc = rc or d.ur(part)
    check(rc == len(psbt) and d.read(d.call("parser_input"), rc) == psbt, f"{name}: round trip")

# a UR that is not a PSBT, and a part from another message in the middle of one
bytes_ur = "ur:bytes/hdeymejtswhhylkepmykhhtsytsnoyoyaxaedsuttydmmhhpktpmsrjtgwdpfnsboxgwlbaawzuefywkdplrsrjynbvygabwjldapfcsdwkbrkch"
p = Parser()
p.call("parser_ur_reset")
check(p.ur(bytes_ur) == UR_ERR_TYPE, "bytes UR rejected")
multi = [v for v in ur["vectors"] if v["seq_len"] > 3]
a, b = multi[0], multi[1]
p = Parser()
p.call("parser_ur_reset")
check(p.ur(a["parts"][0]) == 0, "first part")
check(p.ur(b["parts"][1]) == UR_ERR_MISMATCH, "part of another message rejected")
rc = 0
for part in a["parts"][1:]:
    rc = rc or p.ur(part)
check(rc == len(bytes.fromhex(a["psbt_hex"])), "completes after the foreign part")

print("rpc_psbt.json:", {f"{k}/{'accepted' if ok else 'rejected'}": v for (k, ok), v in sorted(counts.items())})
for f in failures:
    print("FAIL", f)
print(f"{checks - len(failures)}/{checks} checks passed")
sys.exit(1 if failures else 0)
