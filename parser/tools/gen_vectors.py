# /// script
# dependencies = ["embit"]
# ///
"""Writes test PSBTs and the plan the parser is expected to produce (JSON) to build/vectors/.
Expectations come from how each PSBT was built (which inputs and outputs are ours), not from re-implementing the parser.
Also converts Bitcoin Core's rpc_psbt.json to binary files."""
import base64, hashlib, json, os, sys
from embit import bip32, script
from embit.psbt import PSBT, DerivationPath
from embit.transaction import Transaction, TransactionInput, TransactionOutput

MN = " ".join(["abandon"] * 11 + ["about"])  # BIP39 test vector; never use for funds
root = bip32.HDKey.from_seed(hashlib.pbkdf2_hmac("sha512", MN.encode(), b"mnemonic", 2048))
FP = root.my_fingerprint
H = 0x80000000
out_dir = sys.argv[2]
os.makedirs(out_dir, exist_ok=True)


def key(path):
    return root.derive(path).key.get_public_key()


def path_list(path):
    return [int(p[:-1]) + H if p.endswith("h") else int(p) for p in path.split("/")[1:]]


# m/45h stands for a P2SH multisig we cosign: our key and fingerprint are in it, but it is not BIP49's
def multisig(path):
    return script.multisig(1, [key(path)])


# BIP48 P2WSH 2-of-3 with two cosigners from BIP39's other published vectors. m/48h/0h/1h/2h holds four keys:
# a witness script too long for the plan, so the input is not one we sign
COSIGNERS = [bip32.HDKey.from_seed(hashlib.pbkdf2_hmac("sha512", m.encode(), b"mnemonic", 2048))
             for m in ("zoo " * 11 + "wrong",
                       "legal winner thank year wave sausage worth useful legal winner thank yellow",
                       "letter advice cage absurd amount doctor acoustic avoid letter advice cage above")]


def cosigner_keys(path):
    n = 3 if path.startswith("m/48h/0h/1h") else 2
    return [c.derive(path).key.get_public_key() for c in COSIGNERS[:n]]


def wsh_script(path):
    return script.Script(script.multisig(2, sorted([key(path)] + cosigner_keys(path), key=lambda k: k.sec())).data)


def spk(path):
    if path.startswith("m/48h"):
        return script.p2wsh(wsh_script(path))
    if path.startswith("m/45h"):
        return script.p2sh(multisig(path))
    if path.startswith("m/86h"):
        return script.p2tr(key(path))
    if path.startswith("m/49h"):
        return script.p2sh(script.p2wpkh(key(path)))
    return script.p2wpkh(key(path))


def prev_tx(target_spk, amount, vout, salt):
    outs = [TransactionOutput(1000 + i, script.Script(b"\x00\x14" + bytes([salt]) * 20)) for i in range(vout)]
    outs.append(TransactionOutput(amount, target_spk))
    return Transaction(vin=[TransactionInput(bytes([salt]) * 32, 0)], vout=outs)


def keypath(path):
    return {"fingerprint": int.from_bytes(FP, "big"), "path": path_list(path)}


def wsh_expected(path):
    return path is not None and path.startswith("m/48h/0h/0h")


def build(name, inputs, outputs, cosigned=False):
    """inputs: (path, or None for a foreign key, amount, vout, nwu). outputs: (path, or None for external, amount)"""
    vin, prevs, exp_in, exp_out = [], [], [], []
    for n, (path, amount, vout, nwu) in enumerate(inputs):
        s = spk(path) if path else script.p2wpkh(key("m/0h/%d" % n))  # stands in for a foreign key (no fingerprint)
        ptx = prev_tx(s, amount, vout, 0x30 + n)
        prevs.append((ptx, vout, s, amount))
        vin.append(TransactionInput(ptx.txid(), vout, sequence=0xFFFFFFFD))
        exp_in.append({"prev_txid": bytes(reversed(ptx.txid())).hex(), "prev_vout": vout, "sequence": 0xFFFFFFFD,
                       "amount": amount, "spk": s.data.hex(),
                       "key": keypath(path) if path and not path.startswith(("m/45h", "m/48h/0h/1h")) else None,
                       "sighash_type": (0 if path.startswith("m/86h") else 1)
                       if path and not path.startswith(("m/45h", "m/48h/0h/1h")) else 0,
                       "wscript": wsh_script(path).data.hex() if wsh_expected(path) else "",
                       "has_prevtx": nwu})
    vout = []
    for n, (path, amount) in enumerate(outputs):
        s = spk(path) if path else script.p2wpkh(key("m/1h/%d" % n))
        vout.append(TransactionOutput(amount, s))
        exp_out.append({"amount": amount, "spk": s.data.hex(),
                        "key": keypath(path) if path else None})
    psbt = PSBT(Transaction(version=2, vin=vin, vout=vout))
    for inp, (path, _, _, nwu), (ptx, v, s, amount) in zip(psbt.inputs, inputs, prevs):
        inp.witness_utxo = TransactionOutput(amount, s)
        if nwu:
            inp.non_witness_utxo = ptx
        if path and path.startswith("m/86h"):
            inp.taproot_bip32_derivations[key(path)] = ([], DerivationPath(FP, path_list(path)))
        elif path:
            inp.bip32_derivations[key(path)] = DerivationPath(FP, path_list(path))
        if path and path.startswith("m/49h"):
            inp.redeem_script = script.p2wpkh(key(path))
        if path and path.startswith("m/45h"):
            inp.redeem_script = multisig(path)
        if path and path.startswith("m/48h"):
            inp.witness_script = wsh_script(path)
            for c, k in zip(COSIGNERS, cosigner_keys(path)):
                inp.bip32_derivations[k] = DerivationPath(c.my_fingerprint, path_list(path))
    if cosigned:  # the first cosigner has signed already
        psbt.sign_with(COSIGNERS[0])
    for o, (path, _) in zip(psbt.outputs, outputs):
        if path and path.startswith("m/86h"):
            o.taproot_bip32_derivations[key(path)] = ([], DerivationPath(FP, path_list(path)))
        elif path:
            o.bip32_derivations[key(path)] = DerivationPath(FP, path_list(path))
        if path and path.startswith("m/49h"):
            o.redeem_script = script.p2wpkh(key(path))
        if path and path.startswith("m/48h"):
            o.witness_script = wsh_script(path)
            for c, k in zip(COSIGNERS, cosigner_keys(path)):
                o.bip32_derivations[k] = DerivationPath(c.my_fingerprint, path_list(path))
    open(os.path.join(out_dir, name + ".psbt"), "wb").write(psbt.serialize())
    expected = {"fingerprint": int.from_bytes(FP, "big"), "tx_version": 2, "locktime": 0,
                "inputs": exp_in, "outputs": exp_out,
                "pubkeys": [key(p).sec().hex() if p else None for p, _, _, _ in inputs]}
    json.dump(expected, open(os.path.join(out_dir, name + ".json"), "w"), indent=1)


A, T, S = "m/84h/0h/0h", "m/86h/0h/0h", "m/49h/0h/0h"
build("own_p2wpkh_1in", [(A + "/0/0", 100000, 0, False)], [(None, 60000), (A + "/1/0", 39000)])
build("own_p2wpkh_2in_nwu", [(A + "/0/0", 100000, 1, True), (A + "/0/1", 50000, 0, True)],
      [(None, 60000), (A + "/1/0", 89000)])
build("own_p2tr_2in", [(T + "/0/0", 70000, 0, False), (T + "/0/1", 70000, 2, False)],
      [(None, 100000), (T + "/1/0", 39000)])
build("own_mixed_nwu", [(A + "/0/0", 100000, 0, True), (T + "/0/0", 70000, 1, True)],
      [(None, 100000), (A + "/0/5", 20000), (T + "/1/0", 49000)])
build("own_p2sh_p2wpkh_1in", [(S + "/0/0", 100000, 0, False)], [(None, 60000), (S + "/1/0", 39000)])
build("own_mixed_p2sh_nwu", [(A + "/0/0", 100000, 0, True), (S + "/0/1", 50000, 1, True)],
      [(None, 100000), (S + "/1/0", 49000)])
build("own_with_p2sh_multisig_input", [(A + "/0/0", 100000, 0, True), ("m/45h/0/0/0", 30000, 0, True)],
      [(None, 100000), (A + "/1/0", 29000)])
# P2WSH change carries our key; the signer calls it change only once a registered wallet gives the cosigners'
W = "m/48h/0h/0h/2h"
build("own_p2wsh_2of3_1in", [(W + "/0/0", 100000, 0, False)], [(None, 60000), (W + "/1/0", 39000)])
build("own_p2wsh_2of3_cosigned", [(W + "/0/1", 100000, 1, True)], [(None, 60000), (W + "/1/1", 39000)],
      cosigned=True)
build("own_mixed_p2wsh_nwu", [(A + "/0/0", 100000, 0, True), (W + "/0/2", 50000, 0, True)],
      [(None, 100000), (A + "/1/0", 49000)])
build("own_with_p2wsh_2of4_input", [(A + "/0/0", 100000, 0, True), ("m/48h/0h/1h/2h/0/0", 30000, 0, True)],
      [(None, 100000), (A + "/1/0", 29000)])
build("own_with_foreign_input", [(A + "/0/0", 100000, 0, True), (None, 30000, 0, True)],
      [(None, 100000), (A + "/1/0", 29000)])

vectors = json.load(open(sys.argv[1]))
for kind in ("invalid", "invalid_with_msg", "valid"):
    for n, v in enumerate(vectors[kind]):
        b64 = v if isinstance(v, str) else v[0]
        try:
            raw = base64.b64decode(b64, validate=True)
        except Exception:
            continue  # the base64 itself is broken; the parser takes binary, so these are out of scope
        open(os.path.join(out_dir, "rpc_%s_%02d.psbt" % (kind, n)), "wb").write(raw)
