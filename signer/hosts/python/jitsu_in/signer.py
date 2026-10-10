"""Driving signer.wasm from Python, on WAMR.

This module holds a key: see "What a host must not do" in signer/docs/abi.md. Secrets go in as
bytearray, not str or bytes, because only a bytearray can be cleared; each one is zeroed on return.

The layout constants are checked against signer/tests/layout.c by `make check-layout`.
"""

from __future__ import annotations

import hashlib
import re
import struct

from .wamr import Instance

PLAN_SIZE = 6712
PLAN_N_INPUTS = 16
PLAN_N_OUTPUTS = 17
RV_SIZE = 64
RV_FEE = 16
RV_OWNER = 24
RV_WILL_SIGN = 40
RV_N_SIGN = 56
DP_SIZE = 2968
DP_OUTPUTS = 24
DP_OUT_SIZE = 184
DP_OUT_TEXT = 10
DP_OUT_TEXT_CAP = 167
SIG_SIZE = 108
SIG_LEN = 34
SIG_SIG = 35
MSG_SIZE = 1101
MSG_ADDRESS = 0
MSG_TEXT_KIND = 75
MSG_TEXT = 76
MSG_TEXT_CAP = 1025
MAX_INPUTS = 16
MAX_OUTPUTS = 16
XPUB_MAX = 120
DESC_MAX = 180
PREVTX_MAX = 32768

OWNER = ["EXTERNAL", "CHANGE", "SELF"]
TEXT_KIND = ["ADDRESS", "OP_RETURN", "SCRIPT"]
ERRORS = {
    1: "FORMAT", 2: "NO_SEED", 3: "NOT_OURS", 4: "NOTHING_TO_SIGN", 5: "SIGHASH", 6: "SCRIPT",
    7: "PREVTX_MISSING", 8: "PREVTX_MISMATCH", 9: "FEE", 10: "NOT_REVIEWED", 11: "CRYPTO",
    12: "NOT_FOUND",
}
NOT_FOUND = 12


class SignerError(Exception):
    def __init__(self, stage, code):
        super().__init__(f"{stage}: {ERRORS.get(code, f'unknown({code})')}")
        self.stage, self.code = stage, code


class Signer:
    def __init__(self, wasm: bytes, sha256: str | None = None, lib_path=None):
        """`sha256` refuses any module that is not the build you expected."""
        if sha256 and hashlib.sha256(wasm).hexdigest() != sha256.lower():
            raise ValueError(f"not the expected build: sha256 {hashlib.sha256(wasm).hexdigest()}")
        self._e = Instance(wasm, lib_path)
        self._m = self._e.memory
        self._reviewed = False

    def _put(self, at, data):
        if at < 0 or at + len(data) > len(self._m):
            raise IndexError(f"[{at}, {at + len(data)}) is outside the module's memory")
        self._m[at:at + len(data)] = data

    def _cstr(self, at, cap):
        raw = bytes(self._m[at:at + cap])
        return raw.split(b"\0", 1)[0].decode()

    def _input(self, *parts):
        cap = self._e.signer_input_cap()
        if sum(len(p) for p in parts) > cap:
            raise ValueError(f"{sum(len(p) for p in parts)} bytes, cap is {cap}")
        at = self._e.signer_input()
        for p in parts:
            self._put(at, p)
            at += len(p)

    @staticmethod
    def _secret(*args):
        if not all(isinstance(a, bytearray) for a in args):
            raise TypeError("secrets are bytearray, so that they can be cleared")

    def init(self, testnet=False):
        """Call once, before anything else. `testnet` also covers signet."""
        if not self._e.signer_init(1 if testnet else 0):
            raise RuntimeError("init failed")
        self._reviewed = False
        return self

    def seed_from_mnemonic(self, mnemonic: bytearray, passphrase: bytearray | None = None):
        """NFKD-normalised UTF-8. PBKDF2 2048 rounds."""
        passphrase = bytearray() if passphrase is None else passphrase
        try:
            self._secret(mnemonic, passphrase)
            self._input(mnemonic, passphrase)
            if not self._e.signer_seed_from_mnemonic(len(mnemonic), len(passphrase)):
                raise RuntimeError("seed_from_mnemonic failed")
        finally:
            mnemonic[:] = bytes(len(mnemonic))
            passphrase[:] = bytes(len(passphrase))
        return self

    def seed_from_seedqr(self, payload: bytearray, passphrase: bytearray | None = None):
        """The Standard digits as ASCII, or the CompactSeedQR's raw bytes."""
        passphrase = bytearray() if passphrase is None else passphrase
        try:
            self._secret(payload, passphrase)
            self._input(payload, passphrase)
            if not self._e.signer_seed_from_seedqr(len(payload), len(passphrase)):
                raise RuntimeError("seed_from_seedqr failed")
        finally:
            payload[:] = bytes(len(payload))
            passphrase[:] = bytes(len(passphrase))
        return self

    def load_seed(self, seed: bytearray):
        try:
            self._secret(seed)
            if len(seed) != 64:
                raise ValueError(f"a seed is 64 bytes, got {len(seed)}")
            self._put(self._e.signer_input(), seed)
            if not self._e.signer_load_seed():
                raise RuntimeError("load_seed failed")
        finally:
            seed[:] = bytes(len(seed))
        return self

    def _generate(self, data: bytearray, make, name, where) -> bytearray:
        """The module's output is copied out as a bytearray and zeroed in place; `data` is zeroed."""
        try:
            self._secret(data)
            self._input(data)
            n = make()
            if not n:
                raise RuntimeError(f"{name} failed")
            at = where()
            out = bytearray(self._m[at:at + n])
            self._m[at:at + n] = bytes(n)
            return out
        finally:
            data[:] = bytes(len(data))

    def mnemonic_from_entropy(self, entropy: bytearray) -> bytearray:
        return self._generate(entropy, lambda: self._e.signer_mnemonic_from_entropy(len(entropy)),
                              "mnemonic_from_entropy", self._e.signer_mnemonic_output)

    def mnemonic_from_dice(self, rolls: bytearray, words=24) -> bytearray:
        if words not in (12, 24):
            raise ValueError(f"dice make 12 or 24 words, not {words}")
        return self._generate(rolls, lambda: self._e.signer_mnemonic_from_dice(len(rolls), words),
                              "mnemonic_from_dice", self._e.signer_mnemonic_output)

    def seedqr_from_mnemonic(self, mnemonic: bytearray, compact=False) -> bytearray:
        return self._generate(mnemonic, lambda: self._e.signer_seedqr_from_mnemonic(len(mnemonic), int(compact)),
                              "seedqr_from_mnemonic", self._e.signer_seedqr_output)

    def bip85_mnemonic(self, words=24, index=0) -> bytearray:
        if words not in (12, 18, 24) or not 0 <= index < 2**31:
            raise ValueError(f"BIP85 takes 12, 18 or 24 words and an index below 2^31, not {words} and {index}")
        if self.fingerprint == "00000000":
            raise RuntimeError("bip85_mnemonic: no seed is loaded")
        return self._generate(bytearray(), lambda: self._e.signer_bip85_mnemonic(words, index),
                              "bip85_mnemonic", self._e.signer_mnemonic_output)

    def unload(self):
        """Clears the key and everything derived from it."""
        self._e.signer_unload()
        self._reviewed = False

    @property
    def fingerprint(self):
        return f"{self._e.signer_fingerprint() & 0xFFFFFFFF:08x}"

    def set_plan(self, plan: bytes):
        """The plan parser.wasm produced, copied in verbatim. Loading a plan invalidates any review."""
        if len(plan) != PLAN_SIZE:
            raise ValueError(f"a plan is {PLAN_SIZE} bytes, got {len(plan)}")
        self._put(self._e.signer_plan(), plan)
        self._reviewed = False
        return self

    def set_prevtxs(self, prevtxs):
        """The non_witness_utxo for each input in plan order, None where there was none."""
        base, used = self._e.signer_prevtx(), 0
        for i in range(MAX_INPUTS):
            raw = prevtxs[i] if i < len(prevtxs) else None
            if not raw:
                self._e.signer_set_prevtx(i, 0, 0)
                continue
            if used + len(raw) > PREVTX_MAX:
                raise ValueError(f"prevtx {i} does not fit")
            self._put(base + used, raw)
            if not self._e.signer_set_prevtx(i, used, len(raw)):
                raise ValueError(f"prevtx {i} does not fit")
            used += len(raw)
        return self

    def review(self):
        rc = self._e.signer_review()
        if rc != 0:
            raise SignerError("review", rc)
        self._reviewed = True
        at = self._e.signer_review_output()
        total_in, total_out, fee = struct.unpack_from("<QQQ", self._m, at)
        return {
            "total_in": total_in, "total_out": total_out, "fee": fee,
            "n_sign": self._m[at + RV_N_SIGN],
            "owner": list(self._m[at + RV_OWNER:at + RV_OWNER + MAX_OUTPUTS]),
            "will_sign": list(self._m[at + RV_WILL_SIGN:at + RV_WILL_SIGN + MAX_INPUTS]),
        }

    def display(self):
        """Every string here was built inside the module from the plan's bytes."""
        rc = self._e.signer_display()
        if rc != 0:
            raise SignerError("display", rc)
        at = self._e.signer_display_output()
        fee, spend, n = struct.unpack_from("<QQB", self._m, at)
        outputs = []
        for i in range(n):
            o = at + DP_OUTPUTS + i * DP_OUT_SIZE
            amount, owner, kind = struct.unpack_from("<QBB", self._m, o)
            outputs.append({"amount": amount, "owner": owner, "text_kind": kind,
                            "text": self._cstr(o + DP_OUT_TEXT, DP_OUT_TEXT_CAP)})
        return {"fee": fee, "spend": spend, "outputs": outputs}

    def sign(self):
        """Signs only the plan review() was shown. One review permits exactly one signing."""
        if not self._reviewed:
            raise RuntimeError("review() has to pass first; one approval permits one signing")
        rc = self._e.signer_sign()
        self._reviewed = False
        if rc < 0:
            raise SignerError("sign", -rc)
        base, out = self._e.signer_sigs(), []
        for i in range(rc):
            at = base + i * SIG_SIZE
            n = self._m[at + SIG_LEN]
            out.append({"input": self._m[at], "pubkey": bytes(self._m[at + 1:at + 34]),
                        "sig": bytes(self._m[at + SIG_SIG:at + SIG_SIG + n]),
                        "raw": bytes(self._m[at:at + SIG_SIZE])})
        return out

    def find_address(self, address: str, account=0, count=1000):
        """(chain, index) of one of our addresses, or None. Takes a bare address or a BIP21 URI."""
        b = re.sub(r"^bitcoin:", "", address.strip(), flags=re.I).split("?")[0].encode()
        if not (0 <= account < 2**32 and 0 <= count < 2**32):
            raise ValueError(f"account {account} and count {count} out of range")
        self._input(b)
        rc = self._e.signer_find_address(len(b), account, count)
        if rc >= 0:
            return rc >> 20, rc & 0xFFFFF
        if rc != -NOT_FOUND:
            raise SignerError("find_address", -rc)
        return None

    def message_review(self, message: bytes, purpose=84, account=0, chain=0, index=0):
        self._input(message)
        rc = self._e.signer_message_review(len(message), purpose, account, chain, index)
        if rc != 0:
            raise SignerError("message_review", rc)
        at = self._e.signer_message_output()
        return {"address": self._cstr(at + MSG_ADDRESS, MSG_TEXT_KIND),
                "text_kind": "hex" if self._m[at + MSG_TEXT_KIND] else "message",
                "text": self._cstr(at + MSG_TEXT, MSG_TEXT_CAP)}

    def message_sign(self) -> bytes:
        """65 bytes, header then r and s."""
        rc = self._e.signer_message_sign()
        if rc != 0:
            raise SignerError("message_sign", rc)
        at = self._e.signer_message_sig()
        return bytes(self._m[at:at + 65])

    def xpub(self, purpose=84, account=0):
        """The account xpub and its descriptor; for 48, the key expression for wsh(sortedmulti())."""
        if not (0 <= purpose and 0 <= account < 2**32):
            raise ValueError(f"purpose {purpose} and account {account} out of range")
        rc = self._e.signer_xpub(purpose, account)
        if rc != 0:
            raise SignerError("xpub", rc)
        return {"xpub": self._cstr(self._e.signer_xpub_output(), XPUB_MAX),
                "descriptor": self._cstr(self._e.signer_desc_output(), DESC_MAX)}
