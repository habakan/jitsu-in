// Driving signer.wasm from JavaScript.
//
// This module holds a key. That makes it different in kind from parser.wasm, and the difference is
// the host's problem as much as the module's: see "What a host must not do" in docs/abi.md.
//
// The layout constants below are not hand-written. components/signer/tests/layout.c prints them from
// the structs themselves and `make check-layout` fails if these drift from it.

const L = {
  plan: { size: 5016, nInputs: 16, nOutputs: 17 },
  review: { size: 64, totalIn: 0, totalOut: 8, fee: 16, owner: 24, willSign: 40, nSign: 56 },
  display: {
    size: 2968, fee: 0, spend: 8, nOutputs: 16, outputs: 24,
    outSize: 184, outAmount: 0, outOwner: 8, outTextKind: 9, outText: 10, outTextCap: 167,
  },
  sig: { size: 108, input: 0, pubkey: 1, sigLen: 34, sig: 35 },
  limits: { maxInputs: 16, maxOutputs: 16, xpubMax: 120, descMax: 180 },
};

export const OWNER = { EXTERNAL: 0, CHANGE: 1, SELF: 2 };
export const TEXT_KIND = { ADDRESS: 0, OP_RETURN: 1, SCRIPT: 2 };

export const ERRORS = {
  1: "FORMAT", 2: "NO_SEED", 3: "NOT_OURS", 4: "NOTHING_TO_SIGN", 5: "SIGHASH", 6: "SCRIPT",
  7: "PREVTX_MISSING", 8: "PREVTX_MISMATCH", 9: "FEE", 10: "NOT_REVIEWED", 11: "CRYPTO",
};

export class SignerError extends Error {
  constructor(stage, code) {
    super(`${stage}: ${ERRORS[code] ?? `unknown(${code})`}`);
    this.name = "SignerError";
    this.stage = stage;
    this.code = code;
  }
}

async function sha256Hex(bytes) {
  const d = await crypto.subtle.digest("SHA-256", bytes);
  return [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

export class Signer {
  #e;
  #reviewed = false;

  constructor(instance) {
    this.#e = instance.exports;
  }

  /** `sha256` refuses any module that is not the build you expected. For a module that will hold a
   *  key, pinning it is the difference between running your signer and running someone else's. */
  static async load(signerWasm, opts = {}) {
    if (opts.sha256) {
      const got = await sha256Hex(signerWasm);
      if (got !== opts.sha256.toLowerCase()) {
        throw new Error(`not the expected build: sha256 ${got}`);
      }
    }
    const module = await WebAssembly.compile(signerWasm);
    const imports = WebAssembly.Module.imports(module);
    if (imports.length) {
      const names = imports.map((i) => `${i.module}.${i.name}`).join(", ");
      throw new Error(`signer.wasm must have no imports, found: ${names}`);
    }
    const instance = await WebAssembly.instantiate(module, {});
    return new Signer(instance);
  }

  get #mem() {
    return new Uint8Array(this.#e.memory.buffer);
  }

  #view(off, len) {
    const end = off + len;
    if (off < 0 || len < 0 || end > this.#e.memory.buffer.byteLength) {
      throw new RangeError(`[${off}, ${end}) is outside the module's memory`);
    }
    return new DataView(this.#e.memory.buffer, off, len);
  }

  /** Call once, before anything else. `testnet` also covers signet. */
  init({ testnet = false } = {}) {
    if (!this.#e.signer_init(testnet ? 1 : 0)) throw new Error("init failed");
    this.#reviewed = false;
    return this;
  }

  /** Derives the key from a BIP39 mnemonic. PBKDF2 2048 rounds, about half a second.
   *  The module wipes its own input buffer; the strings you passed in are yours to deal with. */
  seedFromMnemonic(mnemonic, passphrase = "") {
    const enc = new TextEncoder();
    const mn = enc.encode(mnemonic.normalize("NFKD"));
    const pass = enc.encode(passphrase.normalize("NFKD"));
    const cap = this.#e.signer_input_cap();
    if (mn.length + pass.length > cap) {
      throw new RangeError(`mnemonic and passphrase are ${mn.length + pass.length} bytes, cap is ${cap}`);
    }
    const at = this.#e.signer_input();
    this.#mem.set(mn, at);
    this.#mem.set(pass, at + mn.length);
    const ok = this.#e.signer_seed_from_mnemonic(mn.length, pass.length);
    mn.fill(0);
    pass.fill(0);
    if (!ok) throw new Error("seed_from_mnemonic failed");
    return this;
  }

  /** For a seed you already have. 64 bytes. */
  loadSeed(seed) {
    if (seed.length !== 64) throw new RangeError(`a seed is 64 bytes, got ${seed.length}`);
    this.#mem.set(seed, this.#e.signer_input());
    if (!this.#e.signer_load_seed()) throw new Error("load_seed failed");
    return this;
  }

  /** Clears the key and everything derived from it. Call it when you are done, not when you
   *  remember to. */
  unload() {
    this.#e.signer_unload();
    this.#reviewed = false;
  }

  get fingerprint() {
    return (this.#e.signer_fingerprint() >>> 0).toString(16).padStart(8, "0");
  }

  /** The plan parser.wasm produced, copied in verbatim. Loading a plan invalidates any review. */
  setPlan(planBytes) {
    if (planBytes.length !== L.plan.size) {
      throw new RangeError(`a plan is ${L.plan.size} bytes, got ${planBytes.length}`);
    }
    this.#mem.set(planBytes, this.#e.signer_plan());
    this.#reviewed = false;
    return this;
  }

  /** The non_witness_utxo for each input, in the same order as the plan's inputs. `null` for an
   *  input that had none. */
  setPrevTxs(prevTxs) {
    const base = this.#e.signer_prevtx();
    let used = 0;
    for (let i = 0; i < L.limits.maxInputs; i++) {
      const raw = prevTxs[i];
      if (!raw || !raw.length) {
        this.#e.signer_set_prevtx(i, 0, 0);
        continue;
      }
      this.#mem.set(raw, base + used);
      if (!this.#e.signer_set_prevtx(i, used, raw.length)) {
        throw new RangeError(`prevtx ${i} does not fit`);
      }
      used += raw.length;
    }
    return this;
  }

  /** Re-derives the keys and checks the plan against them. Nothing is signed until this passes. */
  review() {
    const rc = this.#e.signer_review();
    if (rc !== 0) throw new SignerError("review", rc);
    this.#reviewed = true;
    const v = this.#view(this.#e.signer_review_output(), L.review.size);
    const r = L.review;
    return {
      totalIn: v.getBigUint64(r.totalIn, true),
      totalOut: v.getBigUint64(r.totalOut, true),
      fee: v.getBigUint64(r.fee, true),
      nSign: v.getUint8(r.nSign),
      owner: [...Array(L.limits.maxOutputs)].map((_, i) => v.getUint8(r.owner + i)),
      willSign: [...Array(L.limits.maxInputs)].map((_, i) => v.getUint8(r.willSign + i)),
    };
  }

  /** What to put in front of the person approving. Every string here was built inside the module
   *  from the plan's bytes, so it cannot be a string the PSBT chose. */
  display() {
    const rc = this.#e.signer_display();
    if (rc !== 0) throw new SignerError("display", rc);
    const d = L.display;
    const v = this.#view(this.#e.signer_display_output(), d.size);
    const n = v.getUint8(d.nOutputs);
    const dec = new TextDecoder();
    const outputs = [];
    for (let i = 0; i < n; i++) {
      const o = d.outputs + i * d.outSize;
      const textAt = this.#e.signer_display_output() + o + d.outText;
      const raw = this.#mem.subarray(textAt, textAt + d.outTextCap);
      const nul = raw.indexOf(0);
      outputs.push({
        amount: v.getBigUint64(o + d.outAmount, true),
        owner: v.getUint8(o + d.outOwner),
        textKind: v.getUint8(o + d.outTextKind),
        text: dec.decode(raw.subarray(0, nul < 0 ? raw.length : nul)),
      });
    }
    return {
      fee: v.getBigUint64(d.fee, true),
      spend: v.getBigUint64(d.spend, true),
      outputs,
    };
  }

  /** Signs, and only the plan review() was shown. Returns one entry per signature, ready to hand to
   *  parser.wasm's signature buffer.
   *
   *  One review permits exactly one signing: the module clears its own approval afterwards, so a
   *  second call without reviewing again is refused. One approval, one signature. */
  sign() {
    if (!this.#reviewed) {
      throw new Error("review() has to pass first; one approval permits one signing");
    }
    const rc = this.#e.signer_sign();
    this.#reviewed = false;
    if (rc < 0) throw new SignerError("sign", -rc);
    const base = this.#e.signer_sigs();
    const out = [];
    for (let i = 0; i < rc; i++) {
      const at = base + i * L.sig.size;
      const v = this.#view(at, L.sig.size);
      const len = v.getUint8(L.sig.sigLen);
      out.push({
        input: v.getUint8(L.sig.input),
        pubkey: this.#mem.slice(at + L.sig.pubkey, at + L.sig.pubkey + 33),
        sig: this.#mem.slice(at + L.sig.sig, at + L.sig.sig + len),
        raw: this.#mem.slice(at, at + L.sig.size),
      });
    }
    return out;
  }

  /** The account xpub and an output descriptor, for making a watch-only wallet elsewhere. */
  xpub() {
    const rc = this.#e.signer_xpub();
    if (rc !== 0) throw new SignerError("xpub", rc);
    const dec = new TextDecoder();
    const read = (at, cap) => {
      const raw = this.#mem.subarray(at, at + cap);
      const nul = raw.indexOf(0);
      return dec.decode(raw.subarray(0, nul < 0 ? raw.length : nul));
    };
    return {
      xpub: read(this.#e.signer_xpub_output(), L.limits.xpubMax),
      descriptor: read(this.#e.signer_desc_output(), L.limits.descMax),
    };
  }

  static get LAYOUT() {
    return L;
  }
}
