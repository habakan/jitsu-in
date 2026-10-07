// Driving signer.wasm from JavaScript.
//
// This module holds a key. That makes it different in kind from parser.wasm, and the difference is
// the host's problem as much as the module's: see "What a host must not do" in docs/abi.md.
//
// The layout constants below are not hand-written. signer/tests/layout.c prints them from
// the structs themselves and `make check-layout` fails if these drift from it.

const L = {
  plan: { size: 5016, nInputs: 16, nOutputs: 17 },
  review: { size: 64, totalIn: 0, totalOut: 8, fee: 16, owner: 24, willSign: 40, nSign: 56 },
  display: {
    size: 2968, fee: 0, spend: 8, nOutputs: 16, outputs: 24,
    outSize: 184, outAmount: 0, outOwner: 8, outTextKind: 9, outText: 10, outTextCap: 167,
  },
  sig: { size: 108, input: 0, pubkey: 1, sigLen: 34, sig: 35 },
  limits: { maxInputs: 16, maxOutputs: 16, xpubMax: 120, descMax: 180, prevtxMax: 32768 },
};

/**
 * The exports signer.wasm provides. Declared so that a typo in a name is a type error rather than a
 * call to undefined at runtime.
 * @typedef {{
 *   memory: WebAssembly.Memory,
 *   signer_input: () => number,
 *   signer_input_cap: () => number,
 *   signer_plan: () => number,
 *   signer_prevtx: () => number,
 *   signer_review_output: () => number,
 *   signer_display_output: () => number,
 *   signer_sigs: () => number,
 *   signer_xpub_output: () => number,
 *   signer_desc_output: () => number,
 *   signer_init: (testnet: number) => number,
 *   signer_seed_from_mnemonic: (mnLen: number, passLen: number) => number,
 *   signer_seed_from_seedqr: (qrLen: number, passLen: number) => number,
 *   signer_load_seed: () => number,
 *   signer_unload: () => void,
 *   signer_fingerprint: () => number,
 *   signer_set_prevtx: (i: number, off: number, len: number) => number,
 *   signer_review: () => number,
 *   signer_display: () => number,
 *   signer_sign: () => number,
 *   signer_xpub: () => number,
 *   signer_mnemonic_output: () => number,
 *   signer_mnemonic_from_entropy: (len: number) => number,
 *   signer_mnemonic_from_dice: (len: number, words: number) => number,
 *   signer_bip85_mnemonic: (words: number, index: number) => number,
 * }} SignerExports
 */

/** What review() reports. `owner` has one entry per output, `willSign` one per input.
 *  @typedef {{
 *    totalIn: bigint, totalOut: bigint, fee: bigint, nSign: number,
 *    owner: number[], willSign: number[],
 *  }} Review */

/** One line of what to show. Every string here was built inside the module from the plan's bytes.
 *  @typedef {{ amount: bigint, owner: number, textKind: number, text: string }} DisplayOutput */

/** `spend` is the total of external outputs; ours and change are excluded.
 *  @typedef {{ fee: bigint, spend: bigint, outputs: DisplayOutput[] }} Display */

/** Hand `raw` to parser.wasm's signature buffer; `sig` and `pubkey` are for showing or checking.
 *  @typedef {{ input: number, pubkey: Uint8Array, sig: Uint8Array, raw: Uint8Array }} Signature */

export const OWNER = { EXTERNAL: 0, CHANGE: 1, SELF: 2 };
export const TEXT_KIND = { ADDRESS: 0, OP_RETURN: 1, SCRIPT: 2 };

/** CORE_ERR_* by value, as signer/docs/abi.md lists them.
 *  @type {Record<number, string>} */
export const ERRORS = {
  1: "FORMAT", 2: "NO_SEED", 3: "NOT_OURS", 4: "NOTHING_TO_SIGN", 5: "SIGHASH", 6: "SCRIPT",
  7: "PREVTX_MISSING", 8: "PREVTX_MISMATCH", 9: "FEE", 10: "NOT_REVIEWED", 11: "CRYPTO",
};

export class SignerError extends Error {
  /**
   * @param {string} stage which call refused: "review", "display", "sign" or "xpub"
   * @param {number} code a CORE_ERR_* value
   */
  constructor(stage, code) {
    super(`${stage}: ${ERRORS[code] ?? `unknown(${code})`}`);
    this.name = "SignerError";
    this.stage = stage;
    this.code = code;
  }
}

/** @param {BufferSource} bytes */
async function sha256Hex(bytes) {
  const d = await crypto.subtle.digest("SHA-256", bytes);
  return [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

export class Signer {
  #e;
  #reviewed = false;

  /** @param {WebAssembly.Instance} instance */
  constructor(instance) {
    this.#e = /** @type {SignerExports} */ (/** @type {any} */ (instance.exports));
  }

  /** `sha256` refuses any module that is not the build you expected. For a module that will hold a
   *  key, pinning it is the difference between running your signer and running someone else's. */
  /**
   * @param {BufferSource} signerWasm
   * @param {{ sha256?: string }} [opts]
   */
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

  /**
   * @param {number} off
   * @param {number} len
   */
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
   *  Takes NFKD-normalised UTF-8 bytes, not strings, because a string cannot be cleared; both arrays
   *  are zeroed before this returns, whether or not it succeeds. */
  /**
   * @param {Uint8Array} mnemonic
   * @param {Uint8Array} [passphrase]
   */
  seedFromMnemonic(mnemonic, passphrase = new Uint8Array(0)) {
    try {
      if (!(mnemonic instanceof Uint8Array) || !(passphrase instanceof Uint8Array)) {
        throw new TypeError("mnemonic and passphrase are Uint8Array, so that they can be cleared");
      }
      const cap = this.#e.signer_input_cap();
      if (mnemonic.length + passphrase.length > cap) {
        throw new RangeError(`mnemonic and passphrase are ${mnemonic.length + passphrase.length} bytes, cap is ${cap}`);
      }
      const at = this.#e.signer_input();
      this.#mem.set(mnemonic, at);
      this.#mem.set(passphrase, at + mnemonic.length);
      if (!this.#e.signer_seed_from_mnemonic(mnemonic.length, passphrase.length)) {
        throw new Error("seed_from_mnemonic failed");
      }
    } finally {
      if (mnemonic instanceof Uint8Array) mnemonic.fill(0);
      if (passphrase instanceof Uint8Array) passphrase.fill(0);
    }
    return this;
  }

  /** Derives the key from a SeedQR: the Standard digits as ASCII bytes, or the CompactSeedQR's raw
   *  bytes. The words stay inside the module, so confirm what was loaded by its fingerprint. Both
   *  arrays are zeroed before this returns. */
  /**
   * @param {Uint8Array} payload
   * @param {Uint8Array} [passphrase]
   */
  seedFromSeedQR(payload, passphrase = new Uint8Array(0)) {
    try {
      if (!(payload instanceof Uint8Array) || !(passphrase instanceof Uint8Array)) {
        throw new TypeError("payload and passphrase are Uint8Array, so that they can be cleared");
      }
      const cap = this.#e.signer_input_cap();
      if (payload.length + passphrase.length > cap) {
        throw new RangeError(`payload and passphrase are ${payload.length + passphrase.length} bytes, cap is ${cap}`);
      }
      const at = this.#e.signer_input();
      this.#mem.set(payload, at);
      this.#mem.set(passphrase, at + payload.length);
      if (!this.#e.signer_seed_from_seedqr(payload.length, passphrase.length)) {
        throw new Error("seed_from_seedqr failed");
      }
    } finally {
      if (payload instanceof Uint8Array) payload.fill(0);
      if (passphrase instanceof Uint8Array) passphrase.fill(0);
    }
    return this;
  }

  /** A new mnemonic from 16 to 32 bytes of entropy (12 to 24 words), as UTF-8 bytes to show and then
   *  clear. Nothing is loaded. `entropy` is zeroed, and so is the module's copy of the words. */
  /** @param {Uint8Array} entropy */
  mnemonicFromEntropy(entropy) {
    return this.#generate(entropy, () => this.#e.signer_mnemonic_from_entropy(entropy.length), "mnemonic_from_entropy");
  }

  /** A new mnemonic from dice rolls, the characters 1 to 6: at least 50 for 12 words, 99 for 24. The
   *  entropy is SHA-256 of the rolls. `rolls` is zeroed. */
  /**
   * @param {Uint8Array} rolls
   * @param {12 | 24} [words]
   */
  mnemonicFromDice(rolls, words = 24) {
    return this.#generate(rolls, () => this.#e.signer_mnemonic_from_dice(rolls.length, words), "mnemonic_from_dice");
  }

  /** The BIP85 child mnemonic of the loaded seed (m/83696968'/39'/0'/words'/index'), as UTF-8 bytes to
   *  show and then clear. English; `words` is 12, 18 or 24. The module's copy is zeroed. */
  /** @param {{ words?: 12 | 18 | 24, index?: number }} [opts] */
  bip85Mnemonic({ words = 24, index = 0 } = {}) {
    return this.#generate(new Uint8Array(0), () => this.#e.signer_bip85_mnemonic(words, index), "bip85_mnemonic");
  }

  /**
   * @param {Uint8Array} input
   * @param {() => number} make
   * @param {string} name
   */
  #generate(input, make, name) {
    try {
      const cap = this.#e.signer_input_cap();
      if (input.length > cap) throw new RangeError(`${input.length} bytes, cap is ${cap}`);
      this.#mem.set(input, this.#e.signer_input());
      const n = make();
      if (!n) throw new Error(`${name} failed`);
      const at = this.#e.signer_mnemonic_output();
      const out = this.#mem.slice(at, at + n);
      this.#mem.fill(0, at, at + n);
      return out;
    } finally {
      input.fill(0);
    }
  }

  /** For a seed you already have. 64 bytes. */
  /** @param {Uint8Array} seed */
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
  /** @param {Uint8Array} planBytes */
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
  /** @param {(Uint8Array | null)[]} prevTxs */
  setPrevTxs(prevTxs) {
    const base = this.#e.signer_prevtx();
    let used = 0;
    for (let i = 0; i < L.limits.maxInputs; i++) {
      const raw = prevTxs[i];
      if (!raw || !raw.length) {
        this.#e.signer_set_prevtx(i, 0, 0);
        continue;
      }
      if (used + raw.length > L.limits.prevtxMax) throw new RangeError(`prevtx ${i} does not fit`);
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
    const read = (/** @type {number} */ at, /** @type {number} */ cap) => {
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
