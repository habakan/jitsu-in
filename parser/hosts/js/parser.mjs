// A host for parser.wasm. Hides the linear memory, the offsets and the error codes, so using the
// module is `parse(psbt, fingerprint)` and you get an object. Works in Node and in a browser.
// No dependencies, and nothing here keeps a key.
//
// Every read is bounds-checked: the module tells the host where things are, and a host must never
// take that on trust. See ../../docs/abi.md.

const MAGIC = 0x4e4c5042; // "BPLN"
const ABI_VERSION = 1;

/**
 * The exports parser.wasm provides. Declared so that a typo in a name is a type error rather than a
 * call to undefined at runtime.
 * @typedef {{
 *   memory: WebAssembly.Memory,
 *   parser_input: () => number,
 *   parser_input_cap: () => number,
 *   parser_parse: (len: number, fingerprint: number) => number,
 *   parser_plan: () => number,
 *   parser_sigs: () => number,
 *   parser_output: () => number,
 *   parser_prevtx_off: (i: number) => number,
 *   parser_prevtx_len: (i: number) => number,
 *   parser_finalize: (n: number) => number,
 *   parser_ur_reset: () => void,
 *   parser_ur_receive: (len: number) => number,
 *   parser_ur_progress: () => number,
 *   parser_ur_encode_start: (len: number, fragmentLen: number) => number,
 *   parser_ur_encode_next: () => number,
 * }} ParserExports
 */

/**
 * One input of a plan. `amount` and `spk` come from the PSBT's utxo; verifying `prevtx` against
 * `prevTxid` is the only way to know the amount is real.
 * @typedef {{
 *   prevTxid: Uint8Array,
 *   prevVout: number,
 *   sequence: number,
 *   amount: bigint,
 *   spk: Uint8Array,
 *   key: KeyOrigin | null,
 *   sighashType: number,
 *   prevtx: Uint8Array | null,
 * }} PlanInput
 */

/** @typedef {{ amount: bigint, spk: Uint8Array, key: KeyOrigin | null }} PlanOutput */

/** A signature for the host to hand back, one per input it signed.
 *  @typedef {{ input: number, pubkey: Uint8Array, sig: Uint8Array }} Signature */

// Layout of plan_t, from docs/abi.md. Kept in one place so a version bump touches one table.
const L = {
  magic: 0, version: 4, txVersion: 8, locktime: 12, nInputs: 16, nOutputs: 17,
  inputs: 24, inputSize: 176, outputs: 2840, outputSize: 136,
  in: { prevTxid: 0, prevVout: 32, sequence: 36, amount: 40, spk: 48, key: 132, sighashType: 172 },
  out: { amount: 0, spk: 8, key: 92 },
  key: { depth: 0, fingerprint: 4, path: 8 },
  script: { len: 0, bytes: 1 },
};

const P_ERR = ["OK", "MAGIC", "FORMAT", "DUPLICATE", "TX", "UNSUPPORTED", "LIMIT", "UTXO", "SIG"];
const UR_ERR = ["", "SCHEME", "BYTEWORDS", "PART", "MISMATCH", "LIMIT", "MESSAGE", "TYPE"];

export class ParserError extends Error {
  /**
   * @param {number} code the module's return value: a P_ERR_* when positive, a UR_ERR_* when negative
   * @param {"P_ERR" | "UR_ERR"} [kind]
   */
  constructor(code, kind = "P_ERR") {
    const name = kind === "P_ERR" ? P_ERR[code] : UR_ERR[-code];
    super(`${kind}_${name ?? code}`);
    this.code = code;
    this.name = "ParserError";
  }
}

/** A BIP32 derivation the module read out of the PSBT — BIP380 calls this key origin information.
 *  It is a *claim*: derive the key yourself and check it produces the scriptPubKey before trusting it. */
export class KeyOrigin {
  /**
   * @param {number} fingerprint the master fingerprint this derivation claims
   * @param {number[]} path the raw uint32 path; the high bit means hardened
   */
  constructor(fingerprint, path) {
    this.fingerprint = fingerprint;
    this.path = path;
  }
  toString() {
    const f = this.fingerprint.toString(16).padStart(8, "0");
    return [f, ...this.path.map((/** @type {number} */ v) => (v & 0x80000000 ? `${v & 0x7fffffff}h` : `${v}`))].join("/");
  }
}

export class Parser {
  /**
   * @param {BufferSource} parserWasm the contents of parser.wasm
   * @param {{ sha256?: string }} [opts] when given, the module must hash to exactly this, or it is
   *   refused. Take the value from the project's `checksums.txt` or a release's `SHA256SUMS`.
   */
  static async load(parserWasm, opts = {}) {
    if (opts.sha256) await Parser.#assertDigest(parserWasm, opts.sha256);
    const module = await WebAssembly.compile(parserWasm);
    Parser.#assertNoImports(module);
    return new Parser(await WebAssembly.instantiate(module, {}));
  }

  /** Synchronous variant, for Node or anywhere compiling on the main thread is fine.
   *  It cannot check a digest: SubtleCrypto has no synchronous form. Use `load` if you want one. */
  /** @param {BufferSource} parserWasm */
  static loadSync(parserWasm) {
    const module = new WebAssembly.Module(parserWasm);
    Parser.#assertNoImports(module);
    return new Parser(new WebAssembly.Instance(module, {}));
  }

  /** A hash in a file nobody checks is documentation. Checking it here makes it a gate. */
  /**
   * @param {BufferSource} bytes
   * @param {string} want
   */
  static async #assertDigest(bytes, want) {
    const digest = await crypto.subtle.digest("SHA-256", bytes);
    const got = [...new Uint8Array(digest)].map(b => b.toString(16).padStart(2, "0")).join("");
    if (got !== want.toLowerCase()) {
      throw new Error(`parser.wasm is not the expected build: ${got} != ${want.toLowerCase()}`);
    }
  }

  /** The module must not be able to call the host at all. Checked before it is instantiated. */
  /** @param {WebAssembly.Module} module */
  static #assertNoImports(module) {
    const imports = WebAssembly.Module.imports(module);
    if (imports.length) {
      const names = imports.map(i => `${i.module}.${i.name}`).join(", ");
      throw new Error(`parser.wasm must have no imports, found ${imports.length}: ${names}`);
    }
  }

  /** @param {WebAssembly.Instance} instance */
  constructor(instance) {
    /** @type {ParserExports} */
    this.exports = /** @type {any} */ (instance.exports);
    /** @type {Uint8Array} */
    this.mem = new Uint8Array(0);
    /** @type {DataView} */
    this.view = new DataView(new ArrayBuffer(0));
    const need = /** @type {const} */ (["memory", "parser_input", "parser_input_cap", "parser_parse", "parser_plan"]);
    for (const n of need) if (!this.exports[n]) throw new Error(`not a parser.wasm module: ${n} missing`);
    this.#refresh();
  }

  #refresh() {
    this.mem = new Uint8Array(this.exports.memory.buffer);
    this.view = new DataView(this.exports.memory.buffer);
  }

  /**
   * @param {number} off
   * @param {number} len
   * @returns {number} the offset, once it is known to be inside the module's memory
   */
  #check(off, len) {
    if (!Number.isInteger(off) || !Number.isInteger(len) || off < 0 || len < 0 || off + len > this.mem.length)
      throw new RangeError(`the module returned an offset outside its memory: ${off}+${len}`);
    return off;
  }
  /** @param {number} off */
  #u8(off) { return this.mem[this.#check(off, 1)] ?? 0; }
  /** @param {number} off */
  #u32(off) { return this.view.getUint32(this.#check(off, 4), true); }
  /** @param {number} off */
  #i32(off) { return this.view.getInt32(this.#check(off, 4), true); }
  /** @param {number} off */
  #u64(off) { return this.view.getBigUint64(this.#check(off, 8), true); }
  /**
   * @param {number} off
   * @param {number} len
   */
  #bytes(off, len) { return this.mem.slice(this.#check(off, len), off + len); }

  /** @param {number} off */
  #script(off) {
    const n = this.#u8(off + L.script.len);
    return this.#bytes(off + L.script.bytes, n);
  }

  /**
   * @param {number} off
   * @returns {KeyOrigin | null}
   */
  #key(off) {
    const depth = this.#u8(off + L.key.depth);
    if (!depth) return null; // depth 0 means "the module found no derivation for this"
    /** @type {number[]} */
    const path = [];
    for (let i = 0; i < depth; i++) path.push(this.#u32(off + L.key.path + i * 4));
    return new KeyOrigin(this.#u32(off + L.key.fingerprint), path);
  }

  /** How many bytes the input buffer takes. */
  get inputCapacity() { return this.exports.parser_input_cap(); }

  /** @param {Uint8Array} bytes */
  #writeInput(bytes) {
    if (bytes.length > this.inputCapacity)
      throw new RangeError(`${bytes.length} bytes does not fit in ${this.inputCapacity}`);
    this.#refresh();
    this.mem.set(bytes, this.#check(this.exports.parser_input(), bytes.length));
  }

  /**
   * Parse a PSBT.
   * @param {Uint8Array} psbt
   * @param {number} fingerprint master fingerprint, big-endian (0x73c5da0a). Not a secret.
   * @returns {Plan}
   */
  parse(psbt, fingerprint) {
    this.#writeInput(psbt);
    const rc = this.exports.parser_parse(psbt.length, fingerprint >>> 0);
    if (rc !== 0) throw new ParserError(rc);
    return this.#readPlan();
  }

  #readPlan() {
    this.#refresh();
    const p = this.exports.parser_plan();
    if (this.#u32(p + L.magic) !== MAGIC) throw new Error("plan_t magic mismatch");
    const version = this.#u32(p + L.version);
    if (version !== ABI_VERSION) throw new Error(`plan_t version ${version}, this host speaks ${ABI_VERSION}`);

    const nIn = this.#u8(p + L.nInputs), nOut = this.#u8(p + L.nOutputs);
    const inputs = [], outputs = [];
    for (let i = 0; i < nIn; i++) {
      const o = p + L.inputs + i * L.inputSize;
      const len = this.exports.parser_prevtx_len(i);
      inputs.push({
        prevTxid: this.#bytes(o + L.in.prevTxid, 32),
        prevVout: this.#u32(o + L.in.prevVout),
        sequence: this.#u32(o + L.in.sequence),
        amount: this.#u64(o + L.in.amount),
        spk: this.#script(o + L.in.spk),
        key: this.#key(o + L.in.key),
        sighashType: this.#u8(o + L.in.sighashType),
        // The previous transaction, if the PSBT carried one. Verifying it against prevTxid is
        // the only way to know the amount above is real
        prevtx: len ? this.#bytes(this.exports.parser_input() + this.exports.parser_prevtx_off(i), len) : null,
      });
    }
    for (let i = 0; i < nOut; i++) {
      const o = p + L.outputs + i * L.outputSize;
      outputs.push({
        amount: this.#u64(o + L.out.amount),
        spk: this.#script(o + L.out.spk),
        key: this.#key(o + L.out.key),
      });
    }
    return new Plan(this.#i32(p + L.txVersion), this.#u32(p + L.locktime), inputs, outputs);
  }

  // --- animated QR (UR) ---

  /** Drop decoder state before a new animated QR. */
  urReset() { this.exports.parser_ur_reset(); }

  /**
   * Feed one UR part. Returns the PSBT once the message is complete, otherwise null.
   * @param {string|Uint8Array} part one QR payload
   */
  urReceive(part) {
    const bytes = typeof part === "string" ? new TextEncoder().encode(part) : part;
    this.#writeInput(bytes);
    const rc = this.exports.parser_ur_receive(bytes.length);
    if (rc < 0) throw new ParserError(rc, "UR_ERR");
    if (rc === 0) return null;
    return this.#bytes(this.exports.parser_input(), rc);
  }

  /** Parts received so far. For a progress display only. */
  get urProgress() { return this.exports.parser_ur_progress(); }

  /**
   * Encode a signed PSBT as animated QR parts.
   * @returns {{ seqLen: number, next: () => string }}
   */
  /**
   * @param {number} psbtLen
   * @param {number} [fragmentLen]
   */
  urEncode(psbtLen, fragmentLen = 100) {
    const seqLen = this.exports.parser_ur_encode_start(psbtLen, fragmentLen);
    if (seqLen < 0) throw new ParserError(seqLen, "UR_ERR");
    return {
      seqLen,
      next: () => {
        const n = this.exports.parser_ur_encode_next();
        if (n < 0) throw new ParserError(n, "UR_ERR");
        return new TextDecoder().decode(this.#bytes(this.exports.parser_input(), n));
      },
    };
  }

  /**
   * Insert signatures and return the signed PSBT.
   * @param {{input: number, pubkey: Uint8Array, sig: Uint8Array}[]} sigs
   */
  finalize(sigs) {
    if (sigs.length > 16) throw new RangeError(`${sigs.length} signatures, a plan has at most 16 inputs`);
    for (const s of sigs) {
      if (!(s.input >= 0 && s.input < 16) || s.pubkey.length !== 33 || s.sig.length > 73) {
        throw new RangeError(`input ${s.input}: a signature slot takes a 33-byte pubkey and at most 73 bytes of signature`);
      }
    }
    this.#refresh();
    const base = this.exports.parser_sigs();
    this.mem.fill(0, this.#check(base, 108 * 16), base + 108 * 16);
    sigs.forEach((s, i) => {
      const o = base + i * 108;
      this.mem[o] = s.input;
      this.mem.set(s.pubkey, o + 1);
      this.mem[o + 34] = s.sig.length;
      this.mem.set(s.sig, o + 35);
    });
    const len = this.exports.parser_finalize(sigs.length);
    if (len < 0) throw new ParserError(-len);
    return this.#bytes(this.exports.parser_output(), len);
  }
}

/** What the module read out of the PSBT. Every field is a claim until the host checks it. */
export class Plan {
  /**
   * @param {number} txVersion
   * @param {number} locktime
   * @param {PlanInput[]} inputs
   * @param {PlanOutput[]} outputs
   */
  constructor(txVersion, locktime, inputs, outputs) {
    this.txVersion = txVersion;
    this.locktime = locktime;
    this.inputs = inputs;
    this.outputs = outputs;
  }
  get totalIn() { return this.inputs.reduce((a, i) => a + i.amount, 0n); }
  get totalOut() { return this.outputs.reduce((a, o) => a + o.amount, 0n); }
  /** Derived from the amounts in the plan, which are claims until the prevtx is checked. */
  get fee() { return this.totalIn - this.totalOut; }
}
