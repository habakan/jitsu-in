// Tests build/parser.wasm itself, driving the raw exports rather than going through a host library,
// so that what is checked is the ABI the specification documents.
//
//   1) no imports
//   2) Bitcoin Core's rpc_psbt.json: nothing traps, and accept/reject matches
//   3) the plan matches the committed expectations
//   4) signature insertion, and the ways it has to fail
//   5) animated-QR (UR) reassembly of the same PSBTs, as the reference encoder produced them
//   6) UR encoding of the output, part for part against the reference, and back through the decoder
//
//   node tools/run_tests.mjs build/parser.wasm build/vectors tests/rpc_psbt.json tests/ur_vectors.json
import { readFileSync, readdirSync } from "node:fs";
import { basename, join } from "node:path";

const [WASM, VEC, RPC, URV] = process.argv.slice(2);
if (!URV) {
  console.error("usage: run_tests.mjs parser.wasm VECTOR_DIR rpc_psbt.json ur_vectors.json");
  process.exit(2);
}

const P_OK = 0, P_ERR_TX = 4, P_ERR_UNSUPPORTED = 5, P_ERR_UTXO = 7;
const UR_ERR_MISMATCH = -4, UR_ERR_TYPE = -7;
// The defect in invalid_with_msg[15] is the value length of PSBT_IN_MUSIG2_PARTIAL_SIG (0x1c);
// its message omits musig2
const MUSIG2_BY_FIELD = new Set([15]);
const PLAN_SIZE = 5016;

const moduleBytes = readFileSync(WASM);
const compiled = await WebAssembly.compile(moduleBytes);

let checks = 0;
const failures = [];
function check(cond, msg) {
  checks++;
  if (!cond) failures.push(msg);
}
const hex = (b) => Buffer.from(b).toString("hex");

/** A fresh instance per case, so nothing carries over between vectors. */
class Parser {
  constructor() {
    this.e = new WebAssembly.Instance(compiled, {}).exports;
  }
  get mem() {
    return new Uint8Array(this.e.memory.buffer);
  }
  call(name, ...args) {
    return this.e[name](...args);
  }
  write(bytes, at) {
    this.mem.set(bytes, at);
  }
  read(at, n) {
    return this.mem.slice(at, at + n);
  }
  parse(raw, fp) {
    this.write(raw, this.e.parser_input());
    return this.e.parser_parse(raw.length, fp);
  }
  plan() {
    const b = this.read(this.e.parser_plan(), PLAN_SIZE);
    const v = new DataView(b.buffer, b.byteOffset, b.length);
    const keypath = (o) => {
      const depth = b[o];
      if (depth === 0) return null;
      return {
        fingerprint: v.getUint32(o + 4, true),
        path: [...Array(depth)].map((_, i) => v.getUint32(o + 8 + i * 4, true)),
      };
    };
    const nIn = b[16], nOut = b[17];
    const inputs = [...Array(nIn)].map((_, i) => {
      const o = 24 + 176 * i;
      return {
        prev_txid: hex(b.slice(o, o + 32)),
        prev_vout: v.getUint32(o + 32, true),
        sequence: v.getUint32(o + 36, true),
        amount: Number(v.getBigUint64(o + 40, true)),
        spk: hex(b.slice(o + 49, o + 49 + b[o + 48])),
        key: keypath(o + 132),
        sighash_type: b[o + 172],
      };
    });
    const outputs = [...Array(nOut)].map((_, i) => {
      const o = 24 + 176 * 16 + 136 * i;
      return {
        amount: Number(v.getBigUint64(o, true)),
        spk: hex(b.slice(o + 9, o + 9 + b[o + 8])),
        key: keypath(o + 92),
      };
    });
    return {
      magic: v.getUint32(0, true), version: v.getUint32(4, true),
      tx_version: v.getInt32(8, true), locktime: v.getUint32(12, true), inputs, outputs,
    };
  }
  /** The offset is relative to parser_input(), so the base is added here. */
  prevtx(i) {
    const n = this.e.parser_prevtx_len(i);
    return n ? this.read(this.e.parser_input() + this.e.parser_prevtx_off(i), n) : new Uint8Array(0);
  }
  ur(part) {
    const raw = Buffer.from(part, "utf8");
    this.write(raw, this.e.parser_input());
    return this.e.parser_ur_receive(raw.length);
  }
  finalize(sigs) {
    if (sigs.length) {
      const buf = new Uint8Array(sigs.length * 108);
      sigs.forEach(([i, pub, sig], k) => {
        const o = k * 108;
        buf[o] = i;
        buf.set(pub, o + 1);
        buf[o + 34] = sig.length;
        buf.set(sig, o + 35);
      });
      this.write(buf, this.e.parser_sigs());
    }
    const n = this.e.parser_finalize(sigs.length);
    return [n, n > 0 ? this.read(this.e.parser_output(), n) : new Uint8Array(0)];
  }
}

const readJson = (p) => JSON.parse(readFileSync(p, "utf8"));
const vectorFiles = (pattern) =>
  readdirSync(VEC).filter((f) => pattern.test(f)).sort().map((f) => join(VEC, f));

// --- 1) no imports
{
  const imports = WebAssembly.Module.imports(compiled);
  check(imports.length === 0, `imports: ${imports.map((i) => `${i.module}.${i.name}`).join(", ")}`);
}

// --- 2) Bitcoin Core's rpc_psbt.json
const rpc = readJson(RPC);
const counts = {};
for (const path of vectorFiles(/^rpc_.*\.psbt$/)) {
  const [, kind, idx] = basename(path).match(/^rpc_(\w+?)_(\d+)\.psbt$/);
  const i = Number(idx);
  let rc;
  try {
    rc = new Parser().parse(readFileSync(path), 0);
  } catch (e) {
    check(false, `${kind}[${i}] trapped: ${e.message}`);
    continue;
  }
  const key = `${kind}/${rc === P_OK ? "accepted" : "rejected"}`;
  counts[key] = (counts[key] ?? 0) + 1;
  if (kind.startsWith("invalid") && rc === P_OK) {
    const msg = kind === "invalid_with_msg" ? rpc.invalid_with_msg[i][1] : "";
    check(msg.toLowerCase().includes("musig2") ||
          (kind === "invalid_with_msg" && MUSIG2_BY_FIELD.has(i)),
          `${kind}[${i}] accepted`);
  }
  if (kind === "valid") {
    check([P_OK, P_ERR_UNSUPPORTED, P_ERR_UTXO, P_ERR_TX].includes(rc), `valid[${i}] rejected rc=${rc}`);
  }
}

// --- 3) the plan matches expectations, 4) signature insertion
const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);
for (const path of vectorFiles(/^own_.*\.psbt$/)) {
  const name = basename(path, ".psbt");
  const raw = readFileSync(path);
  const exp = readJson(path.replace(/\.psbt$/, ".json"));
  const p = new Parser();
  check(p.parse(raw, exp.fingerprint) === P_OK, `${name}: parse`);
  const plan = p.plan();
  check(plan.tx_version === exp.tx_version && plan.locktime === exp.locktime, `${name}: header`);
  check(plan.inputs.length === exp.inputs.length && plan.outputs.length === exp.outputs.length,
        `${name}: counts`);
  plan.inputs.forEach((got, i) => {
    const want = exp.inputs[i];
    for (const k of ["prev_txid", "prev_vout", "sequence", "amount", "spk", "key", "sighash_type"]) {
      check(same(got[k], want[k]), `${name}: input ${i} ${k}: ${JSON.stringify(got[k])} != ${JSON.stringify(want[k])}`);
    }
    // That those bytes really are the transaction the input claims is checked against Bitcoin Core,
    // by ../tools/check_against_core.mjs: a txid excludes the witness, and implementing that here
    // would mean a second Bitcoin implementation in the tests
    check((p.prevtx(i).length > 0) === want.has_prevtx, `${name}: input ${i} prevtx presence`);
  });
  plan.outputs.forEach((got, i) => {
    const want = exp.outputs[i];
    for (const k of ["amount", "spk", "key"]) {
      check(same(got[k], want[k]), `${name}: output ${i} ${k}: ${JSON.stringify(got[k])} != ${JSON.stringify(want[k])}`);
    }
  });

  // a different fingerprint selects no key candidates
  {
    const other = new Parser();
    const rc = other.parse(raw, exp.fingerprint ^ 1);
    const pl = other.plan();
    check(rc === P_OK && [...pl.inputs, ...pl.outputs].every((x) => x.key === null),
          `${name}: foreign fingerprint`);
  }

  const sigs = [];
  exp.inputs.forEach((want, i) => {
    if (want.key === null) return;
    if (want.spk.startsWith("5120")) {
      const tail = want.sighash_type ? [want.sighash_type] : [];
      sigs.push([i, Uint8Array.from([0, ...Buffer.from(want.spk, "hex").subarray(1)]),
                 Uint8Array.from([...Array(64).fill(0xab), ...tail])]);
    } else {
      sigs.push([i, Uint8Array.from(Buffer.from(exp.pubkeys[i], "hex")),
                 Uint8Array.from([0x30, 0x44, ...Array(68).fill(0x5a), 0x01])]);
    }
  });
  const [n, out] = p.finalize(sigs);
  const inserted = sigs.reduce((a, [, pub, s]) => a + (pub[0] ? 2 + 33 + 1 + s.length : 2 + 1 + s.length), 0);
  check(n === raw.length + inserted, `${name}: finalize length ${n}`);

  // Checked as bytes rather than by parsing the result with another PSBT library: each signature has
  // to appear as its own key/value record, and everything else has to be the original bytes
  // untouched. That the signed PSBT is valid to a real implementation is checked separately, by
  // ../tools/check_against_core.mjs against Bitcoin Core
  const records = sigs.map(([, pub, sig]) => {
    const key = pub[0] === 0 ? Buffer.from([0x13]) : Buffer.concat([Buffer.from([0x02]), Buffer.from(pub)]);
    return Buffer.concat([Buffer.from([key.length]), key, Buffer.from([sig.length]), Buffer.from(sig)]);
  });
  const signed = Buffer.from(out);
  records.forEach((rec, k) => check(signed.includes(rec), `${name}: input ${sigs[k][0]} signature inserted`));
  // Nothing but those records was added: removing them leaves the input unchanged
  let stripped = signed;
  for (const rec of records) {
    const at = stripped.indexOf(rec);
    if (at >= 0) stripped = Buffer.concat([stripped.subarray(0, at), stripped.subarray(at + rec.length)]);
  }
  check(stripped.equals(raw), `${name}: nothing but the signatures changed`);

  // failures: a signature for a foreign input, the same input twice, too many, a bad pubkey prefix
  const unsigned = exp.inputs.map((w, i) => (w.key === null ? i : -1)).filter((i) => i >= 0);
  if (unsigned.length) {
    check(p.finalize([[unsigned[0], new Uint8Array(33).fill(2), new Uint8Array(71).fill(0x30)]])[0] < 0,
          `${name}: sig for foreign input`);
  }
  check(p.finalize([sigs[0], sigs[0]])[0] < 0, `${name}: duplicate input`);
  check(p.finalize(Array(17).fill(sigs[0]))[0] < 0, `${name}: too many sigs`);
  {
    const [i0, pub0, sig0] = sigs[0];
    check(p.finalize([[i0, Uint8Array.from([5, ...pub0.subarray(1)]), sig0]])[0] < 0,
          `${name}: bad pubkey prefix`);
  }
}
check(new Parser().finalize([])[0] < 0, "finalize before parse");

// --- 5) UR: drop every third pure part so mixed parts have to fill the gaps
const ur = readJson(URV);
for (const v of ur.vectors) {
  const name = `${v.name} ${v.type}/${v.fragment_len}`;
  const psbt = Buffer.from(v.psbt_hex, "hex");
  const exp = readJson(join(VEC, `${v.name}.json`));
  const p = new Parser();
  p.call("parser_ur_reset");
  let rc = 0, fed = 0;
  for (const part of v.parts) {
    const m = part.match(/^UR:[A-Z-]+\/(\d+)-\d+\//);
    if (m && Number(m[1]) <= v.seq_len && Number(m[1]) % 3 === 0) continue;
    rc = p.ur(part);
    fed++;
    if (rc) break;
    const progress = p.call("parser_ur_progress");
    check(progress >>> 16 === v.seq_len, `${name}: progress ${progress >>> 16} != ${v.seq_len}`);
  }
  check(rc === psbt.length && Buffer.from(p.read(p.call("parser_input"), rc)).equals(psbt),
        `${name}: reassembled (rc=${rc}, ${fed} parts)`);
  check(rc > 0 && p.call("parser_parse", rc, exp.fingerprint) === P_OK, `${name}: parses`);
}

// --- 6) encoding: finalize with no signatures returns the PSBT unchanged, which the reference encoded too
for (const v of ur.vectors.filter((v) => v.type === "crypto-psbt")) {
  const name = `encode ${v.name}/${v.fragment_len}`;
  const psbt = Buffer.from(v.psbt_hex, "hex");
  const exp = readJson(join(VEC, `${v.name}.json`));
  const p = new Parser();
  check(p.parse(psbt, exp.fingerprint) === P_OK, `${name}: parse`);
  const [n, out] = p.finalize([]);
  check(n === psbt.length && Buffer.from(out).equals(psbt), `${name}: finalize without signatures`);
  if (v.fragment_len > 1000) {   // UR_MAX_FRAGMENT; the single-part form is checked natively against bc-ur
    check(p.call("parser_ur_encode_start", n, v.fragment_len) === -5, `${name}: fragment limit`);
    continue;
  }
  check(p.call("parser_ur_encode_start", n, v.fragment_len) === v.seq_len, `${name}: seq_len`);
  const ours = [];
  for (let k = 0; k < v.seq_len * 3 + 2; k++) {
    const len = p.call("parser_ur_encode_next");
    ours.push(Buffer.from(p.read(p.call("parser_input"), len)).toString("utf8"));
  }
  if (v.seq_len === 1) {
    check(ours[0] === v.parts[0], `${name}: single part`);
  } else {
    const bySeq = new Map(ours.map((x) => [Number(x.match(/^UR:[A-Z-]+\/(\d+)-/)[1]), x]));
    for (const ref of v.parts) {
      const seq = Number(ref.match(/^UR:[A-Z-]+\/(\d+)-/)[1]);
      check(bySeq.get(seq) === ref, `${name}: part ${seq}`);
    }
  }
  const d = new Parser();
  d.call("parser_ur_reset");
  let rc = 0;
  // odd parts first, so the pure ones are dropped at first and mixed parts have to do the work
  for (const part of [...ours.filter((_, i) => i % 2), ...ours.filter((_, i) => !(i % 2))]) {
    rc = rc || d.ur(part);
  }
  check(rc === psbt.length && Buffer.from(d.read(d.call("parser_input"), rc)).equals(psbt),
        `${name}: round trip`);
}

// --- a UR that is not a PSBT, and a part from another message in the middle of one
{
  const bytesUr = "ur:bytes/hdeymejtswhhylkepmykhhtsytsnoyoyaxaedsuttydmmhhpktpmsrjtgwdpfnsboxgwlbaawzuefywkdplrsrjynbvygabwjldapfcsdwkbrkch";
  const p = new Parser();
  p.call("parser_ur_reset");
  check(p.ur(bytesUr) === UR_ERR_TYPE, "bytes UR rejected");
}
{
  const multi = ur.vectors.filter((v) => v.seq_len > 3);
  const [a, b] = multi;
  const p = new Parser();
  p.call("parser_ur_reset");
  check(p.ur(a.parts[0]) === 0, "first part");
  check(p.ur(b.parts[1]) === UR_ERR_MISMATCH, "part of another message rejected");
  let rc = 0;
  for (const part of a.parts.slice(1)) rc = rc || p.ur(part);
  check(rc === Buffer.from(a.psbt_hex, "hex").length, "completes after the foreign part");
}

const order = Object.keys(counts).sort();
console.log("rpc_psbt.json:", JSON.stringify(Object.fromEntries(order.map((k) => [k, counts[k]]))));
for (const f of failures) console.log("FAIL", f);
console.log(`${checks - failures.length}/${checks} checks passed`);
process.exit(failures.length ? 1 : 0);
