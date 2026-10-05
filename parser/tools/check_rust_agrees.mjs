// While the port from C to Rust is in progress, both modules are built and required to give the
// same answer on every vector and on fuzzed input. The C is the reference until the port is done.
//
// A port that is only checked against its own tests is a port whose bugs become its tests. This
// compares two implementations of the same specification instead.
//
//   node tools/check_rust_agrees.mjs <c.wasm> <rust.wasm> <vector-dir>
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";

const [cPath, rsPath, vecDir] = process.argv.slice(2);
if (!vecDir) {
  console.error("usage: check_rust_agrees.mjs c.wasm rust.wasm VECTOR_DIR");
  process.exit(2);
}

const load = async (p) => (await WebAssembly.instantiate(readFileSync(p), {})).instance.exports;
const C = await load(cPath);
const R = await load(rsPath);
const hex = (b) => Buffer.from(b).toString("hex");

let checks = 0, differ = 0;
const seen = [];
function cmp(what, a, b) {
  checks++;
  if (a !== b) {
    differ++;
    if (seen.length < 5) seen.push(`${what}\n  c    ${a}\n  rust ${b}`);
  }
}

/** The C exposes tx parsing through a probe export; the Rust through rs_tx_parse. */
function runC(bytes) {
  new Uint8Array(C.memory.buffer).set(bytes, C.probe_input());
  const rc = C.probe_tx_parse(bytes.length);
  if (rc !== 1) return `rc=${rc}`;
  const v = new DataView(C.memory.buffer, C.probe_tx_out());
  return readOut(v, new Uint8Array(C.memory.buffer), C.probe_tx_out());
}
function runR(bytes) {
  new Uint8Array(R.memory.buffer).set(bytes, R.rs_input());
  const rc = R.rs_tx_parse(bytes.length);
  if (rc !== 1) return `rc=${rc}`;
  const v = new DataView(R.memory.buffer, R.rs_tx_out());
  return readOut(v, new Uint8Array(R.memory.buffer), R.rs_tx_out());
}
/** The same layout on both sides, so a difference is a difference in behaviour, not in reading. */
function readOut(v, mem, base) {
  const o = {
    version: v.getInt32(0, true),
    locktime: v.getUint32(4, true),
    nIn: v.getUint32(8, true),
    nOut: v.getUint32(12, true),
    segwit: v.getUint32(16, true),
    txid: hex(mem.slice(base + 20, base + 52)),
    outs: [],
  };
  for (let i = 0; i < Math.min(o.nOut, 16); i++) {
    o.outs.push([
      String(v.getBigUint64(56 + i * 8, true)),
      v.getUint32(184 + i * 4, true),
      v.getUint32(248 + i * 4, true),
    ]);
  }
  return JSON.stringify(o);
}

// --- the project's own vectors: the prevtx inside each PSBT is a real transaction
const files = readdirSync(vecDir).filter((f) => f.endsWith(".psbt")).sort();
for (const f of files) {
  const b = readFileSync(join(vecDir, f));
  cmp(`${f} (as a whole, which is not a transaction)`, runC(b), runR(b));
}

// --- SHA-256 over the same bytes
for (const f of files.slice(0, 20)) {
  const b = readFileSync(join(vecDir, f));
  new Uint8Array(C.memory.buffer).set(b, C.probe_input());
  C.probe_sha256(b.length);
  new Uint8Array(R.memory.buffer).set(b, R.rs_input());
  R.rs_sha256(b.length);
  cmp(`${f} sha256`,
      hex(new Uint8Array(C.memory.buffer).slice(C.probe_input(), C.probe_input() + 32)),
      hex(new Uint8Array(R.memory.buffer).slice(R.rs_input(), R.rs_input() + 32)));
}

// --- fuzzed input: neither may trap, and both must refuse or accept identically
let traps = 0;
for (let i = 0; i < 50000; i++) {
  const n = 1 + Math.floor(Math.random() * 400);
  const b = new Uint8Array(n);
  for (let k = 0; k < n; k++) b[k] = Math.floor(Math.random() * 256);
  // a shape that reaches further into the parser than pure noise does
  if (i % 3 === 0) { b[0] = 2; b[1] = 0; b[2] = 0; b[3] = 0; }
  if (i % 5 === 0 && n > 6) { b[4] = 0; b[5] = 1; }
  try {
    cmp(`fuzz ${hex(b).slice(0, 40)}`, runC(b), runR(b));
  } catch (e) {
    traps++;
    if (traps < 3) console.log(`TRAP on ${hex(b).slice(0, 40)}: ${e.message.split("\n")[0]}`);
  }
}

for (const s of seen) console.log(`DIFFER ${s}`);
console.log(`${checks - differ}/${checks} agree, ${traps} trapped`);
process.exit(differ || traps ? 1 : 0);
