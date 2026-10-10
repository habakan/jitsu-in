// Compares the C and the Rust parser through the real ABI: the whole 6,712-byte plan, byte for
// byte, plus the prevtx offsets and the signed PSBT that finalize produces.
//
// The plan is the interface, so comparing it whole is comparing everything a signer would see. A
// field this does not know about cannot hide a difference.
//
//   node tools/check_rust_plan.mjs <c.wasm> <rust.wasm> <vector-dir>
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";

const [cPath, rsPath, vecDir] = process.argv.slice(2);
const load = async (p) => (await WebAssembly.instantiate(readFileSync(p), {})).instance.exports;
const C = await load(cPath);
const R = await load(rsPath);
const PLAN = 6712;
const hex = (b) => Buffer.from(b).toString("hex");

let checks = 0, differ = 0;
const shown = [];
function cmp(what, a, b) {
  checks++;
  if (a !== b) {
    differ++;
    if (shown.length < 6) shown.push(`${what}\n  c    ${a}\n  rust ${b}`);
  }
}

function parse(e, bytes, fp) {
  new Uint8Array(e.memory.buffer).set(bytes, e.parser_input());
  const rc = e.parser_parse(bytes.length, fp);
  if (rc !== 0) return { rc };
  const mem = new Uint8Array(e.memory.buffer);
  const plan = hex(mem.slice(e.parser_plan(), e.parser_plan() + PLAN));
  const prev = [];
  for (let i = 0; i < 16; i++) prev.push(`${e.parser_prevtx_off(i)}:${e.parser_prevtx_len(i)}`);
  return { rc, plan, prev: prev.join(",") };
}

/** finalize with fabricated signatures: the insertion is what is being compared, not the crypto. */
function finalize(e, plan) {
  const sigs = [];
  const mem = new Uint8Array(e.memory.buffer);
  const planBytes = mem.slice(e.parser_plan(), e.parser_plan() + PLAN);
  const nIn = planBytes[16];
  for (let i = 0; i < nIn; i++) {
    const o = 24 + 176 * i;
    const depth = planBytes[o + 132];
    if (!depth) continue;
    const spkLen = planBytes[o + 48];
    const isTr = spkLen === 34 && planBytes[o + 49] === 0x51;
    const pub = new Uint8Array(33);
    const sig = new Uint8Array(isTr ? 64 : 71);
    if (isTr) { pub[0] = 0; sig.fill(0xab); }
    else { pub[0] = 2; pub.fill(0x11, 1); sig[0] = 0x30; sig[1] = 0x44; sig.fill(0x5a, 2); sig[70] = 1; }
    sigs.push([i, pub, sig]);
  }
  if (!sigs.length) return "no signable input";
  const buf = new Uint8Array(sigs.length * 108);
  sigs.forEach(([i, pub, sig], k) => {
    const at = k * 108;
    buf[at] = i;
    buf.set(pub, at + 1);
    buf[at + 34] = sig.length;
    buf.set(sig, at + 35);
  });
  new Uint8Array(e.memory.buffer).set(buf, e.parser_sigs());
  const n = e.parser_finalize(sigs.length);
  if (n <= 0) return `rc=${n}`;
  return hex(new Uint8Array(e.memory.buffer).slice(e.parser_output(), e.parser_output() + n));
}

const FP = 0x73c5da0a;
const files = readdirSync(vecDir).filter((f) => f.endsWith(".psbt")).sort();
for (const f of files) {
  const b = readFileSync(join(vecDir, f));
  for (const fp of [0, FP, FP ^ 1]) {
    const c = parse(C, b, fp), r = parse(R, b, fp);
    cmp(`${f} fp=${fp.toString(16)} rc`, c.rc, r.rc);
    if (c.rc === 0 && r.rc === 0) {
      cmp(`${f} fp=${fp.toString(16)} plan`, c.plan, r.plan);
      cmp(`${f} fp=${fp.toString(16)} prevtx`, c.prev, r.prev);
      cmp(`${f} fp=${fp.toString(16)} finalize`, finalize(C, c.plan), finalize(R, r.plan));
    }
  }
}

// --- fuzzed: a valid PSBT with bytes flipped reaches deeper than noise does
let traps = 0;
const seeds = files.filter((f) => f.startsWith("own_")).map((f) => readFileSync(join(vecDir, f)));
for (let i = 0; i < 20000; i++) {
  const src = seeds[i % seeds.length];
  const b = Uint8Array.from(src);
  for (let k = 0, m = 1 + (i % 4); k < m; k++) {
    b[Math.floor(Math.random() * b.length)] = Math.floor(Math.random() * 256);
  }
  const n = i % 7 === 0 ? 1 + Math.floor(Math.random() * b.length) : b.length;
  try {
    const c = parse(C, b.subarray(0, n), FP), r = parse(R, b.subarray(0, n), FP);
    cmp(`fuzz rc`, c.rc, r.rc);
    if (c.rc === 0 && r.rc === 0) cmp(`fuzz plan`, c.plan, r.plan);
  } catch (e) {
    traps++;
    if (traps < 3) console.log(`TRAP: ${e.message.split("\n")[0]}`);
  }
}

for (const s of shown) console.log(`DIFFER ${s}`);
console.log(`${checks - differ}/${checks} agree, ${traps} trapped`);
process.exit(differ || traps ? 1 : 0);
