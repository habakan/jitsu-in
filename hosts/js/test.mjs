// Tests the host, not the parser: the module itself is covered by the 529 vectors in tools/run_tests.py.
// What matters here is that offsets are hidden correctly, errors arrive as names, and a module that
// returns a bad offset is stopped rather than followed.
//   node hosts/js/test.mjs [build/parser.wasm] [build/vectors]
import { readFileSync, readdirSync } from "fs";
import { Parser, ParserError, KeyOrigin } from "./parser.mjs";

const wasmPath = process.argv[2] ?? "build/parser.wasm";
const vectorDir = process.argv[3] ?? "build/vectors";
const parserWasm = readFileSync(wasmPath);
const FP = 0x73c5da0a;

let checks = 0, failures = 0;
const check = (cond, what) => {
  checks++;
  if (!cond) { failures++; console.log("FAIL " + what); }
};
const throws = (fn, want, what) => {
  checks++;
  try { fn(); failures++; console.log(`FAIL ${what}: did not throw`); }
  catch (e) {
    if (e.message.includes(want) || e.constructor.name === want) return;
    failures++; console.log(`FAIL ${what}: ${e.constructor.name}: ${e.message}`);
  }
};

// --- the hand-made vectors parse, and the shape is sane
const vectors = readdirSync(vectorDir).filter(f => f.startsWith("own_") && f.endsWith(".psbt"));
check(vectors.length >= 4, `${vectors.length} hand-made vectors`);
for (const name of vectors) {
  const p = Parser.loadSync(parserWasm);
  const plan = p.parse(readFileSync(`${vectorDir}/${name}`), FP);
  check(plan.inputs.length > 0 && plan.outputs.length > 0, `${name}: has inputs and outputs`);
  check(plan.fee > 0n && plan.fee < 1000000n, `${name}: fee ${plan.fee} is plausible`);
  check(plan.totalIn - plan.totalOut === plan.fee, `${name}: fee is in minus out`);
  for (const i of plan.inputs) {
    check(i.prevTxid.length === 32, `${name}: txid is 32 bytes`);
    check(i.spk.length > 0 && i.spk.length <= 83, `${name}: input spk length`);
    check(i.key === null || i.key instanceof KeyOrigin, `${name}: input key type`);
    check(i.prevtx === null || i.prevtx.length > 60, `${name}: prevtx looks like a transaction`);
  }
  for (const o of plan.outputs) check(o.spk.length > 0 && o.spk.length <= 83, `${name}: output spk length`);
}

// --- what Bitcoin Core marks invalid is rejected, as a ParserError and not a crash
{
  const invalid = readdirSync(vectorDir).filter(f => f.startsWith("rpc_invalid") && f.endsWith(".psbt"));
  check(invalid.length > 50, `${invalid.length} invalid vectors`);
  let rejected = 0;
  for (const name of invalid) {
    const p = Parser.loadSync(parserWasm);
    try { p.parse(readFileSync(`${vectorDir}/${name}`), FP); }
    catch (e) { if (e instanceof ParserError) rejected++; else { failures++; console.log(`FAIL ${name}: ${e}`); } }
  }
  checks++;
  // Some of Core's "invalid" cases are invalid for reasons outside this module's job, so a few parse
  if (rejected < invalid.length * 0.8) { failures++; console.log(`FAIL only ${rejected}/${invalid.length} rejected`); }
}

// --- a derivation prints the way a human reads it
{
  const p = Parser.loadSync(parserWasm);
  const plan = p.parse(readFileSync(`${vectorDir}/own_p2wpkh_1in.psbt`), FP);
  check(String(plan.inputs[0].key) === "73c5da0a/84h/0h/0h/0/0", `keypath prints as ${plan.inputs[0].key}`);
  check(plan.inputs[0].key.fingerprint === FP, "fingerprint is kept as a number");
}

// --- the same fingerprint, unmatched, means no key is claimed
{
  const p = Parser.loadSync(parserWasm);
  const plan = p.parse(readFileSync(`${vectorDir}/own_p2wpkh_1in.psbt`), 0);
  check(plan.inputs.every(i => i.key === null), "a fingerprint that matches nothing claims nothing");
}

// --- errors arrive as names, not numbers
{
  const p = Parser.loadSync(parserWasm);
  throws(() => p.parse(new Uint8Array([1, 2, 3, 4, 5]), 0), "P_ERR_MAGIC", "not a PSBT");
  throws(() => p.parse(new Uint8Array(p.inputCapacity + 1), 0), "does not fit", "too large for the buffer");
  throws(() => p.urReceive("not a ur"), "UR_ERR_SCHEME", "not a UR");
}

// --- a module that lies about where things are must not be followed
{
  const p = Parser.loadSync(parserWasm);
  p.exports = { ...p.exports, parser_plan: () => 99999999 };
  throws(() => p.parse(readFileSync(`${vectorDir}/own_p2wpkh_1in.psbt`), FP), "RangeError", "offset outside memory");
}

// --- UR: encode what finalize produced, feed the parts back, get the same bytes
{
  const enc = Parser.loadSync(parserWasm);
  enc.parse(readFileSync(`${vectorDir}/own_mixed_nwu.psbt`), FP);
  const out = enc.finalize([]);               // no signatures: re-serializes into the output buffer
  check(out.length > 100, `finalize produced ${out.length} bytes`);

  const seq = enc.urEncode(out.length, 100);
  check(seq.seqLen > 1, `splits into ${seq.seqLen} parts`);

  const dec = Parser.loadSync(parserWasm);
  dec.urReset();
  let got = null, n = 0;
  while (!got && n < seq.seqLen * 3) { got = dec.urReceive(seq.next()); n++; }
  check(got !== null, "reassembles");
  check(got && Buffer.compare(Buffer.from(got), Buffer.from(out)) === 0, "round trip is byte identical");
}

// --- a module with imports is refused before it is instantiated
{
  // (module (import "env" "f" (func)) (memory 1 1))
  const withImport = new Uint8Array([
    0, 97, 115, 109, 1, 0, 0, 0,
    1, 4, 1, 96, 0, 0,                                  // type: () -> ()
    2, 9, 1, 3, 101, 110, 118, 1, 102, 0, 0,            // import "env" "f"
    5, 4, 1, 1, 1, 1,                                   // memory 1 1
  ]);
  throws(() => Parser.loadSync(withImport), "must have no imports", "a module with imports is refused");
}

// --- the digest gate accepts the real build and refuses anything else
{
  const digest = await crypto.subtle.digest("SHA-256", parserWasm);
  const sha256 = [...new Uint8Array(digest)].map(b => b.toString(16).padStart(2, "0")).join("");
  await Parser.load(parserWasm, { sha256 });
  checks++;                                              // no throw: accepted
  try {
    await Parser.load(parserWasm, { sha256: "00".repeat(32) });
    failures++; console.log("FAIL a wrong digest was accepted");
  } catch (e) {
    checks++;
    if (!e.message.includes("not the expected build")) { failures++; console.log(`FAIL ${e.message}`); }
  }
}

console.log(`${checks - failures}/${checks} checks passed`);
process.exit(failures ? 1 : 0);
