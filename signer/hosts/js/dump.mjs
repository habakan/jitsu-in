// Prints what the module reported, so this host's output and the Kotlin host's can be compared
// directly. Two independent hosts driving the same module must agree byte for byte; if they do not,
// one of them is reading the layout wrong.
//
//   node dump.mjs <signer.wasm> <parser.wasm> <psbt>
import { readFileSync } from "node:fs";
import { Signer } from "./signer.mjs";

const [signerPath, parserPath, psbtPath] = process.argv.slice(2);
const OWNER = ["EXTERNAL", "CHANGE", "SELF"];
const TEXT_KIND = ["ADDRESS", "OP_RETURN", "SCRIPT"];
const PLAN_SIZE = Signer.LAYOUT.plan.size;

const P = (await WebAssembly.instantiate(readFileSync(parserPath), {})).instance.exports;
const psbt = readFileSync(psbtPath);
new Uint8Array(P.memory.buffer).set(psbt, P.parser_input());
if (P.parser_parse(psbt.length, 0x73c5da0a) !== 0) throw new Error("the parser refused the PSBT");

const mem = new Uint8Array(P.memory.buffer);
const plan = mem.slice(P.parser_plan(), P.parser_plan() + PLAN_SIZE);
const prevTxs = [];
for (let i = 0; i < plan[Signer.LAYOUT.plan.nInputs]; i++) {
  const len = P.parser_prevtx_len(i);
  const at = P.parser_input() + P.parser_prevtx_off(i);
  prevTxs.push(len ? mem.slice(at, at + len) : null);
}

const S = await Signer.load(readFileSync(signerPath));
S.init().seedFromMnemonic("abandon ".repeat(11) + "about").setPlan(plan).setPrevTxs(prevTxs);
S.review();
const d = S.display();
console.log(`fingerprint ${S.fingerprint}`);
console.log(`fee ${d.fee} spend ${d.spend}`);
for (const o of d.outputs) {
  console.log(`out ${o.amount} ${OWNER[o.owner]} ${TEXT_KIND[o.textKind]} ${o.text}`);
}
for (const s of S.sign()) {
  console.log(`sig ${s.input} ` + [...s.sig].map((b) => b.toString(16).padStart(2, "0")).join(""));
}
S.unload();
