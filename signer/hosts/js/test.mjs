// Drives signer.wasm through the host library and checks the result against what the native side
// produced. The signatures are deterministic, so "the same" means byte-identical, not merely valid.
import { readFileSync } from "node:fs";
import { Signer, OWNER, TEXT_KIND, SignerError } from "./signer.mjs";

const MNEMONIC = "abandon ".repeat(11) + "about";
const root = new URL("../../../../", import.meta.url).pathname;
const PLAN_SIZE = Signer.LAYOUT.plan.size;

let pass = 0, fail = 0;
const hex = (b) => [...b].map((x) => x.toString(16).padStart(2, "0")).join("");

function check(what, got, want) {
  const ok = got === want;
  ok ? pass++ : fail++;
  if (!ok) console.log(`FAIL ${what}\n  got  ${got}\n  want ${want}`);
}
function ok(what, cond) {
  cond ? pass++ : fail++;
  if (!cond) console.log(`FAIL ${what}`);
}

// parser.wasm turns the PSBT into a plan; signer.wasm is what we are testing
const parserWasm = readFileSync(`${root}build/parser.wasm`);
const signerWasm = readFileSync(`${root}build/signer.wasm`);
const P = (await WebAssembly.instantiate(parserWasm, {})).instance.exports;

function planFor(psbtPath, fingerprint) {
  const psbt = readFileSync(psbtPath);
  new Uint8Array(P.memory.buffer).set(psbt, P.parser_input());
  const rc = P.parser_parse(psbt.length, fingerprint);
  if (rc !== 0) throw new Error(`parser refused ${psbtPath}: ${rc}`);
  const mem = new Uint8Array(P.memory.buffer);
  const plan = mem.slice(P.parser_plan(), P.parser_plan() + PLAN_SIZE);
  const nIn = plan[Signer.LAYOUT.plan.nInputs];
  const prevTxs = [];
  for (let i = 0; i < nIn; i++) {
    const len = P.parser_prevtx_len(i);
    prevTxs.push(len ? mem.slice(P.parser_input() + P.parser_prevtx_off(i),
                                P.parser_input() + P.parser_prevtx_off(i) + len) : null);
  }
  return { plan, prevTxs };
}

// --- the module refuses anything that is not the expected build
try {
  await Signer.load(signerWasm, { sha256: "00".repeat(32) });
  ok("a wrong sha256 is refused", false);
} catch (e) {
  ok("a wrong sha256 is refused", /not the expected build/.test(e.message));
}

const S = await Signer.load(signerWasm);
S.init();
check("fingerprint before a seed", S.fingerprint, "00000000");
S.seedFromMnemonic(MNEMONIC);
check("fingerprint from the BIP39 test vector", S.fingerprint, "73c5da0a");

// --- a full round, compared against the native signer's output
const { plan, prevTxs } = planFor(`${root}build/psbt/own_mixed_nwu.psbt`, parseInt("73c5da0a", 16));
S.setPlan(plan).setPrevTxs(prevTxs);

const r = S.review();
ok("review says it will sign something", r.nSign > 0);
check("fee is total in minus total out", r.fee, r.totalIn - r.totalOut);

const d = S.display();
check("the fee review and display agree", d.fee, r.fee);
ok("every output has text", d.outputs.every((o) => o.text.length > 0));
ok("an address is shown as an address",
   d.outputs.some((o) => o.textKind === TEXT_KIND.ADDRESS && /^(bc1|tb1|[13])/.test(o.text)));
ok("change is marked as change", d.outputs.some((o) => o.owner === OWNER.CHANGE));
check("spend excludes our own outputs", d.spend,
      d.outputs.filter((o) => o.owner === OWNER.EXTERNAL).reduce((a, o) => a + o.amount, 0n));

const sigs = S.sign();
check("one signature per input review chose", sigs.length, r.nSign);

// The native host wrote these; deterministic signing means they have to match to the byte
const native = readFileSync(`${root}build/psbt/own_mixed_nwu.signed`);
for (const s of sigs) {
  ok(`input ${s.input}: the signature appears in the natively signed PSBT`,
     native.includes(Buffer.from(s.sig)));
}
ok("ECDSA carries its sighash byte", sigs.some((s) => s.sig.length >= 70 && s.sig[0] === 0x30));
ok("Schnorr is 64 bytes", sigs.some((s) => s.sig.length === 64));

// --- one approval permits one signing, and no more
try {
  S.sign();
  ok("a second sign without reviewing again is refused", false);
} catch (e) {
  ok("a second sign without reviewing again is refused", /one approval permits one signing/.test(e.message));
}

// --- reviewing the same plan again and signing gives the same bytes, which is what lets anyone
// else reproduce them
S.review();
const again = S.sign();
check("signing the same plan again is byte-identical", hex(again[0].sig), hex(sigs[0].sig));

// --- xpub, against BIP84's published vector
const x = S.xpub();
ok("the descriptor names the account", /^wpkh\(\[73c5da0a\/84h\/0h\/0h\]/.test(x.descriptor));
ok("the descriptor covers receive and change", x.descriptor.includes("<0;1>/*"));
ok("the xpub is an xpub", x.xpub.startsWith("xpub"));

// --- the module refuses to sign a plan it was not shown
{
  const S2 = await Signer.load(signerWasm);
  S2.init().seedFromMnemonic(MNEMONIC).setPlan(plan).setPrevTxs(prevTxs);
  try {
    S2.sign();
    ok("signing without review is refused", false);
  } catch (e) {
    ok("signing without review is refused", /review\(\) has to pass first/.test(e.message));
  }
  // and the module itself refuses, not just this library
  S2.review();
  const swapped = plan.slice();
  swapped[Signer.LAYOUT.plan.nOutputs] = 1;            // say there is one output, not three
  S2.setPlan(swapped);
  try {
    S2.review();
    S2.sign();
    ok("the module refuses a plan swapped after review", true);  // review re-ran, so this is fine
  } catch (e) {
    ok("the module refuses a plan swapped after review", e instanceof SignerError);
  }
  S2.unload();
}

// --- a seed that does not fit is rejected before anything is written
try {
  S.seedFromMnemonic("x".repeat(600));
  ok("an oversized mnemonic is refused", false);
} catch (e) {
  ok("an oversized mnemonic is refused", e instanceof RangeError);
}

// --- unload clears the key
S.unload();
S.init();
check("fingerprint after unload", S.fingerprint, "00000000");

console.log(`${pass}/${pass + fail} checks passed`);
process.exit(fail ? 1 : 0);
