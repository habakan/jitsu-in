// Drives signer.wasm through the host library and checks the result against what the native side
// produced. The signatures are deterministic, so "the same" means byte-identical, not merely valid.
import { readFileSync } from "node:fs";
import { createECDH, createHash, createHmac, pbkdf2Sync } from "node:crypto";
import { Signer, OWNER, TEXT_KIND, SignerError } from "./signer.mjs";
// WASM_RUNTIME=wamr runs both modules in WAMR's interpreter instead of V8
if (process.env.WASM_RUNTIME === "wamr") globalThis.WebAssembly = (await import("../../../tools/wamr_webassembly.mjs")).default;

const MNEMONIC = "abandon ".repeat(11) + "about";
const root = new URL("../../../", import.meta.url).pathname;
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
const mnBytes = new TextEncoder().encode(MNEMONIC);
S.seedFromMnemonic(mnBytes);
ok("the mnemonic is zeroed", mnBytes.every((b) => b === 0));
check("fingerprint from the BIP39 test vector", S.fingerprint, "73c5da0a");

// --- a full round, compared against the native signer's output
const { plan, prevTxs } = planFor(`${root}parser/build/vectors/own_mixed_nwu.psbt`, parseInt("73c5da0a", 16));
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
const native = readFileSync(`${root}signer/tests/golden/own_mixed_nwu.signed`);
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
  S2.init().seedFromMnemonic(new TextEncoder().encode(MNEMONIC)).setPlan(plan).setPrevTxs(prevTxs);
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
  S.seedFromMnemonic(new Uint8Array(600).fill(0x78));
  ok("an oversized mnemonic is refused", false);
} catch (e) {
  ok("an oversized mnemonic is refused", e instanceof RangeError);
}
// and the module refuses lengths whose sum wraps around 32 bits, rather than reading past its buffer
{
  const E = (await WebAssembly.instantiate(signerWasm, {})).instance.exports;
  E.signer_init(0);
  let rc;
  try {
    rc = E.signer_seed_from_mnemonic(0xffffff00, 0x200);
  } catch (e) {
    rc = e.constructor.name;
  }
  check("mnemonic and passphrase lengths that wrap", rc, 0);
}

// --- unload clears the key
S.unload();
S.init();
check("fingerprint after unload", S.fingerprint, "00000000");

// --- after unload, no secret is left anywhere in linear memory. SHA-512 keeps its message schedule
// as native u64 words, so each secret is also searched for with every 8 bytes reversed
{
  const mn = new TextEncoder().encode(MNEMONIC);
  // every HMAC-SHA512 from the mnemonic to each key. Chain codes below m/84h/0h/0h are in the xpub
  const secrets = [["mnemonic", Buffer.from(mn)]];
  const hmac = (name, key, msg) => {
    const ipad = Buffer.alloc(128, 0x36);
    Buffer.from(key).forEach((b, i) => (ipad[i] ^= b));
    const out = createHmac("sha512", key).update(msg).digest();
    if (msg[0] === 0) secrets.push([`${name} input`, msg]);  // hardened: 0x00 || parent key
    secrets.push([`${name} inner hash`, createHash("sha512").update(ipad).update(msg).digest()],
                 [`${name} tweak`, out.subarray(0, 32)]);
    if (!name.startsWith("m/84h/0h/0h")) secrets.push([`${name} chain code`, out.subarray(32)]);
    return out;
  };
  const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
  const ser = (n) => Buffer.from(n.toString(16).padStart(64, "0"), "hex");
  const child = ([k, c], i, name) => {
    const ecdh = createECDH("secp256k1");
    ecdh.setPrivateKey(k);
    const data = i >= 0x80000000 ? Buffer.concat([Buffer.alloc(1), k]) : ecdh.getPublicKey(null, "compressed");
    const I = hmac(name, c, Buffer.concat([data, Buffer.from([i >>> 24, (i >> 16) & 255, (i >> 8) & 255, i & 255])]));
    const key = ser((BigInt("0x" + I.subarray(0, 32).toString("hex")) + BigInt("0x" + k.toString("hex"))) % N);
    secrets.push([`${name} key`, key]);
    return [key, I.subarray(32)];
  };
  const seed = pbkdf2Sync(mn, "mnemonic", 2048, 64, "sha512");
  secrets.push(["seed", seed]);
  const I = hmac("m", "Bitcoin seed", seed);
  secrets.push(["m key", I.subarray(0, 32)]);
  const H = 0x80000000;
  for (const purpose of [84, 86]) {
    let node = [I.subarray(0, 32), I.subarray(32)], path = "m";
    for (const i of [purpose + H, H, H]) node = child(node, i, (path += `/${i - H}h`));
    for (const chain of [0, 1]) {
      const c = child(node, chain, `${path}/${chain}`);
      for (let i = 0; i < 4; i++) child(c, i, `${path}/${chain}/${i}`);
    }
  }
  const swap = (b) => Buffer.concat([...Array(b.length >> 3)].map((_, i) => Buffer.from(b.subarray(8 * i, 8 * i + 8)).reverse()));

  async function survivors(round) {
    const E = (await WebAssembly.instantiate(signerWasm, {})).instance.exports;
    const mem = () => new Uint8Array(E.memory.buffer);
    E.signer_init(0);
    mem().set(mn, E.signer_input());
    E.signer_seed_from_mnemonic(mn.length, 0);
    if (round) {
      mem().set(plan, E.signer_plan());
      let used = 0;
      prevTxs.forEach((raw, i) => {
        if (!raw) return E.signer_set_prevtx(i, 0, 0);
        mem().set(raw, E.signer_prevtx() + used);
        E.signer_set_prevtx(i, used, raw.length);
        used += raw.length;
      });
      ok("the leak check signs a real plan", E.signer_review() === 0 && E.signer_sign() > 0);
      E.signer_xpub();
    }
    E.signer_unload();
    const m = Buffer.from(mem());
    return secrets.filter(([, s]) => [s, swap(s)].some((v) =>
      [...Array(v.length >> 4)].some((_, i) => m.indexOf(v.subarray(16 * i, 16 * i + 16)) >= 0)))
      .map(([name]) => name).join(", ");
  }
  check("secrets left after loading a seed and unloading", await survivors(false), "");
  check("secrets left after signing, xpub and unloading", await survivors(true), "");
}

console.log(`${pass}/${pass + fail} checks passed`);
process.exit(fail ? 1 : 0);
