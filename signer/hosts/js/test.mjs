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
  S2.unload();
}
// and the module itself refuses a plan changed in its memory after review, not just this library
for (const tamper of [false, true]) {
  const E = (await WebAssembly.instantiate(signerWasm, {})).instance.exports;
  const mem = () => new Uint8Array(E.memory.buffer);
  const mn = new TextEncoder().encode(MNEMONIC);
  E.signer_init(0);
  mem().set(mn, E.signer_input());
  E.signer_seed_from_mnemonic(mn.length, 0);
  mem().set(plan, E.signer_plan());
  let used = 0;
  prevTxs.forEach((raw, i) => {
    if (!raw) return E.signer_set_prevtx(i, 0, 0);
    mem().set(raw, E.signer_prevtx() + used);
    E.signer_set_prevtx(i, used, raw.length);
    used += raw.length;
  });
  check(`review passes (tampered after: ${tamper})`, E.signer_review(), 0);
  if (tamper) mem()[E.signer_plan() + 24 + 176 * 16] ^= 1;  // the first output's amount, by one satoshi
  const rc = E.signer_sign();
  if (tamper) check("a plan changed after review is refused as not reviewed", rc, -10);
  else ok("the same plan untouched signs", rc > 0);
}

// --- prevtxs that overflow the module's buffer are refused before they are written
{
  const S3 = await Signer.load(signerWasm);
  S3.init().seedFromMnemonic(new TextEncoder().encode(MNEMONIC)).setPlan(plan);
  try {
    S3.setPrevTxs([new Uint8Array(20000), new Uint8Array(20000)]);
    ok("prevtxs over the buffer are refused", false);
  } catch (e) {
    ok("prevtxs over the buffer are refused", e instanceof RangeError);
  }
  S3.setPrevTxs(prevTxs);
  check("the signer still reviews afterwards", S3.review().nSign > 0, true);
  S3.unload();
}

// --- making a new mnemonic, from entropy and from dice, against BIP39's and the dice vectors
{
  const G = await Signer.load(signerWasm);
  G.init();
  const dec = (b) => new TextDecoder().decode(b);
  const ent = Uint8Array.from(Buffer.from("9e885d952ad362caeb4efe34a8e91bd2", "hex"));
  const mn = G.mnemonicFromEntropy(ent);
  check("BIP39's 9e885d95... vector", dec(mn),
        "ozone drill grab fiber curtain grace pudding thank cruise elder eight picnic");
  ok("the entropy passed in is zeroed", ent.every((b) => b === 0));
  check("the generated words load", G.seedFromMnemonic(mn).fingerprint.length, 8);
  ok("the words returned are cleared by loading them", mn.every((b) => b === 0));
  const enc = (t) => new TextEncoder().encode(t);
  check("50 dice rolls", dec(G.mnemonicFromDice(enc("1".repeat(50)), 12)),
        "diet glad hat rural panther lawsuit act drop gallery urge where fit");
  check("99 dice rolls", dec(G.mnemonicFromDice(enc("2".repeat(45) + "5".repeat(53) + "6"))),
        "lizard broken love tired depend eyebrow excess lonely advance father various cram ignore panic feed plunge miss regret boring unique galaxy fan detail fly");
  for (const [what, call] of [["15 bytes of entropy", () => G.mnemonicFromEntropy(new Uint8Array(15))],
                              ["98 rolls for 24 words", () => G.mnemonicFromDice(enc("1".repeat(98)))],
                              ["a 7 among the rolls", () => G.mnemonicFromDice(enc("7" + "1".repeat(49)), 12)]]) {
    try {
      call();
      ok(`${what} is refused`, false);
    } catch (e) {
      ok(`${what} is refused`, /failed/.test(e.message));
    }
  }
  // the words never stay in the module's output buffer once the library has read them
  const E = (await WebAssembly.instantiate(signerWasm, {})).instance.exports;
  E.signer_init(0);
  new Uint8Array(E.memory.buffer).set(Buffer.from("9e885d952ad362caeb4efe34a8e91bd2", "hex"), E.signer_input());
  const n = E.signer_mnemonic_from_entropy(16);
  check("the raw ABI writes the words", new TextDecoder().decode(new Uint8Array(E.memory.buffer, E.signer_mnemonic_output(), n)),
        "ozone drill grab fiber curtain grace pudding thank cruise elder eight picnic");
  E.signer_unload();
  ok("unload clears the words", Buffer.from(E.memory.buffer).indexOf(Buffer.from("ozone drill")) < 0);
  G.unload();
}

// --- BIP85 children of the loaded seed, against a derivation written here. Every step is hardened, so
// it is only HMAC and addition mod n; the words come from mnemonicFromEntropy, checked against BIP39 above
{
  const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
  const big = (b) => BigInt("0x" + Buffer.from(b).toString("hex"));
  const child = (words, index) => {
    const I = createHmac("sha512", "Bitcoin seed").update(pbkdf2Sync(MNEMONIC, "mnemonic", 2048, 64, "sha512")).digest();
    let k = I.subarray(0, 32), c = I.subarray(32);
    for (const i of [83696968, 39, 0, words, index].map((v) => (v | 0x80000000) >>> 0)) {
      const J = createHmac("sha512", c).update(Buffer.concat([Buffer.alloc(1), k, Buffer.from([i >>> 24, (i >> 16) & 255, (i >> 8) & 255, i & 255])])).digest();
      k = Buffer.from(((big(J.subarray(0, 32)) + big(k)) % N).toString(16).padStart(64, "0"), "hex");
      c = J.subarray(32);
    }
    return Uint8Array.from(createHmac("sha512", "bip-entropy-from-k").update(k).digest().subarray(0, words * 4 / 3));
  };
  const B = await Signer.load(signerWasm);
  B.init().seedFromMnemonic(new TextEncoder().encode(MNEMONIC));
  const dec = (b) => new TextDecoder().decode(b);
  for (const [words, index] of [[12, 0], [12, 1], [24, 0], [18, 7]]) {
    check(`BIP85 ${words} words, index ${index}`, dec(B.bip85Mnemonic({ words, index })), dec(B.mnemonicFromEntropy(child(words, index))));
  }
  check("BIP85 12 words, index 0, by value", dec(B.bip85Mnemonic({ words: 12 })),
        "prosper short ramp prepare exchange stove life snack client enough purpose fold");
  try {
    B.bip85Mnemonic({ words: 15 });
    ok("BIP85 with 15 words is refused", false);
  } catch (e) {
    ok("BIP85 with 15 words is refused", /bip85_mnemonic failed/.test(e.message));
  }
  B.unload();
  const E = (await WebAssembly.instantiate(signerWasm, {})).instance.exports;
  const mn = new TextEncoder().encode(MNEMONIC);
  E.signer_init(0);
  new Uint8Array(E.memory.buffer).set(mn, E.signer_input());
  E.signer_seed_from_mnemonic(mn.length, 0);
  check("the raw ABI writes a child", E.signer_bip85_mnemonic(12, 0) > 0, true);
  E.signer_unload();
  ok("unload clears the child", Buffer.from(E.memory.buffer).indexOf(Buffer.from("prosper short")) < 0);
}

// --- a mnemonic whose BIP39 checksum fails, or that is not English, loads nothing
for (const [what, bad] of [["a bad checksum", "abandon ".repeat(11) + "abandon"], ["a double space", MNEMONIC.replace(" ", "  ")],
                           ["capitals", "A" + MNEMONIC.slice(1)]]) {
  const B = await Signer.load(signerWasm);
  try {
    B.init().seedFromMnemonic(new TextEncoder().encode(bad));
    ok(`a mnemonic with ${what} is refused`, false);
  } catch (e) {
    ok(`a mnemonic with ${what} is refused`, /seed_from_mnemonic failed/.test(e.message) && B.fingerprint === "00000000");
  }
}

// --- SeedQR, against the published vector 4: the words never leave the module, so the fingerprint
// has to equal the one from typing them
{
  const words = "forum undo fragile fade shy sign arrest garment culture tube off merit";
  const digits = "073318950739065415961602009907670428187212261116";
  const compact = Buffer.from("5bbd9d71a8ec7990831aff359d426545", "hex");
  const enc = (t) => new TextEncoder().encode(t);
  const Q = await Signer.load(signerWasm);
  const fp = (pass) => Q.init().seedFromMnemonic(enc(words), enc(pass)).fingerprint;
  const want = fp(""), wantPass = fp("TREZOR");
  const qr = enc(digits);
  check("SeedQR digits give the typed words' fingerprint", Q.init().seedFromSeedQR(qr).fingerprint, want);
  ok("the SeedQR payload is zeroed", qr.every((b) => b === 0));
  check("CompactSeedQR gives the same", Q.init().seedFromSeedQR(Uint8Array.from(compact)).fingerprint, want);
  check("SeedQR with a passphrase", Q.init().seedFromSeedQR(enc(digits), enc("TREZOR")).fingerprint, wantPass);
  for (const [what, bad] of [["a bad checksum", digits.slice(0, 47) + "7"], ["47 digits", digits.slice(1)],
                             ["a non-digit", "x" + digits.slice(1)]]) {
    Q.unload();
    try {
      Q.init().seedFromSeedQR(enc(bad));
      ok(`SeedQR with ${what} is refused`, false);
    } catch (e) {
      ok(`SeedQR with ${what} is refused`, /seed_from_seedqr failed/.test(e.message) && Q.fingerprint === "00000000");
    }
  }
  try {
    Q.seedFromSeedQR(new Uint8Array(400), new Uint8Array(200));
    ok("an oversized SeedQR is refused", false);
  } catch (e) {
    ok("an oversized SeedQR is refused", e instanceof RangeError);
  }
  Q.unload();
  // nothing of the words or the entropy is left once it is unloaded
  const E = (await WebAssembly.instantiate(signerWasm, {})).instance.exports;
  E.signer_init(0);
  new Uint8Array(E.memory.buffer).set(compact, E.signer_input());
  check("the raw ABI loads a CompactSeedQR", E.signer_seed_from_seedqr(compact.length, 0), 1);
  E.signer_unload();
  const m = Buffer.from(E.memory.buffer);
  ok("no words or entropy left after SeedQR", m.indexOf(Buffer.from(words)) < 0 && m.indexOf(Buffer.from("forum undo")) < 0 &&
     m.indexOf(compact.subarray(0, 8)) < 0);
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
