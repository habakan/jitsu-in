// Drives signer.wasm through the host library and checks the result against what the native side
// produced. The signatures are deterministic, so "the same" means byte-identical, not merely valid.
import { readFileSync } from "node:fs";
import { ECDH, createECDH, createHash, createHmac, createPublicKey, pbkdf2Sync, verify } from "node:crypto";
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

// --- xpub, against BIP84's and BIP86's published vectors, and against a derivation done here
const x = S.xpub();
check("xpub() is BIP84's account 0", x.xpub,
      "xpub6CatWdiZiodmUeTDp8LT5or8nmbKNcuyvz7WyksVFkKB4RHwCD3XyuvPEbvqAQY3rAPshWcMLoP2fMFMKHPJ4ZeZXYVUhLv1VMrjPC7PW6V");
ok("the descriptor names the account", /^wpkh\(\[73c5da0a\/84h\/0h\/0h\]/.test(x.descriptor));
ok("the descriptor covers receive and change", x.descriptor.endsWith("/<0;1>/*)"));
const tr = S.xpub({ purpose: 86 });
check("BIP86's account 0", tr.xpub,
      "xpub6BgBgsespWvERF3LHQu6CnqdvfEvtMcQjYrcRzx53QJjSxarj2afYWcLteoGVky7D3UKDP9QyrLprQ3VCECoY49yfdDEHGCtMMj92pReUsQ");
check("the tr() descriptor", tr.descriptor, `tr([73c5da0a/86h/0h/0h]${tr.xpub}/<0;1>/*)`);
{
  const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
  const big = (b) => BigInt("0x" + Buffer.from(b).toString("hex"));
  const pub = (k) => { const e = createECDH("secp256k1"); e.setPrivateKey(k); return e.getPublicKey(null, "compressed"); };
  const b58 = (data) => {
    const p = Buffer.concat([data, createHash("sha256").update(createHash("sha256").update(data).digest()).digest().subarray(0, 4)]);
    let n = big(p), s = "";
    for (; n > 0n; n /= 58n) s = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"[Number(n % 58n)] + s;
    return s;
  };
  const xpubAt = (purpose, account) => {
    const I = createHmac("sha512", "Bitcoin seed").update(pbkdf2Sync(MNEMONIC, "mnemonic", 2048, 64, "sha512")).digest();
    let k = I.subarray(0, 32), c = I.subarray(32), parent;
    for (const i of [purpose, 0, account].map((v) => (v | 0x80000000) >>> 0)) {
      parent = pub(k);
      const J = createHmac("sha512", c).update(Buffer.concat([Buffer.alloc(1), k, Buffer.from([i >>> 24, (i >> 16) & 255, (i >> 8) & 255, i & 255])])).digest();
      k = Buffer.from(((big(J.subarray(0, 32)) + big(k)) % N).toString(16).padStart(64, "0"), "hex");
      c = J.subarray(32);
    }
    const fp = createHash("ripemd160").update(createHash("sha256").update(parent).digest()).digest().subarray(0, 4);
    const child = Buffer.alloc(4);
    child.writeUInt32BE((account | 0x80000000) >>> 0);
    return b58(Buffer.concat([Buffer.from("0488b21e03", "hex"), fp, child, c, pub(k)]));
  };
  check("this test's own derivation agrees with BIP84", xpubAt(84, 0), x.xpub);
  for (const [purpose, account] of [[84, 1], [86, 1], [86, 0x7fffffff]]) {
    const got = S.xpub({ purpose, account });
    check(`m/${purpose}'/0'/${account}'`, got.xpub, xpubAt(purpose, account));
    ok(`m/${purpose}'/0'/${account}' descriptor`, got.descriptor.includes(`/${purpose}h/0h/${account}h]${got.xpub}/`));
  }
}
// a refusal leaves nothing of the previous xpub to be read as its own
{
  const E = (await WebAssembly.instantiate(signerWasm, {})).instance.exports;
  const mn = new TextEncoder().encode(MNEMONIC), mem = () => new Uint8Array(E.memory.buffer);
  E.signer_init(0);
  mem().set(mn, E.signer_input());
  E.signer_seed_from_mnemonic(mn.length, 0);
  check("the raw ABI exports an xpub", E.signer_xpub(84, 0), 0);
  check("then refuses BIP44", E.signer_xpub(44, 0), 1);
  ok("and the xpub and descriptor buffers are empty", mem()[E.signer_xpub_output()] === 0 && mem()[E.signer_desc_output()] === 0);
}
// JavaScript would wrap these into a valid i32, so the library refuses them before the module sees them
for (const [what, opts] of [["2^32 + 1", { account: 2 ** 32 + 1 }], ["1.5", { account: 1.5 }], ["-1", { account: -1 }]]) {
  try {
    S.xpub(opts);
    ok(`xpub for account ${what} is refused`, false);
  } catch (e) {
    ok(`xpub for account ${what} is refused`, e instanceof RangeError);
  }
}
for (const [what, opts] of [["BIP44", { purpose: 44 }], ["a hardened account", { account: 0x80000000 }]]) {
  try {
    S.xpub(opts);
    ok(`xpub for ${what} is refused`, false);
  } catch (e) {
    ok(`xpub for ${what} is refused`, e instanceof SignerError && /FORMAT/.test(e.message));
  }
}

// --- which of our addresses an address is, against BIP84's and BIP86's vectors
{
  const found = (a, o) => JSON.stringify(S.findAddress(a, o));
  check("BIP84 0/1", found("bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g"), '{"chain":0,"index":1}');
  check("BIP84 change 1/0", found("bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el"), '{"chain":1,"index":0}');
  check("BIP86 0/1", found("bc1p4qhjn9zdvkux4e44uhx8tc55attvtyu358kutcqkudyccelu0was9fqzwh"), '{"chain":0,"index":1}');
  check("BIP49 change 1/0, in base58", found("34K56kSjgUCUSD8GTtuF7c9Zzwokbs6uZ7"), '{"chain":1,"index":0}');
  check("a BIP21 URI in upper case, as a QR carries it",
        found("bitcoin:BC1QNJG0JD8228AQ7EGYZACY8CYS3KNF9XVRERKF9G?amount=0.1"), '{"chain":0,"index":1}');
  check("not ours", found("bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3"), "null");
  check("beyond count", found("bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g", { count: 1 }), "null");
  check("another account", found("bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g", { account: 1, count: 20 }), "null");
  for (const [what, a, err, opts] of [["a testnet address", "tb1q6rz28mcfaxtmd6v789l9rrlrusdprr9pqcpvkl", SignerError],
                                ["base58", "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2", SignerError],
                                ["an oversized string", "bc1q" + "q".repeat(1100), RangeError],
                                ["a NUL inside", "bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g\0junk", SignerError],
                                ["a count JavaScript would wrap", "bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g", RangeError, { count: 2 ** 32 + 5 }]]) {
    try {
      S.findAddress(a, opts);
      ok(`findAddress refuses ${what}`, false);
    } catch (e) {
      ok(`findAddress refuses ${what}`, e instanceof err);
    }
  }
}

// --- BIP49: P2SH-P2WPKH inputs and change, beside P2WPKH (Core signs the same PSBTs: check-core-diff)
{
  const P2 = await Signer.load(signerWasm);
  P2.init().seedFromMnemonic(new TextEncoder().encode(MNEMONIC));
  for (const name of ["own_p2sh_p2wpkh_1in", "own_mixed_p2sh_nwu"]) {
    const v = planFor(`${root}parser/build/vectors/${name}.psbt`, parseInt("73c5da0a", 16));
    const rv = P2.setPlan(v.plan).setPrevTxs(v.prevTxs).review();
    check(`${name}: every input of ours is signed`, rv.nSign, name.includes("mixed") ? 2 : 1);
    const dv = P2.display();
    ok(`${name}: the change is a P2SH address, and marked as change`,
       dv.outputs.some((o) => o.owner === OWNER.CHANGE && o.text.startsWith("3")));
    const sv = P2.sign();
    ok(`${name}: ECDSA with a compressed key for each`, sv.every((s) => s.sig[0] === 0x30 && (s.pubkey[0] === 2 || s.pubkey[0] === 3)));
  }
  // a P2SH multisig we cosign is left alone, not a reason to refuse the input of ours beside it
  {
    const m = planFor(`${root}parser/build/vectors/own_with_p2sh_multisig_input.psbt`, parseInt("73c5da0a", 16));
    const rm = P2.setPlan(m.plan).setPrevTxs(m.prevTxs).review();
    ok("beside a P2SH multisig we cosign, our P2WPKH input alone is signed", rm.nSign === 1 && rm.willSign[0] && !rm.willSign[1]);
    check("and signed", P2.sign().length, 1);
  }
  // a P2SH that is not P2SH(P2WPKH(our key)), whatever the PSBT says, is refused
  const v = planFor(`${root}parser/build/vectors/own_p2sh_p2wpkh_1in.psbt`, parseInt("73c5da0a", 16));
  v.plan[24 + 52 + 10] ^= 1;  // a byte of the first input's script hash
  try {
    P2.setPlan(v.plan).setPrevTxs(v.prevTxs).review();
    ok("a P2SH hiding another script is refused", false);
  } catch (e) {
    ok("a P2SH hiding another script is refused", /NOT_OURS/.test(e.message));
  }
  const x49 = P2.xpub({ purpose: 49 });
  check("the BIP49 descriptor", x49.descriptor, `sh(wpkh([73c5da0a/49h/0h/0h]${x49.xpub}/<0;1>/*))`);
  P2.unload();
}

// --- BIP48 P2WSH multisig: signed only once the witness script is a multisig of at most three keys, hashes to
// the input's script and holds our key. Core signs the same PSBTs byte for byte: check-core-diff
{
  const W = await Signer.load(signerWasm);
  W.init().seedFromMnemonic(new TextEncoder().encode(MNEMONIC));
  const FP = parseInt("73c5da0a", 16);
  const IN = (i) => 24 + 176 * i, WS = (i) => 5016 + 106 * i;
  const sha = (b) => createHash("sha256").update(b).digest();
  const refused = (what, plan, prevTxs, re) => {
    try {
      W.setPlan(plan).setPrevTxs(prevTxs).review();
      ok(what, false);
    } catch (e) {
      ok(what, re.test(e.message));
    }
  };
  for (const [name, n] of [["own_p2wsh_2of3_1in", 1], ["own_p2wsh_2of3_cosigned", 1], ["own_mixed_p2wsh_nwu", 2]]) {
    const v = planFor(`${root}parser/build/vectors/${name}.psbt`, FP);
    check(`${name}: every input of ours is signed`, W.setPlan(v.plan).setPrevTxs(v.prevTxs).review().nSign, n);
    if (!name.includes("mixed")) {
      ok(`${name}: the P2WSH change is shown as an external address`,
         W.display().outputs.every((o) => o.owner === OWNER.EXTERNAL && o.text.startsWith("bc1q")) &&
         W.display().outputs.some((o) => o.text.length === 62));
    }
    const sv = W.sign();
    ok(`${name}: ECDSA with a compressed key for each`,
       sv.length === n && sv.every((s) => s.sig[0] === 0x30 && s.sig.at(-1) === 1 && (s.pubkey[0] === 2 || s.pubkey[0] === 3)));
  }
  {
    const m = planFor(`${root}parser/build/vectors/own_with_p2wsh_2of4_input.psbt`, FP);
    const rm = W.setPlan(m.plan).setPrevTxs(m.prevTxs).review();
    ok("a four-key witness script is not ours to sign; the P2WPKH beside it is", rm.nSign === 1 && rm.willSign[0] && !rm.willSign[1]);
  }
  const base = planFor(`${root}parser/build/vectors/own_p2wsh_2of3_1in.psbt`, FP);
  const fresh = () => Uint8Array.from(base.plan);
  // a witness script and an input script that agree with each other, but not with this test's intent
  const rehash = (plan) => plan.set(sha(plan.subarray(WS(0) + 1, WS(0) + 1 + plan[WS(0)])), IN(0) + 49 + 2);
  {
    const plan = fresh();
    for (let k = 0; k < 3; k++) plan[WS(0) + 1 + 1 + 34 * k + 5] ^= 1;  // a byte of every key, ours among them
    refused("a witness script that does not hash to the input's script is refused", plan, base.prevTxs, /NOT_OURS/);
    rehash(plan);
    refused("a multisig without our key is refused", plan, base.prevTxs, /NOT_OURS/);
  }
  for (const [what, mutate] of [
    ["OP_CHECKMULTISIGVERIFY", (pl) => { pl[WS(0) + pl[WS(0)]] = 0xaf; }],
    ["a threshold above the key count", (pl) => { pl[WS(0) + 1] = 0x54; }],
    ["a key count that is not the number of keys", (pl) => { pl[WS(0) + pl[WS(0)] - 1] = 0x52; }],
    ["an uncompressed key prefix", (pl) => { pl[WS(0) + 1 + 2] = 0x04; }],
  ]) {
    const plan = fresh();
    mutate(plan);
    rehash(plan);
    refused(`a witness script with ${what} is refused`, plan, base.prevTxs, /SCRIPT/);
  }
  {
    const plan = fresh();
    plan.fill(0, WS(0), WS(0) + 106);
    refused("a P2WSH input to be signed without its witness script is refused", plan, base.prevTxs, /SCRIPT/);
  }
  {
    const plan = fresh();
    plan[IN(0) + 172] = 0x03;
    refused("a P2WSH input with SIGHASH_SINGLE is refused", plan, base.prevTxs, /SIGHASH/);
  }
  {
    const plan = fresh();
    plan[WS(0)] -= 1;  // 2-of-3 fills all 105 bytes, so shortening it leaves OP_CHECKMULTISIG past the end
    refused("a byte past the witness script's length is refused", plan, base.prevTxs, /FORMAT/);
    const p2 = fresh();
    p2.set(p2.subarray(WS(0), WS(0) + 106), WS(1));
    refused("a witness script for an input that is not there is refused", p2, base.prevTxs, /FORMAT/);
    const p3 = planFor(`${root}parser/build/vectors/own_p2wpkh_1in.psbt`, FP);
    p3.plan.set(base.plan.subarray(WS(0), WS(0) + 106), WS(0));
    refused("a witness script beside a P2WPKH input is refused", p3.plan, p3.prevTxs, /FORMAT/);
  }
  W.unload();
}

// --- a registered multisig: its change is change, an input of another wallet is refused, and the public keys go
// out as CBOR that urtypes (Krux, Specter DIY) reads back as these descriptors
{
  const W = await Signer.load(signerWasm);
  W.init().seedFromMnemonic(new TextEncoder().encode(MNEMONIC));
  const FP = parseInt("73c5da0a", 16);
  const key = (fp, xpub) => `[${fp}/48h/0h/0h/2h]${xpub}/<0;1>/*`;
  const K0 = key("73c5da0a", "xpub6DkFAXWQ2dHxq2vatrt9qyA3bXYU4ToWQwCHbf5XB2mSTexcHZCeKS1VZYcPoBd5X8yVcbXFHJR9R8UCVpt82VX1VhR28mCyxUFL4r6KFrf");
  const K1 = key("3f635a63", "xpub6FHZCoNb3tg3o1GAJQxSwgFNF8mLRtTk2GgkF7n5rwzoxBhUEdFWa8cyZRHqytAzKZWsKz8627cQEMCCfR5GDSv6yXegqirpgDUX41Pxybr");
  const K2 = key("b8688df1", "xpub6FQya7zGhR92kacYsNnjreouvnHJMpXYsUXnW6NJJAJRCKsa26TzDy4LdnGhEurr3d6y1J8PJ7EEMKQp74XTqYvmGJNogYXSKDszYHtF8mX");
  const K3 = key("28645006", "xpub6DnEBNkSJKBYQmsbhS1sP9cNdtU5c9PLFGCjTJmxicxc13WB8zNNGQazabQpyFAGW5bV9tMko4uBxDxjUKL6dSAcx1tEbgEHtgSqyRsekh6");
  check("the CBOR of the account's keys", Buffer.from(W.accountCbor()).toString("hex"), "a2011a73c5da0a0284d90134d90190d90194d9012fa403582102f1f347891b20f7568eae3ec9869fbfb67bcab6f358326f10ecc42356bd55939d0458206eaae365ae0e0a0aab84325cfe7cd76c3b909035f889e7d3f1b847a9a0797ecb06d90130a201861831f500f500f5021a73c5da0a081a3d05ff75d90134d90194d9012fa403582102707a62fdacc26ea9b63b1c197906f56ee0180d0bcf1966e1a2da34f5f3a09a9b0458204a53a0ab21b9dc95869c4e92a161194e03c0ef3ff5014ac692f433c4765490fc06d90130a201861854f500f500f5021a73c5da0a081a7ef32bdbd90134d90199d9012fa403582103418278a2885c8bb98148158d1474634097a179c642f23cf1cc04da629ac6f0fb045820c61a8f27e98182314d2444da3e600eb5836ec8ad183c86c311f95df8082b18aa06d90130a201861856f500f500f5021a73c5da0a081a035270dad90134d90191d9019ad9012fa4035821021a3bf5fbf737d0f36993fd46dc4913093beb532d654fe0dfd98bd27585dc9f29045820bba0c7ca160a870efeb940ab90d0f4284fea1b5e0d2117677e823fc37e2d576306d90130a201881830f500f500f502f5021a73c5da0a081a1cf29716");
  const ms = W.multisigLoad(`wsh(sortedmulti(2,${K0},${K1},${K2}))`);
  ok("a 2 of 3 with ours first and Core's receive address",
     ms.threshold === 2 && ms.ours === 0 && ms.fingerprints.join() === "73c5da0a,3f635a63,b8688df1" &&
     ms.receive === "bc1qea2gkgeszr7wm66x2ejkgdxm9nhg9462sszn75zmkhazev0t02vs70kkll" && ms.descriptor.endsWith("#d9p6ar8k"));
  check("the CBOR of the wallet", Buffer.from(W.multisigCbor()).toString("hex"), "d90191d90197a201020283d9012fa4035821021a3bf5fbf737d0f36993fd46dc4913093beb532d654fe0dfd98bd27585dc9f29045820bba0c7ca160a870efeb940ab90d0f4284fea1b5e0d2117677e823fc37e2d576306d90130a201881830f500f500f502f5021a73c5da0a081a1cf29716d9012fa4035821030e435aae36818255097925c6d2cedae9867961a5ddcc2e80bd6a0d00687286c304582038d3b00251a463b0ffe9b595d21752664c5a231c89fc2fb4f695ab90cdcd77dd06d90130a201881830f500f500f502f5021a3f635a63081aee71f8c5d9012fa40358210339710356a496726c84692621b2b6e3645dd35bc0026c587f16411897990a1e1f045820a732876f758546f2e3aa40a0ba12c5ea24ee18f9086e854e573bea1e219d172f06d90130a201881830f500f500f502f5021ab8688df1081affd9c519");
  for (const name of ["own_p2wsh_2of3_1in", "own_p2wsh_2of3_cosigned"]) {
    const v = planFor(`${root}parser/build/vectors/${name}.psbt`, FP);
    const r = W.setPlan(v.plan).setPrevTxs(v.prevTxs).review();
    ok(`${name}: with the wallet registered, the P2WSH output is change`, r.owner[0] === OWNER.EXTERNAL && r.owner[1] === OWNER.CHANGE);
    const d = W.display();
    check(`${name}: and only the payment is spent`, d.spend, 60000n);
    check(`${name}: still signs`, W.sign().length, 1);
  }
  {
    const v = planFor(`${root}parser/build/vectors/own_mixed_p2wsh_nwu.psbt`, FP);
    const r = W.setPlan(v.plan).setPrevTxs(v.prevTxs).review();
    ok("a P2WSH input beside P2WPKH is signed with the wallet registered", r.nSign === 2);
  }
  W.multisigLoad(`wsh(sortedmulti(2,${K0},${K1},${K3}))`);
  {
    const v = planFor(`${root}parser/build/vectors/own_p2wsh_2of3_1in.psbt`, FP);
    try {
      W.setPlan(v.plan).setPrevTxs(v.prevTxs).review();
      ok("an input of another wallet holding our key is refused", false);
    } catch (e) {
      ok("an input of another wallet holding our key is refused", /WALLET/.test(e.message));
    }
  }
  W.multisigUnload();
  {
    const v = planFor(`${root}parser/build/vectors/own_p2wsh_2of3_1in.psbt`, FP);
    const r = W.setPlan(v.plan).setPrevTxs(v.prevTxs).review();
    ok("unregistered again, the input signs and the change is external", r.nSign === 1 && r.owner[1] === OWNER.EXTERNAL);
  }
  try {
    W.multisigLoad(`wsh(sortedmulti(2,${K3},${K1}))`);
    ok("a wallet without our key is refused", false);
  } catch (e) {
    ok("a wallet without our key is refused", /multisigLoad: WALLET/.test(e.message));
  }
  W.unload();
}

// --- BIP137 message signing, verified with Node's own ECDSA against BIP84's published m/84'/0'/0'/0/0 key
{
  const M = await Signer.load(signerWasm);
  M.init().seedFromMnemonic(new TextEncoder().encode(MNEMONIC));
  const enc = (t) => new TextEncoder().encode(t);
  const pub = ECDH.convertKey("0330d54fd0dd420a6e5f8d3624f5f3482cae350f79d5f0753bf5beef9c2d91af3c", "secp256k1", "hex", undefined, "uncompressed");
  const key = createPublicKey({ key: Buffer.concat([Buffer.from("3056301006072a8648ce3d020106052b8104000a034200", "hex"), pub]), format: "der", type: "spki" });
  const once = (m) => createHash("sha256").update(Buffer.concat([Buffer.from("\x18Bitcoin Signed Message:\n", "latin1"), Buffer.from([m.length]), m])).digest();
  for (const text of ["This is an example of a signed message.", "", "caf\u00e9\nnext line"]) {
    const m = enc(text);
    const shown = M.messageReview(m);
    check(`"${text}": the address is BIP84's first`, shown.address, "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu");
    check(`"${text}": shown ${/^[\x20-\x7e]*$/.test(text) ? "as it is" : "in hex"}`, shown.text,
          /^[\x20-\x7e]*$/.test(text) ? text : Buffer.from(m).toString("hex"));
    const sig = M.messageSign();
    ok(`"${text}": a P2WPKH header`, sig[0] >= 39 && sig[0] <= 42);
    ok(`"${text}": the signature verifies under the published key`,
       verify("sha256", once(m), { key, dsaEncoding: "ieee-p1363" }, sig.subarray(1)));
  }
  try {
    M.messageSign();
    ok("one review permits one message signature", false);
  } catch (e) {
    ok("one review permits one message signature", /messageSign: NOT_REVIEWED/.test(e.message));
  }
  for (const [what, opts] of [["P2TR", { purpose: 86 }], ["chain 2", { chain: 2 }], ["index 100000", { index: 100000 }]]) {
    try {
      M.messageReview(enc("x"), opts);
      ok(`a message review for ${what} is refused`, false);
    } catch (e) {
      ok(`a message review for ${what} is refused`, /messageReview: FORMAT/.test(e.message));
    }
  }
  M.unload();
  // the module itself refuses a message changed in its memory after the review
  const E = (await WebAssembly.instantiate(signerWasm, {})).instance.exports;
  const mn = enc(MNEMONIC), m = enc("pay the bearer 1 BTC");
  const mem = () => new Uint8Array(E.memory.buffer);
  E.signer_init(0);
  mem().set(mn, E.signer_input());
  E.signer_seed_from_mnemonic(mn.length, 0);
  mem().set(m, E.signer_input());
  check("the raw ABI reviews a message", E.signer_message_review(m.length, 84, 0, 0, 0), 0);
  // every copy: the one shown is in the display buffer, the one signed is the core's own
  for (let at = 0; (at = Buffer.from(E.memory.buffer).indexOf(Buffer.from("pay the bearer 1 BTC"), at)) >= 0;) {
    mem()[at + 15] = "9".charCodeAt(0);
  }
  check("a message changed after review is refused", E.signer_message_sign(), 10);
  // a review does not survive a re-init, which may change the network, nor does a signature an unload
  mem().set(m, E.signer_input());
  check("a fresh review", E.signer_message_review(m.length, 84, 0, 0, 0), 0);
  E.signer_init(1);
  check("is forgotten by init", E.signer_message_sign(), 10);
  E.signer_init(0);
  mem().set(m, E.signer_input());
  E.signer_message_review(m.length, 84, 0, 0, 0);
  check("signs once reviewed again", E.signer_message_sign(), 0);
  E.signer_unload();
  ok("and unload clears the signature", new Uint8Array(E.memory.buffer, E.signer_message_sig(), 65).every((b) => b === 0));
}

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
  try {
    G.mnemonicFromDice(/** @type {any} */ ("1".repeat(99)));
    ok("dice rolls as a string are refused for what they are", false);
  } catch (e) {
    ok("dice rolls as a string are refused for what they are", e instanceof TypeError && /Uint8Array/.test(e.message));
  }
  const kept = enc("1".repeat(99));
  try {
    G.mnemonicFromDice(kept, /** @type {any} */ (18));
    ok("18 words from dice is refused", false);
  } catch (e) {
    ok("18 words from dice is refused, and the rolls are kept to retry", e instanceof RangeError && kept[0] === 0x31);
  }
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
  // a longer mnemonic made before leaves nothing after a shorter one's NUL
  new Uint8Array(E.memory.buffer).set(new Uint8Array(32).fill(7), E.signer_input());
  E.signer_mnemonic_from_entropy(32);
  new Uint8Array(E.memory.buffer).set(Buffer.from("9e885d952ad362caeb4efe34a8e91bd2", "hex"), E.signer_input());
  const short = E.signer_mnemonic_from_entropy(16);
  ok("a shorter mnemonic leaves nothing of the longer one after it",
     new Uint8Array(E.memory.buffer, E.signer_mnemonic_output() + short, 256 - short).every((b) => b === 0));
  E.signer_unload();
  ok("unload clears the words", Buffer.from(E.memory.buffer).indexOf(Buffer.from("ozone drill")) < 0);
  G.unload();
}

// --- making a SeedQR from the words, against the published vector 4, and reading it back
{
  const Q = await Signer.load(signerWasm);
  Q.init();
  const enc = (t) => new TextEncoder().encode(t);
  const words = enc("forum undo fragile fade shy sign arrest garment culture tube off merit");
  const digits = Q.seedQRFromMnemonic(words);
  check("Standard SeedQR digits", new TextDecoder().decode(digits), "073318950739065415961602009907670428187212261116");
  ok("the words passed in are zeroed", words.every((b) => b === 0));
  const compact = Q.seedQRFromMnemonic(enc("forum undo fragile fade shy sign arrest garment culture tube off merit"), { compact: true });
  check("CompactSeedQR bytes", hex(compact), "5bbd9d71a8ec7990831aff359d426545");
  const want = Q.seedFromMnemonic(enc("forum undo fragile fade shy sign arrest garment culture tube off merit")).fingerprint;
  check("the CompactSeedQR made here loads the same key", Q.init().seedFromSeedQR(compact).fingerprint, want);
  try {
    Q.seedQRFromMnemonic(enc("abandon ".repeat(11) + "abandon"));
    ok("a SeedQR of a bad mnemonic is refused", false);
  } catch (e) {
    ok("a SeedQR of a bad mnemonic is refused", /seedqr_from_mnemonic failed/.test(e.message));
  }
  Q.unload();
  const E = (await WebAssembly.instantiate(signerWasm, {})).instance.exports;
  E.signer_init(0);
  new Uint8Array(E.memory.buffer).set(enc("forum undo fragile fade shy sign arrest garment culture tube off merit"), E.signer_input());
  check("the raw ABI writes the digits", E.signer_seedqr_from_mnemonic(70, 0), 48);
  new Uint8Array(E.memory.buffer).set(enc("forum undo fragile fade shy sign arrest garment culture tube off merit"), E.signer_input());
  check("then the compact bytes", E.signer_seedqr_from_mnemonic(70, 1), 16);
  ok("which leave nothing of the digits after them", new Uint8Array(E.memory.buffer, E.signer_seedqr_output() + 16, 80).every((b) => b === 0));
  E.signer_unload();
  ok("unload clears the SeedQR", Buffer.from(E.memory.buffer).indexOf(Buffer.from("073318950739065415961602")) < 0);
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
  // JavaScript would wrap these to index 0 or 1 at the i32 boundary, and the user would write down another child
  for (const [what, opts] of [["15 words", { words: 15 }], ["index NaN", { index: NaN }], ["index 2^32", { index: 2 ** 32 }], ["index 1.7", { index: 1.7 }]]) {
    try {
      B.bip85Mnemonic(/** @type {any} */ (opts));
      ok(`BIP85 with ${what} is refused`, false);
    } catch (e) {
      ok(`BIP85 with ${what} is refused`, e instanceof RangeError);
    }
  }
  B.unload();
  try {
    B.init().bip85Mnemonic();
    ok("BIP85 with no seed says so", false);
  } catch (e) {
    ok("BIP85 with no seed says so", /no seed is loaded/.test(e.message));
  }
  const E = (await WebAssembly.instantiate(signerWasm, {})).instance.exports;
  const mn = new TextEncoder().encode(MNEMONIC);
  E.signer_init(0);
  new Uint8Array(E.memory.buffer).set(mn, E.signer_input());
  E.signer_seed_from_mnemonic(mn.length, 0);
  check("the raw ABI writes a child", E.signer_bip85_mnemonic(12, 0) > 0, true);
  E.signer_unload();
  ok("unload clears the child", Buffer.from(E.memory.buffer).indexOf(Buffer.from("prosper short")) < 0);
}

// --- what a keyboard adds loads the same wallet; a mnemonic whose BIP39 checksum fails, or a word
// that is not English BIP39, loads nothing
for (const typed of [" " + MNEMONIC.replace(" ", "  ").toUpperCase() + "\n", "Abandon" + MNEMONIC.slice(7)]) {
  const B = await Signer.load(signerWasm);
  check(`${JSON.stringify(typed.slice(0, 18))}... loads the same wallet`,
        B.init().seedFromMnemonic(new TextEncoder().encode(typed)).fingerprint, "73c5da0a");
}
for (const [what, bad] of [["a bad checksum", "abandon ".repeat(11) + "abandon"], ["a word not in the list", MNEMONIC.replace("about", "abaut")]]) {
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
    Q.seedFromSeedQR(new Uint8Array(800), new Uint8Array(300));
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
  S.seedFromMnemonic(new Uint8Array(1100).fill(0x78));
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
  // every HMAC-SHA512 from the mnemonic to each key. Chain codes below m/84h/0h/0h and m/86h/0h/0h are in the xpubs
  const secrets = [["mnemonic", Buffer.from(mn)]];
  const hmac = (name, key, msg) => {
    const ipad = Buffer.alloc(128, 0x36);
    Buffer.from(key).forEach((b, i) => (ipad[i] ^= b));
    const out = createHmac("sha512", key).update(msg).digest();
    if (msg[0] === 0) secrets.push([`${name} input`, msg]);  // hardened: 0x00 || parent key
    secrets.push([`${name} inner hash`, createHash("sha512").update(ipad).update(msg).digest()],
                 [`${name} tweak`, out.subarray(0, 32)]);
    if (!/^m\/8[46]h\/0h\/0h/.test(name)) secrets.push([`${name} chain code`, out.subarray(32)]);
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
      ok("the leak check exports both xpubs", E.signer_xpub(84, 0) === 0 && E.signer_xpub(86, 0) === 0);
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
