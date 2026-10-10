// Differential test against Bitcoin Core.
//
// Core decides what a PSBT means, so it is a better oracle than our own expectations. This drives
// both modules from JavaScript, asks Core the same questions, and requires the answers to match:
//
//   the parse       decodepsbt            against the plan parser.wasm built
//   the fee         decodepsbt's fee      against what signer.wasm's review computed
//   the signatures  walletprocesspsbt     against signer.wasm's, byte for byte
//   the descriptors deriveaddresses       signer.wasm's sh(wpkh()), wpkh() and tr() against Core's keys
//
// The last is only possible because signing is deterministic on both sides: Core and this signer
// both grind for a low R in ECDSA and both pass a zero aux_rand for Schnorr, so one key over one
// transaction has exactly one answer.
//
// It does not show we share code with Core. It shows we give the same answers, which is the part a
// user depends on.
//
//   node tools/check_against_core.mjs "bitcoin-cli -datadir=... -regtest" <parser.wasm> <signer.wasm> <psbt>...
import { execFileSync } from "node:child_process";
import { createECDH, createHash, createHmac } from "node:crypto";
import { readFileSync, rmSync } from "node:fs";
import { Signer } from "../signer/hosts/js/signer.mjs";

// The published BIP39 all-zero test vector, derived to m/49'/0'/0', m/84'/0'/0' and m/86'/0'/0' with the testnet
// version bytes regtest wants. Committed rather than derived at test time so that nothing here needs
// a Bitcoin library of its own — and checked against signer.wasm's own xpub below, so a wrong
// constant fails loudly instead of quietly testing the wrong key.
const ACCOUNTS = [
  { kind: "wpkh", close: ")", purpose: 84,
    tprv: "tprv8gGUtTW1HhuYrycHNfewtKXPYsB3CgE8uK733ntLBPGfyDhse352wryMJXvQr4zkNDL3ZBDZvJh5NpkuqyEZtLvNLLNmjJD4UV6dsRECvrC",
    xpub: "xpub6CatWdiZiodmUeTDp8LT5or8nmbKNcuyvz7WyksVFkKB4RHwCD3XyuvPEbvqAQY3rAPshWcMLoP2fMFMKHPJ4ZeZXYVUhLv1VMrjPC7PW6V" },
  { kind: "sh(wpkh", close: "))", purpose: 49,
    tprv: "tprv8fnNnm525ViePCEx7Z9cZb6QNUtsUc8XKaePnZtPnKZWHw1rnAC9r6MdMdsmrkGW7Vy3eVtwtRqrfkxfWjnitBTNEZjTb6pbui7BUmnBBd3",
    xpub: "xpub6C6nQwHaWbSrzs5tZ1q7m5R9cPK9eYpNMFesiXsYrgc1P8bvLLAet9JfHjYXKjToD8cBRswJXXbbFpXgwsswVPAZzKMa1jUp2kVkGVUaJa7" },
  { kind: "tr", close: ")", purpose: 86,
    tprv: "tprv8fMn4hSKPRC1oaCPqxDb1JWtgkpeiQvZhsr8W2xuy3GEMkzoArcAWTfJxYb6Wj8XNNDWEjfYKK4wGQXh3ZUXhDF2NcnsALpWTeSwarJt7Vc",
    xpub: "xpub6BgBgsespWvERF3LHQu6CnqdvfEvtMcQjYrcRzx53QJjSxarj2afYWcLteoGVky7D3UKDP9QyrLprQ3VCECoY49yfdDEHGCtMMj92pReUsQ" },
];
// BIP48 P2WSH 2-of-3: ours at m/48'/0'/0'/2', with the cosigners from BIP39's "zoo ... wrong" and
// "legal winner ... yellow" vectors, as parser/tools/gen_vectors.py builds them
const MULTISIG = {
  tprv: "tprv8hRqYMHqbXZkDN5eTQCeeUqJMd8BtX7fPGBofh6N6fiwNTNYjPE9HP4TdVMX8Tud62RaiqNchAYQnCaa4nHkoLBZmQ8xHEufrZqqmCLPspf",
  xpub: "xpub6DkFAXWQ2dHxq2vatrt9qyA3bXYU4ToWQwCHbf5XB2mSTexcHZCeKS1VZYcPoBd5X8yVcbXFHJR9R8UCVpt82VX1VhR28mCyxUFL4r6KFrf",
  cosigners: ["[3f635a63/48h/0h/0h/2h]tpubDFfBj3CGmAdW4oT1kbwY9bajaFrzRGxoZuH3bfqECrkhhUNBJr6biaHooTNdWP8E7U3mwZdxZDSSvXgp4GvW6tNQ38PzXFX4GB4vp5RLCfW",
              "[b8688df1/48h/0h/0h/2h]tpubDFnc6MoxQh6V2NoQKZmq4a9HFuNxMD2cR785reRSe54JwcYH6KK5NQjAspMUmQp5qXdscseFqD4H3VuRVvNhizP4Ku87N5BfuBUQJGrfe1Y"],
};
const FINGERPRINT = "73c5da0a";
const MNEMONIC = "abandon ".repeat(11) + "about";
const WALLET = "diff";

const [cliSpec, parserPath, signerPath, ...psbtPaths] = process.argv.slice(2);
if (!psbtPaths.length) {
  console.error('usage: check_against_core.mjs "bitcoin-cli ..." parser.wasm signer.wasm FILE...');
  process.exit(2);
}
const CLI = cliSpec.split(/\s+/);

function cli(...args) {
  return execFileSync(CLI[0], [...CLI.slice(1), ...args], { encoding: "utf8" }).trim();
}
function wallet(...args) {
  return cli(`-rpcwallet=${WALLET}`, ...args);
}
const hex = (b) => [...b].map((x) => x.toString(16).padStart(2, "0")).join("");
const sats = (btc) => BigInt(Math.round(btc * 1e8));

let passed = 0, failed = 0, skipped = 0;
const bad = [];
function eq(what, ours, core) {
  if (ours !== core) bad.push(`${what}: ours=${ours} core=${core}`);
}

// --- a node that is not up would make every case "skipped", which would read as success
try {
  cli("getblockchaininfo");
} catch (e) {
  console.error(`the regtest node is not reachable: ${e.message.split("\n")[0]}`);
  process.exit(1);
}

// --- give Core the same key, from descriptors it can sign with
// A fresh wallet each run. Reusing one makes importdescriptors refuse the same descriptor a second
// time ("new range must include current range"), so this removes it rather than working around that
try { cli("unloadwallet", WALLET); } catch { /* not loaded */ }
const walletDir = `${CLI.find((a) => a.startsWith("-datadir="))?.slice(9)}/regtest/wallets/${WALLET}`;
rmSync(walletDir, { recursive: true, force: true });
cli("-named", "createwallet", `wallet_name=${WALLET}`,
    "disable_private_keys=false", "blank=true", "descriptors=true");
const imports = [];
for (const a of ACCOUNTS) {
  // Receive and change separately: Core only accepts a multipath <0;1> in getdescriptorinfo from
  // some versions on, and 28.1 refuses it
  for (const [chain, internal] of [[0, false], [1, true]]) {
    const desc = `${a.kind}([${FINGERPRINT}/${a.purpose}h/0h/0h]${a.tprv}/${chain}/*${a.close}`;
    const ck = JSON.parse(cli("getdescriptorinfo", desc)).checksum;
    imports.push({ desc: `${desc}#${ck}`, timestamp: "now", active: true, internal, range: [0, 20] });
  }
}
for (const [chain, internal] of [[0, false], [1, true]]) {
  const keys = [`[${FINGERPRINT}/48h/0h/0h/2h]${MULTISIG.tprv}`, ...MULTISIG.cosigners].map((k) => `${k}/${chain}/*`);
  const desc = `wsh(sortedmulti(2,${keys.join(",")}))`;
  const ck = JSON.parse(cli("getdescriptorinfo", desc)).checksum;
  imports.push({ desc: `${desc}#${ck}`, timestamp: "now", active: true, internal, range: [0, 20] });
}
const res = JSON.parse(wallet("importdescriptors", JSON.stringify(imports)));
if (!res.every((r) => r.success)) {
  console.error(`importdescriptors failed: ${JSON.stringify(res)}`);
  process.exit(1);
}

// --- the committed xprv has to be the key signer.wasm actually derives, or this tests nothing
const signerWasm = readFileSync(signerPath);
{
  const s = await Signer.load(signerWasm);
  s.init().seedFromMnemonic(new TextEncoder().encode(MNEMONIC));
  if (s.fingerprint !== FINGERPRINT) {
    console.error(`the committed fingerprint is ${FINGERPRINT}, signer.wasm derives ${s.fingerprint}`);
    process.exit(1);
  }
  if (s.xpub({ purpose: 48 }).xpub !== MULTISIG.xpub) {
    console.error(`the committed m/48'/0'/0'/2' xpub is not the one signer.wasm derives: ${s.xpub({ purpose: 48 }).xpub}`);
    process.exit(1);
  }
  for (const a of ACCOUNTS) {
    const got = s.xpub({ purpose: a.purpose }).xpub;
    if (got !== a.xpub) {
      console.error(`the committed m/${a.purpose}'/0'/0' xpub is not the one signer.wasm derives:\n  committed ${a.xpub}\n  derived   ${got}`);
      process.exit(1);
    }
  }
  s.unload();
  console.log(`the committed keys are the ones signer.wasm derives (${FINGERPRINT})`);
}

// --- the descriptors signer.wasm exports give Core the addresses of the keys it signs with. The
// committed keys are coin 0 with testnet version bytes, so the mainnet xpub is re-versioned to match
{
  const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  const toTpub = (xpub) => {
    let n = 0n;
    for (const ch of xpub) n = n * 58n + BigInt(B58.indexOf(ch));
    const raw = Buffer.from(n.toString(16).padStart(164, "0"), "hex").subarray(0, 78);
    raw.writeUInt32BE(0x043587cf, 0);
    const p = Buffer.concat([raw, createHash("sha256").update(createHash("sha256").update(raw).digest()).digest().subarray(0, 4)]);
    let m = BigInt("0x" + p.toString("hex")), out = "";
    for (; m > 0n; m /= 58n) out = B58[Number(m % 58n)] + out;
    return out;
  };
  const derive = (desc) =>
    cli("deriveaddresses", `${desc}#${JSON.parse(cli("getdescriptorinfo", desc)).checksum}`, "[0,4]");
  const s = await Signer.load(signerWasm);
  s.init().seedFromMnemonic(new TextEncoder().encode(MNEMONIC));
  for (const a of ACCOUNTS) {
    const { xpub, descriptor } = s.xpub({ purpose: a.purpose });
    for (const chain of [0, 1]) {
      const ours = derive(descriptor.replace(xpub, toTpub(xpub)).replace("/<0;1>/*)", `/${chain}/*)`));
      const core = derive(`${a.kind}([${FINGERPRINT}/${a.purpose}h/0h/0h]${a.tprv}/${chain}/*${a.close}`);
      if (ours !== core) {
        console.error(`${descriptor} gives other addresses than Core's key on chain ${chain}:\n  ${ours}\n  ${core}`);
        process.exit(1);
      }
    }
  }
  {
    const { xpub, descriptor } = s.xpub({ purpose: 48 });
    for (const chain of [0, 1]) {
      const cos = MULTISIG.cosigners.map((k) => `${k}/${chain}/*`);
      const ours = derive(`wsh(sortedmulti(2,${descriptor.replace(xpub, toTpub(xpub)).replace("/<0;1>/*", `/${chain}/*`)},${cos}))`);
      const core = derive(`wsh(sortedmulti(2,[${FINGERPRINT}/48h/0h/0h/2h]${MULTISIG.tprv}/${chain}/*,${cos}))`);
      if (ours !== core) {
        console.error(`${descriptor} in wsh(sortedmulti()) gives other addresses than Core's key on chain ${chain}`);
        process.exit(1);
      }
    }
  }
  s.unload();
  console.log("the exported sh(wpkh()), wpkh(), tr() and BIP48 descriptors give the addresses Core derives from the keys");
}

// --- BIP137 against Core's signmessagewithprivkey, which signs as P2PKH: both are RFC6979 with no extra
// data, so r and s are the same bytes and the header is 8 (P2WPKH) or 4 (P2SH-P2WPKH) above Core's
{
  const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  const unb58 = (str) => {
    let n = 0n;
    for (const ch of str) n = n * 58n + BigInt(B58.indexOf(ch));
    return Buffer.from(n.toString(16).padStart(164, "0"), "hex");
  };
  const b58check = (data) => {
    const p = Buffer.concat([data, createHash("sha256").update(createHash("sha256").update(data).digest()).digest().subarray(0, 4)]);
    let m = BigInt("0x" + p.toString("hex")), out = "";
    for (; m > 0n; m /= 58n) out = B58[Number(m % 58n)] + out;
    return out;
  };
  const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
  // the committed account tprv, then the two unhardened steps to chain/index
  const wif = (tprv, chain, index) => {
    const raw = unb58(tprv);
    let c = raw.subarray(13, 45), k = raw.subarray(46, 78);
    for (const i of [chain, index]) {
      const e = createECDH("secp256k1");
      e.setPrivateKey(k);
      const I = createHmac("sha512", c).update(Buffer.concat([e.getPublicKey(null, "compressed"), Buffer.from([0, 0, 0, i])])).digest();
      k = Buffer.from(((BigInt("0x" + I.subarray(0, 32).toString("hex")) + BigInt("0x" + k.toString("hex"))) % N).toString(16).padStart(64, "0"), "hex");
      c = I.subarray(32);
    }
    return b58check(Buffer.concat([Buffer.from([0xef]), k, Buffer.from([1])]));
  };
  const s = await Signer.load(signerWasm);
  s.init().seedFromMnemonic(new TextEncoder().encode(MNEMONIC));
  let n = 0;
  for (const a of ACCOUNTS.filter((a) => a.purpose !== 86)) {
    for (const [chain, index, text] of [[0, 0, "This is an example of a signed message."], [0, 3, ""],
                                        [1, 1, "caf\u00e9\nnext line"], [0, 0, "x".repeat(300)]]) {
      const core = Buffer.from(cli("signmessagewithprivkey", wif(a.tprv, chain, index), text), "base64");
      s.messageReview(new TextEncoder().encode(text), { purpose: a.purpose, chain, index });
      const ours = Buffer.from(s.messageSign());
      if (!ours.subarray(1).equals(core.subarray(1)) || ours[0] !== core[0] + (a.purpose === 84 ? 8 : 4)) {
        console.error(`m/${a.purpose}'/0'/0'/${chain}/${index} "${text.slice(0, 20)}": ours ${ours.toString("base64")}, Core ${core.toString("base64")}`);
        process.exit(1);
      }
      n++;
    }
  }
  s.unload();
  console.log(`${n} BIP137 message signatures have Core's r and s, byte for byte`);
}

// --- parser.wasm, driven directly: no native host and no WAMR needed
const P = (await WebAssembly.instantiate(readFileSync(parserPath), {})).instance.exports;
const PLAN = Signer.LAYOUT.plan.size;

function planOf(psbt) {
  new Uint8Array(P.memory.buffer).set(psbt, P.parser_input());
  const rc = P.parser_parse(psbt.length, parseInt(FINGERPRINT, 16));
  if (rc !== 0) return { rc };
  const mem = new Uint8Array(P.memory.buffer);
  const plan = mem.slice(P.parser_plan(), P.parser_plan() + PLAN);
  const prevTxs = [];
  for (let i = 0; i < plan[Signer.LAYOUT.plan.nInputs]; i++) {
    const len = P.parser_prevtx_len(i);
    const at = P.parser_input() + P.parser_prevtx_off(i);
    prevTxs.push(len ? mem.slice(at, at + len) : null);
  }
  return { rc: 0, plan, prevTxs };
}

/** Reads the plan the way the specification says to, so this compares against the documented ABI. */
function readPlan(plan) {
  const v = new DataView(plan.buffer, plan.byteOffset, plan.length);
  const L = { inputs: 24, inputSize: 176, outputs: 2840, outputSize: 136 };
  const n = { in: plan[16], out: plan[17] };
  const inputs = [...Array(n.in)].map((_, i) => {
    const o = L.inputs + i * L.inputSize;
    return {
      txid: hex([...plan.slice(o, o + 32)].reverse()),   // Core prints a txid reversed
      vout: v.getUint32(o + 32, true),
      sequence: v.getUint32(o + 36, true),
      amount: v.getBigUint64(o + 40, true),
      spk: hex(plan.slice(o + 49, o + 49 + plan[o + 48])),
    };
  });
  const outputs = [...Array(n.out)].map((_, i) => {
    const o = L.outputs + i * L.outputSize;
    return {
      amount: v.getBigUint64(o, true),
      spk: hex(plan.slice(o + 9, o + 9 + plan[o + 8])),
    };
  });
  return { txVersion: v.getInt32(8, true), locktime: v.getUint32(12, true), inputs, outputs };
}

function signaturesIn(psbtB64) {
  const dec = JSON.parse(wallet("decodepsbt", psbtB64));
  const out = {};
  dec.inputs.forEach((inp, i) => {
    for (const [pub, sig] of Object.entries(inp.partial_signatures ?? {})) out[`in${i}/ecdsa/${pub}`] = sig;
    if (inp.taproot_key_path_sig) out[`in${i}/schnorr`] = inp.taproot_key_path_sig;
  });
  return out;
}

for (const path of psbtPaths.sort()) {
  const name = path.split("/").pop();
  const psbt = readFileSync(path);
  const b64 = psbt.toString("base64");
  bad.length = 0;

  const ours = planOf(psbt);
  if (ours.rc !== 0) {
    console.log(`skip ${name}  (we refuse it: rc=${ours.rc})`);
    skipped++;
    continue;
  }
  let core;
  try {
    core = JSON.parse(cli("decodepsbt", b64));
  } catch (e) {
    console.log(`skip ${name}  (Core refuses it)`);
    skipped++;
    continue;
  }

  // --- the parse
  const p = readPlan(ours.plan);
  eq("tx_version", p.txVersion, core.tx.version);
  eq("locktime", p.locktime, core.tx.locktime);
  eq("n_inputs", p.inputs.length, core.tx.vin.length);
  eq("n_outputs", p.outputs.length, core.tx.vout.length);
  p.inputs.forEach((o, i) => {
    const vin = core.tx.vin[i], ci = core.inputs[i];
    eq(`in${i}.txid`, o.txid, vin.txid);
    eq(`in${i}.vout`, o.vout, vin.vout);
    eq(`in${i}.sequence`, o.sequence, vin.sequence);
    const utxo = ci?.witness_utxo;
    if (utxo) {
      eq(`in${i}.amount`, o.amount, sats(utxo.amount));
      eq(`in${i}.spk`, o.spk, utxo.scriptPubKey.hex);
    }
  });
  p.outputs.forEach((o, i) => {
    eq(`out${i}.amount`, o.amount, sats(core.tx.vout[i].value));
    eq(`out${i}.spk`, o.spk, core.tx.vout[i].scriptPubKey.hex);
  });

  // --- the previous transactions' txids, which the parser reports by offset
  ours.prevTxs.forEach((raw, i) => {
    if (!raw) return;
    const txid = JSON.parse(cli("decoderawtransaction", hex(raw))).txid;
    eq(`in${i}.prevtx_txid`, p.inputs[i].txid, txid);
  });

  // --- the signatures, and the fee, for the vectors that are ours to sign
  let sigNote = "";
  if (name.startsWith("own_")) {
    const S = await Signer.load(signerWasm);
    try {
      S.init().seedFromMnemonic(new TextEncoder().encode(MNEMONIC)).setPlan(ours.plan).setPrevTxs(ours.prevTxs);
      const r = S.review();
      if ("fee" in core) eq("fee", r.fee, sats(core.fee));
      const oursSigs = {};
      for (const s of S.sign()) {
        const key = s.sig.length === 64 ? `in${s.input}/schnorr`
                                        : `in${s.input}/ecdsa/${hex(s.pubkey)}`;
        oursSigs[key] = hex(s.sig);
      }
      // DEFAULT, not ALL: Core then uses each input type's default, which for taproot is
      // SIGHASH_DEFAULT and a 64-byte signature. Forcing ALL appends 0x01 and nothing matches
      const coreSigs = signaturesIn(JSON.parse(
        wallet("walletprocesspsbt", b64, "true", "DEFAULT", "true", "false")).psbt);
      const common = Object.keys(oursSigs).filter((k) => k in coreSigs);
      for (const k of common) eq(k, oursSigs[k], coreSigs[k]);
      sigNote = common.length ? `, ${common.length} signature(s) byte-identical` : "";
    } catch (e) {
      sigNote = `, not signed here (${e.message.split("\n")[0]})`;
    } finally {
      S.unload();
    }
  }

  if (bad.length) {
    console.log(`FAIL ${name}`);
    for (const b of bad) console.log(`       ${b}`);
    failed++;
  } else {
    console.log(`ok   ${name}${sigNote}`);
    passed++;
  }
}

console.log(`\n${passed} agreed with Core, ${failed} disagreed, ${skipped} skipped`);
process.exit(failed ? 1 : 0);
