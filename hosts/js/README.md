# JavaScript host

No dependencies. Works in Node and in a browser, including from `file://`.

Two different byte arrays are involved and it is worth keeping them apart: the **module** is the
`parser.wasm` file you load once, and the **PSBT** is the transaction you hand it afterwards.

```js
import { Parser } from "./parser.mjs";

// once: load the module itself
const parser = await Parser.load(await fetch("parser.wasm").then(r => r.arrayBuffer()));

// per transaction: hand it a PSBT and the master fingerprint (not a secret)
const plan = parser.parse(psbt, 0x73c5da0a);

console.log(plan.inputs.length, "in /", plan.outputs.length, "out");
for (const out of plan.outputs) {
  console.log(Number(out.amount) / 1e8, Buffer.from(out.spk).toString("hex"),
              out.key ? `claimed as ${out.key}` : "");
}
console.log("fee", Number(plan.fee) / 1e8);
```

In Node: `const parser = Parser.loadSync(readFileSync("parser.wasm"));`

## What you get

`plan.inputs[i]` — `prevTxid`, `prevVout`, `sequence`, `amount` (BigInt), `spk` (Uint8Array),
`key`, `sighashType`, and `prevtx` (the `non_witness_utxo`, or `null`).

`plan.outputs[i]` — `amount`, `spk`, `key`.

`key` is a `KeyPath` or `null`. It prints as `73c5da0a/84h/0h/0h/0/0`. **It is a claim**: the module
read it out of the PSBT. Derive the key yourself and check it produces `spk` before you call an
output change, or an input yours.

`plan.fee` is `totalIn - totalOut`. Those amounts are also claims until you check each input's
`prevtx` against its `prevTxid`.

## Animated QR

```js
parser.urReset();
for (const payload of qrFrames) {
  const psbt = parser.urReceive(payload);   // null until the message is complete
  if (psbt) { /* parse it */ break; }
}

const { seqLen, next } = parser.urEncode(signedPsbt.length, 100);
for (let i = 0; i < seqLen; i++) render(next());
```

## Errors

Anything the module rejects throws a `ParserError` with `.code` and a readable `.message`
(`P_ERR_MAGIC`, `P_ERR_LIMIT`, `UR_ERR_BYTEWORDS`, …). An offset outside the module's memory throws
a `RangeError` — that would mean the module is not the one you think it is.
