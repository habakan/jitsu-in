# JavaScript host

No dependencies. Works in Node and in a browser, including from `file://`.

```js
import { Parser } from "./parser.mjs";

const parser = await Parser.load(await (await fetch("parser.wasm")).arrayBuffer());
const plan = parser.parse(psbtBytes, 0x73c5da0a);   // master fingerprint, not a secret

console.log(plan.inputs.length, "in /", plan.outputs.length, "out");
for (const out of plan.outputs) {
  console.log(Number(out.amount) / 1e8, Buffer.from(out.spk).toString("hex"),
              out.key ? `claimed as ${out.key}` : "");
}
console.log("fee", Number(plan.fee) / 1e8);
```

In Node, `Parser.loadSync(readFileSync("parser.wasm"))` avoids the await.

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
