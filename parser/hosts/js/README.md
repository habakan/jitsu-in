# JavaScript host

No dependencies. Works in Node and in a browser, including from `file://`.

```js
import { Parser } from "./parser.mjs";

const parserWasm = await fetch("parser.wasm").then(r => r.arrayBuffer());
const parser = await Parser.load(parserWasm);

const plan = parser.parse(psbt, 0x73c5da0a);   // fingerprint of your master key; not a secret
const rawPlan = parser.rawPlan();              // 5,016-byte plan_t for a matching signer.wasm

console.log(plan.inputs.length, "in /", plan.outputs.length, "out");
for (const out of plan.outputs) {
  console.log(Number(out.amount) / 1e8, Buffer.from(out.spk).toString("hex"),
              out.key ? `claimed as ${out.key}` : "");
}
console.log("fee", Number(plan.fee) / 1e8);
```

In Node: `const parser = Parser.loadSync(readFileSync("parser.wasm"));`

You load `parser.wasm` once and keep the `parser`; `parse` is called per transaction.

## What you get

`plan.inputs[i]` — `prevTxid`, `prevVout`, `sequence`, `amount` (BigInt), `spk` (Uint8Array),
`key`, `sighashType`, and `prevtx` (the `non_witness_utxo`, or `null`).

`plan.outputs[i]` — `amount`, `spk`, `key`.

`parser.rawPlan()` returns a copy of the 5,016-byte ABI-v1 `plan_t`, for passing to a matching
`signer.wasm`. Call it after a successful `parse()`; the next `parse()`, `urReceive()`, or `urEncode()` invalidates it.

`key` is a `KeyOrigin?` — BIP380's name for this. It prints as `73c5da0a/84h/0h/0h/0/0`. **It is a claim**: the module
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

## Checking you have the right module

```js
const parser = await Parser.load(parserWasm, { sha256: "7c89bf15…" });
```

The module is refused unless it hashes to exactly that. Take the value from the project's
`checksums.txt` or a release's `SHA256SUMS`. `loadSync` cannot do this: `SubtleCrypto` has no synchronous form.

A hash written in a file nobody checks is documentation. Passing it here makes it a gate.

## Tests

```sh
make check-hosts      # from the repository root; also part of `make test`
```

The tests check that every hand-made vector parses to a sane shape, Bitcoin Core's invalid vectors are
rejected as `ParserError` rather than crashing, derivations print as `73c5da0a/84h/0h/0h/0/0`,
errors arrive by name, a UR round trip is byte-identical, and a module that returns an offset
outside its memory is stopped with a `RangeError`.
