// Encodes the test PSBTs in build/vectors/ as multipart URs with @ngraveio/bc-ur (a port of the Blockchain
// Commons reference encoder) and writes tests/ur_vectors.json, so the tests themselves do not need Node.
// Usage: NODE_PATH=<dir with @ngraveio/bc-ur> node tools/gen_ur_vectors.cjs build/vectors tests/ur_vectors.json
const fs = require("fs");
const path = require("path");
const { UR, UREncoder } = require("@ngraveio/bc-ur");
const version = require("@ngraveio/bc-ur/package.json").version;

const [dir, out] = process.argv.slice(2);
const vectors = [];
for (const file of fs.readdirSync(dir).filter((f) => /^own_.*\.psbt$/.test(f)).sort()) {
  const psbt = fs.readFileSync(path.join(dir, file));
  for (const [type, fragmentLen] of [["crypto-psbt", 60], ["psbt", 150], ["crypto-psbt", 5000]]) {
    const ur = new UR(UR.fromBuffer(psbt).cbor, type);
    const encoder = new UREncoder(ur, fragmentLen, 1);
    const parts = [];
    const count = encoder.fragmentsLength === 1 ? 1 : 3 * encoder.fragmentsLength;
    for (let i = 0; i < count; i++) parts.push(encoder.nextPart().toUpperCase());
    vectors.push({ name: file.replace(".psbt", ""), type, fragment_len: fragmentLen, seq_len: encoder.fragmentsLength,
                   psbt_hex: psbt.toString("hex"), parts });
  }
}
fs.writeFileSync(out, JSON.stringify({ generator: `@ngraveio/bc-ur ${version}`, vectors }, null, 1) + "\n");
console.log(`${vectors.length} vectors`);
