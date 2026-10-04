# Releases

How a release is produced, and how you check one.

## Checking a release

```sh
# 1. the hash of what you downloaded matches the manifest
sha256sum -c SHA256SUMS

# 2. the manifest was signed by the maintainer
gpg --verify SHA256SUMS.asc SHA256SUMS

# 3. the file was built by this repository's workflow, from a known commit
gh attestation verify parser.wasm --repo habakan/wasm-psbt-parser
```

The maintainer's public key is at https://github.com/habakan.gpg, fingerprint
`8BD4 8DD6 70AF 9B34 7EA0  41CF 36D4 93A2 8A8B EB79`
(also in [SECURITY.md](../SECURITY.md)).

Step 3 is independent of step 2: it does not depend on the maintainer's key at all, only on GitHub's
signing of the build. Steps 2 and 3 fail for different reasons, which is the point of having both.

## Checking it yourself, without trusting any of that

The build is reproducible. Check out the tag, build with the pinned toolchain, and compare:

```sh
sha256sum build/parser.wasm
```

macOS arm64 and Linux x86_64 produce the same bytes. The toolchain (wasi-sdk 34.0, binaryen 132)
is pinned by version and by the SHA-256 of its tarball, so "the same toolchain" is checkable too.
This is the strongest of the three: it does not require trusting the maintainer or GitHub.

You can also check the shape of what you downloaded without running it:

```sh
wasm-tools validate --features=-all,floats,saturating-float-to-int,bulk-memory-opt,-mutable-global parser.wasm
wasm-tools print parser.wasm | grep -c '^\s*(import '    # must be 0
```

And a host can refuse anything else:

```js
await Parser.load(parserWasm, { sha256: "…" });
```

## Making a release

```sh
git tag -s v0.1.0 -m "v0.1.0"      # -s signs the tag
git push origin v0.1.0
```

The workflow builds `parser.wasm` with the pinned toolchain, checks its shape, writes `SHA256SUMS`,
attaches a build provenance attestation, and creates the release.

Then sign the manifest and attach it:

```sh
gh release download v0.1.0 -p SHA256SUMS
gpg --armor --detach-sign SHA256SUMS
gh release upload v0.1.0 SHA256SUMS.asc
```

Signing is deliberately a separate, manual step: **the key never goes near CI.** A key held by a CI
runner signs whatever the runner is told to sign, which is not the property anyone wants from it.

## Versioning

Tags are `vMAJOR.MINOR.PATCH`. The number that matters to a host is `plan_t.version`, which is
independent: adding a field, changing a size, or changing a meaning bumps it, and a host that sees an
unknown version must refuse rather than guess. See [the ABI](abi.md#versioning).
