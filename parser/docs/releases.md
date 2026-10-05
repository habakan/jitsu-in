# Releases

How a release is produced, and how you check one.

## Checking a release

```sh
# 1. the hashes of both modules match the manifest
sha256sum -c SHA256SUMS

# 2. the manifest was signed by the maintainer
gpg --verify SHA256SUMS.asc SHA256SUMS

# 3. the file was built by this repository's workflow, from a known commit
gh attestation verify parser.wasm --repo habakan/jitsu-in
gh attestation verify signer.wasm --repo habakan/jitsu-in
```

The maintainer's public key is at https://github.com/habakan.gpg, fingerprint
`8BD4 8DD6 70AF 9B34 7EA0  41CF 36D4 93A2 8A8B EB79`
(also in [SECURITY.md](../../SECURITY.md)).

Step 3 is independent of step 2: it does not depend on the maintainer's key at all, only on GitHub's
signing of the build. Steps 2 and 3 fail for different reasons, which is the point of having both.

## Checking it yourself, without trusting any of that

The build is reproducible. Check out the tag, build with the pinned toolchain, and compare:

```sh
git checkout v0.1.0
gh release download v0.1.0 -p SHA256SUMS

# the same toolchain the release was built with, pinned by version and by the hash of its tarball
curl -sLO https://github.com/WebAssembly/wasi-sdk/releases/download/wasi-sdk-34/wasi-sdk-34.0-x86_64-linux.tar.gz
echo "b761e3a0721dbae9c09a0059e5fdb2bf917d1b4a8a7b430fb3b5aafb0984b2c4  wasi-sdk-34.0-x86_64-linux.tar.gz" | sha256sum -c -
tar xzf wasi-sdk-34.0-x86_64-linux.tar.gz
curl -sLO https://github.com/WebAssembly/binaryen/releases/download/version_132/binaryen-version_132-x86_64-linux.tar.gz
echo "195ddc94f9bc89f45abdabb0b9eea86023d727ba90eac8b35b80f2544fc30572  binaryen-version_132-x86_64-linux.tar.gz" | sha256sum -c -
tar xzf binaryen-version_132-x86_64-linux.tar.gz

SDK=$PWD/wasi-sdk-34.0-x86_64-linux
make deps
make all \
  LLVM=$SDK/bin WASI=$SDK/share/wasi-sysroot \
  RTLIB=$SDK/lib/clang/23/lib/wasm32-unknown-wasi \
  WASM_OPT=$PWD/binaryen-version_132/bin/wasm-opt

(cd build && sha256sum -c ../SHA256SUMS)
```

The macOS arm64 tarballs (`-arm64-macos`) produce the same bytes. `make` alone uses whatever clang is
on your machine and is **not** expected to reproduce the release: the versions above are the ones that
do. [.github/workflows/ci.yml](../../.github/workflows/ci.yml) pins the build tools; the
[release workflow](../../.github/workflows/release.yml) runs it for the tagged commit.

One trap worth naming: if a different `wasm-opt` is earlier on your `PATH`, `WASM_OPT` above is what
decides, so set it explicitly as shown rather than relying on the `PATH`.

This is the strongest of the three checks: it does not require trusting the maintainer or GitHub.

You can also check the shape of what you downloaded without running it:

```sh
for module in parser.wasm signer.wasm; do
  features=-all,floats,saturating-float-to-int,bulk-memory-opt,-mutable-global
  if [ "$module" = signer.wasm ]; then features="$features,sign-extension"; fi
  wasm-tools validate --features="$features" "$module"
  test "$(wasm-tools print "$module" | grep -c '^\s*(import ')" = 0
done
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

The workflow runs the CI test suite for the tag, then publishes both `parser.wasm` and `signer.wasm`
from that tested build. It writes `SHA256SUMS` and attaches a build provenance attestation to each
module before creating the release.

Then sign the manifest and attach it:

```sh
gh release download v0.1.0 -p SHA256SUMS
gpg --armor --detach-sign SHA256SUMS
gh release upload v0.1.0 SHA256SUMS.asc
```

Signing is deliberately a separate, manual step: **the key never goes near CI.** A key held by a CI
runner signs whatever the runner is told to sign, which is not the property anyone wants from it.

## Keeping the hash honest

`checksums.txt` holds the hashes of the current `parser.wasm` and `signer.wasm`, and CI rebuilds with
the pinned toolchain and compares against them on every commit. A change to either module changes its
hash, and the job fails until `checksums.txt` is updated on purpose — so the files cannot quietly drift
out of step with what gets released.

## Versioning

Tags are `vMAJOR.MINOR.PATCH`. The number that matters to a host is `plan_t.version`, which is
independent: adding a field, changing a size, or changing a meaning bumps it, and a host that sees an
unknown version must refuse rather than guess. See [the ABI](abi.md#versioning).
