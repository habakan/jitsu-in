# Rust + Wasmi host PoC

This small executable runs the pinned `signer.wasm` through Wasmi, derives the public BIP39 test
vector, checks its master fingerprint, and unloads the key. It prints timings and never prints the
mnemonic or seed.

From the repository root:

```sh
make build/signer.wasm
cargo run --release --manifest-path signer/hosts/rust-poc/Cargo.toml -- build/signer.wasm
cargo check --manifest-path signer/hosts/rust-poc/Cargo.toml --target armv7-linux-androideabi
cargo check --manifest-path signer/hosts/rust-poc/Cargo.toml --target aarch64-linux-android
cargo check --manifest-path signer/hosts/rust-poc/Cargo.toml --target aarch64-apple-ios
cargo check --manifest-path signer/hosts/rust-poc/Cargo.toml --target aarch64-apple-ios-sim
```

This validates the Rust runtime path and target compilation. It does not yet integrate the host into
the Tauri mobile plugin or measure startup and derivation on a physical iOS device.
