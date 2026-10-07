# Driving signer.wasm from your language

`signer.wasm` is the half that holds the key. It takes the `plan_t` that `parser.wasm` produced,
re-derives the keys to check it, builds what a person should be shown, and returns signatures.

It is 77,520 bytes with **zero imports**: no clock, no randomness, no filesystem, no network. The
shared conventions are in [../../docs/module-abi.md](../../docs/module-abi.md); this page is
what is specific to this module.

Two host libraries drive it, and `make check-hosts-agree` requires their output to match byte for
byte:

| | | |
|---|---|---|
| JavaScript | [hosts/js/signer.mjs](../hosts/js/signer.mjs) | 82 checks in [test.mjs](../hosts/js/test.mjs) |
| Kotlin / JVM / Android | [hosts/kotlin/Signer.kt](../hosts/kotlin/Signer.kt) | 46 checks in [Test.kt](../hosts/kotlin/Test.kt) |
| Swift / macOS / iOS | [hosts/swift/Sources/WasmSigner/Signer.swift](../hosts/swift/Sources/WasmSigner/Signer.swift) | 43 checks in [SignerCheck](../hosts/swift/Sources/SignerCheck/main.swift) |

## What a host must not do

This module holds a secret, which makes the host's behaviour part of the security of the whole, in a
way it is not for `parser.wasm`.

- **Do not log, serialise or copy the input buffer.** The mnemonic, the SeedQR and the seed pass through
  `signer_input()`. The module wipes it after use; whatever your language did with the string you
  built it from is yours to clear
- **Do not keep the mnemonic in a garbage-collected string** any longer than it takes to write it in.
  In JavaScript you cannot reliably clear a `String`; build a `Uint8Array`, write it, and `fill(0)`
- **Call `signer_unload()` when you are finished**, not when you happen to remember. It zeroes the
  master key and everything derived from it
- **Pin the module's hash.** A module that holds a key is the last place to accept whatever bytes
  arrived. `Signer.load(wasm, { sha256 })` refuses anything else
- Nothing about this module stops a host reading its linear memory. On the device, that is why the
  debug probe has to be unplugged; in a browser, the page that loaded it can see the key. This module
  isolates the parser from the key, not the key from its host

## The sequence

```
signer_init(testnet)
signer_seed_from_mnemonic(...)   or   signer_seed_from_seedqr(...)   or   signer_load_seed()
signer_plan()        <- write the 5016-byte plan_t here
signer_set_prevtx(i, off, len)   for each input, after writing into signer_prevtx()
signer_review()      -> re-derives keys, decides what is ours, computes the fee
signer_display()     -> the strings and amounts to show
signer_sign()        -> signatures, and only for the plan review() was shown
signer_unload()
```

**One approval permits one signing.** `signer_review()` records the SHA-256 of the plan; `signer_sign()`
requires the plan in memory to still hash to it, and then clears the approval. Signing again means
reviewing again. This is what binds what was displayed to what was signed: a plan swapped in after the
review fails the hash, and a plan swapped in before it is the plan that gets displayed.

## Exports

### Buffers

| | what goes in it |
|---|---|
| `signer_input() -> ptr` | the mnemonic or a SeedQR payload followed by the passphrase, a 64-byte seed, or a message to sign |
| `signer_input_cap() -> u32` | how many bytes that is (512); check before writing |
| `signer_plan() -> ptr` | the `plan_t`, 5016 bytes, copied verbatim from `parser_plan()` |
| `signer_prevtx() -> ptr` | the `non_witness_utxo` bytes, laid out however you like within 32768 |
| `signer_review_output() -> ptr` | `core_review_t`, 64 bytes |
| `signer_display_output() -> ptr` | `core_display_t`, 2968 bytes |
| `signer_sigs() -> ptr` | up to 16 x `plan_sig_t` of 108 bytes |
| `signer_xpub_output() -> ptr` | the account xpub, NUL-terminated, at most 120 |
| `signer_desc_output() -> ptr` | the output descriptor, NUL-terminated, at most 180 |
| `signer_message_output() -> ptr` | `core_message_t`, 1101 bytes: what to show before signing a message |
| `signer_message_sig() -> ptr` | the BIP137 signature, 65 bytes |

### Operations

| | returns |
|---|---|
| `signer_init(testnet: i32)` | 1 on success. `testnet` covers signet too |
| `signer_seed_from_mnemonic(mn_len, pass_len)` | 1 on success. PBKDF2 2048 rounds, about half a second |
| `signer_seed_from_seedqr(qr_len, pass_len)` | 1 on success. Standard (48 or 96 digits) or Compact (16 or 32 bytes); 0 if the BIP39 checksum fails |
| `signer_load_seed()` | 1 on success, using the first 64 bytes of the input buffer |
| `signer_set_prevtx(i, off, len)` | 1 on success. `len` of 0 means that input has no previous transaction |
| `signer_review()` | 0 on success, otherwise one of the errors below |
| `signer_display()` | 0 on success |
| `signer_sign()` | the number of signatures, or the negated error |
| `signer_message_review(len, purpose, account, chain, index)` | 0 on success. The message in the input buffer (at most 512 bytes) and the key at m/purpose'/coin'/account'/chain/index, `purpose` 49 or 84; see below |
| `signer_message_sign()` | 0 on success, `NOT_REVIEWED` unless it is the message and key the last review showed |
| `signer_xpub(purpose, account)` | 0 on success. m/purpose'/coin'/account' with `purpose` 49 (`sh(wpkh())`), 84 (`wpkh()`) or 86 (`tr()`) and `account` below 2^31, otherwise `FORMAT` |
| `signer_fingerprint()` | the master fingerprint, or 0 when no seed is loaded |
| `signer_unload()` | nothing. Zeroes the key, the plan, the signatures and the display |

## Signing a message

`signer_message_review` and `signer_message_sign` make a
[BIP137](https://github.com/bitcoin/bips/blob/master/bip-0137.mediawiki) signature: the header (35-38
for P2SH-P2WPKH, 39-42 for P2WPKH), then r and s; most wallets take it in base64. As with a
transaction, one review permits one signature, and the module signs only the message and key it
hashed at review time, wherever else in memory they may have been changed since. A message is shown
as it is only when every byte is printable ASCII; anything else, a newline or UTF-8 included, is shown
in hex, since such bytes could render as something other than what is signed.

The key is chosen by integers, not by the `signmessage m/84h/... ascii:...` text QR codes carry:
reading that text is the host's, and the module checks the path it is given. The nonce is RFC6979
with no extra data, as in Bitcoin Core's `signmessage`, so `make check-core-diff` requires r and s to
be the bytes Core gives for the same key. P2TR has no BIP137 form; BIP322 is not here yet.

## Errors

| code | name | what it means |
|---|---|---|
| 1 | `FORMAT` | over a limit, an unused field is non-zero, or an amount is out of range |
| 2 | `NO_SEED` | no key is loaded |
| 3 | `NOT_OURS` | an input claims our fingerprint, but its key does not produce its script |
| 4 | `NOTHING_TO_SIGN` | no input in the plan is ours |
| 5 | `SIGHASH` | a sighash type this signer does not allow |
| 6 | `SCRIPT` | an input to be signed is not P2WPKH, P2SH-P2WPKH or P2TR |
| 7 | `PREVTX_MISSING` | two or more inputs including SegWit v0, and no previous transaction |
| 8 | `PREVTX_MISMATCH` | the previous transaction disagrees with the claimed amount, txid or vout |
| 9 | `FEE` | the fee does not add up, or overflows |
| 10 | `NOT_REVIEWED` | the plan is not the one review passed, or the approval was already used |
| 11 | `CRYPTO` | a libsecp256k1 call failed, or the signature did not verify |

## Structures

All little-endian, as wasm32 is. The numbers here are printed by
[../tests/layout.c](../tests/layout.c) from the structs themselves, and `make check-layout` fails if
this page and the code disagree.

### `core_review_t` (64 bytes)

| offset | size | field |
|---:|---:|---|
| 0 | 8 | `total_in`, satoshis |
| 8 | 8 | `total_out`, satoshis |
| 16 | 8 | `fee`, satoshis |
| 24 | 16 | `owner[]`, one byte per output: 0 external, 1 change, 2 ours |
| 40 | 16 | `will_sign[]`, one byte per input |
| 56 | 1 | `n_sign`, how many inputs will be signed |

### `core_display_t` (2968 bytes)

| offset | size | field |
|---:|---:|---|
| 0 | 8 | `fee`, satoshis |
| 8 | 8 | `spend`, the total of external outputs only |
| 16 | 1 | `n_outputs` |
| 24 | 16 x 184 | `outputs[]` |

Each output, at `24 + i * 184`:

| offset | size | field |
|---:|---:|---|
| 0 | 8 | `amount`, satoshis |
| 8 | 1 | `owner`: 0 external, 1 change, 2 ours |
| 9 | 1 | `text_kind`: 0 an address, 1 OP_RETURN data, 2 the whole script |
| 10 | 167 | `text`, NUL-terminated |

**Every string here was built inside the module from the plan's bytes.** None of it is a string the
PSBT chose, which is why it is safe to put in front of a person.

### `plan_sig_t` (108 bytes)

| offset | size | field |
|---:|---:|---|
| 0 | 1 | `input`, which input this signs |
| 1 | 33 | `pubkey`: compressed for P2WPKH and P2SH-P2WPKH, `0x00` then the x-only output key for P2TR |
| 34 | 1 | `sig_len` |
| 35 | 73 | `sig`: DER plus the sighash byte for ECDSA, 64 or 65 bytes for Schnorr |

### `core_message_t` (1101 bytes)

| offset | size | field |
|---:|---:|---|
| 0 | 75 | `address`, of the key that will sign, NUL-terminated |
| 75 | 1 | `text_kind`: 0 the message itself, 1 its hex |
| 76 | 1025 | `text`, NUL-terminated |

Hand these to `parser_sigs()` and call `parser_finalize()`; `parser.wasm` inserts them into the
original PSBT and leaves every other byte alone.

## Signatures are deterministic

ECDSA grinds for a low R as Bitcoin Core does, and Schnorr passes a zero `aux_rand`, which Core,
Trezor, Jade and BDK all do too. So the same key over the same plan always gives the same bytes.

That is a property worth having: this module in a browser reproduces the device's signature exactly,
and CI requires both to equal what Bitcoin Core produces for the same PSBT
(`make check-core-diff`). **It also means this must be revisited before multisig**, where BIP340
says deterministic nonces are unsafe.

## What this module does not do

Single-signature P2WPKH (BIP84), P2SH-P2WPKH (BIP49) and P2TR key path (BIP86), `SIGHASH_ALL` and Taproot's
`SIGHASH_DEFAULT`. No multisig, no script trees, no legacy P2PKH signing. The full list is in
jitsu-in-pico's `docs/limitations.md`.
