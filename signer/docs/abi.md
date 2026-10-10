# Driving signer.wasm from your language

`signer.wasm` is the half that holds the key. It takes the `plan_t` that `parser.wasm` produced,
re-derives the keys to check it, builds what a person should be shown, and returns signatures.

It is 90,021 bytes with **zero imports**: no clock, no randomness, no filesystem, no network. The
shared conventions are in [../../docs/module-abi.md](../../docs/module-abi.md); this page is
what is specific to this module.

Two host libraries drive it, and `make check-hosts-agree` requires their output to match byte for
byte:

| | | |
|---|---|---|
| JavaScript | [hosts/js/signer.mjs](../hosts/js/signer.mjs) | 146 checks in [test.mjs](../hosts/js/test.mjs) |
| Kotlin / JVM / Android | [hosts/kotlin/Signer.kt](../hosts/kotlin/Signer.kt) | 71 checks in [Test.kt](../hosts/kotlin/Test.kt) |
| Swift / macOS / iOS | [hosts/swift/Sources/WasmSigner/Signer.swift](../hosts/swift/Sources/WasmSigner/Signer.swift) | 68 checks in [SignerCheck](../hosts/swift/Sources/SignerCheck/main.swift) |

## What a host must not do

This module holds a secret, which makes the host's behaviour part of the security of the whole, in a
way it is not for `parser.wasm`.

- **Do not log, serialise or copy the input buffer.** The mnemonic, the SeedQR and the seed pass through
  `signer_input()`. The module wipes it after use; whatever your language did with the string you
  built it from is yours to clear
- **A new mnemonic, a BIP85 child, or a SeedQR made for a backup, comes out of the module, once.** The host
  libraries copy it out of `signer_mnemonic_output()` or `signer_seedqr_output()` and zero it there;
  the copy they return is yours to clear. The module has no randomness of its own, so the entropy has
  to come from the host: a CSPRNG, or dice
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
signer_plan()        <- write the 6712-byte plan_t here
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
| `signer_input() -> ptr` | the mnemonic or a SeedQR payload followed by the passphrase, a 64-byte seed, entropy or dice rolls for a new mnemonic, an address to find, a message to sign, or a multisig setup |
| `signer_input_cap() -> u32` | how many bytes that is (1024); check before writing |
| `signer_plan() -> ptr` | the `plan_t`, 6712 bytes, copied verbatim from `parser_plan()` |
| `signer_prevtx() -> ptr` | the `non_witness_utxo` bytes, laid out however you like within 32768 |
| `signer_review_output() -> ptr` | `core_review_t`, 64 bytes |
| `signer_display_output() -> ptr` | `core_display_t`, 2968 bytes |
| `signer_sigs() -> ptr` | up to 16 x `plan_sig_t` of 108 bytes |
| `signer_xpub_output() -> ptr` | the account xpub, NUL-terminated, at most 120 |
| `signer_desc_output() -> ptr` | the output descriptor, NUL-terminated, at most 180 |
| `signer_mnemonic_output() -> ptr` | a new mnemonic, NUL-terminated, at most 256. Secret: clear it once read |
| `signer_seedqr_output() -> ptr` | a SeedQR made from a mnemonic, at most 96 bytes. Secret: clear it once read |
| `signer_message_output() -> ptr` | `core_message_t`, 1101 bytes: what to show before signing a message |
| `signer_message_sig() -> ptr` | the BIP137 signature, 65 bytes |
| `signer_multisig_output() -> ptr` | `core_multisig_t`, 732 bytes: what to show before trusting a multisig |
| `signer_cbor_output() -> ptr` | a crypto-account or crypto-output, CBOR, at most 1024 bytes |

### Operations

| | returns |
|---|---|
| `signer_init(testnet: i32)` | 1 on success. `testnet` covers signet too |
| `signer_seed_from_mnemonic(mn_len, pass_len)` | 1 on success. English BIP39 words with a valid checksum; surrounding and repeated whitespace and capitals are normalised first, the passphrase is used as given. PBKDF2 2048 rounds, about half a second |
| `signer_seed_from_seedqr(qr_len, pass_len)` | 1 on success. Standard (48 or 96 digits) or Compact (16 or 32 bytes); 0 if the BIP39 checksum fails |
| `signer_load_seed()` | 1 on success, using the first 64 bytes of the input buffer |
| `signer_mnemonic_from_entropy(len)` | the length of the new mnemonic, or 0. 16, 20, 24, 28 or 32 bytes of entropy give 12 to 24 words. Nothing is loaded |
| `signer_mnemonic_from_dice(len, words)` | the same from dice rolls, the characters `1` to `6`: at least 50 for 12 words, 99 for 24. The entropy is SHA-256 of the rolls, the first 16 bytes for 12 words |
| `signer_seedqr_from_mnemonic(mn_len, compact)` | the length of the SeedQR for the 12 or 24 word mnemonic in the input buffer, or 0: the Standard digits as ASCII (48 or 96, for QR numeric mode), or with `compact` the CompactSeedQR's 16 or 32 bytes (for byte mode) |
| `signer_bip85_mnemonic(words, index)` | the length of the loaded seed's BIP85 child mnemonic at m/83696968'/39'/0'/words'/index' in `signer_mnemonic_output()`, or 0. English; `words` is 12, 18 or 24 and `index` below 2^31 |
| `signer_set_prevtx(i, off, len)` | 1 on success. `len` of 0 means that input has no previous transaction |
| `signer_review()` | 0 on success, otherwise one of the errors below |
| `signer_display()` | 0 on success |
| `signer_sign()` | the number of signatures, or the negated error |
| `signer_message_review(len, purpose, account, chain, index)` | 0 on success. The message in the input buffer (at most 512 bytes) and the key at m/purpose'/coin'/account'/chain/index, `purpose` 49 or 84; see below |
| `signer_message_sign()` | 0 on success, `NOT_REVIEWED` unless it is the message and key the last review showed |
| `signer_xpub(purpose, account)` | 0 on success. m/purpose'/coin'/account' with `purpose` 49 (`sh(wpkh())`), 84 (`wpkh()`) or 86 (`tr()`), or m/48'/coin'/account'/2' and its key expression for `sortedmulti()` with 48, and `account` below 2^31, otherwise `FORMAT`, with the xpub and descriptor buffers emptied |
| `signer_find_address(len, account, count)` | where the address in `signer_input()` is on m/purpose'/coin'/account', receive then change, indices 0 to `count`-1: `chain << 20 \| index`, or the negated error; `NOT_FOUND` when it is not there. See below |
| `signer_fingerprint()` | the master fingerprint, or 0 when no seed is loaded |
| `signer_multisig_load(len)` | 0 on success. Registers the multisig in the input buffer; see below |
| `signer_multisig_unload()` | nothing. Forgets the registered multisig |
| `signer_account_cbor(account)` | the length of a crypto-account in `signer_cbor_output()`, or the negated error |
| `signer_multisig_cbor()` | the length of the registered multisig's crypto-output, or `-WALLET` when there is none |
| `signer_unload()` | nothing. Zeroes the key, the plan, the signatures and the display |

## Finding our addresses

`signer_find_address` answers "is this address mine?" before someone sends to it. The purpose follows
from the address: `3`/`2` (base58 P2SH) is BIP49, `bc1q`/`tb1q` is BIP84, `bc1p`/`tb1p` is BIP86.
Anything else, or an address for the other network, is `FORMAT`. A bech32 address may be all upper
case, since that is what a QR's alphanumeric mode carries, but not mixed, and may hold only `0-9a-zA-Z`;
a base58 one is compared as it is, since its case is part of it. `count` is 1 to 100,000.
The host libraries' `findAddress` strips a `bitcoin:` URI and returns `{ chain, index }`.

An address of the right form but the wrong length (P2WSH, or one cut short) cannot be ours and is
`NOT_FOUND` at once. Otherwise each index is a derivation, and an address that is not ours costs all
of them: 2 x 1000 took 0.13 s (P2WPKH) and 0.40 s (P2TR) in V8, and 7.8 s and 26 s in WAMR's classic
interpreter, on an M-series Mac. Chicory and WasmKit are slower still, so their tests pass a count of 20.

## Registering a multisig

Without a registered wallet, a P2WSH input is signed when its witness script is a multisig of at most three
keys that hashes to its script and holds our key, and P2WSH change is shown as an external output: the signer
cannot tell the cosigners' keys from anyone else's. `signer_multisig_load` gives it those keys. It takes a
`wsh(sortedmulti(k,...))` descriptor (with `/<0;1>/*`, `/**` or `/0/*` after each key, and its checksum checked
when there is one), a BSMS 1.0 record (BIP129), or the setup file Coldcard reads and Sparrow, BlueWallet and
Nunchuk write. Keys are xpub or tpub, or SLIP-132's Zpub or Vpub, and every origin step is hardened.

It is refused with `FORMAT` for anything else, a key twice, a threshold above the key count or a key on the
other network, and with `WALLET` unless exactly one key is ours: the seed re-derives it at its origin, chain code
and all. Our fingerprint on another key is what the wrong passphrase looks like. A BSMS record whose address
is not the wallet's first receive address is `WALLET` too.

What `signer_multisig_output()` holds is for a person to compare with the coordinator before relying on it,
the receive address above all. From then on a P2WSH input with our key is signed only when its witness script
is the wallet's at that path (`WALLET` otherwise), and a P2WSH output at our key's path is change or ours once
the wallet's keys there hash to it and one of its inputs is being signed. Loading another seed unloads the wallet.

`signer_multisig_cbor()` and `signer_account_cbor()` describe public keys as BCR-2020-010 and -015 do, for
`parser_ur_encode_cbor()`: the wallet as `wsh(sortedmulti())`, and the account's `sh(wpkh())`, `wpkh()`, `tr()`
and BIP48 key as `wsh(cosigner())`, each key a crypto-hdkey with its origin and parent fingerprint.

## Signing a message

`signer_message_review` and `signer_message_sign` make a
[BIP137](https://github.com/bitcoin/bips/blob/master/bip-0137.mediawiki) signature: the header (35-38
for P2SH-P2WPKH, 39-42 for P2WPKH), then r and s; most wallets take it in base64. As with a
transaction, one review permits one signature, and the module signs only the message and key it
hashed at review time, so a message or key swapped in afterwards is refused. Like the plan's, that hash
is in memory the host can write: it binds review to signing, it does not defend against the host. A
message is shown as it is only when every byte is printable ASCII; anything else, a newline or UTF-8
included, is shown in hex, since such bytes could render as something other than what is signed.

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
| 6 | `SCRIPT` | an input to be signed is not P2WPKH, P2SH-P2WPKH, P2TR, or P2WSH with a multisig of at most three keys |
| 7 | `PREVTX_MISSING` | two or more inputs including SegWit v0, and no previous transaction |
| 8 | `PREVTX_MISMATCH` | the previous transaction disagrees with the claimed amount, txid or vout |
| 9 | `FEE` | the fee does not add up, or overflows |
| 10 | `NOT_REVIEWED` | the plan is not the one review passed, or the approval was already used |
| 11 | `CRYPTO` | a libsecp256k1 call failed, or the signature did not verify |
| 12 | `NOT_FOUND` | `signer_find_address`: none of the addresses searched is this one |
| 13 | `WALLET` | a multisig without our key, or whose BSMS address disagrees; a P2WSH input not of the registered one |

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

Hand these to `parser_sigs()` and call `parser_finalize()`; `parser.wasm` inserts them into the
original PSBT and leaves every other byte alone.

### `core_message_t` (1101 bytes)

| offset | size | field |
|---:|---:|---|
| 0 | 75 | `address`, of the key that will sign, NUL-terminated |
| 75 | 1 | `text_kind`: 0 the message itself, 1 its hex |
| 76 | 1025 | `text`, NUL-terminated |

### `core_multisig_t` (732 bytes)

| offset | size | field |
|---:|---:|---|
| 0 | 1 | `threshold` |
| 1 | 1 | `n`, how many keys |
| 2 | 1 | `ours`, which of them |
| 4 | 3 x 4 | `fingerprints[]`, as integers (73c5da0a is 0x73c5da0a) |
| 16 | 75 | `receive`, the first receive address, NUL-terminated |
| 91 | 640 | `descriptor`, with xpub or tpub, `<0;1>` and its checksum, NUL-terminated |

## Signatures are deterministic

ECDSA grinds for a low R as Bitcoin Core does, and Schnorr passes a zero `aux_rand`, which Core,
Trezor, Jade and BDK all do too. So the same key over the same plan always gives the same bytes.

That is a property worth having: this module in a browser reproduces the device's signature exactly,
and CI requires both to equal what Bitcoin Core produces for the same PSBT
(`make check-core-diff`). P2WSH multisig is ECDSA under OP_CHECKMULTISIG, where each cosigner signs
on its own and RFC6979 stays safe; **it must be revisited before MuSig2 or FROST**, where BIP340 says
deterministic nonces are unsafe.

## What this module does not do

P2WPKH (BIP84), P2SH-P2WPKH (BIP49), P2TR key path (BIP86) and P2WSH multisig of at most three keys
(BIP48), `SIGHASH_ALL` and Taproot's `SIGHASH_DEFAULT`. P2WSH change is shown as change only for a registered
wallet. No taproot multisig, no script trees, no legacy P2PKH
signing. The full list is in
jitsu-in-pico's `docs/limitations.md`.
