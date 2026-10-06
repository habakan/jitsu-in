# Security policy

## Reporting a vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Use GitHub's private vulnerability reporting on this repository
([Security → Report a vulnerability](https://github.com/habakan/jitsu-in/security/advisories/new)),
or email the maintainer. Public key: https://github.com/habakan.gpg

Fingerprint: `8BD4 8DD6 70AF 9B34 7EA0  41CF 36D4 93A2 8A8B EB79`

We aim to acknowledge a report within one week and to publish a fix within 90 days.

### What to include

- a description of the problem and how it could be exploited
- its impact. For `parser.wasm` that usually means **a plan that does not match the PSBT**: a wrong
  amount, a wrong scriptPubKey, a wrong derivation, or an output hidden from the plan. For
  `signer.wasm` it means **signing something other than what was displayed**, accepting a plan it
  should refuse, or leaving key material behind after `signer_unload()`
- the PSBT or UR payload that reproduces it, as a file or hex
- a proposed patch, if you have one

Never include private keys or recovery phrases. If a report needs a key, generate a throwaway one.

## What each module is responsible for

`parser.wasm` turns untrusted bytes into a `plan_t` and nothing else. It holds no keys, has **zero
imports**, and cannot call the host. A security problem there is anything that makes it
**misrepresent the transaction**, or that reads or writes outside its own linear memory.

`signer.wasm` holds the key. A security problem there is anything that makes it sign something other
than the plan `signer_review()` passed, accept a plan it should refuse with one of the
[errors its ABI lists](signer/docs/abi.md#errors), or leave key material in memory after `signer_unload()`.

Things that are **not** findings on their own, because the ABI
([parser](parser/docs/abi.md), [signer](signer/docs/abi.md),
[the shared convention](docs/module-abi.md)) requires the host to handle them:

- a host that trusts `plan_keypath_t` without re-deriving the key
- a host that does not bounds-check an offset this module returns
- a host that does not check `magic` and `version`
- a host that keeps a mnemonic in a string it cannot clear, or never calls `signer_unload()`
- a host that reads the module's linear memory. Neither module isolates a key from its own host;
  what they isolate is the parser from the key
- rejecting input that is out of the documented range

An input that makes either module loop forever or exhaust its memory **is** a finding — the host may
be a device with no way to recover.

## Scope

This repository: both modules and the three host libraries shipped with each. A problem in some
other host that consumes these modules belongs with that host.
