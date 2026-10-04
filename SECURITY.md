# Security policy

## Reporting a vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Use GitHub's private vulnerability reporting on this repository
([Security → Report a vulnerability](https://github.com/habakan/wasm-psbt-parser/security/advisories/new)),
or email the maintainer. Public key: https://github.com/habakan.gpg

We aim to acknowledge a report within one week and to publish a fix within 90 days.

### What to include

- a description of the problem and how it could be exploited
- its impact — for this module that usually means **a plan that does not match the PSBT**:
  a wrong amount, a wrong scriptPubKey, a wrong derivation, or an output that is hidden from the plan
- the PSBT or UR payload that reproduces it, as a file or hex
- a proposed patch, if you have one

Never include private keys or recovery phrases. If a report needs a key, generate a throwaway one.

## What this module is responsible for

It turns untrusted bytes into a `plan_t` and nothing else. It holds no keys, has **zero imports**,
and cannot call the host. Within that, a security problem is anything that makes the parser
**misrepresent the transaction**, or that reads or writes outside its own linear memory.

Things that are **not** findings on their own, because [the ABI](docs/abi.md) requires the host to
handle them:

- a host that trusts `plan_keypath_t` without re-deriving the key
- a host that does not bounds-check an offset this module returns
- a host that does not check `magic` and `version`
- rejecting input that is out of the documented range (see `## What is accepted`)

An input that makes the module loop forever or exhaust its memory **is** a finding — the host may be
a device with no way to recover.

## Scope

This repository. A problem in a host that consumes this module belongs with that host.
