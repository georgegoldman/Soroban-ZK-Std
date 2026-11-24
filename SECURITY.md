# Security Policy

Soroban-ZK-Std is cryptographic infrastructure for Stellar. We take soundness bugs,
side channels and supply-chain attacks seriously.

## Reporting a vulnerability

**Please do not open a public issue or PR for security problems.**

1. Use GitHub's private reporting: **Security → Report a vulnerability** on
   <https://github.com/georgegoldman/Soroban-ZK-Std/security/advisories/new>.
2. Include: affected crate/version or commit, a description, impact, and a proof of concept
   or failing test if you have one.
3. You will receive an acknowledgement within **72 hours** and a status update within
   **7 days**. We will credit you in the advisory unless you prefer to stay anonymous.

## Scope

In scope:

- Proof-system soundness/completeness bugs (Groth16, PLONK-KZG, Halo2-IPA, Bulletproofs, STARK helpers)
- Field/curve arithmetic errors, subgroup/invalid-curve acceptance, malleability
- Timing or side-channel leaks in operations that handle secret data
- Memory-safety issues in `unsafe` code (e.g. `zeroize`)
- Budget/DoS issues that make a verifier unusable in one Soroban transaction
- Supply-chain issues in this repository, its CI workflows or its dependencies

Out of scope: issues in third-party services, social engineering, or vulnerabilities that
require a compromised maintainer account.

## Supported versions

Only the latest commit on `main` and the most recently published release of each crate receive fixes.

## Contributor safety (supply-chain)

Malicious pull requests ("PolinRider"-style droppers) have targeted this repository.

- Read the diff on GitHub **before** checking a branch out: `gh pr diff <N>`.
- Never run `npm install`, build scripts or `init`-style files from an untrusted branch.
- CI blocks known indicators (`scripts/check-malware.py`): hidden whitespace payloads, obfuscated
  `_0x…` identifiers, `init`/`api.js`/`postcss.config*` droppers, install-time hooks in
  `package.json`, auto-running `.vscode/tasks.json`, fake font files, and base64-encoded Rust.
- If you think your machine or GitHub token was exposed, rotate credentials immediately and tell the maintainers.

## Dependency audit

`cargo-deny` runs in CI (`deny.toml`). Every ignored advisory is documented with a reason and
is reviewed whenever dependencies change.
