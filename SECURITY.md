# Security Policy

Soroban-ZK-Std is cryptographic infrastructure for Stellar Protocol 25 (X-Ray).
We take soundness bugs, side channels, memory-safety flaws, and supply-chain
attacks seriously.

## Supported Versions

| Crate / Branch | Status | Security Fixes |
| --- | --- | --- |
| `main` (latest commit) | Active | Supported |
| `soroban-zk-core` (latest release, `0.1.x`) | Active | Supported |
| `soroban-zk-std` (latest release, `0.1.x`) | Active | Supported |
| Older tags / unmaintained forks | Unsupported | Not supported |

Only the latest commit on `main` and the most recently published release of each
crate receive security fixes.

## Reporting a Vulnerability

**Please do not open a public issue or PR for security problems.**

1. Use GitHub's private reporting channel: **Security -> Report a vulnerability**
   at <https://github.com/georgegoldman/Soroban-ZK-Std/security/advisories/new>.
2. Include: affected crate/version or commit SHA, technical description, security
   impact (soundness, DoS, side-channel, or supply-chain), and a proof of concept
   or failing test if available.
3. Response SLA: you will receive an acknowledgement within **72 hours** and a
   triage/status update within **7 days**. We coordinate disclosure timelines
   with reporters and credit you in the advisory unless you prefer to remain
   anonymous.

## Audit Scope

### In Scope

- Proof-system soundness and completeness bugs (Groth16, PLONK-KZG, Halo2-IPA,
  Bulletproofs, STARK/FRI helpers)
- Field/curve arithmetic errors, canonical encoding bypasses, off-curve or
  low-order subgroup acceptance, and proof malleability
- Timing or cache side-channel leaks in operations handling secret scalars or
  viewing keys
- Memory-safety or undefined behavior in `unsafe` code (`zeroize.rs` volatile
  writes)
- Budget/DoS vectors (stack overflow within 64 KB, WASM bloat past 64 KB, or
  unbounded allocation/CPU exhaustion inside a single Soroban transaction)
- Storage key collisions, missing authorization checks on VK rotation, or
  incomplete state rollback across failed verification runs
- Supply-chain attacks targeting this repository, its CI workflows, frontend
  dependencies, or Cargo dependencies

### Out of Scope

- Vulnerabilities in third-party hosting services or user wallets
- Social engineering or attacks requiring an already-compromised maintainer
  account
- Software-fallback (`arkworks`) timing behavior during local unit tests when
  not compiled into on-chain WASM contracts

## Threat Model & Trust Boundaries

### 1. Curve & Subgroup Validation (CAP-0074 Boundary)

- **Threat**: An attacker submits malformed coordinates (`x >= p` or `y >= p`),
  points not on the BN254 curve `y^2 = x^3 + 3`, or G2 points in a small-order
  cofactor subgroup to forge pairings or induce invalid-curve attacks.
- **Mitigation**: `host.rs` (`g1_from_host_bytes`, `g2_from_host_bytes`),
  `pairing.rs` (`validate_g2_coords`), and `vk.rs` (`vk_from_bytes`) enforce
  strict fixed byte lengths (`64 B` G1, `128 B` G2, `32 B` Fr), canonical field
  bounds (`< Fq` / `< Fr`), on-curve equations, and prime-order subgroup checks
  before invoking `bn254_multi_pairing_check`. Corrupted or truncated payloads
  fail closed with `ZkError::DeserializationError`.

### 2. Fiat-Shamir Transcripts & Domain Separation (DSTs)

- **Threat**: Weak Fiat-Shamir challenges (omitting public inputs, verification
  keys, or protocol identifiers from transcript absorption) allow a prover to
  grind challenges or replay challenges across distinct proof systems/circuits.
- **Mitigation**: Transcript implementations absorb explicit domain separation
  tags (DSTs) and canonical big-endian encodings of public parameters and
  commitments before squeezing verifier challenges. Callers integrating custom
  circuits must bind application context (contract ID, network passphrase,
  recipient/asset identifiers) into the public inputs.

### 3. Replay Protection & Proof Malleability (`nullifier.rs`)

- **Threat**: Re-submitting an accepted proof triggers duplicate state
  transitions; additionally, Groth16 proofs `(A, B, C)` can be re-randomized
  into distinct valid encodings for the same statement.
- **Mitigation**: `NullifierStore` persists `SHA-256(proof_bytes || public_inputs_bytes)`
  under `NullifierKey::Spent(BytesN<32>)` in `StorageType::Persistent` and
  checks `is_spent` before running expensive pairing verification. Because
  `NullifierStore` hashes raw proof bytes, applications that must defend against
  Groth16 proof re-randomization (such as shielded asset spends) should also
  expose a circuit-enforced nullifier (e.g., `Poseidon2(secret, commitment)`) as
  a public input and enforce uniqueness via a custom `NullifierSet`.
- **Archival note**: Persistent nullifier entries carry a 30-day TTL
  (`518,400` ledgers) extended on write; long-lived protocols must renew TTLs or
  manage archival restoration to prevent post-expiry replay.

### 4. Storage Authorization & Rollback Safety (`vk.rs`, `cache.rs`)

- **Threat**: Unauthorized verification key replacement lets an attacker forge
  proofs for arbitrary statements; partial cleanup on failed verification leaves
  stale temporary state.
- **Mitigation**: `save_vk` and `clear_vk` are low-level helpers—calling
  contracts **must** gate them with `admin.require_auth()` (as shown in
  `ZkContract::set_verifying_key`). `VerificationContext` clears
  `ProofContextKey::Active` via `Drop` on normal and `?`-error returns, backed
  by Soroban's atomic host rollback on traps. All internal keys (`VkStorageKey`,
  `NullifierKey`, `ConstantKey`, `ProofContextKey`) use `#[contracttype]` enums
  to prevent collisions with external `Symbol`/`String` keys.

### 5. Constant-Time Guarantees & Memory Hygiene (`zeroize.rs`)

- **Guarantees**: Core BN254 modular field operations (`add`, `sub`, `mul`,
  inversion) in `soroban-zk-core` avoid secret-dependent branches and table
  lookups. Temporary stack and heap secrets wrapped in `SensitiveBuffer<T>` or
  `SensitiveVec<T>` are wiped via `core::ptr::write_volatile` on `Drop` so LLVM
  cannot elide zeroization.
- **Known Limitations**:
  - On-chain Soroban verifiers operate on **public** proofs and public inputs;
    constant-time guarantees primarily protect off-chain provers and viewing-key
    decryption (`ElGamalCiphertext::decrypt_amount_point`).
  - `write_volatile` prevents dead-store elimination in WASM guest linear memory
    but cannot wipe copies made by dereferencing `Copy` types into unwrapped
    locals, nor does it inspect opaque host-managed `Bytes` handles.
  - All `unsafe` pointer code in `zeroize.rs` is gated by Miri tests
    (`cargo +nightly miri test -p soroban-zk-core --lib`).

### 6. CI Supply-Chain Gates (PolinRider & Contributor Guard)

Malicious pull requests ("PolinRider"-style droppers) have targeted this
repository. Defense-in-depth CI gates enforce supply-chain safety before any
build or Node/pnpm execution:

- **Pre-build malware scanner (`scripts/check-malware.py`, `.github/workflows/security-scan.yml`, and `docs-checker.yml` `security-gate`)**:
  Blocks hidden whitespace payloads, obfuscated `_0x...` identifiers,
  `init`/`api.js`/`postcss.config*` droppers, install-time hooks in
  `package.json`, auto-running `.vscode/tasks.json`, fake font binaries, and
  base64-encoded Rust payloads.
- **Contributor guard (`scripts/contributor-guard.py`, `.github/workflows/contributor-guard.yml`)**:
  Runs read-only metadata and diff checks on every PR without executing PR code,
  blocking forbidden binaries (`.wasm`, `.rlib`, fonts, archives), unauthorized
  edits to maintainer-only security/CI files, and unrequested `Cargo.lock`
  changes.
- **Dependency audit (`deny.toml`)**: `cargo-deny` audits licenses, bans, and
  RustSec advisories in CI; every ignored advisory requires documented
  justification.
- **Node/pnpm safety**: `docs-checker.yml` installs frontend dependencies with
  `pnpm install --frozen-lockfile --ignore-scripts` strictly after `security-gate`
  passes.
- **Maintainer review hygiene**: Inspect diffs on GitHub (`gh pr diff <N>`)
  before checking out an untrusted branch, and rotate credentials immediately if
  exposure is suspected.

## Cryptographic Assumptions

1. **BN254 (alt_bn128) Pairing Security**: Groth16 and PLONK-KZG security rely
   on the hardness of the discrete logarithm and q-SDH / knowledge-of-exponent
   assumptions over BN254 (~100-bit concrete security level following Kim-Barbulescu
   NFS advances, standard across Ethereum EIP-196/197 and Stellar CAP-0074).
2. **Trusted Setup Boundaries**: Groth16 requires a circuit-specific ceremony
   (powers-of-tau + phase 2); PLONK-KZG requires a universal SRS; Halo2-IPA,
   Bulletproofs, and FRI/STARK helpers are transparent (no trusted setup).
3. **Hash Collision & Preimage Resistance**: CAP-0075 `Poseidon2`, Rescue-Prime,
   and `gadgets::hash::sha256` (FIPS-180-4) are assumed collision- and
   preimage-resistant. Note that 256-bit SHA-256 outputs can exceed the 254-bit
   BN254 scalar modulus `r` and must be reduced or truncated explicitly before
   use as BN254 scalar field inputs.
4. **Protocol 25 Host Soundness**: On-chain contracts trust the Stellar validator
   runtime's implementation of CAP-0074 (`bn254_g1_add`, `bn254_g1_mul`,
   `bn254_multi_pairing_check`) and CAP-0075 (`poseidon2_permutation`) as well as
   Soroban's deterministic WASM execution and atomic transaction rollback.
