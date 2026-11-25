# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Complete crates.io package metadata (`authors`, `homepage`, `documentation`, `readme`, `keywords`, `categories`, `rust-version`, `include`) for `soroban-zk-core` and `soroban-zk-std`.
- Crate-level `README.md` for `soroban-zk-core`.
- Root `CHANGELOG.md` following Keep a Changelog format.
- `cargo package --workspace --no-verify` verification step in GitHub Actions CI.

### Removed
- Unused `[patch."https://github.com/rust-num/num-traits"]` override from root `Cargo.toml`.

## [0.1.4] - 2026-03-01

### Added
- Protocol 25 (`soroban-sdk` 29.x) BN254 multi-pairing Groth16 verifier and Poseidon2 host-function wrappers.
- `soroban-zk-macros` procedural macros (`include_snarkjs_vk!`, `snarkjs_vk!`, `#[zk_verifier]`).
- `soroban-zk-core` `#![no_std]` primitives: BN254 field/curve arithmetic, ElGamal encryption, Bulletproofs range proofs, Rescue-Prime, SHA-256 padding/word helpers, and volatile-zeroing guards.
