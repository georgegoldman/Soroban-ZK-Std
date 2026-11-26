//! Zero-knowledge hashing gadgets (Issue #367, Phase 4).
//!
//! - [`mimc`]: circomlib-compatible MiMC-7 and MiMC Feistel sponge over BN254 Fr.
//! - [`poseidon`]: BN254 Poseidon2 with flexible input chunk dimensions.
//! - [`rescue_prime`]: Rescue-Prime sponge over BN254 Fr (pure software).
//! - [`sha256`]: standard SHA-256 over field-element byte streams (pure software).

pub mod mimc;
pub mod poseidon;
pub mod rescue_prime;
pub mod sha256;

pub use sha256::FieldByteAlign;
