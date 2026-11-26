//! Circuit building blocks, gadgets, and ZK hashers (Issue #367).
//!
//! This module collects the gadget suite required to assemble advanced
//! zero-knowledge conditions inside a verifier:
//!
//! - [`boolean`]: base boolean & bitwise operations (bit-splitting, AND/OR/XOR,
//!   equality, multiplexer, single-bit safety).
//! - [`nonnative`]: non-native arithmetic over a foreign field using multi-limbed
//!   coordinates with carry-tracked addition, reduced multiplication, and
//!   complete modular arithmetic (`add_mod`, `sub`, `neg`, `inv`).
//! - [`lut`]: functional lookup tables for cheap, gas-friendly constraint checks.
//! - [`hash`]: ZK-friendly (Poseidon2, Rescue-Prime) and standard (SHA-256)
//!   hashing gadgets.

pub mod boolean;
pub mod hash;
pub mod lut;
pub mod nonnative;
