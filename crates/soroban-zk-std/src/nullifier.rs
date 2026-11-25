//! Anti-replay tracking for ZK verification contexts (Issue #467).
//!
//! A valid Groth16 proof is a static byte string — nothing inside the proof
//! itself prevents an attacker from submitting the *same* proof a second time.
//! This module provides a lightweight, opt-in nullifier registry that records
//! a cryptographic commitment to each accepted proof and rejects any duplicate
//! submission.
//!
//! ## Design
//!
//! **Nullifier derivation** — For each proof we derive a 32-byte nullifier:
//!
//! ```text
//! nullifier = SHA-256(
//!     "soroban-zk-nullifier-v1"
//!     || (proof_bytes.len() as u32).to_be_bytes()
//!     || proof_bytes
//!     || (inputs_bytes.len() as u32).to_be_bytes()
//!     || inputs_bytes
//! )
//! ```
//!
//! SHA-256 is computed via Soroban's native `env.crypto().sha256` host
//! precompile over a host-managed `Bytes` preimage assembled with
//! `Bytes::append` (zero guest heap allocation). The domain-separation tag and
//! big-endian `u32` length prefixes prevent ambiguity/collision between
//! different `(proof_bytes, inputs_bytes)` splits (e.g. `([1, 2], [3])` vs
//! `([1], [2, 3])`). The inclusion of public inputs ensures that the same
//! circuit proof submitted with *different* public inputs (e.g. a different
//! recipient) still produces a distinct nullifier and is therefore treated as
//! an independent event.
//!
//! **Storage layout** — Nullifiers are persisted under `StorageType::Persistent`
//! using the [`NullifierKey`] `#[contracttype]` key. Each entry stores a
//! `bool` (`true` = spent). TTL is extended on every write so entries outlive
//! the proof they protect.
//!
//! **`NullifierSet` trait** — Contracts that want to roll their own storage
//! strategy (e.g. a Merkle tree) can implement this trait. The concrete
//! [`NullifierStore`] covers the standard Soroban-persistent-storage case.
//!
//! ## Usage
//!
//! ```rust,ignore
//! use soroban_zk_std::nullifier::NullifierStore;
//!
//! let store = NullifierStore::new(&env);
//! store.mark_spent(&env, &proof_bytes, &inputs_bytes)?;  // first use → Ok(())
//! store.mark_spent(&env, &proof_bytes, &inputs_bytes)?;  // replay    → Err(ReplayDetected)
//! ```
//!
//! ## Security notes
//!
//! * **No constant-time requirement** — The nullifier check is a simple storage
//!   lookup (`has`) followed by a storage write (`set`). Because the nullifier
//!   *itself* commits only to the already-public proof bytes and public inputs,
//!   there is no side-channel concern that would require a constant-time
//!   comparison here.
//! * **Rollback safety** — Soroban's persistent storage is committed atomically
//!   with the transaction. If the calling contract panics or the transaction
//!   fails after `mark_spent` is called, the storage write is rolled back and
//!   the nullifier is **not** recorded.
//! * **No standard library** — This module is strictly `#![no_std]`. All
//!   hashing is performed via Soroban's native `env.crypto().sha256` host
//!   precompile with zero guest heap allocation.

use soroban_sdk::{contracttype, Bytes, BytesN, Env};

use crate::ZkContractError;

// ── Domain separation ────────────────────────────────────────────────────────

/// Domain separation tag prepended to every nullifier preimage.
pub const NULLIFIER_DOMAIN_TAG: &[u8] = b"soroban-zk-nullifier-v1";

// ── TTL constants (same policy as VK storage) ───────────────────────────────

/// Lower TTL bound (in ledgers) before the nullifier entry is re-extended.
/// ~1 day at 5 s ledger close time.
pub const NULLIFIER_TTL_THRESHOLD: u32 = 17_280;

/// Target TTL (in ledgers) nullifier entries are extended to on write.
/// ~30 days at 5 s ledger close time.
pub const NULLIFIER_TTL_AMOUNT: u32 = 518_400;

// ── Storage key ─────────────────────────────────────────────────────────────

/// A 32-byte nullifier key stored in `StorageType::Persistent`.
///
/// The `#[contracttype]` attribute XDR-encodes the discriminant alongside the
/// payload, so these keys are namespaced and cannot collide with plain
/// `Symbol`/`String` keys written by user code.
///
/// The inner [`BytesN<32>`] contains the SHA-256 digest of
/// `proof_bytes || public_inputs_bytes`.
#[contracttype]
#[derive(Clone)]
pub enum NullifierKey {
    /// A spent nullifier.  The inner value is the 32-byte SHA-256 digest of
    /// `proof_bytes || public_inputs_bytes`.
    Spent(BytesN<32>),
}

// ── Trait ────────────────────────────────────────────────────────────────────

/// A pluggable interface for nullifier registries.
///
/// Implement this trait to substitute the default SHA-256 / persistent-storage
/// strategy with a custom one (e.g. a Poseidon-based Merkle accumulator).
pub trait NullifierSet {
    /// Returns `true` if the nullifier derived from `proof_bytes` and
    /// `inputs_bytes` has already been recorded as spent.
    fn is_spent(&self, env: &Env, proof_bytes: &Bytes, inputs_bytes: &Bytes) -> bool;

    /// Records the nullifier as spent.
    ///
    /// Returns [`ZkContractError::ReplayDetected`] if the nullifier is already
    /// present in storage, without modifying any state. Returns
    /// [`ZkContractError::StorageError`] if the underlying write fails.
    fn mark_spent(
        &self,
        env: &Env,
        proof_bytes: &Bytes,
        inputs_bytes: &Bytes,
    ) -> Result<(), ZkContractError>;
}

// ── Concrete implementation ──────────────────────────────────────────────────

/// The standard nullifier store backed by `StorageType::Persistent`.
///
/// **Nullifier derivation:**
///
/// ```text
/// nullifier = SHA-256(
///     "soroban-zk-nullifier-v1"
///     || (proof_bytes.len() as u32).to_be_bytes()
///     || proof_bytes
///     || (inputs_bytes.len() as u32).to_be_bytes()
///     || inputs_bytes
/// )
/// ```
///
/// Uses Soroban's native `env.crypto().sha256` host precompile over a
/// host-managed [`Bytes`] preimage — zero guest heap allocation.
///
/// **Storage:** Each nullifier is persisted under a [`NullifierKey::Spent`]
/// entry with a 30-day TTL.
///
/// Create one with [`NullifierStore::new`].
#[derive(Clone)]
pub struct NullifierStore;

impl NullifierStore {
    /// Creates a new `NullifierStore`.  The store itself is stateless; all
    /// state lives in the Soroban `Env`'s persistent storage.
    #[inline]
    pub fn new(_env: &Env) -> Self {
        NullifierStore
    }

    /// Derives the 32-byte nullifier for the given `proof_bytes` and
    /// `inputs_bytes`, returning it as a host-managed [`BytesN<32>`].
    ///
    /// Computation:
    /// `SHA-256(b"soroban-zk-nullifier-v1" || len(proof_bytes) || proof_bytes || len(inputs_bytes) || inputs_bytes)`
    /// using big-endian `u32` length prefixes and Soroban's native
    /// `env.crypto().sha256` host precompile (zero guest heap allocation).
    pub fn derive_nullifier(env: &Env, proof_bytes: &Bytes, inputs_bytes: &Bytes) -> BytesN<32> {
        let mut preimage = Bytes::from_slice(env, NULLIFIER_DOMAIN_TAG);
        preimage.extend_from_array(&proof_bytes.len().to_be_bytes());
        preimage.append(proof_bytes);
        preimage.extend_from_array(&inputs_bytes.len().to_be_bytes());
        preimage.append(inputs_bytes);

        env.crypto().sha256(&preimage).to_bytes()
    }

    /// Extends the persistent-storage TTL of an existing spent nullifier entry.
    ///
    /// Returns `true` if the nullifier exists in persistent storage and its
    /// TTL was extended, or `false` if the nullifier is not present or
    /// `threshold > extend_to` (avoiding host panics on missing keys or
    /// invalid TTL bounds).
    pub fn extend_nullifier_ttl(
        env: &Env,
        nullifier: &BytesN<32>,
        threshold: u32,
        extend_to: u32,
    ) -> bool {
        if threshold > extend_to {
            return false;
        }
        let key = NullifierKey::Spent(nullifier.clone());
        let store = env.storage().persistent();
        if !store.has(&key) {
            return false;
        }
        store.extend_ttl(&key, threshold, extend_to);
        true
    }
}

impl NullifierSet for NullifierStore {
    fn is_spent(&self, env: &Env, proof_bytes: &Bytes, inputs_bytes: &Bytes) -> bool {
        let nullifier = Self::derive_nullifier(env, proof_bytes, inputs_bytes);
        env.storage()
            .persistent()
            .has(&NullifierKey::Spent(nullifier))
    }

    fn mark_spent(
        &self,
        env: &Env,
        proof_bytes: &Bytes,
        inputs_bytes: &Bytes,
    ) -> Result<(), ZkContractError> {
        let nullifier = Self::derive_nullifier(env, proof_bytes, inputs_bytes);
        let key = NullifierKey::Spent(nullifier);
        let store = env.storage().persistent();

        // Reject replays before touching state.
        if store.has(&key) {
            return Err(ZkContractError::ReplayDetected);
        }

        store.set(&key, &true);
        store.extend_ttl(&key, NULLIFIER_TTL_THRESHOLD, NULLIFIER_TTL_AMOUNT);
        Ok(())
    }
}

// ── Utility: serialize public inputs for hashing ─────────────────────────────

/// Serialises a `Vec<U256>` of public inputs into a flat `Bytes` buffer
/// (big-endian, 32 bytes per element) for inclusion in the nullifier hash.
///
/// This is provided as a convenience so callers do not need to reimplement
/// the serialisation themselves.
pub fn inputs_to_bytes(env: &Env, inputs: &soroban_sdk::Vec<soroban_sdk::U256>) -> Bytes {
    let mut buf = Bytes::new(env);
    for input in inputs.iter() {
        let be = input.to_be_bytes();
        let mut arr = [0u8; 32];
        for i in 0..32u32 {
            arr[i as usize] = be.get_unchecked(i);
        }
        buf.extend_from_array(&arr);
    }
    buf
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ZkContract;
    use soroban_sdk::{Bytes, Env, U256};

    fn env() -> Env {
        let e = Env::default();
        e.cost_estimate().budget().reset_unlimited();
        e
    }

    // Helper: register the contract so we can call `as_contract`
    fn setup() -> (Env, soroban_sdk::Address) {
        let env = env();
        let id = env.register(ZkContract, ());
        (env, id)
    }

    // Build a short proof-bytes and inputs-bytes for testing.
    fn dummy_proof(env: &Env) -> Bytes {
        Bytes::from_array(env, &[1u8, 2, 3, 4, 5, 6, 7, 8])
    }

    fn dummy_inputs(env: &Env) -> Bytes {
        Bytes::from_array(env, &[0u8; 32])
    }

    // ── NullifierStore unit tests ────────────────────────────────────────────

    #[test]
    fn first_mark_succeeds() {
        let (env, id) = setup();
        env.as_contract(&id, || {
            let store = NullifierStore::new(&env);
            let proof = dummy_proof(&env);
            let inputs = dummy_inputs(&env);
            assert!(!store.is_spent(&env, &proof, &inputs));
            assert!(store.mark_spent(&env, &proof, &inputs).is_ok());
        });
    }

    #[test]
    fn second_mark_returns_replay_detected() {
        let (env, id) = setup();
        env.as_contract(&id, || {
            let store = NullifierStore::new(&env);
            let proof = dummy_proof(&env);
            let inputs = dummy_inputs(&env);

            store.mark_spent(&env, &proof, &inputs).unwrap();

            let err = store.mark_spent(&env, &proof, &inputs).unwrap_err();
            assert_eq!(err, ZkContractError::ReplayDetected);
        });
    }

    #[test]
    fn is_spent_reflects_state() {
        let (env, id) = setup();
        env.as_contract(&id, || {
            let store = NullifierStore::new(&env);
            let proof = dummy_proof(&env);
            let inputs = dummy_inputs(&env);

            assert!(!store.is_spent(&env, &proof, &inputs));
            store.mark_spent(&env, &proof, &inputs).unwrap();
            assert!(store.is_spent(&env, &proof, &inputs));
        });
    }

    #[test]
    fn different_proof_bytes_produce_different_nullifiers() {
        let (env, id) = setup();
        env.as_contract(&id, || {
            let store = NullifierStore::new(&env);
            let inputs = dummy_inputs(&env);
            let proof_a = Bytes::from_array(&env, &[1u8; 8]);
            let proof_b = Bytes::from_array(&env, &[2u8; 8]);

            store.mark_spent(&env, &proof_a, &inputs).unwrap();

            // proof_b is a distinct event; it has not been spent yet.
            assert!(!store.is_spent(&env, &proof_b, &inputs));
            assert!(store.mark_spent(&env, &proof_b, &inputs).is_ok());
        });
    }

    #[test]
    fn same_proof_different_inputs_produces_distinct_nullifiers() {
        let (env, id) = setup();
        env.as_contract(&id, || {
            let store = NullifierStore::new(&env);
            let proof = dummy_proof(&env);
            let inputs_a = Bytes::from_array(&env, &[0u8; 32]);
            let inputs_b = Bytes::from_array(&env, &[1u8; 32]);

            store.mark_spent(&env, &proof, &inputs_a).unwrap();

            // The same proof with different public inputs is treated as a new event.
            assert!(!store.is_spent(&env, &proof, &inputs_b));
            assert!(store.mark_spent(&env, &proof, &inputs_b).is_ok());
        });
    }

    #[test]
    fn nullifier_persists_in_storage_under_namespaced_key() {
        let (env, id) = setup();
        env.as_contract(&id, || {
            let store = NullifierStore::new(&env);
            let proof = dummy_proof(&env);
            let inputs = dummy_inputs(&env);

            store.mark_spent(&env, &proof, &inputs).unwrap();

            // Confirm the raw key exists in persistent storage.
            let nullifier = NullifierStore::derive_nullifier(&env, &proof, &inputs);
            let key = NullifierKey::Spent(nullifier);
            assert!(env.storage().persistent().has(&key));
        });
    }

    #[test]
    fn inputs_to_bytes_serialises_correctly() {
        let (env, id) = setup();
        env.as_contract(&id, || {
            let inputs =
                soroban_sdk::vec![&env, U256::from_u128(&env, 0), U256::from_u128(&env, 1)];
            let buf = inputs_to_bytes(&env, &inputs);
            // Two 32-byte elements → 64 bytes.
            assert_eq!(buf.len(), 64);
        });
    }

    #[test]
    fn derive_nullifier_is_deterministic() {
        let (env, id) = setup();
        env.as_contract(&id, || {
            let proof = dummy_proof(&env);
            let inputs = dummy_inputs(&env);
            let n1 = NullifierStore::derive_nullifier(&env, &proof, &inputs);
            let n2 = NullifierStore::derive_nullifier(&env, &proof, &inputs);
            assert_eq!(n1, n2);
        });
    }

    #[test]
    fn mark_spent_does_not_write_on_replay() {
        // Verify that a replay attempt leaves storage unchanged (no double-write).
        let (env, id) = setup();
        env.as_contract(&id, || {
            let store = NullifierStore::new(&env);
            let proof = dummy_proof(&env);
            let inputs = dummy_inputs(&env);

            store.mark_spent(&env, &proof, &inputs).unwrap();

            // Attempt replay — must fail, must not panic.
            let result = store.mark_spent(&env, &proof, &inputs);
            assert_eq!(result, Err(ZkContractError::ReplayDetected));

            // Storage entry count: nullifier key is present exactly once.
            let nullifier = NullifierStore::derive_nullifier(&env, &proof, &inputs);
            assert!(env
                .storage()
                .persistent()
                .has(&NullifierKey::Spent(nullifier)));
        });
    }

    #[test]
    fn derive_nullifier_prevents_concatenation_collision() {
        let (env, id) = setup();
        env.as_contract(&id, || {
            // (proof=[1, 2], inputs=[3]) vs (proof=[1], inputs=[2, 3])
            let proof_a = Bytes::from_array(&env, &[1u8, 2u8]);
            let inputs_a = Bytes::from_array(&env, &[3u8]);
            let proof_b = Bytes::from_array(&env, &[1u8]);
            let inputs_b = Bytes::from_array(&env, &[2u8, 3u8]);

            let n_a = NullifierStore::derive_nullifier(&env, &proof_a, &inputs_a);
            let n_b = NullifierStore::derive_nullifier(&env, &proof_b, &inputs_b);
            assert_ne!(n_a, n_b);

            // Boundary splits with empty buffers must also remain distinct.
            let empty = Bytes::new(&env);
            let full = Bytes::from_array(&env, &[1u8, 2u8, 3u8]);
            let n_empty_proof = NullifierStore::derive_nullifier(&env, &empty, &full);
            let n_empty_inputs = NullifierStore::derive_nullifier(&env, &full, &empty);
            let n_both_empty = NullifierStore::derive_nullifier(&env, &empty, &empty);

            assert_ne!(n_empty_proof, n_empty_inputs);
            assert_ne!(n_empty_proof, n_a);
            assert_ne!(n_empty_inputs, n_a);
            assert_eq!(
                n_both_empty,
                NullifierStore::derive_nullifier(&env, &empty, &empty)
            );
        });
    }

    #[test]
    fn derive_nullifier_applies_domain_separation_and_length_prefixes() {
        let (env, id) = setup();
        env.as_contract(&id, || {
            let proof = Bytes::from_array(&env, &[0xAAu8, 0xBBu8]);
            let inputs = Bytes::from_array(&env, &[0xCCu8]);

            let derived = NullifierStore::derive_nullifier(&env, &proof, &inputs);

            // Build expected preimage manually.
            let mut expected_preimage = Bytes::from_slice(&env, b"soroban-zk-nullifier-v1");
            expected_preimage.extend_from_array(&2u32.to_be_bytes());
            expected_preimage.append(&proof);
            expected_preimage.extend_from_array(&1u32.to_be_bytes());
            expected_preimage.append(&inputs);
            let expected = env.crypto().sha256(&expected_preimage).to_bytes();

            assert_eq!(derived, expected);

            // Must not equal unprefixed, undomained concatenation hash.
            let mut raw = proof.clone();
            raw.append(&inputs);
            let raw_digest = env.crypto().sha256(&raw).to_bytes();
            assert_ne!(derived, raw_digest);
        });
    }

    #[test]
    fn extend_nullifier_ttl_handles_existing_missing_and_invalid_bounds() {
        let (env, id) = setup();
        env.as_contract(&id, || {
            let store = NullifierStore::new(&env);
            let proof = dummy_proof(&env);
            let inputs = dummy_inputs(&env);
            let nullifier = NullifierStore::derive_nullifier(&env, &proof, &inputs);

            // Negative case: missing key returns false without panicking.
            assert!(!NullifierStore::extend_nullifier_ttl(
                &env,
                &nullifier,
                NULLIFIER_TTL_THRESHOLD,
                NULLIFIER_TTL_AMOUNT,
            ));

            // Mark spent, then verify invalid bounds (threshold > extend_to) return false.
            store.mark_spent(&env, &proof, &inputs).unwrap();
            assert!(!NullifierStore::extend_nullifier_ttl(
                &env,
                &nullifier,
                NULLIFIER_TTL_AMOUNT,
                NULLIFIER_TTL_THRESHOLD,
            ));

            // Happy path: valid bounds on an existing nullifier return true.
            assert!(NullifierStore::extend_nullifier_ttl(
                &env,
                &nullifier,
                NULLIFIER_TTL_THRESHOLD,
                NULLIFIER_TTL_AMOUNT,
            ));
        });
    }

    #[test]
    fn derive_nullifier_host_sha256_reduces_cpu_instructions() {
        use crate::gadgets::hash::sha256::sha256 as sw_sha256;
        use alloc::vec::Vec;

        let (env, id) = setup();
        env.as_contract(&id, || {
            // Realistic Groth16 proof (256 bytes) + 4 public inputs (128 bytes).
            let proof = Bytes::from_array(&env, &[0x42u8; 256]);
            let inputs = Bytes::from_array(&env, &[0x11u8; 128]);

            // Measure host precompile path.
            env.cost_estimate().budget().reset_unlimited();
            let host_before = env.cost_estimate().budget().cpu_instruction_cost();
            let _host_digest = NullifierStore::derive_nullifier(&env, &proof, &inputs);
            let host_cost = env.cost_estimate().budget().cpu_instruction_cost() - host_before;

            // Measure legacy byte-by-byte copy + pure-Rust software SHA-256 path.
            env.cost_estimate().budget().reset_unlimited();
            let sw_before = env.cost_estimate().budget().cpu_instruction_cost();
            let mut buf: Vec<u8> = Vec::with_capacity((proof.len() + inputs.len()) as usize);
            for b in proof.iter() {
                buf.push(b);
            }
            for b in inputs.iter() {
                buf.push(b);
            }
            let sw_digest = BytesN::from_array(&env, &sw_sha256(&buf));
            let sw_cost = env.cost_estimate().budget().cpu_instruction_cost() - sw_before;

            assert_eq!(sw_digest.len(), 32);
            assert!(
                host_cost < sw_cost,
                "expected host sha256 ({host_cost} insns) to use fewer CPU instructions than legacy byte-copy + software sha256 ({sw_cost} insns)"
            );
        });
    }
}
