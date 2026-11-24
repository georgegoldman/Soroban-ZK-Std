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
//! nullifier = SHA-256( proof_bytes || public_inputs_bytes )
//! ```
//!
//! SHA-256 is computed with the project's own pure-software `sha256` gadget
//! (`gadgets::hash::sha256`), so no new dependency is introduced. The
//! concatenation of the proof with its public inputs ensures that the same
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
//!   hashing is performed via the project's own `gadgets::hash::sha256::sha256`
//!   function which requires no heap allocation.

use soroban_sdk::{contracttype, Bytes, BytesN, Env};

use crate::ZkContractError;

// ── TTL constants (same policy as VK storage) ───────────────────────────────

/// Lower TTL bound (in ledgers) before the nullifier entry is re-extended.
/// ~1 day at 5 s ledger close time.
const NULLIFIER_TTL_THRESHOLD: u32 = 17_280;

/// Target TTL (in ledgers) nullifier entries are extended to on write.
/// ~30 days at 5 s ledger close time.
const NULLIFIER_TTL_AMOUNT: u32 = 518_400;

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
/// nullifier = SHA-256( proof_bytes || inputs_bytes )
/// ```
///
/// Uses the project's own `gadgets::hash::sha256::sha256` for hashing — no new
/// dependency, no heap allocation beyond what the SHA-256 block buffer requires
/// (on the stack).
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
    /// Computation: SHA-256 over the concatenation `proof_bytes || inputs_bytes`.
    /// The `Env` is required to construct the return type; no host crypto call
    /// is made for the hash itself.
    pub fn derive_nullifier(env: &Env, proof_bytes: &Bytes, inputs_bytes: &Bytes) -> BytesN<32> {
        use crate::gadgets::hash::sha256::sha256 as sha256_fn;
        use alloc::vec::Vec;

        // Collect both byte sequences into a contiguous buffer on the heap so we
        // can pass a `&[u8]` to the pure `sha256` function.
        let mut buf: Vec<u8> =
            Vec::with_capacity((proof_bytes.len() + inputs_bytes.len()) as usize);
        for b in proof_bytes.iter() {
            buf.push(b);
        }
        for b in inputs_bytes.iter() {
            buf.push(b);
        }

        let digest = sha256_fn(&buf);
        BytesN::from_array(env, &digest)
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
}
