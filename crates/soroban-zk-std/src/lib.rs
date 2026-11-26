#![no_std]
extern crate alloc;

pub mod bls12_381_kzg;
pub mod cache;
pub mod events;
pub mod gadgets;
pub mod groth16;
pub mod halo2;
pub mod host;
pub mod merkle_tree;
pub mod nullifier;
pub mod pairing;
pub mod plonk_kzg;
pub mod poseidon2;
pub mod stark;
pub use gadgets::hash::rescue_prime;
pub mod telemetry;
/// Noir / Barretenberg UltraHonk verification (Issue #574).
pub mod ultrahonk;
pub mod verifier;
pub mod vk;
pub mod zkvm;

/// Compile-time SnarkJS verifying-key embedding and the `#[zk_verifier]`
/// contract attribute (Issue #567). Enabled by the default `macros` feature.
#[cfg(feature = "macros")]
pub use soroban_zk_macros::{include_snarkjs_vk, snarkjs_vk, zk_verifier};

/// Implementation detail of the `soroban-zk-macros` expansions. Not public API.
#[doc(hidden)]
pub mod __private {
    pub use ethnum::u256;
    pub use soroban_zk_core::G1Affine;
}

#[cfg(feature = "contract")]
use crate::nullifier::NullifierSet;

pub use bls12_381_kzg::{
    barycentric_evaluate, compress_g1, kzg_commitment_to_versioned_hash, verify_kzg_blob_proof,
    verify_kzg_proof, verify_kzg_proof_batch, KzgOpeningProof,
};
pub use events::{
    publish_legacy_event, publish_verification_event, ZkFailureContext, ZkVerificationEvent,
    ZkVerificationFailure, ZkVerificationStage,
};
pub use groth16::{groth16_verify, groth16_verify_batch, Groth16Proof, Groth16VerifyingKey};
pub use halo2::{Halo2StorageKey, LookupTable, PermutationKey};
pub use merkle_tree::{
    IncrementalMerkleTree, MerkleProof, MerkleStorageKey, MerkleTreeState, ZERO_HASHES,
};
pub use pairing::{pairing_check, G2Affine};
pub use plonk_kzg::{verify_plonk_kzg, verify_plonk_kzg_batch};
pub use ultrahonk::{
    derive_challenges, verify_ultrahonk, verify_ultrahonk_parsed, ChallengeHash,
    UltraHonkChallenges, UltraHonkProof, UltraHonkVk,
};
pub use vk::{
    clear_proof_context, clear_vk, load_vk, save_vk, set_proof_context, vk_from_bytes, vk_to_bytes,
    OwnedVerifyingKey, VerificationContext, VkMeta, VkStorageKey, G1_GENERATOR, G2_GENERATOR,
    VK_CHUNK_SIZE,
};

pub use rescue_prime::{
    rescue_prime_hash, rescue_prime_hash_cached, RescueParams, RescueSponge, ROUNDS, STATE,
};
pub use zkvm::{
    mask_bn254_fr, risc0_claim_digest_from_journal, risc0_groth16_vk, sp1_committed_values_digest,
    sp1_groth16_vk, split_digest, verify_risc0_journal, verify_risc0_receipt, verify_sp1_receipt,
    Risc0Receipt, Risc0VerifierParams, Sp1Receipt, Sp1VerifierParams,
};

use ethnum::u256 as eth_u256;
use soroban_sdk::{contracterror, Env, U256};
#[cfg(feature = "contract")]
use soroban_sdk::{Address, Bytes, Vec};
use soroban_zk_core::{Bn254, Fr, SafeFrom, ZkError};

/// Validates a Soroban U256 as a BN254 scalar.
/// This prevents "out of bounds" field element errors in ZK verifiers.
pub fn validate_soroban_scalar(_env: &Env, val: U256) -> bool {
    let mut bytes = [0u8; 32];
    val.to_be_bytes().copy_into_slice(&mut bytes);

    // Convert Big-Endian bytes to ethnum u256
    let internal_val = eth_u256::from_be_bytes(bytes);

    Bn254::is_valid_scalar(internal_val)
}

/// Helper trait to add this functionality directly to the Env
pub trait ZkEnv {
    fn is_bn254_scalar(&self, val: U256) -> bool;
}

impl ZkEnv for Env {
    fn is_bn254_scalar(&self, val: U256) -> bool {
        validate_soroban_scalar(self, val)
    }
}

/// Zero-copy conversion from a Soroban host-managed [`U256`] into a validated
/// BN254 [`Fr`] field element.
///
/// This trait is designed to wrap the `env.crypto().bn254_fr_from_u256()` host
/// call when it becomes available as a native Soroban API.  The current
/// implementation performs the conversion in software via big-endian byte
/// mapping with no heap allocation, then delegates range validation to
/// [`Fr::safe_from`].
pub trait HostConvert {
    /// Converts a Soroban `U256` into a BN254 scalar field element.
    ///
    /// Returns `Err(`[`ZkError::InvalidFieldElement`]`)` if the value lies
    /// outside `[0, r)`.  Never panics; no heap allocation.
    fn fr_from_u256(&self, val: U256) -> Result<Fr, ZkError>;
}

impl HostConvert for Env {
    #[inline(always)]
    fn fr_from_u256(&self, val: U256) -> Result<Fr, ZkError> {
        // Zero-copy stack allocation: read the Soroban U256 as big-endian bytes
        // and reinterpret as an ethnum u256 for field validation.
        let mut bytes = [0u8; 32];
        val.to_be_bytes().copy_into_slice(&mut bytes);
        let raw = eth_u256::from_be_bytes(bytes);
        Fr::safe_from(raw)
    }
}

#[cfg(feature = "contract")]
use soroban_sdk::{contract, contractimpl};

/// Contract-facing error type for the `ZkContract` entry points.
///
/// `ZkError` (in `soroban-zk-core`) deliberately avoids depending on the
/// Soroban SDK, so contract methods translate it into this `#[contracterror]`
/// type, which the SDK can marshal across the host boundary.
#[contracterror]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZkContractError {
    /// A supplied value was ≥ the BN254 scalar field modulus.
    InvalidFieldElement = 1,
    /// Mismatched input lengths or empty slices.
    InvalidInput = 2,
    /// Serialized bytes could not be decoded.
    DeserializationError = 3,
    /// A raw host call trapped or was unavailable.
    HostError = 4,
    /// A storage read/write/remove failed or required data was missing.
    StorageError = 5,
    /// A ZK constraint or gadget invariant was violated by the supplied witness.
    ConstraintUnsatisfied = 6,
    /// A previously-accepted proof was submitted again (anti-replay protection).
    ///
    /// This error is returned by [`nullifier::NullifierStore::mark_spent`] (and
    /// by [`ZkContract::verify_proof`] when `anti_replay` is `true`) if the
    /// nullifier of the submitted proof + public inputs already exists in
    /// `StorageType::Persistent`.
    ReplayDetected = 7,
    /// The proof was well-formed but failed the cryptographic verification equation.
    VerificationFailed = 8,
}

impl From<ZkError> for ZkContractError {
    fn from(e: ZkError) -> Self {
        match e {
            ZkError::InvalidFieldElement => ZkContractError::InvalidFieldElement,
            ZkError::InvalidInput => ZkContractError::InvalidInput,
            ZkError::DeserializationError => ZkContractError::DeserializationError,
            ZkError::HostError => ZkContractError::HostError,
            ZkError::StorageError => ZkContractError::StorageError,
            ZkError::ConstraintUnsatisfied => ZkContractError::ConstraintUnsatisfied,
            // STARK / FRI failures are proof-integrity failures; the contract
            // reports them through the closest existing contract error.
            ZkError::BoundaryConstraintFailed
            | ZkError::TransitionConstraintFailed
            | ZkError::MerkleVerificationFailed
            | ZkError::FriVerificationFailed => ZkContractError::ConstraintUnsatisfied,
        }
    }
}

/// The reference `ZkContract`. Gated behind the default-on `contract` feature so
/// that contracts which only need the library (e.g. `verifier-sample`) can opt
/// out with `default-features = false` and avoid linking its exported entry
/// points (and the whole proof-system stack they pull in) into their WASM.
#[cfg(feature = "contract")]
#[contract]
pub struct ZkContract;

#[cfg(feature = "contract")]
#[contractimpl]
impl ZkContract {
    /// Benchmark function to ensure CI measures REAL library footprint.
    pub fn validate_scalar(env: Env, val: U256) -> bool {
        // This forces the compiler to include the ethnum and soroban-zk-core logic
        env.is_bn254_scalar(val)
    }

    /// Poseidon2 hash of a list of BN254 field elements, using the
    /// instance-storage cache for the round constants and matrix diagonal
    /// (Issue #124).
    ///
    /// The first invocation populates the cache from code; later invocations
    /// reuse the constants stored in `StorageType::Instance` instead of
    /// rebuilding them on every call.
    pub fn poseidon2_hash(env: Env, inputs: soroban_sdk::Vec<U256>) -> U256 {
        let mut sponge = poseidon2::Poseidon2Sponge::new_cached(&env);
        for input in inputs.iter() {
            sponge.absorb(core::slice::from_ref(&input));
        }
        sponge.squeeze()
    }

    /// Returns the Halo2 permutation key (`sigma`) for a `rows × cols` grid,
    /// lazily initialising it in `StorageType::Instance` on first use so that
    /// subsequent contract calls read the cached key instead of rebuilding it.
    pub fn halo2_permutation_key(
        env: Env,
        rows: u32,
        cols: u32,
    ) -> Result<Vec<u32>, ZkContractError> {
        let key =
            halo2::get_or_init_permutation_key(&env, rows, cols).map_err(ZkContractError::from)?;
        Ok(key.sigma)
    }

    /// Lazily builds the range-check lookup table `[0, max] -> 1`, caches it in
    /// `StorageType::Instance` under `(id, max)`, then returns the table output for
    /// `value` (a membership proof that `value <= max`).
    pub fn halo2_range_lookup(
        env: Env,
        id: u32,
        max: u32,
        value: U256,
    ) -> Result<U256, ZkContractError> {
        let lut =
            halo2::get_or_init_range_lookup_table(&env, id, max).map_err(ZkContractError::from)?;
        lut.lookup(&[value]).map_err(ZkContractError::from)
    }

    /// Persists a verification key (serialized via [`vk::vk_to_bytes`]) to
    /// `StorageType::Persistent`, chunked if necessary.
    ///
    /// **Safety:** the caller must authorize before the key is replaced, so a
    /// hostile key swap is impossible without the admin's signature.
    pub fn set_verifying_key(
        env: Env,
        admin: Address,
        vk_bytes: Bytes,
    ) -> Result<(), ZkContractError> {
        admin.require_auth();
        let owned = vk::vk_from_bytes(&env, &vk_bytes).map_err(ZkContractError::from)?;
        let vk = owned.as_vk();
        vk::save_vk(&env, &vk).map_err(ZkContractError::from)
    }

    /// Purges the on-ledger verification key (cleanup hook for key rotation).
    /// Requires the admin's authorization.
    pub fn clear_verifying_key(env: Env, admin: Address) -> Result<(), ZkContractError> {
        admin.require_auth();
        vk::clear_vk(&env);
        Ok(())
    }

    /// Loads the stored verification key, verifies a Groth16 proof against it,
    /// Verifies a zero-knowledge proof with comprehensive structured event emission.
    ///
    /// This method emits the versioned [`ZkVerificationEvent`] schema so
    /// developers and indexers can inspect verification telemetry, including:
    /// - Success/failure status
    /// - Protocol tag, public-input count, and proof byte length
    /// - Anti-replay hit, verification stage, and stable error code
    /// - A conservative static cycle-cost estimate
    ///
    /// When `anti_replay` is `true` the verifier additionally records a
    /// SHA-256 commitment over `proof_bytes || public_inputs` in
    /// `StorageType::Persistent`.  Any attempt to re-submit the same proof
    /// will return [`ZkContractError::ReplayDetected`] **before** running the
    /// pairing check, eliminating the gas cost of a redundant verification.
    ///
    /// # Event Topics
    /// Events are published with topics: `("zk_verification", "groth16", success_bool)`
    ///
    /// # Verification Stages (with event emission)
    /// 1. Anti-replay check - detects previously verified proofs
    /// 2. Verifying key load - loads VK from storage
    /// 3. Proof deserialization - decodes proof bytes into curve points
    /// 4. Public inputs validation - checks field element bounds
    /// 5. Pairing check - the cryptographic verification
    /// 6. Nullifier recording - prevents replay attacks
    pub fn verify_proof(
        env: Env,
        proof_bytes: Bytes,
        public_inputs: Vec<U256>,
        anti_replay: bool,
    ) -> Result<bool, ZkContractError> {
        use crate::events::{
            publish_verification_event, ZkFailureContext, ZkVerificationEvent, ZkVerificationStage,
        };

        let proof_length = proof_bytes.len();
        let public_inputs_count = public_inputs.len();
        let proof_system = "groth16";

        // ── Anti-replay check (fast-path: reject before expensive pairing) ──
        if anti_replay {
            let inputs_buf = nullifier::inputs_to_bytes(&env, &public_inputs);
            let nstore = nullifier::NullifierStore::new(&env);

            if nstore.is_spent(&env, &proof_bytes, &inputs_buf) {
                let error = ZkContractError::ReplayDetected;
                let event = ZkVerificationEvent::failure(
                    &env,
                    proof_system,
                    public_inputs_count,
                    proof_length,
                    anti_replay,
                    &error,
                    ZkVerificationStage::AntiReplayCheck,
                    Some(ZkFailureContext::with_info(&env, "Proof already verified")),
                );
                publish_verification_event(&env, event);
                return Err(error);
            }
        }

        let result: Result<bool, ZkError> = (|| {
            let owned = vk::load_vk(&env).inspect_err(|&e| {
                let event = ZkVerificationEvent::failure(
                    &env,
                    proof_system,
                    public_inputs_count,
                    proof_length,
                    anti_replay,
                    &ZkContractError::from(e),
                    ZkVerificationStage::VerifyingKeyLoad,
                    Some(ZkFailureContext::with_info(&env, "VK not found in storage")),
                );
                publish_verification_event(&env, event);
            })?;

            let vk = owned.as_vk();
            // RAII guard: the proof-context flag is cleared when `_ctx` drops,
            // on success, on any `?` early return, and on the error paths below.
            let _ctx = vk::VerificationContext::begin(&env, &proof_bytes);

            // A Groth16 proof is exactly 256 bytes; copy it into a stack buffer
            // instead of collecting into a heap `Vec`.
            let mut proof_buf = [0u8; 256];
            let proof = if proof_bytes.len() as usize == proof_buf.len() {
                proof_bytes.copy_into_slice(&mut proof_buf);
                Groth16Proof::from_bytes(&proof_buf)
            } else {
                Err(ZkError::DeserializationError)
            };
            let proof = proof.inspect_err(|&e| {
                let event = ZkVerificationEvent::failure(
                    &env,
                    proof_system,
                    public_inputs_count,
                    proof_length,
                    anti_replay,
                    &ZkContractError::from(e),
                    ZkVerificationStage::ProofDeserialization,
                    Some(ZkFailureContext::with_info(
                        &env,
                        "Invalid proof encoding or curve points",
                    )),
                );
                publish_verification_event(&env, event);
            })?;

            let mut inputs: alloc::vec::Vec<eth_u256> =
                alloc::vec::Vec::with_capacity(public_inputs.len() as usize);

            for (index, input) in public_inputs.iter().enumerate() {
                let mut buf = [0u8; 32];
                input.to_be_bytes().copy_into_slice(&mut buf);
                let eth_input = eth_u256::from_be_bytes(buf);

                if !Bn254::is_valid_scalar(eth_input) {
                    let event = ZkVerificationEvent::failure(
                        &env,
                        proof_system,
                        public_inputs_count,
                        proof_length,
                        anti_replay,
                        &ZkContractError::InvalidFieldElement,
                        ZkVerificationStage::PublicInputsValidation,
                        Some(ZkFailureContext::invalid_input(index as u32)),
                    );
                    publish_verification_event(&env, event);
                    return Err(ZkError::InvalidFieldElement);
                }
                inputs.push(eth_input);
            }

            groth16_verify(&env, &vk, &proof, &inputs)
        })();

        // ── Handle verification result and emit appropriate events ──
        match result {
            Ok(true) => {
                // Successful verification - record nullifier if enabled
                if anti_replay {
                    let inputs_buf = nullifier::inputs_to_bytes(&env, &public_inputs);
                    let nstore = nullifier::NullifierStore::new(&env);

                    if nstore.mark_spent(&env, &proof_bytes, &inputs_buf).is_err() {
                        let event = ZkVerificationEvent::failure(
                            &env,
                            proof_system,
                            public_inputs_count,
                            proof_length,
                            anti_replay,
                            &ZkContractError::StorageError,
                            ZkVerificationStage::NullifierRecording,
                            Some(ZkFailureContext::with_info(&env, "Storage write failed")),
                        );
                        publish_verification_event(&env, event);
                        return Err(ZkContractError::StorageError);
                    }
                }

                // Emit success event
                let event = ZkVerificationEvent::success(
                    &env,
                    proof_system,
                    public_inputs_count,
                    proof_length,
                    anti_replay,
                );
                publish_verification_event(&env, event);
                Ok(true)
            }
            Ok(false) => {
                // Pairing check returned false - proof is mathematically invalid
                let event = ZkVerificationEvent::pairing_failure(
                    &env,
                    proof_system,
                    public_inputs_count,
                    proof_length,
                    anti_replay,
                );
                publish_verification_event(&env, event);
                Ok(false)
            }
            Err(e) => {
                // Error already handled and event emitted in the verification chain
                Err(ZkContractError::from(e))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{Bytes, Env, U256};

    #[test]
    fn host_convert_zero_is_valid() {
        let env = Env::default();
        let val = U256::from_u128(&env, 0);
        assert!(env.fr_from_u256(val).is_ok());
    }

    #[test]
    fn host_convert_small_value_is_valid() {
        let env = Env::default();
        let val = U256::from_u128(&env, 42);
        assert!(env.fr_from_u256(val).is_ok());
    }

    #[test]
    fn host_convert_above_modulus_is_err() {
        let env = Env::default();
        let bytes = Bytes::from_array(&env, &[0xff_u8; 32]);
        let val = U256::from_be_bytes(&env, &bytes);
        assert_eq!(env.fr_from_u256(val), Err(ZkError::InvalidFieldElement));
    }

    #[test]
    fn host_convert_modulus_itself_is_err() {
        let env = Env::default();
        let modulus_bytes: [u8; 32] = [
            0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81,
            0x58, 0x5d, 0x97, 0x81, 0x6a, 0x91, 0x68, 0x71, 0xca, 0x8d, 0x3c, 0x20, 0x8c, 0x16,
            0xd8, 0x7c, 0xfd, 0x47,
        ];
        let bytes = Bytes::from_array(&env, &modulus_bytes);
        let val = U256::from_be_bytes(&env, &bytes);
        assert_eq!(env.fr_from_u256(val), Err(ZkError::InvalidFieldElement));
    }

    #[test]
    fn host_convert_returns_err_not_panic_on_overflow() {
        let env = Env::default();
        // u256::MAX is far above the BN254 modulus — must return Err, never panic.
        let bytes = Bytes::from_array(&env, &[0xff_u8; 32]);
        let val = U256::from_be_bytes(&env, &bytes);
        let result = env.fr_from_u256(val);
        assert!(result.is_err());
    }

    #[test]
    fn poseidon2_hash_matches_uncached_and_reuses_cache() {
        let env = Env::default();
        env.cost_estimate().budget().reset_unlimited();
        let id = env.register(ZkContract, ());
        let client = ZkContractClient::new(&env, &id);

        let inputs = soroban_sdk::vec![&env, U256::from_u128(&env, 1), U256::from_u128(&env, 2)];

        // The cached on-chain hash equals the pure (uncached) library hash.
        let raw = [U256::from_u128(&env, 1), U256::from_u128(&env, 2)];
        let expected = poseidon2::hash_to_field(&env, &raw);
        assert_eq!(client.poseidon2_hash(&inputs), expected);

        // A second invocation hits the populated instance cache and is stable.
        assert_eq!(client.poseidon2_hash(&inputs), expected);

        // The constants are present in the contract's instance storage.
        env.as_contract(&id, || {
            let store = env.storage().instance();
            assert!(store.has(&cache::ConstantKey::Poseidon2RoundConstants));
            assert!(store.has(&cache::ConstantKey::Poseidon2MatDiag));
            assert!(store.has(&cache::ConstantKey::FrModulus));
        });
    }

    #[test]
    fn halo2_permutation_key_is_cached_across_calls() {
        let env = Env::default();
        env.cost_estimate().budget().reset_unlimited();
        let id = env.register(ZkContract, ());
        let client = ZkContractClient::new(&env, &id);

        // First call lazily populates the instance cache with the identity key.
        let first = client.halo2_permutation_key(&2, &3);
        assert_eq!(first.len(), 6);
        env.as_contract(&id, || {
            assert!(env
                .storage()
                .instance()
                .has(&halo2::Halo2StorageKey::PermutationKey(2, 3)));
        });

        // Second call reads the cached key and returns identical data.
        let second = client.halo2_permutation_key(&2, &3);
        assert_eq!(second.len(), first.len());
        for i in 0..first.len() {
            assert_eq!(second.get(i).unwrap(), first.get(i).unwrap());
        }
    }

    #[test]
    fn halo2_range_lookup_uses_instance_cache() {
        let env = Env::default();
        env.cost_estimate().budget().reset_unlimited();
        let id = env.register(ZkContract, ());
        let client = ZkContractClient::new(&env, &id);

        let one = U256::from_u128(&env, 1);
        // First call caches the range table; both bounds map to 1.
        assert_eq!(
            client.halo2_range_lookup(&1, &15, &U256::from_u128(&env, 7)),
            one
        );
        env.as_contract(&id, || {
            assert!(env
                .storage()
                .instance()
                .has(&halo2::Halo2StorageKey::RangeLookupTable(1, 15)));
        });

        // Cache hit: an in-range value still resolves, an out-of-range one fails.
        assert_eq!(
            client.halo2_range_lookup(&1, &15, &U256::from_u128(&env, 15)),
            one
        );
        assert!(client
            .try_halo2_range_lookup(&1, &15, &U256::from_u128(&env, 16))
            .is_err());
    }

    // ── State-rollback safety tests (Issue #466) ─────────────────────────────

    /// After `verify_proof` returns (either success or a `StorageError` because
    /// no VK is stored), the proof-context temporary entry must not persist.
    ///
    /// This test exercises the end-to-end contract path: no VK stored → the
    /// verifier inner closure returns `ZkError::StorageError` via `load_vk`
    /// before even creating the `VerificationContext`, so the temporary flag
    /// should never have been written.
    #[test]
    fn verify_proof_leaves_no_temp_state_when_no_vk_stored() {
        let env = Env::default();
        env.cost_estimate().budget().reset_unlimited();
        let id = env.register(ZkContract, ());
        let client = ZkContractClient::new(&env, &id);

        // No VK stored → StorageError from load_vk, before VerificationContext is created.
        let proof_bytes = Bytes::from_array(&env, &[0u8; 256]);
        let inputs = soroban_sdk::vec![&env];
        let result = client.try_verify_proof(&proof_bytes, &inputs, &false);
        assert!(result.is_err(), "should fail because no VK is stored");

        // The proof-context temporary flag must not have been set.
        env.as_contract(&id, || {
            assert!(
                !env.storage().temporary().has(&vk::ProofContextKey::Active),
                "no temp state must remain after a StorageError path"
            );
        });
    }

    /// When a stored VK exists but the proof bytes are structurally invalid
    /// (wrong length), `verify_proof` must still clean up the proof-context
    /// temporary entry that `VerificationContext::begin` wrote.
    #[test]
    fn verify_proof_clears_temp_state_on_deserialization_error() {
        use vk::{OwnedVerifyingKey, G1_GENERATOR, G2_GENERATOR};

        let env = Env::default();
        env.cost_estimate().budget().reset_unlimited();
        let id = env.register(ZkContract, ());

        // Store a minimal valid VK so load_vk succeeds.
        env.as_contract(&id, || {
            let ic = alloc::vec![G1_GENERATOR, G1_GENERATOR];
            let owned = OwnedVerifyingKey {
                alpha_g1: G1_GENERATOR,
                beta_g2: G2_GENERATOR,
                gamma_g2: G2_GENERATOR,
                delta_g2: G2_GENERATOR,
                ic,
            };
            vk::save_vk(&env, &owned.as_vk()).expect("save_vk must succeed");
        });

        let client = ZkContractClient::new(&env, &id);

        // Submit a proof that is the wrong length → DeserializationError from
        // Groth16Proof::from_bytes, which fires after VerificationContext::begin.
        let bad_proof = Bytes::from_array(&env, &[0xFFu8; 128]); // wrong: must be 256 bytes
        let inputs = soroban_sdk::vec![&env, U256::from_u128(&env, 1)];
        let result = client.try_verify_proof(&bad_proof, &inputs, &false);
        assert!(result.is_err(), "wrong-length proof must be rejected");

        // Temporary storage must be clean — VerificationContext::drop must have run.
        env.as_contract(&id, || {
            assert!(
                !env.storage().temporary().has(&vk::ProofContextKey::Active),
                "VerificationContext must clear temp storage even after DeserializationError"
            );
        });
    }

    /// A well-formed 256-byte proof whose public input is out of range fails
    /// after the `VerificationContext` guard is created (stack-buffer path);
    /// the guard must still clear temporary storage.
    #[test]
    fn verify_proof_clears_temp_state_on_invalid_public_input() {
        use vk::{OwnedVerifyingKey, G1_GENERATOR, G2_GENERATOR};

        let env = Env::default();
        env.cost_estimate().budget().reset_unlimited();
        let id = env.register(ZkContract, ());

        env.as_contract(&id, || {
            let owned = OwnedVerifyingKey {
                alpha_g1: G1_GENERATOR,
                beta_g2: G2_GENERATOR,
                gamma_g2: G2_GENERATOR,
                delta_g2: G2_GENERATOR,
                ic: alloc::vec![G1_GENERATOR, G1_GENERATOR],
            };
            vk::save_vk(&env, &owned.as_vk()).expect("save_vk must succeed");
        });

        // a = G1, b = G2, c = G1: valid curve points, exactly 256 bytes.
        let mut proof = Bytes::new(&env);
        proof.extend_from_array(&pairing::g1_to_bytes(&G1_GENERATOR));
        proof.extend_from_array(&G2_GENERATOR.to_bytes());
        proof.extend_from_array(&pairing::g1_to_bytes(&G1_GENERATOR));
        assert_eq!(proof.len(), 256);

        // u256::MAX is far above the BN254 scalar modulus.
        let too_big = U256::from_be_bytes(&env, &Bytes::from_array(&env, &[0xFFu8; 32]));
        let inputs = soroban_sdk::vec![&env, too_big];
        let client = ZkContractClient::new(&env, &id);
        let result = client.try_verify_proof(&proof, &inputs, &false);
        assert_eq!(result, Err(Ok(ZkContractError::InvalidFieldElement)));

        env.as_contract(&id, || {
            assert!(
                !env.storage().temporary().has(&vk::ProofContextKey::Active),
                "VerificationContext must clear temp storage after an invalid public input"
            );
        });
    }

    /// Oversized proofs are rejected without touching the 256-byte stack
    /// buffer (no `copy_into_slice` length-mismatch panic).
    #[test]
    fn verify_proof_rejects_oversized_proof_without_panicking() {
        use vk::{OwnedVerifyingKey, G1_GENERATOR, G2_GENERATOR};

        let env = Env::default();
        env.cost_estimate().budget().reset_unlimited();
        let id = env.register(ZkContract, ());
        env.as_contract(&id, || {
            let owned = OwnedVerifyingKey {
                alpha_g1: G1_GENERATOR,
                beta_g2: G2_GENERATOR,
                gamma_g2: G2_GENERATOR,
                delta_g2: G2_GENERATOR,
                ic: alloc::vec![G1_GENERATOR, G1_GENERATOR],
            };
            vk::save_vk(&env, &owned.as_vk()).expect("save_vk must succeed");
        });

        let client = ZkContractClient::new(&env, &id);
        let proof = Bytes::from_array(&env, &[0u8; 300]);
        let inputs = soroban_sdk::vec![&env, U256::from_u128(&env, 1)];
        let result = client.try_verify_proof(&proof, &inputs, &false);
        assert_eq!(result, Err(Ok(ZkContractError::DeserializationError)));
        env.as_contract(&id, || {
            assert!(!env.storage().temporary().has(&vk::ProofContextKey::Active));
        });
    }
}
