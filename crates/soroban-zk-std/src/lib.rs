#![no_std]
extern crate alloc;

pub mod cache;
pub mod gadgets;
pub mod groth16;
pub mod host;
pub mod pairing;
pub mod poseidon2;
pub mod vk;

pub use groth16::{groth16_verify, Groth16Proof, Groth16VerifyingKey};
pub use pairing::{pairing_check, G2Affine};
pub use vk::{
    clear_proof_context, clear_vk, load_vk, save_vk, set_proof_context, vk_from_bytes,
    vk_to_bytes, G1_GENERATOR, G2_GENERATOR, OwnedVerifyingKey, VkMeta, VkStorageKey,
    VK_CHUNK_SIZE,
};

use ethnum::u256 as eth_u256;
use soroban_sdk::{contracterror, Address, Bytes, Env, U256, Vec};
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
    /// A circuit constraint was unsatisfied.
    ConstraintUnsatisfied = 6,
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
        }
    }
}

#[contract]
pub struct ZkContract;

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
    /// and clears the short-lived proof-context flag afterwards. Demonstrates
    /// the Phase-3 cleanup pattern: the temporary flag is removed whether the
    /// verification succeeds or fails.
    pub fn verify_proof(
        env: Env,
        proof_bytes: Bytes,
        public_inputs: Vec<U256>,
    ) -> Result<bool, ZkContractError> {
        let result: Result<bool, ZkError> = (|| {
            let owned = vk::load_vk(&env)?;
            let vk = owned.as_vk();

            // Mark the in-flight run with a temporary proof-context flag.
            vk::set_proof_context(&env, &proof_bytes);

            let outcome = (|| {
                let proof_buf: alloc::vec::Vec<u8> = proof_bytes.iter().collect();
                let proof = Groth16Proof::from_bytes(&proof_buf)?;
                let mut inputs: alloc::vec::Vec<eth_u256> =
                    alloc::vec::Vec::with_capacity(public_inputs.len() as usize);
                for input in public_inputs.iter() {
                    let mut buf = [0u8; 32];
                    input.to_be_bytes().copy_into_slice(&mut buf);
                    inputs.push(eth_u256::from_be_bytes(buf));
                }
                groth16_verify(&env, &vk, &proof, &inputs)
            })();

            // Always clear the proof-context flag (the Temporary entry also
            // expires automatically).
            vk::clear_proof_context(&env);
            outcome
        })();
        result.map_err(ZkContractError::from)
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
}
