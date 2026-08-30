//! Instance-storage caching of recurring BN254 cryptographic constants (Issue #124).
//!
//! The BN254 Poseidon2 permutation depends on a fixed matrix diagonal and 64
//! round-constant rows, and field arithmetic depends on the Fr modulus. These
//! values are deterministic and identical on every contract invocation, yet the
//! pure builders in [`crate::poseidon2`] rebuild them from code on each call.
//!
//! This module caches them in the contract's `StorageType::Instance` using lazy
//! initialisation: the first read within a contract computes the constant and
//! writes it to instance storage; later reads return the stored copy. The
//! instance TTL is bumped on every access so the cache stays live for as long
//! as the contract is in active use.
//!
//! ## Security
//! Instance storage is owned exclusively by the contract — external callers
//! cannot write to it — so a cached constant cannot be tampered with by a
//! third party. Because every value is also fully recomputable from code, a
//! cache miss (for example after TTL expiry) is recovered transparently with
//! no loss of correctness.

use soroban_sdk::{contracttype, Bytes, Env, Vec, U256};
use soroban_zk_core::G1Affine;

/// Copy a `Bytes` value into a fixed-size byte array for decoding.
fn bytes_to_array<const N: usize>(b: &Bytes) -> [u8; N] {
    let mut arr = [0u8; N];
    for (i, byte) in b.iter().take(N).enumerate() {
        arr[i] = byte;
    }
    arr
}

use crate::groth16::{g1_from_bytes, g2_from_bytes};
use crate::pairing::{g1_to_bytes, G2Affine};

/// Lower TTL bound (in ledgers) for the instance entry. When the remaining
/// time-to-live drops below this threshold, the entry is extended back up to
/// [`INSTANCE_BUMP_AMOUNT`]. ~1 day at 5s ledger close time.
const INSTANCE_LIFETIME_THRESHOLD: u32 = 17_280;

/// Target TTL (in ledgers) the instance entry is extended to on access.
/// ~30 days at 5s ledger close time.
const INSTANCE_BUMP_AMOUNT: u32 = 518_400;

/// Keys for the recurring cryptographic constants cached in instance storage.
#[contracttype]
#[derive(Clone)]
pub enum ConstantKey {
    /// BN254 Poseidon2 (t=3) 64 round-constant rows.
    Poseidon2RoundConstants,
    /// BN254 Poseidon2 internal matrix diagonal (M_I − I) = [1, 1, 2].
    Poseidon2MatDiag,
    /// BN254 Fr field modulus r.
    FrModulus,
    /// Canonical BN254 G1 generator point (1, 2).
    G1Generator,
    /// Canonical BN254 G2 generator point.
    G2Generator,
}

/// Bump the instance TTL so the cached constants stay live during active use.
fn bump(env: &Env) {
    env.storage()
        .instance()
        .extend_ttl(INSTANCE_LIFETIME_THRESHOLD, INSTANCE_BUMP_AMOUNT);
}

/// Return the cached BN254 Poseidon2 round constants, computing and storing
/// them on the first call within the contract.
pub fn round_constants(env: &Env) -> Vec<Vec<U256>> {
    let store = env.storage().instance();
    let value = match store.get(&ConstantKey::Poseidon2RoundConstants) {
        Some(rc) => rc,
        None => {
            let rc = crate::poseidon2::round_constants(env);
            store.set(&ConstantKey::Poseidon2RoundConstants, &rc);
            rc
        }
    };
    bump(env);
    value
}

/// Return the cached BN254 Poseidon2 matrix diagonal, computing and storing it
/// on the first call within the contract.
pub fn mat_diag(env: &Env) -> Vec<U256> {
    let store = env.storage().instance();
    let value = match store.get(&ConstantKey::Poseidon2MatDiag) {
        Some(mat) => mat,
        None => {
            let mat = crate::poseidon2::mat_diag(env);
            store.set(&ConstantKey::Poseidon2MatDiag, &mat);
            mat
        }
    };
    bump(env);
    value
}

/// Return the cached BN254 Fr modulus, computing and storing it on the first
/// call within the contract.
pub fn fr_modulus(env: &Env) -> U256 {
    let store = env.storage().instance();
    let value = match store.get(&ConstantKey::FrModulus) {
        Some(m) => m,
        None => {
            let m = crate::poseidon2::fr_modulus(env);
            store.set(&ConstantKey::FrModulus, &m);
            m
        }
    };
    bump(env);
    value
}

/// Return the cached canonical BN254 G1 generator, computing and storing it on
/// the first call within the contract.
///
/// ## Collision safety
/// The generator is stored under the `#[contracttype]` key `ConstantKey::G1Generator`.
/// Because `contracttype` keys are XDR-encoded with a type discriminant, this
/// key is distinct from any plain `Symbol`/`String` key an external dApp might
/// write to its own instance storage. A foreign entry therefore cannot
/// overwrite — or be clobbered by — the cached generator.
pub fn g1_generator(env: &Env) -> G1Affine {
    let store = env.storage().instance();
    let value = match store.get::<ConstantKey, soroban_sdk::Bytes>(&ConstantKey::G1Generator) {
        Some(b) => {
            // Cached bytes are ours; if decoding ever fails we recompute.
            g1_from_bytes(&bytes_to_array::<64>(&b)).unwrap_or(crate::vk::G1_GENERATOR)
        }
        None => {
            let b = soroban_sdk::Bytes::from_array(env, &g1_to_bytes(&crate::vk::G1_GENERATOR));
            store.set(&ConstantKey::G1Generator, &b);
            crate::vk::G1_GENERATOR
        }
    };
    bump(env);
    value
}

/// Return the cached canonical BN254 G2 generator, computing and storing it on
/// the first call within the contract. See [`g1_generator`] for the collision
/// safety rationale.
pub fn g2_generator(env: &Env) -> G2Affine {
    let store = env.storage().instance();
    let value = match store.get::<ConstantKey, soroban_sdk::Bytes>(&ConstantKey::G2Generator) {
        Some(b) => g2_from_bytes(&bytes_to_array::<128>(&b)).unwrap_or(crate::vk::G2_GENERATOR),
        None => {
            let b = soroban_sdk::Bytes::from_array(env, &crate::vk::G2_GENERATOR.to_bytes());
            store.set(&ConstantKey::G2Generator, &b);
            crate::vk::G2_GENERATOR
        }
    };
    bump(env);
    value
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ZkContract;
    use soroban_sdk::Env;

    fn env() -> Env {
        let e = Env::default();
        e.cost_estimate().budget().reset_unlimited();
        e
    }

    #[test]
    fn round_constants_lazy_init_then_cache_hit() {
        let env = env();
        let id = env.register(ZkContract, ());
        env.as_contract(&id, || {
            let store = env.storage().instance();
            // Cold: nothing cached yet.
            assert!(!store.has(&ConstantKey::Poseidon2RoundConstants));

            // First read populates the cache and matches the pure builder.
            let first = round_constants(&env);
            assert!(store.has(&ConstantKey::Poseidon2RoundConstants));
            assert_eq!(first, crate::poseidon2::round_constants(&env));

            // Second read is a cache hit returning identical data.
            let second = round_constants(&env);
            assert_eq!(first, second);
        });
    }

    #[test]
    fn mat_diag_and_modulus_are_cached() {
        let env = env();
        let id = env.register(ZkContract, ());
        env.as_contract(&id, || {
            assert_eq!(mat_diag(&env), crate::poseidon2::mat_diag(&env));
            assert_eq!(fr_modulus(&env), crate::poseidon2::fr_modulus(&env));

            let store = env.storage().instance();
            assert!(store.has(&ConstantKey::Poseidon2MatDiag));
            assert!(store.has(&ConstantKey::FrModulus));
        });
    }

    #[test]
    fn generator_cache_isolated_from_external_keys() {
        let env = env();
        let id = env.register(ZkContract, ());
        env.as_contract(&id, || {
            // Populate the cached generator.
            assert_eq!(g1_generator(&env), crate::vk::G1_GENERATOR);
            assert_eq!(g2_generator(&env), crate::vk::G2_GENERATOR);

            // An external dApp writes an unrelated value under a `Symbol` key
            // that happens to share the human-readable name "G1Generator".
            let foreign = soroban_sdk::Symbol::new(&env, "G1Generator");
            env.storage()
                .instance()
                .set(&foreign, &soroban_sdk::Bytes::from_array(&env, &[9u8; 32]));

            // Our cached generator read is unaffected and still correct.
            assert_eq!(g1_generator(&env), crate::vk::G1_GENERATOR);
            assert_eq!(g2_generator(&env), crate::vk::G2_GENERATOR);
            // The foreign entry remains distinct and untouched.
            assert!(env.storage().instance().has(&foreign));
            assert!(env.storage().instance().has(&ConstantKey::G1Generator));
        });
    }
}
