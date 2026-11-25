//! Poseidon / Poseidon2 hashing gadget (Issue #367, Phase 4).
//!
//! The BN254-native instance of Poseidon is *Poseidon2* (CAP-0075), which is
//! already implemented and tested in [`crate::poseidon2`]. This module exposes
//! it through the gadget API with **flexible input chunk dimensions**: callers
//! may supply the message already split into chunks of any width `<= rate`, and
//! each chunk is absorbed as a domain-separated block. This lets higher-level
//! circuits tune the rate for gas (fewer, wider chunks cost less) while keeping
//! a single canonical digest.

use soroban_sdk::{Env, Vec, U256};
use soroban_zk_core::ZkError;

/// Hash a flat list of BN254 field elements using the Poseidon2 sponge
/// (t=3, rate=2). Equivalent to [`crate::poseidon2::hash_to_field`].
pub fn poseidon_hash(env: &Env, inputs: &[U256]) -> U256 {
    crate::poseidon2::hash_to_field(env, inputs)
}

/// Hash a message supplied as pre-chunked blocks. Each chunk is absorbed
/// separately, giving domain separation between chunks. Every chunk must have
/// width `<= rate` (2 for BN254 t=3); the last chunk may be shorter.
///
/// The overall digest is the Poseidon2 squeeze after all chunks are absorbed.
pub fn poseidon_hash_chunked(env: &Env, chunks: &[Vec<U256>]) -> Result<U256, ZkError> {
    let rate: u32 = 2;
    let mut sponge = crate::poseidon2::Poseidon2Sponge::new(env);
    for chunk in chunks {
        if chunk.len() > rate {
            return Err(ZkError::InvalidInput);
        }
        // Convert the soroban Vec chunk into a stack slice for the sponge.
        let mut buf = [U256::from_u128(env, 0), U256::from_u128(env, 0)];
        for (i, x) in chunk.iter().enumerate() {
            buf[i] = x;
        }
        sponge.absorb(&buf[..chunk.len() as usize]);
    }
    Ok(sponge.squeeze())
}

/// Poseidon sponge configurable at the type level via the existing Poseidon2
/// implementation. Provided for API symmetry with the other hashing gadgets.
pub use crate::poseidon2::Poseidon2Sponge;

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{vec, Env};

    fn env() -> Env {
        let e = Env::default();
        e.cost_estimate().budget().reset_unlimited();
        e
    }

    #[test]
    fn chunked_matches_flat_for_two_elements() {
        let env = env();
        let a = U256::from_u128(&env, 1);
        let b = U256::from_u128(&env, 2);
        let flat = poseidon_hash(&env, &[a.clone(), b.clone()]);
        let chunked = poseidon_hash_chunked(&env, &[vec![&env, a, b]]).unwrap();
        assert_eq!(flat, chunked);
    }

    #[test]
    fn chunked_rejects_oversized_chunk() {
        let env = env();
        let a = U256::from_u128(&env, 1);
        let b = U256::from_u128(&env, 2);
        let c = U256::from_u128(&env, 3);
        assert_eq!(
            poseidon_hash_chunked(&env, &[vec![&env, a, b, c]]),
            Err(ZkError::InvalidInput)
        );
    }

    #[test]
    fn chunked_is_deterministic() {
        let env = env();
        let a = U256::from_u128(&env, 7);
        let b = U256::from_u128(&env, 11);
        let c = U256::from_u128(&env, 13);
        let first = poseidon_hash_chunked(
            &env,
            &[vec![&env, a.clone()], vec![&env, b.clone(), c.clone()]],
        )
        .unwrap();
        let second = poseidon_hash_chunked(&env, &[vec![&env, a], vec![&env, b, c]]).unwrap();
        assert_eq!(first, second);
    }
}
