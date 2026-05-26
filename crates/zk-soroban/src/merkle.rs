//! Merkle authentication path verification for STARK proofs.
//!
//! Uses Poseidon2 (via CAP-0075) as the node hash function.
//! Spec: docs/math/merkle.md

use soroban_sdk::{Env, Vec, U256};
use zk_core::ZkError;

use crate::poseidon2::hash_to_field;

/// Maximum supported tree depth (2^32 leaves).
pub const MAX_DEPTH: usize = 32;

/// Verify a Merkle authentication path.
///
/// # Arguments
/// * `env`      — Soroban execution environment
/// * `root`     — Expected Merkle root
/// * `leaf`     — Leaf value (will be hashed as a single-element input)
/// * `index`    — Leaf index (determines left/right at each level)
/// * `path`     — Sibling hashes from leaf to root (length = tree depth)
///
/// # Returns
/// `Ok(true)` if the path is valid, `Ok(false)` if not,
/// `Err(ZkError::InvalidInput)` if the path length exceeds `MAX_DEPTH`.
pub fn verify_merkle_path(
    env: &Env,
    root: &U256,
    leaf: &U256,
    index: u64,
    path: &[U256],
) -> Result<bool, ZkError> {
    if path.len() > MAX_DEPTH {
        return Err(ZkError::InvalidInput);
    }

    // Hash the leaf value
    let mut current = hash_to_field(env, core::slice::from_ref(leaf));

    let mut idx = index;
    for sibling in path {
        // Determine ordering: if current index is even, current is left child
        let (left, right) = if idx & 1 == 0 {
            (current.clone(), sibling.clone())
        } else {
            (sibling.clone(), current.clone())
        };

        current = hash_to_field(env, &[left, right]);
        idx >>= 1;
    }

    Ok(&current == root)
}

/// Compute a Merkle root from a list of leaf values.
///
/// Leaves are hashed with Poseidon2. The tree is padded to the next power
/// of two with zero leaves if necessary.
///
/// Returns `Err(ZkError::InvalidInput)` if `leaves` is empty or exceeds
/// `2^MAX_DEPTH`.
pub fn compute_merkle_root(env: &Env, leaves: &[U256]) -> Result<U256, ZkError> {
    if leaves.is_empty() || leaves.len() > (1 << MAX_DEPTH) {
        return Err(ZkError::InvalidInput);
    }

    // Hash all leaves
    let mut layer: Vec<U256> = Vec::new(env);
    for leaf in leaves {
        let h = hash_to_field(env, core::slice::from_ref(leaf));
        layer.push_back(h);
    }

    // Pad to power of two
    let mut size = layer.len();
    let mut target = 1usize;
    while target < size {
        target <<= 1;
    }
    let zero = U256::from_u128(env, 0);
    while size < target {
        layer.push_back(zero.clone());
        size += 1;
    }

    // Build tree bottom-up
    while layer.len() > 1 {
        let mut next: Vec<U256> = Vec::new(env);
        let mut i = 0;
        while i + 1 < layer.len() {
            let left = layer.get(i as u32).unwrap();
            let right = layer.get((i + 1) as u32).unwrap();
            let parent = hash_to_field(env, &[left, right]);
            next.push_back(parent);
            i += 2;
        }
        layer = next;
    }

    Ok(layer.get(0).unwrap())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::Env;

    fn env() -> Env {
        let e = Env::default();
        e.cost_estimate().budget().reset_unlimited();
        e
    }

    #[test]
    fn single_leaf_root() {
        let env = env();
        let leaf = U256::from_u128(&env, 42);
        let root = compute_merkle_root(&env, &[leaf.clone()]).unwrap();
        // Root of a single-leaf tree is hash(leaf) padded to power-of-two
        assert_ne!(root, U256::from_u128(&env, 0));
    }

    #[test]
    fn two_leaf_path_valid() {
        let env = env();
        let leaves = [
            U256::from_u128(&env, 1),
            U256::from_u128(&env, 2),
        ];
        let root = compute_merkle_root(&env, &leaves).unwrap();

        // Build path for leaf 0: sibling is hash(leaf[1])
        let sibling = hash_to_field(&env, &[leaves[1].clone()]);
        let valid = verify_merkle_path(&env, &root, &leaves[0], 0, &[sibling]).unwrap();
        assert!(valid);
    }

    #[test]
    fn wrong_sibling_fails() {
        let env = env();
        let leaves = [
            U256::from_u128(&env, 1),
            U256::from_u128(&env, 2),
        ];
        let root = compute_merkle_root(&env, &leaves).unwrap();

        // Use wrong sibling
        let wrong_sibling = U256::from_u128(&env, 999);
        let valid = verify_merkle_path(&env, &root, &leaves[0], 0, &[wrong_sibling]).unwrap();
        assert!(!valid);
    }

    #[test]
    fn empty_path_is_leaf_hash() {
        let env = env();
        let leaf = U256::from_u128(&env, 7);
        let expected_root = hash_to_field(&env, &[leaf.clone()]);
        let valid = verify_merkle_path(&env, &expected_root, &leaf, 0, &[]).unwrap();
        assert!(valid);
    }

    #[test]
    fn path_too_long_returns_error() {
        let env = env();
        let leaf = U256::from_u128(&env, 1);
        let root = U256::from_u128(&env, 0);
        let path: [U256; 33] = core::array::from_fn(|_| U256::from_u128(&env, 0));
        let result = verify_merkle_path(&env, &root, &leaf, 0, &path);
        assert_eq!(result, Err(ZkError::InvalidInput));
    }

    #[test]
    fn empty_leaves_returns_error() {
        let env = env();
        let result = compute_merkle_root(&env, &[]);
        assert_eq!(result, Err(ZkError::InvalidInput));
    }
}
