use alloc::vec::Vec as AllocVec;
//! Instance-storage caching of Halo2 verification artefacts.
//!
//! Halo2/PLONKish verifiers depend on two large structures that are identical
//! on every invocation of a given circuit:
//!
//! * the **permutation key** `sigma` — an `N`-entry bijection over the circuit's
//!   cells (`N = rows * cols`), derived from the copy constraints; and
//! * the **lookup tables** ([`Lut`]) — fixed `(inputs…, output)` rows that
//!   range/lookup gadgets consult.
//!
//! Re-deriving them for every contract call wastes CPU and, when the key is
//! supplied with a proof, forces a full re-parse of the `sigma` vector. This
//! module caches them in the contract's `StorageType::Instance` using lazy
//! initialisation: the first access computes/derives the value and writes it to
//! instance storage; later accesses read the stored copy. The instance TTL is
//! bumped on every access so the cache survives for as long as the contract is
//! in active use.
//!
//! ## Security
//! Instance storage is owned exclusively by the contract — external callers
//! cannot write to it — so a cached key cannot be tampered with by a third
//! party. Every cached value is either recomputable from code (the identity
//! permutation, the range lookup table) or written through an authenticated
//! entry point, so a cache miss is recovered transparently. On read, a cached
//! entry is re-validated and any corrupt entry is treated as a miss; a poisoned
//! cache slot therefore can never alter verification semantics.

use soroban_sdk::{contracttype, Env, Vec, U256};
use soroban_zk_core::ZkError;

use crate::cache::{INSTANCE_BUMP_AMOUNT, INSTANCE_LIFETIME_THRESHOLD};
use crate::gadgets::lut::Lut;

/// Maximum number of rows accepted by [`get_or_init_range_lookup_table`].
/// Maximum number of rows accepted by [`get_or_init_range_lookup_table`].
///
/// A guard against unbounded instance-storage growth: a range table materialises
/// one row per value, so an over-large bound is rejected instead of being cached.
pub const MAX_LOOKUP_ROWS: u32 = 1 << 20;

/// Instance-storage keys for cached Halo2 artefacts.
///
/// The enum discriminant namespaces these keys in XDR, so they cannot collide
/// with plain `Symbol`/`String` keys an external dApp might write to its own
/// instance storage.
#[contracttype]
#[derive(Clone)]
pub enum Halo2StorageKey {
    /// Canonical permutation key for a `rows × cols` grid.
    PermutationKey(u32, u32),
    /// Cached lookup table with the caller-chosen `id`.
    LookupTable(u32),
}

/// A dimension-tagged Halo2 permutation key (`sigma`).
///
/// `sigma[i]` is the target cell of cell `i`, with cells indexed column-major
/// (`cell = col * rows + row`), matching
/// `soroban_zk_core::halo2::VerificationKey::permutation_sigma`.
#[contracttype]
#[derive(Clone)]
pub struct PermutationKey {
    /// Number of rows (evaluation-domain size).
    pub rows: u32,
    /// Number of columns.
    pub cols: u32,
    /// The `rows * cols` permutation mapping, column-major.
    pub sigma: Vec<u32>,
}

impl PermutationKey {
    /// Number of cells `rows * cols`, saturating instead of wrapping on abuse.
    pub fn cell_count(&self) -> u32 {
        self.rows.saturating_mul(self.cols)
    }

    /// Structural validation: non-zero dimensions, exact length, in-range
    /// targets, and bijectivity (every cell is hit exactly once). A key that
    /// fails any of these is rejected before it is cached or used.
    pub fn validate(&self) -> Result<(), ZkError> {
        if self.rows == 0 || self.cols == 0 {
            return Err(ZkError::InvalidInput);
        }
        let n = self.cell_count() as usize;
        if self.sigma.len() as usize != n {
            return Err(ZkError::InvalidInput);
        }

        let mut seen = AllocVec::<bool>::with_capacity(n);
        seen.resize(n, false);
        for cell in self.sigma.iter() {
            let target = cell as usize;
            if target >= n || seen[target] {
                return Err(ZkError::InvalidInput);
            }
            seen[target] = true;
        }
        Ok(())
    }

    /// Copy `sigma` into a fixed `[usize; N]` array directly consumable by
    /// `soroban_zk_core::halo2::VerificationKey::permutation_sigma`.
    pub fn to_sigma_array<const N: usize>(&self) -> Result<[usize; N], ZkError> {
        if self.sigma.len() as usize != N {
            return Err(ZkError::InvalidInput);
        }
        let mut out = [0usize; N];
        for (i, cell) in self.sigma.iter().enumerate() {
            out[i] = cell as usize;
        }
        Ok(out)
    }
}

/// A cached lookup table: `width` input columns plus one output column.
#[contracttype]
#[derive(Clone)]
pub struct LookupTable {
    /// Number of input columns.
    pub width: u32,
    /// Rows, each `width + 1` columns.
    pub rows: Vec<Vec<U256>>,
}

/// Bump the instance TTL so the cached artefacts stay live during active use.
fn bump(env: &Env) {
    env.storage()
        .instance()
        .extend_ttl(INSTANCE_LIFETIME_THRESHOLD, INSTANCE_BUMP_AMOUNT);
}

/// Build the canonical identity permutation key `sigma[i] = i` for a
/// `rows × cols` grid.
pub fn identity_permutation_key(
    env: &Env,
    rows: u32,
    cols: u32,
) -> Result<PermutationKey, ZkError> {
    let n = rows.checked_mul(cols).ok_or(ZkError::InvalidInput)?;
    if n == 0 {
        return Err(ZkError::InvalidInput);
    }
    let mut sigma = Vec::new(env);
    for i in 0..n {
        sigma.push_back(i);
    }
    Ok(PermutationKey { rows, cols, sigma })
}

/// Persist `key` to instance storage, replacing any existing entry for the same
/// grid. The key is validated first, so a malformed key is never written.
pub fn cache_permutation_key(env: &Env, key: &PermutationKey) -> Result<(), ZkError> {
    key.validate()?;
    env.storage()
        .instance()
        .set(&Halo2StorageKey::PermutationKey(key.rows, key.cols), key);
    bump(env);
    Ok(())
}

/// Read the cached permutation key for a `rows × cols` grid, bumping the TTL on
/// a hit.
///
/// Returns `None` on a miss **and** when a stored entry is corrupt or carries
/// the wrong dimensions: callers then recompute from code, so a poisoned cache
/// entry can never change the verification result.
pub fn load_permutation_key(env: &Env, rows: u32, cols: u32) -> Option<PermutationKey> {
    let stored: Option<PermutationKey> = env
        .storage()
        .instance()
        .get(&Halo2StorageKey::PermutationKey(rows, cols));
    match stored {
        Some(key) if key.rows == rows && key.cols == cols && key.validate().is_ok() => {
            bump(env);
            Some(key)
        }
        _ => None,
    }
}

/// Return the cached permutation key for `rows × cols`, lazily initialising it
/// to the identity permutation on first use.
pub fn get_or_init_permutation_key(
    env: &Env,
    rows: u32,
    cols: u32,
) -> Result<PermutationKey, ZkError> {
    if let Some(key) = load_permutation_key(env, rows, cols) {
        return Ok(key);
    }
    let key = identity_permutation_key(env, rows, cols)?;
    cache_permutation_key(env, &key)?;
    Ok(key)
}

/// Return the `sigma` array of the cached permutation key, ready to be embedded
/// into a `soroban_zk_core::halo2::VerificationKey` for the same dimensions.
pub fn get_or_init_sigma_array<const N: usize>(
    env: &Env,
    rows: u32,
    cols: u32,
) -> Result<[usize; N], ZkError> {
    let key = get_or_init_permutation_key(env, rows, cols)?;
    key.to_sigma_array::<N>()
}

/// Remove a cached permutation key (cleanup / key-rotation hook).
pub fn clear_permutation_key(env: &Env, rows: u32, cols: u32) {
    env.storage()
        .instance()
        .remove(&Halo2StorageKey::PermutationKey(rows, cols));
}

/// Persist a lookup table under `id`. The table is validated through [`Lut`]
/// first, so a malformed table is never cached.
pub fn cache_lookup_table(env: &Env, id: u32, table: &LookupTable) -> Result<(), ZkError> {
    Lut::new(table.width, table.rows.clone())?;
    env.storage()
        .instance()
        .set(&Halo2StorageKey::LookupTable(id), table);
    bump(env);
    Ok(())
}

/// Load the lookup table cached under `id` as a [`Lut`], bumping the TTL on a
/// hit. Returns `Ok(None)` on a miss.
pub fn load_lookup_table(env: &Env, id: u32) -> Result<Option<Lut>, ZkError> {
    let stored: Option<LookupTable> = env
        .storage()
        .instance()
        .get(&Halo2StorageKey::LookupTable(id));
    match stored {
        Some(table) => {
            let lut = Lut::new(table.width, table.rows)?;
            bump(env);
            Ok(Some(lut))
        }
        None => Ok(None),
    }
}

/// Build the canonical range-check table `[0, max] -> 1` lazily and cache it
/// under `id`, returning the ready-to-query [`Lut`].
pub fn get_or_init_range_lookup_table(env: &Env, id: u32, max: u32) -> Result<Lut, ZkError> {
    if let Some(lut) = load_lookup_table(env, id)? {
        return Ok(lut);
    }
    if max >= MAX_LOOKUP_ROWS {
        return Err(ZkError::InvalidInput);
    }

    let one = U256::from_u128(env, 1);
    let mut rows = Vec::new(env);
    for value in 0..=max {
        let mut row = Vec::new(env);
        row.push_back(U256::from_u32(env, value));
        row.push_back(one.clone());
        rows.push_back(row);
    }
    let table = LookupTable { width: 1, rows };
    cache_lookup_table(env, id, &table)?;
    Lut::new(table.width, table.rows)
}

/// Remove a cached lookup table (cleanup / key-rotation hook).
pub fn clear_lookup_table(env: &Env, id: u32) {
    env.storage()
        .instance()
        .remove(&Halo2StorageKey::LookupTable(id));
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

    fn u32_vec(env: &Env, values: &[u32]) -> Vec<u32> {
        let mut v = Vec::new(env);
        for value in values {
            v.push_back(*value);
        }
        v
    }

    #[test]
    fn identity_permutation_lazy_init_then_cache_hit() {
        let env = env();
        let id = env.register(ZkContract, ());
        env.as_contract(&id, || {
            let store = env.storage().instance();
            assert!(!store.has(&Halo2StorageKey::PermutationKey(2, 3)));

            // First access populates the cache with the identity permutation.
            let first = get_or_init_permutation_key(&env, 2, 3).unwrap();
            assert_eq!(first.rows, 2);
            assert_eq!(first.cols, 3);
            assert_eq!(first.sigma.len(), 6);
            for i in 0..first.sigma.len() {
                assert_eq!(first.sigma.get(i).unwrap(), i);
            }
            assert!(store.has(&Halo2StorageKey::PermutationKey(2, 3)));

            // Second access is a cache hit returning identical data.
            let second = get_or_init_permutation_key(&env, 2, 3).unwrap();
            assert_eq!(second.sigma.len(), first.sigma.len());
            for i in 0..first.sigma.len() {
                assert_eq!(second.sigma.get(i).unwrap(), first.sigma.get(i).unwrap());
            }
        });
    }

    #[test]
    fn custom_permutation_key_round_trips_and_fills_sigma_array() {
        let env = env();
        let id = env.register(ZkContract, ());
        env.as_contract(&id, || {
            // A 2x2 copy-constraint permutation that swaps each row's pair.
            let key = PermutationKey {
                rows: 2,
                cols: 2,
                sigma: u32_vec(&env, &[1, 0, 3, 2]),
            };
            cache_permutation_key(&env, &key).unwrap();

            let loaded = load_permutation_key(&env, 2, 2).unwrap();
            assert_eq!(loaded.sigma.len(), 4);
            assert_eq!(loaded.sigma.get(0).unwrap(), 1);
            assert_eq!(loaded.sigma.get(3).unwrap(), 2);

            // A different grid is a miss (no cross-dimension aliasing).
            assert!(load_permutation_key(&env, 4, 4).is_none());

            // The cached key converts to the fixed array the core verifier wants.
            let arr: [usize; 4] = get_or_init_sigma_array(&env, 2, 2).unwrap();
            assert_eq!(arr, [1, 0, 3, 2]);

            // Clearing the slot forces a fresh identity initialisation.
            clear_permutation_key(&env, 2, 2);
            assert!(load_permutation_key(&env, 2, 2).is_none());
            let rebuilt = get_or_init_permutation_key(&env, 2, 2).unwrap();
            assert_eq!(rebuilt.sigma.get(0).unwrap(), 0);
        });
    }

    #[test]
    fn malformed_permutation_keys_are_rejected() {
        let env = env();
        let id = env.register(ZkContract, ());
        env.as_contract(&id, || {
            // Wrong length for the declared dimensions.
            let wrong_len = PermutationKey {
                rows: 2,
                cols: 2,
                sigma: u32_vec(&env, &[0, 1, 2]),
            };
            assert_eq!(wrong_len.validate(), Err(ZkError::InvalidInput));
            assert_eq!(
                cache_permutation_key(&env, &wrong_len),
                Err(ZkError::InvalidInput)
            );

            // Target outside the cell range.
            let out_of_range = PermutationKey {
                rows: 2,
                cols: 2,
                sigma: u32_vec(&env, &[0, 1, 2, 9]),
            };
            assert_eq!(out_of_range.validate(), Err(ZkError::InvalidInput));

            // Not a bijection: two cells map to the same target.
            let duplicate = PermutationKey {
                rows: 2,
                cols: 2,
                sigma: u32_vec(&env, &[0, 0, 2, 3]),
            };
            assert_eq!(duplicate.validate(), Err(ZkError::InvalidInput));

            // Degenerate dimensions.
            let zero = PermutationKey {
                rows: 0,
                cols: 3,
                sigma: u32_vec(&env, &[]),
            };
            assert_eq!(zero.validate(), Err(ZkError::InvalidInput));
            assert!(matches!(
                identity_permutation_key(&env, 0, 3),
                Err(ZkError::InvalidInput)
            ));
        });
    }

    #[test]
    fn corrupted_cache_entry_falls_back_to_recompute() {
        let env = env();
        let id = env.register(ZkContract, ());
        env.as_contract(&id, || {
            // Seed a good key, then overwrite it with a corrupt one.
            get_or_init_permutation_key(&env, 2, 2).unwrap();
            let corrupt = PermutationKey {
                rows: 2,
                cols: 2,
                sigma: u32_vec(&env, &[0, 0, 2, 3]),
            };
            env.storage()
                .instance()
                .set(&Halo2StorageKey::PermutationKey(2, 2), &corrupt);

            // The poisoned entry is ignored and the identity key is rebuilt.
            let key = get_or_init_permutation_key(&env, 2, 2).unwrap();
            assert_eq!(key.sigma.get(1).unwrap(), 1);
        });
    }

    #[test]
    fn range_lookup_table_is_lazily_cached() {
        let env = env();
        let id = env.register(ZkContract, ());
        env.as_contract(&id, || {
            let store = env.storage().instance();
            assert!(!store.has(&Halo2StorageKey::LookupTable(7)));

            let lut = get_or_init_range_lookup_table(&env, 7, 15).unwrap();
            assert!(store.has(&Halo2StorageKey::LookupTable(7)));
            assert_eq!(lut.len(), 16);
            let one = U256::from_u128(&env, 1);
            assert!(lut.assert_lookup(&[U256::from_u128(&env, 0)], &one).is_ok());
            assert!(lut
                .assert_lookup(&[U256::from_u128(&env, 15)], &one)
                .is_ok());
            assert_eq!(
                lut.assert_lookup(&[U256::from_u128(&env, 16)], &one),
                Err(ZkError::ConstraintUnsatisfied)
            );

            // A second call is served from the cache and stays consistent.
            let cached = get_or_init_range_lookup_table(&env, 7, 15).unwrap();
            assert_eq!(cached.len(), 16);
            assert!(cached
                .assert_lookup(&[U256::from_u128(&env, 3)], &one)
                .is_ok());

            // Oversized tables are rejected instead of being cached.
            assert!(matches!(
                get_or_init_range_lookup_table(&env, 8, MAX_LOOKUP_ROWS),
                Err(ZkError::InvalidInput)
            ));
            assert!(!store.has(&Halo2StorageKey::LookupTable(8)));

            // Cleanup hook removes the entry.
            clear_lookup_table(&env, 7);
            assert!(!store.has(&Halo2StorageKey::LookupTable(7)));
        });
    }
}
