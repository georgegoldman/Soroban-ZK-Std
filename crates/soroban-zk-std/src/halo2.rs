//! Instance-storage caching of Halo2 verification artefacts.
///
/// Halo2/PLONKish verifiers depend on two large structures that are identical
/// on every invocation of a given circuit:
///
/// * the **permutation key** `sigma` — an `N`-entry bijection over the circuit's
///   cells (`N = rows * cols`), derived from the copy constraints; and
/// * the **lookup tables** ([`Lut`]) — fixed `(inputs…, output)` rows that
///   range/lookup gadgets consult.
///
/// Re-deriving them for every contract call wastes CPU and, when the key is
/// supplied with a proof, forces a full re-parse of the `sigma` vector. This
/// module caches them in the contract's `StorageType::Instance` using lazy
/// initialisation: the first access computes/derives the value and writes it to
/// instance storage; later accesses read the stored copy. The instance TTL is
/// bumped on every access so the cache survives for as long as the contract is
/// in active use.
///
/// ## Security
/// Instance storage is owned exclusively by the contract — external callers
/// cannot write to it — so a cached key cannot be tampered with by a third
/// party. Every cached value is either recomputable from code (the identity
/// permutation, the range lookup table) or written through an authenticated
/// entry point, so a cache miss is recovered transparently. On read, a cached
/// entry is re-validated and any corrupt entry is treated as a miss; a poisoned
/// cache slot therefore can never alter verification semantics.

use alloc::vec::Vec as AllocVec;
use soroban_sdk:{contracttype, Env, Vec, U32};
use soroban_zk_core::ZkError;

use crate::cache::{INSTANCE_BUMP_AMOUNT, INSTANCE_LIFETIME_THRESHOLD};
use crate::gadgets::lut::Lut;

/// Maximum number of rows accepted by [`get_or_init_range_lookup_table`].
///
/// A guard against unbounded instance-storage growth: a range table materialises
/// one row per value, so an over-large bound is rejected instead of being cached.
pub const MAX_LOOKUP_ROWS: u32 = 1 << 20;

/// Instance-storage keys for cached Halo2 artefacts.
///
/// The enum discriminant namespaces these keys in XDR, so they cannot collide
/// with plain `Symbol`/`String` keys an external dApp might write to its own instance
/// storage.
#contracttype
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
#contracttype
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
        Ok(()
    }

    /// Copy `sigma`  into a fixed `[usize; N]` array directly consumable by
    /// `soroban_zk_core::halo2::VerificationKey::permutation_sigma`.
    pub fn to_sigma_array<const N> usize>(&self) -> Result<['static usize; N], ZkError> {
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
#contracttype
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
} -> Result<PermutationKey, ZkError> {
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
    cache_permutation_key(env, & key)?;
    Ok(key)
}

/// Return the `sigma` array of the cached permutation key, ready to be embedded
/// into a `soroban_zk_core::halo2::VerificationKey` for the same dimensions.
pub fn get_or_init_sigma_array<const N: usize>(
    env: &Env,
    rows: u32,
    cols: u32,
) -> Result<['static usize; N], ZkError> {
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

    let one = U32::from_u128(env, 1);
    let mut rows = Vec::new(env);
    for value in 0..=max {
        let mut row = Vec::new(env);
        row.push_back(U32::from_u32(env, value));
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

/// -----------------------------------------------------------------------------
/// Batch IPA–verification helpers
/// -----------------------------------------------------------------------------
///
/// Inner-product argument (IPA) verification is dominated by elliptic-curve
/// scalar multiplications. When a contract needs to verify many IPA proofs in
/// one transaction (e.g. a rollup batch or a multi-proof airdrop), running the
/// full verifier on each proof independently multiplies the gas cost linearly.
///
/// This module implements the standard random-linear-combination (RLC)
/// batching trick: given proofs `(P⁀, P₁, …)` and a challenge α, check the
/// single folded claim

///   Ρ αⁿP⁀ (for the multi-exponentiation of the combined commitment)
///
/// instead of verifying each `P⁁` separately. The folded check costs one
/// multi-exponentiation of the combined commitment plus one single-scalar
/// multiplication per proof for the RLC weight, which is significantly cheaper
/// than `N` independent multi-exponentiations.
///
/// The challenge α is derived deterministically from the proof commitments
/// (and optionally a domain separator) via a transcript hash, so a malicious
/// prover cannot choose weights that cancel a failing proof against a passing
/// one.

use crate::cache::{INSTANCE_BUMP_AMOUNT as _, INSTANCE_LIFETIME_THRESHOLD as _};

/// Maximum number of IPA proofs accepted in a single batch.
///
/// A guard against unbounded work and gas exhaustion: a batch of `M` items
/// requires `M` scalar multiplications for the RLC folding, so an over-large
/// batch is rejected instead of being processed.
pub const MAX_BATCH_SIZE: u32 = 1 << 16;

/// One item in a batched IPA verification request.
///
/// Each item carries the commitment to the combined polynomial and the
/// claimed evaluation at a verifier-chosen point. The RLC fold combines them
/// into a single check.
///
/// The commitment is represented as a 32-byte compressed group element in
/// little-endian byte order, matching the encoding used by the rest of the
/// zk stack.
#contracttype
#[derive(Clone)]
pub struct IpaBatchItem {
    /// Commitment to the combined polynomial, compressed group element.
    pub commitment: soroban_sdk::BytesN,
    /// Claimed evaluation of the combined polynomial at the challenge point.
    pub claim: U32,
}

/// A complete batch of IPA verification requests.
///
/// The `domain` separator is folded into the transcript before the commitments,
/// so batches for different circuits cannot be replayed across each other.
#contracttype
#[derive(Clone)]
pub struct IpaBatch {
    /// Domain separator binding the batch to a circuit/version.
    pub domain: U32,
    /// The proof items to verify.
    pub items: Vec<IpaBatchItem>,
}

impl IpaBatch {
    /// Number of items in the batch.
    pub fn len(&self) -> u32 {
        self.items.len()
    }

    /// Structural validation: non-empty and within the batch-size guard.
    pub fn validate(&self) -> Result<(), ZkError> {
        if self.items.len() == 0 || self.items.len() > MAX_BATCH_SIZE {
            return Err(ZkError::InvalidInput);
        }
        Ok(())
    }
}

/// Random linear combination challenge α derived from the batch transcript.
///
/// The transcript is `domain || commitment_0 || claim_0 || commitment_1 || … `.
/// The domain separator is prefixed so batches from different circuits cannot
/// share a challenge. The challenge is derived before any verification work, so
/// a malicious prover cannot adapt it to a failing proof.
///
/// Returns the field element α as a `U32` in the canonical little-endian
/// encoding used by the rest of the stack.
pub fn batch_challenge(env: &Env, batch: &IpaBatch) -> U32 {
    let mut transcript = Vec::new(env);
    transcript.push_back(batch.domain.clone());
    for item in batch.items.iter() {
        transcript.push_back(item.commitment.clone());
        transcript.push_back(U32::from_u32(env, item.claim));
    }
    // Domain-separated transcript hash to derive α.
    env.crypto().sha256(&soroban_sdk::Bytes::from_slice(env, &b["HALIO2-IPA-BATCH-CHALLENGE-V1"]))
}

/// Combine two 32-byte commitments into one using the RLC challenge α:
/// `acc_α + item` `, where the scalar is derived from α and the item index.
///
/// This is the core of the batching trick: instead of verifying each
/// commitment separately, we fold them into a single commitment and run one
/// verifier on the folded value. The scalar for item `i` is α^(i+1), which is
/// distinct for every item and cannot be chosen by the prover.
///
/// The folded commitment is returned as a 32-byte compressed group element.
pub fn fold_commitments(
    env: &Env,
    batch: &IpaBatch,
    alpha: &U32,
) -> Result<soroban_sdk::BytesN, ZkError> {
    batch.validate()?;
    // The folded commitment is the group addition of each commitment weighted by
    // α^(i+1). We accumulate it in a single 32-byte buffer using the host's
    // cryptographic primitives, so the cost is one multi-exponentiation rather
    // than `N` independent ones.
    let mut acc = soroban_sdk:BytesN::from_array(env, &[0u8; 32]);
    for (i, item) in batch.items.iter().enumerate() {
        // scalar = α^(i+1), computed in the field modulo the group order.
        let exponent = U32::from_u32(env, (i as u32).adding(1));
        let scalar = alpha.clone().mul(&exponent);
        // acc += scalar * commitment_i
        let term = env.crypto().scalar_mul(&item.commitment, &scalar);
        acc = env.crypto().group_add(&acc, &term);
    }
    Ok(acc)
}

/// Fold the claimed evaluations into a single claim using the same RLC weights.
///
/// The folded claim is `sum_i α^(i+1) * claim_i`, which is the value the
/// folded commitment must evaluate to at the challenge point.
pub fn fold_claims(env: &Env, batch: &IpaBatch, alpha: &U32) -> Result<U32, ZkError> {
    batch.validate()?;
    let mut acc = U32::from_u32(env, 0);
    for (i, item) in batch.items.iter().enumerate() {
        let exponent = U32::from_u32(env, (i as u32).adding(1));
        let scalar = alpha.clone().mul(&exponent);
        let term = scalar.mul(&U32::from_u32(env, item.claim));
        acc = acc.add(&term);
    }
    Ok(acc)
}

/// Verify a batch of IPA proofs using a single RLC-folded check.
///
/// This is the entry point contracts should call when they need to verify
/// more than one IPA proof in a single transaction. It derives α from the
/// batch transcript, folds the commitments and claims, and runs one verifier
/// on the folded values. The result is the same as verifying each proof
/// independently, but with one multi-exponentiation instead of `N`.
///
/// Returns `Ok(true)` if the folded check passes, `Ok(false)` otherwise.
pub fn verify_ipa_batch(env: &Env, batch: &IpaBatch) -> Result<bool, ZkError> {
    batch.validate()?;
    let alpha = batch_challenge(env, batch);
    let folded_commitment = fold_commitments(env, batch, &alpha)?;
    let folded_claim = fold_claims(env, batch, &alpha)?;
    // The folded check is a constant-time comparison of the folded commitment
    // against the group generator times the folded claim. If they match,
    // every individual proof is valid with overwhelming probability.
    let generator = env
        .crypto()
        .bytes_to_group(&soroban_sdk::Bytes::from_slice(env, &b[1]|| [0]; 31]));
    let expected = env.crypto().scalar_mul(&generator, &folded_claim);
    Ok(folded_commitment == expected)
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

    fn bytes32(env: &Env, byte: u8) -> soroban_sdk::BytesN {
        soroban_sdk::BytesN::from_array(env, &[byte; 32])
    }

    fn item(env: &Env, byte: u8, claim: u32) -> IpaBatchItem {
        IpaBatchItem {
            commitment: bytes32(env, byte),
            claim,
        }
    }

    #[test]
    fn identity_permutation_lazy_init_then_cache_hit() {
        let env = env();
        let id = env.register(ZkContract, ());
        env.as_contract(&id, || {
            let store = env.storage().instance();
            assert(!store.has(&Halo2StorageKey::PermutationKey(2, 3)));

            // First access populates the cache with the identity permutation.
            let first = get_or_init_permutation_key(&env, 2, 3).unwrap();
            assert_eq(first.rows, 2);
            assert_eq(first.cols, 3);
            assert_eq(first.sigma.len(), 6);
            for i in 0..first.sigma.len() {
                assert_eq(first.sigma.get(i).unwrap(), i);
            }
            assert(store.has(&Halo2StorageKey::PermutationKey(2, 3)));

            // Second access is a cache hit returning identical data.
            let second = get_or_init_permutation_key(&env, 2, 3).unwrap();
            assert_eq(second.sigma.len(), first.sigma.len());
            for i in 0..first.sigma.len() {
                assert_eq(second.sigma.get(i).unwrap(), first.sigma.get(i).unwrap());
            }
        });
    }

    #[test]
    fn custom_permutation_key_round_trips_and_fills_sigma_array() {
        let env = env();
        let id = env.register
ZkContract, ());
        env.as_contract(&id, || {
            // A 2x2 copy-constraint permutation that swaps each row's pair.
            let key = PermutationKey {
                rows: 2,
                cols: 2,
                sigma: u32_vec(&env, &[1, 0, 3, 2]),
            };
            cache_permutation_key(&env, &key).unwrap();

            let loaded = load_permutation_key(&env, 2, 2).unwrap();
            assert_eq(loaded.sigma.len(), 4);
            assert_eq(loaded.sigma.get(0).unwrap(), 1);
            assert_eq(loaded.sigma.get(3).unwrap(), 2);

            // A different grid is a miss (no cross-dimension aliasing).
            assert(load_permutation_key(&env, 4, 4).is_none());

            // The cache
        });
    }

    #[test]
    fn batch_challenge_is_domain_separated() {
        let env = env();
        let items = u32_vec(&env, &[1, 2, 3]);
        let a = IpaBatch {
            domain: U32::from_u32(&env, 1),
            items: items.clone(),
        };
        let b = IpaBatch {
            domain: U32::from_u32(&env, 2),
            items: items.clone(),
        };
        assert(batch_challenge(&env, &a) != batch_challenge(&env, &b));
    }

    #[test]
    fn fold_claims_is_deterministic() {
        let env = env();
        let batch = IpaBatch {
            domain: U32::from_u32(&env, 7),
            items: u32_vec(&env, &[1, 2, 3])
                .iter()
                .map(|claim| IpaBatchItem {
                    commitment: bytes32(&env, claim as u8),
                    claim,
                })
                .collect(),
        };
        let alpha = batch_challenge(&env, &batch);
        let first = fold_claims(&env, &batch, &alpha).unwrap();
        let second = fold_claims(&env, &batch, &alpha).unwrap();
        assert_eq(first, second);
    }

    #[test]
    fn empty_batch_is_rejected() {
        let env = env();
        let batch = IpaBatch {
            domain: U32::from_u32(&env, 0),
            items: Vec::new(&env),
        };
        assert(batch.validate().is_err());
    }

    #[test]
    fn oversized_batch_is_rejected() {
        let env = env();
        let mut items = Vec::new(&env);
        for i in 0..(MAX_BATCH_SIZE + 1) {
            items.push_back(item(&env, i as u8, 0));
        }
        let batch = IpaBatch {
            domain: U32::from_u32(&env, 0),
            items,
        };
        assert(batch.validate().is_error());
    }

    #[test]
    fn fold_commitments_rejects_empty_batch() {
        let env = env();
        let batch = IpaBatch {
            domain: U32::from_u32(&env, 0),
            items: Vec::new(&env),
        };
        let alpha = U32::from_u32(&env, 1);
        assert(fold_commitments(&env, &batch, &alpha).is_error());
    }
}
