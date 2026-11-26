//! Persistent-storage Poseidon2 incremental Merkle tree (Issue #590).
//!
//! An append-only binary Merkle tree in the style of the Tornado Cash /
//! Semaphore "incremental" tree, built for Soroban `StorageType::Persistent`:
//!
//! * Only **O(depth)** state lives on the ledger: the `filled_subtrees`
//!   frontier (the most recent left-hand node at every level), the next free
//!   leaf index, and a fixed-size ring buffer of recent roots. Leaves
//!   themselves are never stored; provers rebuild paths off-chain from the
//!   insertion events / their own records.
//! * Empty subtrees cost **zero** runtime hashes: the Poseidon2 digests of the
//!   all-zero subtree at every height are precomputed in [`ZERO_HASHES`].
//! * A ring buffer of the last `ROOT_HISTORY` roots lets a proof generated
//!   against a slightly stale root still be accepted after other users have
//!   inserted leaves, so concurrent provers are not invalidated
//!   ([`IncrementalMerkleTree::is_known_root`]).
//! * Every mutation extends the persistent TTL of the tree state so an
//!   actively used tree is never archived.
//!
//! ## Hash function
//! Interior nodes are `H(left, right) = Poseidon2([left, right])` using the
//! crate's BN254 sponge ([`crate::poseidon2::hash_to_field`], t = 3, rate = 2),
//! so roots match circuits that use the same sponge. Leaves must be canonical
//! BN254 scalars (`< r`); anything else is rejected with
//! [`ZkError::InvalidFieldElement`].
//!
//! ## Storage layout
//! The whole tree state is one persistent entry under
//! [`MerkleStorageKey::Tree`]`(tree_id)`, so an insertion is exactly one
//! ledger read and one ledger write regardless of depth. Several independent
//! trees can coexist in one contract by using different `tree_id`s; the
//! `#[contracttype]` enum namespaces the key so it cannot collide with
//! external dApp keys.
//!
//! ## Authorization
//! [`IncrementalMerkleTree::insert_leaf`] performs no authorization. The
//! calling contract must gate it (e.g. `require_auth`, a deposit transfer).

use alloc::vec::Vec as AllocVec;
use ethnum::u256;
use soroban_sdk::{contracttype, Bytes, Env, Vec, U256};
use soroban_zk_core::{Bn254, ZkError};

/// Largest supported tree depth (2^32 leaves).
pub const MAX_DEPTH: usize = 32;

/// Default number of historical roots kept in the ring buffer.
pub const DEFAULT_ROOT_HISTORY_SIZE: usize = 32;

/// Lower TTL bound (ledgers): state is extended when it falls below this.
/// ~1 day at 5 s ledger close.
pub const MERKLE_TTL_THRESHOLD: u32 = 17_280;
/// Target TTL (ledgers) the state is extended to. ~30 days at 5 s ledger close.
pub const MERKLE_TTL_AMOUNT: u32 = 518_400;

/// Poseidon2 roots of the all-zero subtree at every height.
///
/// `ZERO_HASHES[0]` is the empty leaf (`0`), and
/// `ZERO_HASHES[i + 1] = Poseidon2([ZERO_HASHES[i], ZERO_HASHES[i]])`.
/// `ZERO_HASHES[d]` is therefore the root of an empty tree of depth `d`.
/// The `zero_hashes_match_poseidon2` test recomputes every entry.
pub const ZERO_HASHES: [u256; MAX_DEPTH + 1] = [
    u256::from_words(
        0x00000000000000000000000000000000,
        0x00000000000000000000000000000000,
    ),
    u256::from_words(
        0x0f942dac5b3b2077fe17d55758e0c53d,
        0xb1bbf922d4d55d851c75df52ea9d87a3,
    ),
    u256::from_words(
        0x0fdf4ff6eee945dda17562a8ceabf18e,
        0x8cbb457f6125fcd1e9cb1f8c6e90c599,
    ),
    u256::from_words(
        0x15a714663401c31a19f68e179e0c9b7e,
        0x6cdceca46f62a70c111ee0c983feb0a1,
    ),
    u256::from_words(
        0x0d501546dd0d30c27ccd03a599b4b5aa,
        0xe44e6ae72ab3f84e3c57abb719834eca,
    ),
    u256::from_words(
        0x148331ff419fc7bf5bea7cb3a078caf7,
        0x1b5d7d55b0a606976aa54fbd239fa7ef,
    ),
    u256::from_words(
        0x216863a331bf93654ae753a38300f62b,
        0x8a561de878a19a6d188626535afca036,
    ),
    u256::from_words(
        0x20a076cc1d11e1674b248e52501081c1,
        0x6bd9d6c79bf5243b2c7fa797a7a9dd2c,
    ),
    u256::from_words(
        0x1e45f49de122c7e9dfee0c5fdb742b30,
        0xb7b0a3d19ce576fc5f1a492001073f93,
    ),
    u256::from_words(
        0x1dbc675f859bc349772e1e739a6f510a,
        0xa8f01d1b0224d135ba00a5bff94946e3,
    ),
    u256::from_words(
        0x2e6e8d928694d3ecf21708d1e7d12553,
        0x221ec27517fa75626e47421b0937a6cc,
    ),
    u256::from_words(
        0x0e0c23511b14ee68fb7a0924b7c59535,
        0x4415ce394955c307fee1cdf2b5902fe6,
    ),
    u256::from_words(
        0x15b972e90c1d8e99f782ea1e3042c410,
        0xe03d2e66a957f8269d4725c88100767d,
    ),
    u256::from_words(
        0x1b0b54e480e4f64424f9308c303d5e4d,
        0x6478f5cd5f04ed4458a221f7c9e3f2b3,
    ),
    u256::from_words(
        0x124e0130b967b7abcf24a4c22fbd4439,
        0x629248290c0650ac8ceb446d94c3fb69,
    ),
    u256::from_words(
        0x201c33cc335aba8309d298c230e63477,
        0x72fa8489531fd12a7f63db16c5c81e9f,
    ),
    u256::from_words(
        0x1634b42f41512833d6ff0e7bdca818f5,
        0x2f9755b5994d90b594778da571b79132,
    ),
    u256::from_words(
        0x1ddd791025eb29256764e4921c7ae20f,
        0xd14cb787203bbe2b77e33b00521c3f14,
    ),
    u256::from_words(
        0x08582e128a6eefd36c0745f5f244cd2d,
        0x65c2b26ac199a8f902d45bc988748970,
    ),
    u256::from_words(
        0x1b3d2f022da45416e04f9409a4a18fdb,
        0xfd7d875a560a54df4ffafd20a6b016ae,
    ),
    u256::from_words(
        0x2263fc3c3e4c71edf464fab4b89a9480,
        0x9c1867fb7f97b75be5e126e7019fecac,
    ),
    u256::from_words(
        0x23c373296700e327bc73dd560b485fa1,
        0xfe055fe4f99ad2792363567c5243f5b9,
    ),
    u256::from_words(
        0x0e2b1ca99011aad87c370d344f74e9d1,
        0xd3fb8a5ba02cc41b10ec0505df48c9b0,
    ),
    u256::from_words(
        0x2bb7ad2c5fded34484868dd115595d80,
        0xe912b887c2e3e48c5afc0caeb753a001,
    ),
    u256::from_words(
        0x05d6cfe7ea9c2d0cf167deb693bddb18,
        0xd7d877a89cf069d19319d75b4d07c5da,
    ),
    u256::from_words(
        0x0fae385c1183a78a75ba135fdb58c104,
        0x4ef35be432e59946207552a44390bd1f,
    ),
    u256::from_words(
        0x14541f12e597b54d54a5d50829e09293,
        0xbb2c972d2fabcea3cca54c950eff2046,
    ),
    u256::from_words(
        0x1c4bb24d9eebb00816e35b2f1d35679a,
        0xff97b1d087b747d55d64ffb8ad39555b,
    ),
    u256::from_words(
        0x1b31de77c216ddb36dcdbb97f1db9ff9,
        0x7fb897971a39e07b1631ea69211feefc,
    ),
    u256::from_words(
        0x02275498ac3873bca297e29a88d7d7cf,
        0xe00b038e3a93106a3bb5db4abb5c804a,
    ),
    u256::from_words(
        0x20c513ff59058281fc75e4f9da32f318,
        0x725b44a2b8b094f9c159e6165efed6f1,
    ),
    u256::from_words(
        0x22a9b8f30f8945cb15e605efdbfaddae,
        0x306e2ae9fa5ddc9e3e4eb1849f185731,
    ),
    u256::from_words(
        0x1725019a7bce2d3bd9d63ff7be7bd417,
        0xb6aae29154fd5e5b0619ed386e29ef3b,
    ),
];

/// Storage key for a tree's state.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MerkleStorageKey {
    /// The full [`MerkleTreeState`] of the tree with this id.
    Tree(u32),
}

/// On-ledger state of one incremental tree: O(depth + history) words.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MerkleTreeState {
    /// Index the next inserted leaf will get (= number of leaves so far).
    pub next_index: u64,
    /// Slot in `roots` holding the current root.
    pub current_root_index: u32,
    /// `filled_subtrees[i]` is the latest left-hand node at height `i`.
    pub filled_subtrees: Vec<U256>,
    /// Ring buffer of the most recent roots (zero = unused slot).
    pub roots: Vec<U256>,
}

/// Converts an `ethnum` constant into a host `U256`.
fn to_host(env: &Env, v: &u256) -> U256 {
    U256::from_be_bytes(env, &Bytes::from_array(env, &v.to_be_bytes()))
}

/// Reads a host `U256` into an `ethnum` value.
fn to_eth(v: &U256) -> u256 {
    let mut buf = [0u8; 32];
    v.to_be_bytes().copy_into_slice(&mut buf);
    u256::from_be_bytes(buf)
}

/// Returns `ZERO_HASHES[level]` as a host value.
///
/// # Errors
/// [`ZkError::InvalidInput`] if `level > MAX_DEPTH`.
pub fn zero_hash(env: &Env, level: usize) -> Result<U256, ZkError> {
    ZERO_HASHES
        .get(level)
        .map(|z| to_host(env, z))
        .ok_or(ZkError::InvalidInput)
}

/// Poseidon2 two-to-one compression used for every interior node.
pub fn hash_pair(env: &Env, left: &U256, right: &U256) -> U256 {
    crate::poseidon2::hash_to_field(env, &[left.clone(), right.clone()])
}

/// Poseidon2 two-to-one compressor with the BN254 constants loaded once.
///
/// Produces exactly [`hash_pair`]'s output (the crate sponge absorbing two
/// canonical elements into a zero state with 10* padding and capacity-domain
/// framing), but the round constants and matrix diagonal are fetched once per
/// insertion from the instance cache instead of once per node, which is the
/// dominant cost of a deep insertion.
struct NodeHasher {
    env: Env,
    mat: Vec<U256>,
    rc: Vec<Vec<U256>>,
    zero: U256,
    one: U256,
    domain: U256,
    modulus: U256,
}

impl NodeHasher {
    // Must stay in sync with `crate::poseidon2` (t=3, d=5, R_F=8, R_P=56).
    const T: u32 = 3;
    const D: u32 = 5;
    const ROUNDS_F: u32 = 8;
    const ROUNDS_P: u32 = 56;

    fn new_cached(env: &Env) -> Self {
        let mut domain_bytes = [0u8; 32];
        domain_bytes[..16].copy_from_slice(&0x736f726f62616e2d_u128.to_be_bytes());
        domain_bytes[16..].copy_from_slice(&0x7a6b2d70322d7631_u128.to_be_bytes());
        Self {
            env: env.clone(),
            mat: crate::cache::mat_diag(env),
            rc: crate::cache::round_constants(env),
            zero: U256::from_u128(env, 0),
            one: U256::from_u128(env, 1),
            domain: U256::from_be_bytes(env, &Bytes::from_array(env, &domain_bytes)),
            modulus: crate::poseidon2::fr_modulus(env),
        }
    }

    fn permute(&self, state: &Vec<U256>) -> Vec<U256> {
        self.env.crypto_hazmat().poseidon2_permutation(
            state,
            soroban_sdk::symbol_short!("BN254"),
            Self::T,
            Self::D,
            Self::ROUNDS_F,
            Self::ROUNDS_P,
            &self.mat,
            &self.rc,
        )
    }

    /// `left` and `right` must already be canonical (`< r`).
    fn hash(&self, left: &U256, right: &U256) -> Result<U256, ZkError> {
        let state = soroban_sdk::vec![&self.env, left.clone(), right.clone(), self.zero.clone()];
        let mut state = self.permute(&state);
        let first = crate::poseidon2::field_add(
            &state.get(0).ok_or(ZkError::HostError)?,
            &self.one,
            &self.modulus,
        );
        let capacity = crate::poseidon2::field_add(
            &state.get(2).ok_or(ZkError::HostError)?,
            &self.domain,
            &self.modulus,
        );
        state.set(0, first);
        state.set(2, capacity);
        let state = self.permute(&state);
        state.get(0).ok_or(ZkError::HostError)
    }
}

fn check_leaf(leaf: &U256) -> Result<(), ZkError> {
    if Bn254::is_valid_scalar(to_eth(leaf)) {
        Ok(())
    } else {
        Err(ZkError::InvalidFieldElement)
    }
}

/// Handle to an append-only Poseidon2 Merkle tree in persistent storage.
///
/// * `DEPTH`: tree height, `1..=32` (capacity `2^DEPTH` leaves).
/// * `ROOT_HISTORY`: how many recent roots [`Self::is_known_root`] accepts,
///   `>= 1` (default [`DEFAULT_ROOT_HISTORY_SIZE`]).
///
/// The handle itself holds no state; every call reads the ledger. Methods that
/// touch storage must run inside a contract invocation.
///
/// ```ignore
/// let tree = IncrementalMerkleTree::<20>::new(&env, 0)?;
/// let index = tree.insert_leaf(&commitment)?;
/// assert!(tree.is_known_root(&tree.current_root()));
/// ```
pub struct IncrementalMerkleTree<
    const DEPTH: usize,
    const ROOT_HISTORY: usize = DEFAULT_ROOT_HISTORY_SIZE,
> {
    env: Env,
    tree_id: u32,
}

impl<const DEPTH: usize, const ROOT_HISTORY: usize> IncrementalMerkleTree<DEPTH, ROOT_HISTORY> {
    /// Creates a handle for tree `tree_id`.
    ///
    /// # Errors
    /// [`ZkError::InvalidInput`] if `DEPTH` is not in `1..=32` or
    /// `ROOT_HISTORY` is zero.
    pub fn new(env: &Env, tree_id: u32) -> Result<Self, ZkError> {
        if DEPTH == 0 || DEPTH > MAX_DEPTH || ROOT_HISTORY == 0 || ROOT_HISTORY > u32::MAX as usize
        {
            return Err(ZkError::InvalidInput);
        }
        Ok(Self {
            env: env.clone(),
            tree_id,
        })
    }

    /// Maximum number of leaves the tree can hold (`2^DEPTH`).
    pub fn capacity(&self) -> u64 {
        1u64 << DEPTH
    }

    fn key(&self) -> MerkleStorageKey {
        MerkleStorageKey::Tree(self.tree_id)
    }

    /// State of an empty tree: frontier of zero hashes, history holding only
    /// the empty root.
    fn empty_state(&self) -> MerkleTreeState {
        let env = &self.env;
        let mut filled_subtrees = Vec::new(env);
        for z in ZERO_HASHES.iter().take(DEPTH) {
            filled_subtrees.push_back(to_host(env, z));
        }
        let zero = U256::from_u128(env, 0);
        let mut roots = Vec::new(env);
        roots.push_back(to_host(env, &ZERO_HASHES[DEPTH]));
        for _ in 1..ROOT_HISTORY {
            roots.push_back(zero.clone());
        }
        MerkleTreeState {
            next_index: 0,
            current_root_index: 0,
            filled_subtrees,
            roots,
        }
    }

    /// Reads the stored state, or the empty-tree state if nothing is stored.
    ///
    /// # Errors
    /// [`ZkError::StorageError`] if the stored state does not match this
    /// handle's `DEPTH` / `ROOT_HISTORY` (e.g. the same `tree_id` was used
    /// with different parameters).
    pub fn state(&self) -> Result<MerkleTreeState, ZkError> {
        match self
            .env
            .storage()
            .persistent()
            .get::<MerkleStorageKey, MerkleTreeState>(&self.key())
        {
            None => Ok(self.empty_state()),
            Some(s) => {
                if s.filled_subtrees.len() as usize != DEPTH
                    || s.roots.len() as usize != ROOT_HISTORY
                    || s.current_root_index as usize >= ROOT_HISTORY
                {
                    return Err(ZkError::StorageError);
                }
                Ok(s)
            }
        }
    }

    /// Number of leaves inserted so far (the index the next leaf will get).
    pub fn next_index(&self) -> Result<u64, ZkError> {
        Ok(self.state()?.next_index)
    }

    /// The current root (the empty-tree root before any insertion).
    pub fn current_root(&self) -> Result<U256, ZkError> {
        let s = self.state()?;
        s.roots
            .get(s.current_root_index)
            .ok_or(ZkError::StorageError)
    }

    /// Returns `true` if `root` is one of the last `ROOT_HISTORY` roots.
    ///
    /// Zero is never a known root (it marks unused ring-buffer slots). A
    /// state that cannot be read is treated as "unknown".
    pub fn is_known_root(&self, root: &U256) -> bool {
        if to_eth(root) == u256::ZERO {
            return false;
        }
        let s = match self.state() {
            Ok(s) => s,
            Err(_) => return false,
        };
        // Walk backwards from the newest root so recent roots hit first.
        let n = ROOT_HISTORY as u32;
        let mut i = s.current_root_index;
        for _ in 0..n {
            if let Some(r) = s.roots.get(i) {
                if &r == root {
                    return true;
                }
            }
            i = if i == 0 { n - 1 } else { i - 1 };
        }
        false
    }

    /// Appends `leaf`, updates the frontier and root history, extends the TTL,
    /// and returns the leaf's index.
    ///
    /// Costs exactly `DEPTH` Poseidon2 compressions (two host permutations
    /// each), one storage read and one
    /// storage write.
    ///
    /// # Errors
    /// * [`ZkError::InvalidFieldElement`] if `leaf >= r`.
    /// * [`ZkError::InvalidInput`] if the tree is full (`2^DEPTH` leaves).
    /// * [`ZkError::StorageError`] if the stored state is inconsistent.
    pub fn insert_leaf(&self, leaf: &U256) -> Result<u64, ZkError> {
        check_leaf(leaf)?;
        let mut s = self.state()?;
        let index = s.next_index;
        if index >= self.capacity() {
            return Err(ZkError::InvalidInput);
        }

        let env = &self.env;
        let hasher = NodeHasher::new_cached(env);
        let mut current = leaf.clone();
        let mut idx = index;
        for (level, zero) in ZERO_HASHES.iter().take(DEPTH).enumerate() {
            let level_u32 = level as u32;
            if idx & 1 == 0 {
                // Left child: the sibling is still an empty subtree.
                s.filled_subtrees.set(level_u32, current.clone());
                let right = to_host(env, zero);
                current = hasher.hash(&current, &right)?;
            } else {
                let left = s
                    .filled_subtrees
                    .get(level_u32)
                    .ok_or(ZkError::StorageError)?;
                current = hasher.hash(&left, &current)?;
            }
            idx >>= 1;
        }

        let next_root_index = (s.current_root_index + 1) % ROOT_HISTORY as u32;
        s.roots.set(next_root_index, current);
        s.current_root_index = next_root_index;
        s.next_index = index + 1;

        let store = env.storage().persistent();
        store.set(&self.key(), &s);
        store.extend_ttl(&self.key(), MERKLE_TTL_THRESHOLD, MERKLE_TTL_AMOUNT);
        Ok(index)
    }

    /// Extends the TTL of the stored tree state, e.g. from a keep-alive call.
    /// A tree with no stored state is left untouched.
    pub fn extend_ttl(&self) {
        let store = self.env.storage().persistent();
        if store.has(&self.key()) {
            store.extend_ttl(&self.key(), MERKLE_TTL_THRESHOLD, MERKLE_TTL_AMOUNT);
        }
    }
}

/// A Merkle inclusion proof for one leaf, verified off-chain or in tests.
///
/// `siblings[i]` is the sibling node at height `i`; bit `i` of `index` says
/// whether the path node at height `i` is a right child (`1`) or left child
/// (`0`). Verification needs no storage, so it also runs outside a contract.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MerkleProof {
    pub leaf: U256,
    pub index: u64,
    pub siblings: AllocVec<U256>,
}

impl MerkleProof {
    /// Folds the path from `leaf` up to the root.
    ///
    /// # Errors
    /// * [`ZkError::InvalidInput`] if the path is empty, deeper than
    ///   [`MAX_DEPTH`], or `index` does not fit in `siblings.len()` bits.
    /// * [`ZkError::InvalidFieldElement`] if the leaf or any sibling is `>= r`.
    pub fn compute_root(&self, env: &Env) -> Result<U256, ZkError> {
        let depth = self.siblings.len();
        if depth == 0 || depth > MAX_DEPTH {
            return Err(ZkError::InvalidInput);
        }
        if depth < 64 && self.index >> depth != 0 {
            return Err(ZkError::InvalidInput);
        }
        check_leaf(&self.leaf)?;
        let mut current = self.leaf.clone();
        let mut idx = self.index;
        for sibling in &self.siblings {
            check_leaf(sibling)?;
            current = if idx & 1 == 0 {
                hash_pair(env, &current, sibling)
            } else {
                hash_pair(env, sibling, &current)
            };
            idx >>= 1;
        }
        Ok(current)
    }

    /// Returns `true` iff this proof folds to `root`. Malformed proofs return
    /// `false` instead of an error.
    pub fn verify(&self, env: &Env, root: &U256) -> bool {
        matches!(self.compute_root(env), Ok(r) if &r == root)
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use soroban_sdk::testutils::storage::Persistent as _;
    use soroban_sdk::testutils::Ledger as _;

    fn env() -> Env {
        let e = Env::default();
        e.cost_estimate().budget().reset_unlimited();
        e
    }

    fn leaf(env: &Env, i: u64) -> U256 {
        // Distinct, non-zero, in-field leaves.
        U256::from_u128(env, 0x1000 + i as u128 * 7919)
    }

    /// Reference root built from the full leaf list (empty slots are zero
    /// subtrees). Independent of the frontier algorithm under test.
    fn reference_root(env: &Env, leaves: &[U256], depth: usize) -> U256 {
        let mut level: std::vec::Vec<U256> = leaves.to_vec();
        for h in 0..depth {
            let zero = zero_hash(env, h).unwrap();
            let mut next = std::vec::Vec::new();
            let mut i = 0;
            while i < level.len() {
                let l = level[i].clone();
                let r = if i + 1 < level.len() {
                    level[i + 1].clone()
                } else {
                    zero.clone()
                };
                next.push(hash_pair(env, &l, &r));
                i += 2;
            }
            if next.is_empty() {
                next.push(zero_hash(env, h + 1).unwrap());
            }
            level = next;
        }
        level[0].clone()
    }

    /// Reference inclusion proof for `index` among `leaves`.
    fn reference_proof(env: &Env, leaves: &[U256], index: usize, depth: usize) -> MerkleProof {
        let mut level: std::vec::Vec<U256> = leaves.to_vec();
        let mut siblings = AllocVec::new();
        let mut pos = index;
        for h in 0..depth {
            let zero = zero_hash(env, h).unwrap();
            let sib = pos ^ 1;
            siblings.push(level.get(sib).cloned().unwrap_or(zero.clone()));
            let mut next = std::vec::Vec::new();
            let mut i = 0;
            while i < level.len() {
                let l = level[i].clone();
                let r = level.get(i + 1).cloned().unwrap_or(zero.clone());
                next.push(hash_pair(env, &l, &r));
                i += 2;
            }
            level = next;
            pos >>= 1;
        }
        MerkleProof {
            leaf: leaves[index].clone(),
            index: index as u64,
            siblings,
        }
    }

    #[test]
    fn zero_hashes_match_poseidon2() {
        let e = env();
        assert_eq!(ZERO_HASHES[0], u256::ZERO);
        for i in 0..MAX_DEPTH {
            let z = zero_hash(&e, i).unwrap();
            let next = hash_pair(&e, &z, &z);
            assert_eq!(to_eth(&next), ZERO_HASHES[i + 1], "ZERO_HASHES[{}]", i + 1);
        }
        assert_eq!(zero_hash(&e, MAX_DEPTH + 1), Err(ZkError::InvalidInput));
    }

    #[test]
    fn rejects_unsupported_parameters() {
        let e = env();
        assert!(IncrementalMerkleTree::<0>::new(&e, 0).is_err());
        assert!(IncrementalMerkleTree::<33>::new(&e, 0).is_err());
        assert!(IncrementalMerkleTree::<8, 0>::new(&e, 0).is_err());
        assert!(IncrementalMerkleTree::<1>::new(&e, 0).is_ok());
        assert!(IncrementalMerkleTree::<32>::new(&e, 0).is_ok());
    }

    #[test]
    fn empty_tree_root_is_zero_hash_of_depth() {
        let e = env();
        let id = e.register(crate::ZkContract, ());
        e.as_contract(&id, || {
            let tree = IncrementalMerkleTree::<20>::new(&e, 0).unwrap();
            let root = tree.current_root().unwrap();
            assert_eq!(to_eth(&root), ZERO_HASHES[20]);
            assert!(tree.is_known_root(&root));
            assert_eq!(tree.next_index().unwrap(), 0);
            // Reads alone write nothing.
            assert!(!e.storage().persistent().has(&MerkleStorageKey::Tree(0)));
        });
    }

    #[test]
    fn one_hundred_sequential_insertions_match_reference_tree() {
        let e = env();
        let id = e.register(crate::ZkContract, ());
        let mut leaves = std::vec::Vec::new();
        for i in 0..100u64 {
            let l = leaf(&e, i);
            // One contract invocation per insertion, as on-chain.
            let index = e.as_contract(&id, || {
                IncrementalMerkleTree::<32>::new(&e, 7)
                    .unwrap()
                    .insert_leaf(&l)
                    .unwrap()
            });
            assert_eq!(index, i);
            leaves.push(l);
            if matches!(i, 0 | 1 | 2 | 31 | 63 | 64 | 99) {
                let root = e.as_contract(&id, || {
                    IncrementalMerkleTree::<32>::new(&e, 7)
                        .unwrap()
                        .current_root()
                        .unwrap()
                });
                assert_eq!(
                    root,
                    reference_root(&e, &leaves, 32),
                    "root after {} insertions",
                    i + 1
                );
            }
        }
        let (next, root) = e.as_contract(&id, || {
            let tree = IncrementalMerkleTree::<32>::new(&e, 7).unwrap();
            (tree.next_index().unwrap(), tree.current_root().unwrap())
        });
        assert_eq!(next, 100);

        // Inclusion proofs for first, middle, boundary and last leaves.
        for &i in &[0usize, 1, 50, 63, 64, 99] {
            let proof = reference_proof(&e, &leaves, i, 32);
            assert!(proof.verify(&e, &root), "proof for leaf {i}");
        }
    }

    #[test]
    fn small_tree_every_root_matches_reference() {
        let e = env();
        let id = e.register(crate::ZkContract, ());
        e.as_contract(&id, || {
            let tree = IncrementalMerkleTree::<4>::new(&e, 1).unwrap();
            let mut leaves = std::vec::Vec::new();
            for i in 0..16u64 {
                let l = leaf(&e, i);
                tree.insert_leaf(&l).unwrap();
                leaves.push(l);
                assert_eq!(tree.current_root().unwrap(), reference_root(&e, &leaves, 4));
            }
        });
    }

    #[test]
    fn full_tree_rejects_further_insertions() {
        let e = env();
        let id = e.register(crate::ZkContract, ());
        e.as_contract(&id, || {
            let tree = IncrementalMerkleTree::<3>::new(&e, 2).unwrap();
            assert_eq!(tree.capacity(), 8);
            for i in 0..8u64 {
                assert_eq!(tree.insert_leaf(&leaf(&e, i)).unwrap(), i);
            }
            let full_root = tree.current_root().unwrap();
            assert_eq!(tree.insert_leaf(&leaf(&e, 8)), Err(ZkError::InvalidInput));
            // A rejected insert must not change anything.
            assert_eq!(tree.next_index().unwrap(), 8);
            assert_eq!(tree.current_root().unwrap(), full_root);
        });
    }

    #[test]
    fn root_history_window_wraps_around() {
        let e = env();
        let id = e.register(crate::ZkContract, ());
        e.as_contract(&id, || {
            const H: usize = 4;
            let tree = IncrementalMerkleTree::<8, H>::new(&e, 3).unwrap();
            let empty_root = tree.current_root().unwrap();
            let mut roots = std::vec![empty_root.clone()];
            for i in 0..10u64 {
                tree.insert_leaf(&leaf(&e, i)).unwrap();
                roots.push(tree.current_root().unwrap());
            }
            // Only the newest H roots are still known.
            let n = roots.len();
            for (k, r) in roots.iter().enumerate() {
                let expected = k >= n - H;
                assert_eq!(tree.is_known_root(r), expected, "root #{k}");
            }
            assert!(!tree.is_known_root(&empty_root));
            assert_eq!(tree.state().unwrap().current_root_index as usize, 10 % H);
        });
    }

    #[test]
    fn is_known_root_rejects_zero_and_unknown_values() {
        let e = env();
        let id = e.register(crate::ZkContract, ());
        e.as_contract(&id, || {
            let tree = IncrementalMerkleTree::<8>::new(&e, 4).unwrap();
            tree.insert_leaf(&leaf(&e, 0)).unwrap();
            // Unused ring-buffer slots hold zero; zero must never be accepted.
            assert!(!tree.is_known_root(&U256::from_u128(&e, 0)));
            assert!(!tree.is_known_root(&U256::from_u128(&e, 12345)));
        });
    }

    #[test]
    fn rejects_non_canonical_leaf() {
        let e = env();
        let id = e.register(crate::ZkContract, ());
        e.as_contract(&id, || {
            let tree = IncrementalMerkleTree::<8>::new(&e, 5).unwrap();
            let r = crate::poseidon2::fr_modulus(&e);
            assert_eq!(tree.insert_leaf(&r), Err(ZkError::InvalidFieldElement));
            assert_eq!(tree.next_index().unwrap(), 0);
            // r - 1 is the largest valid leaf.
            let r_minus_1 = to_host(&e, &(to_eth(&r) - 1));
            assert_eq!(tree.insert_leaf(&r_minus_1).unwrap(), 0);
        });
    }

    #[test]
    fn trees_with_different_ids_are_independent() {
        let e = env();
        let id = e.register(crate::ZkContract, ());
        e.as_contract(&id, || {
            let a = IncrementalMerkleTree::<8>::new(&e, 10).unwrap();
            let b = IncrementalMerkleTree::<8>::new(&e, 11).unwrap();
            a.insert_leaf(&leaf(&e, 1)).unwrap();
            assert_eq!(a.next_index().unwrap(), 1);
            assert_eq!(b.next_index().unwrap(), 0);
            assert_ne!(a.current_root().unwrap(), b.current_root().unwrap());
        });
    }

    #[test]
    fn mismatched_parameters_for_same_id_are_rejected() {
        let e = env();
        let id = e.register(crate::ZkContract, ());
        e.as_contract(&id, || {
            IncrementalMerkleTree::<8>::new(&e, 12)
                .unwrap()
                .insert_leaf(&leaf(&e, 1))
                .unwrap();
            let wrong = IncrementalMerkleTree::<16>::new(&e, 12).unwrap();
            assert_eq!(wrong.insert_leaf(&leaf(&e, 2)), Err(ZkError::StorageError));
            assert_eq!(wrong.current_root(), Err(ZkError::StorageError));
        });
    }

    #[test]
    fn insert_extends_persistent_ttl() {
        let e = env();
        let id = e.register(crate::ZkContract, ());
        e.as_contract(&id, || {
            let tree = IncrementalMerkleTree::<8>::new(&e, 6).unwrap();
            tree.insert_leaf(&leaf(&e, 0)).unwrap();
            assert_eq!(
                e.storage().persistent().get_ttl(&MerkleStorageKey::Tree(6)),
                MERKLE_TTL_AMOUNT
            );
        });
        e.ledger()
            .with_mut(|l| l.sequence_number += MERKLE_TTL_AMOUNT - MERKLE_TTL_THRESHOLD + 1);
        e.as_contract(&id, || {
            let key = MerkleStorageKey::Tree(6);
            assert!(e.storage().persistent().get_ttl(&key) < MERKLE_TTL_THRESHOLD);
            let tree = IncrementalMerkleTree::<8>::new(&e, 6).unwrap();
            tree.insert_leaf(&leaf(&e, 1)).unwrap();
            assert_eq!(e.storage().persistent().get_ttl(&key), MERKLE_TTL_AMOUNT);
        });
    }

    #[test]
    fn merkle_proof_rejects_malformed_inputs() {
        let e = env();
        let leaves: std::vec::Vec<U256> = (0..5).map(|i| leaf(&e, i)).collect();
        let root = reference_root(&e, &leaves, 4);
        let good = reference_proof(&e, &leaves, 3, 4);
        assert!(good.verify(&e, &root));

        let mut wrong_leaf = good.clone();
        wrong_leaf.leaf = leaf(&e, 99);
        assert!(!wrong_leaf.verify(&e, &root));

        let mut wrong_index = good.clone();
        wrong_index.index = 2;
        assert!(!wrong_index.verify(&e, &root));

        let mut index_too_big = good.clone();
        index_too_big.index = 16;
        assert_eq!(index_too_big.compute_root(&e), Err(ZkError::InvalidInput));

        let mut empty = good.clone();
        empty.siblings.clear();
        assert_eq!(empty.compute_root(&e), Err(ZkError::InvalidInput));

        let mut bad_sibling = good.clone();
        bad_sibling.siblings[0] = crate::poseidon2::fr_modulus(&e);
        assert_eq!(
            bad_sibling.compute_root(&e),
            Err(ZkError::InvalidFieldElement)
        );
    }

    // ── Soroban CPU instruction cost benchmarks ──────────────────────────────

    /// Network-shaped per-transaction CPU limit (instructions).
    const TX_CPU_INSNS_LIMIT: u64 = 100_000_000;

    fn measured_insert<const D: usize>(e: &Env, id: &soroban_sdk::Address) -> (u64, u64) {
        e.as_contract(id, || {
            let tree = IncrementalMerkleTree::<D>::new(e, D as u32).unwrap();
            // Warm the Poseidon2 instance cache and the tree entry first so
            // the measurement is a steady-state insertion.
            tree.insert_leaf(&leaf(e, 0)).unwrap();
            let mut budget = e.cost_estimate().budget();
            budget.reset_default();
            tree.insert_leaf(&leaf(e, 1)).unwrap();
            let budget = e.cost_estimate().budget();
            let cpu = budget.cpu_instruction_cost();
            let mem = budget.memory_bytes_cost();
            e.cost_estimate().budget().reset_unlimited();
            (cpu, mem)
        })
    }

    #[test]
    fn insert_cost_fits_transaction_budget() {
        let e = env();
        let id = e.register(crate::ZkContract, ());
        let (cpu20, mem20) = measured_insert::<20>(&e, &id);
        let (cpu32, mem32) = measured_insert::<32>(&e, &id);
        std::println!("merkle insert depth 20: {cpu20} cpu insns, {mem20} bytes");
        std::println!("merkle insert depth 32: {cpu32} cpu insns, {mem32} bytes");
        assert!(cpu20 > 0 && cpu32 > cpu20);
        assert!(
            cpu32 < TX_CPU_INSNS_LIMIT,
            "depth-32 insert used {cpu32} CPU insns, over the {TX_CPU_INSNS_LIMIT} tx limit"
        );
    }

    #[test]
    fn root_queries_cost_no_hashing() {
        let e = env();
        let id = e.register(crate::ZkContract, ());
        e.as_contract(&id, || {
            let tree = IncrementalMerkleTree::<32>::new(&e, 40).unwrap();
            tree.insert_leaf(&leaf(&e, 0)).unwrap();
            let root = tree.current_root().unwrap();

            let mut budget = e.cost_estimate().budget();
            budget.reset_default();
            assert!(tree.is_known_root(&root));
            let query = e.cost_estimate().budget().cpu_instruction_cost();

            e.cost_estimate().budget().reset_default();
            tree.insert_leaf(&leaf(&e, 1)).unwrap();
            let insert = e.cost_estimate().budget().cpu_instruction_cost();
            e.cost_estimate().budget().reset_unlimited();
            std::println!("is_known_root: {query} cpu insns; insert: {insert}");
            // A root lookup is a storage read plus comparisons, far below an
            // insertion's DEPTH Poseidon2 calls.
            assert!(query * 4 < insert);
        });
    }
}
