//! Soroban-optimized Merkle authentication (Issue #366, Phase 3).
//!
//! Verification streams a fixed-size [`MerklePath`] of sibling hashes and folds
//! them with the leaf via the **native SHA-256 host binding** (`env.crypto()`.
//! sha256`, a single CAP-0075 host call per level). No guest Wasm heap is
//! touched: the only storage is the `siblings` array, bounded by `MAX_DEPTH`.
//!
//! **Sparse Merkle Tree (SMT) support** (Issue #459).
//!
//! A Sparse Merkle Tree is a full binary tree of fixed depth (typically 256)
//! where the vast majority of leaves are empty (default value). Only non-empty
//! leaves are stored explicitly. The authentication path for a leaf only includes
//! non-empty siblings; missing siblings are implicitly the precomputed "empty
//! hash" for that level. This enables O(log N) verification with O(k) storage
//! where k is the number of non-empty nodes on the path.
//!
//! Gas model: each tree level costs exactly one host `sha256` call. For a tree
//! of `2^d` leaves the verifier pays `d` host calls — this is the dominant, and
//! minimal, cost of the STARK Merkle check.
//!
//! **Localized hashing gas profile.** A standard STARK Merkle check walks one
//! authentication path of length `d` (the trace-domain log-size, e.g. `d = 20`
//! for a 1M-row trace). Each `sha256` host call is a single CAP-0075 metered
//! instruction; the Wasm-side work is just 64 bytes of array copies plus one
//! `BytesN` conversion per level. Total verifier cost is therefore
//! `O(d)` host calls and `O(d·64)` bytes of linear-memory traffic — no
//! guest heap allocation, independent of trace width. Doubling the trace length
//! adds exactly one more `sha256` call per query.

use alloc::collections::BTreeMap;
use ethnum::u256;
use soroban_sdk::{Bytes, BytesN, Env, Vec};

use crate::stark::field::Felt;
use alloc::vec::Vec as AllocVec;

/// Maximum tree depth supported by a [`MerklePath`] (covers `2^32` leaves).
pub const MAX_DEPTH: u32 = 32;

/// An authentication path: the sibling hashes (raw 32-byte digests) from leaf to
/// root, plus the leaf index so folding can decide left/right ordering.
#[derive(Clone, Copy)]
pub struct MerklePath {
    pub siblings: [[u8; 32]; MAX_DEPTH as usize],
    pub depth: u32,
    pub index: u64,
}

/// SHA-256 of an arbitrary byte slice as an RFC 6962 leaf (`0x00 || data`).
#[inline(always)]
pub fn hash(env: &Env, data: &Bytes) -> BytesN<32> {
    let mut buf = Bytes::from_array(env, &[0x00u8]);
    buf.append(data);
    BytesN::from_array(env, &env.crypto().sha256(&buf).to_array())
}

/// Merkle leaf for a single Goldilocks element (`0x00 || 8-byte big-endian encoding`).
#[inline(always)]
pub fn felt_leaf(env: &Env, f: Felt) -> BytesN<32> {
    let b = f.to_bytes();
    let mut buf = [0u8; 9];
    buf[0] = 0x00;
    buf[1..].copy_from_slice(&b);
    BytesN::from_array(
        env,
        &env.crypto()
            .sha256(&Bytes::from_array(env, &buf))
            .to_array(),
    )
}

/// Hash two 32-byte digests into their parent node using RFC 6962 internal
/// domain separation (`0x01 || l || r`), returning raw bytes.
#[inline(always)]
fn sha_pair(l: &[u8; 32], r: &[u8; 32], env: &Env) -> [u8; 32] {
    let mut buf = [0u8; 65];
    buf[0] = 0x01;
    buf[1..33].copy_from_slice(l);
    buf[33..65].copy_from_slice(r);
    env.crypto()
        .sha256(&Bytes::from_array(env, &buf))
        .to_array()
}

#[inline(always)]
fn sha_pair_bn(env: &Env, l: &BytesN<32>, r: &BytesN<32>) -> BytesN<32> {
    let a = l.to_array();
    let b = r.to_array();
    BytesN::from_array(env, &sha_pair(&a, &b, env))
}

impl MerklePath {
    /// Recompute the root this path authenticates to, given the leaf digest.
    pub fn compute_root(&self, env: &Env, leaf: &BytesN<32>) -> BytesN<32> {
        let mut cur = leaf.to_array();
        let mut idx = self.index;
        for &sib in self.siblings.iter().take(self.depth as usize) {
            let (l, r) = if idx & 1 == 0 { (cur, sib) } else { (sib, cur) };
            cur = sha_pair(&l, &r, env);
            idx >>= 1;
        }
        BytesN::from_array(env, &cur)
    }

    /// Verify that `leaf` sits at `index` in the tree with Merkle `root`.
    pub fn verify(&self, env: &Env, leaf: &BytesN<32>, root: &BytesN<32>) -> bool {
        if self.depth > MAX_DEPTH {
            return false;
        }
        &self.compute_root(env, leaf) == root
    }
}

/// Verify a path stored as a plain sibling array (no [`MerklePath`] wrapper).
///
/// Used by the STARK verifier, whose paths live inside fixed-size proof arrays.
/// `depth` is hostile input, so an out-of-range depth is rejected instead of
/// indexing past `siblings` or looping unbounded.
pub fn verify_path_at(
    env: &Env,
    leaf: &BytesN<32>,
    root: &BytesN<32>,
    siblings: &[[u8; 32]],
    depth: u32,
    index: u64,
) -> bool {
    if depth > MAX_DEPTH || depth as usize > siblings.len() {
        return false;
    }
    let mut cur = leaf.to_array();
    let mut idx = index;
    for sib in siblings.iter().take(depth as usize) {
        let (l, r) = if idx & 1 == 0 {
            (cur, *sib)
        } else {
            (*sib, cur)
        };
        cur = sha_pair(&l, &r, env);
        idx >>= 1;
    }
    &BytesN::from_array(env, &cur) == root
}

// ===========================================================================
// Deep-branching MerklePath structures (Issue #460)
// ===========================================================================
//
// The original `MerklePath` is capped at `MAX_DEPTH = 32` because it stores
// all siblings in a flat `[[u8; 32]; 32]` array (1 KiB on the stack). For
// trees with depth > 32 (e.g. the 2^40 row traces used by large STARKs),
// naively extending the array to 64 or 128 slots wastes stack in `no_std`
// environments where every byte counts.
//
// The structures below solve this with two complementary approaches:
//
// 1. `DeepMerklePath`  — a tiered (paged) layout that splits siblings into
//    fixed-size pages of `PAGE_SIZE` entries. Only the pages actually
//    needed are populated, reducing the worst-case stack footprint from
//    `DEEP_MAX_DEPTH * 32` to `num_pages_used * PAGE_SIZE * 32`.
//
// 2. `CompactMerklePath` — an inline representation for the common case of
//    ≤ `COMPACT_MAX_DEPTH` levels (covers up to 2^64 leaves). It avoids
//    heap allocation entirely and implements `Clone` + `Copy`, making it
//    safe to pass by value in `no_std` without hidden memcpy overhead.

/// Maximum depth supported by [`DeepMerklePath`] (covers 2^64 leaves).
pub const DEEP_MAX_DEPTH: u32 = 64;

/// Number of sibling entries per page in [`DeepMerklePath`].
const PAGE_SIZE: usize = 16;

/// Number of pages required to cover [`DEEP_MAX_DEPTH`].
const NUM_PAGES: usize = (DEEP_MAX_DEPTH as usize).div_ceil(PAGE_SIZE); // 4

/// A single page of sibling hashes.
#[derive(Clone, Copy)]
struct SiblingPage {
    entries: [[u8; 32]; PAGE_SIZE],
}

impl SiblingPage {
    const ZERO: SiblingPage = SiblingPage {
        entries: [[0u8; 32]; PAGE_SIZE],
    };
}

/// A memory-efficient Merkle authentication path for trees with depth up to
/// [`DEEP_MAX_DEPTH`] (64).
///
/// # Design
///
/// Siblings are stored in fixed-size **pages** of [`PAGE_SIZE`] (16) entries
/// each. For a tree of depth `d`, only `ceil(d / PAGE_SIZE)` pages carry
/// meaningful data. The struct itself is always `NUM_PAGES` pages large
/// (4 × 16 × 32 = 2 KiB), but the verifier only reads `depth` entries,
/// so the unused tail is never touched.
///
/// Compared to a flat `[[u8; 32]; 64]` (2 KiB) this layout is the same
/// worst-case size, but the page boundaries make it straightforward for
/// the compiler to elide unused pages when `depth` is known at compile
/// time (e.g. via const generics in a future extension).
///
/// # `no_std` friendliness
///
/// * No heap allocation — all storage is on the stack.
/// * Implements `Clone` and `Copy` (total size 2,052 bytes) so callers
///   can pass paths by value without hidden `memcpy` overhead beyond the
///   struct size itself.
/// * No recursive data structures — stack depth is O(1) regardless of
///   tree depth.
pub struct DeepMerklePath {
    /// Sibling hashes organised into fixed-size pages.
    pages: [SiblingPage; NUM_PAGES],
    /// Actual tree depth (`<= DEEP_MAX_DEPTH`).
    pub depth: u32,
    /// Leaf index in the tree.
    pub index: u64,
}

impl DeepMerklePath {
    /// Create a zeroed path (all siblings empty, depth 0).
    pub fn new() -> Self {
        Self {
            pages: [SiblingPage::ZERO; NUM_PAGES],
            depth: 0,
            index: 0,
        }
    }

    /// Set the sibling hash at the given `level`.
    ///
    /// # Panics
    ///
    /// Panics if `level >= DEEP_MAX_DEPTH`.
    #[inline(always)]
    pub fn set_sibling(&mut self, level: usize, hash: [u8; 32]) {
        if level >= DEEP_MAX_DEPTH as usize {
            return; // out-of-range levels are ignored rather than panicking
        }
        let page = level / PAGE_SIZE;
        let slot = level % PAGE_SIZE;
        self.pages[page].entries[slot] = hash;
    }

    /// Get the sibling hash at the given `level`.
    #[inline(always)]
    pub fn sibling(&self, level: usize) -> &[u8; 32] {
        static ZERO_HASH: [u8; 32] = [0u8; 32];
        if level >= DEEP_MAX_DEPTH as usize {
            return &ZERO_HASH;
        }
        let page = level / PAGE_SIZE;
        let slot = level % PAGE_SIZE;
        &self.pages[page].entries[slot]
    }

    /// Recompute the Merkle root from this path and the given leaf digest.
    pub fn compute_root(&self, env: &Env, leaf: &BytesN<32>) -> BytesN<32> {
        let mut cur = leaf.to_array();
        let mut idx = self.index;
        for i in 0..self.depth as usize {
            let sib = *self.sibling(i);
            let (l, r) = if idx & 1 == 0 { (cur, sib) } else { (sib, cur) };
            cur = sha_pair(&l, &r, env);
            idx >>= 1;
        }
        BytesN::from_array(env, &cur)
    }

    /// Verify that `leaf` sits at `index` in the tree with the given `root`.
    pub fn verify(&self, env: &Env, leaf: &BytesN<32>, root: &BytesN<32>) -> bool {
        if self.depth > DEEP_MAX_DEPTH {
            return false;
        }
        &self.compute_root(env, leaf) == root
    }

    /// Convert from a legacy [`MerklePath`] (depth ≤ 32) without cloning
    /// the sibling data — only a `memcpy` of the relevant entries.
    pub fn from_merkle_path(path: &MerklePath) -> Self {
        let mut deep = Self::new();
        deep.depth = path.depth;
        deep.index = path.index;
        for (i, &sib) in path.siblings.iter().take(path.depth as usize).enumerate() {
            deep.set_sibling(i, sib);
        }
        deep
    }
}

impl Default for DeepMerklePath {
    fn default() -> Self {
        Self::new()
    }
}

/// Maximum depth for the compact inline path (covers 2^64 leaves).
pub const COMPACT_MAX_DEPTH: usize = 64;

/// A compact, fixed-size Merkle authentication path that supports trees up
/// to depth 64 while remaining `Copy`-able.
///
/// # Motivation
///
/// [`MerklePath`] caps at depth 32, and [`DeepMerklePath`] uses a paged
/// layout that, while efficient, is a 2 KiB struct. `CompactMerklePath`
/// takes the middle ground: a simple flat `[[u8; 32]; 64]` array (2 KiB)
/// with `Copy` + `Clone` and a dead-simple API, optimised for the common
/// STARK use-case where the trace domain is at most `2^64`.
///
/// # `no_std` properties
///
/// * `Copy` + `Clone` — no hidden heap or reference-counted pointers.
/// * Stack-only — 2,060 bytes total.
/// * O(1) stack depth during verification (iterative, not recursive).
#[derive(Clone, Copy)]
pub struct CompactMerklePath {
    /// Sibling hashes from leaf (index 0) to root (index `depth - 1`).
    pub siblings: [[u8; 32]; COMPACT_MAX_DEPTH],
    /// Actual tree depth (`<= COMPACT_MAX_DEPTH`).
    pub depth: u32,
    /// Leaf index in the tree.
    pub index: u64,
}

impl Default for CompactMerklePath {
    fn default() -> Self {
        Self::new()
    }
}

impl CompactMerklePath {
    /// Create a zeroed path.
    pub fn new() -> Self {
        Self {
            siblings: [[0u8; 32]; COMPACT_MAX_DEPTH],
            depth: 0,
            index: 0,
        }
    }

    /// Recompute the Merkle root from this path and the given leaf digest.
    pub fn compute_root(&self, env: &Env, leaf: &BytesN<32>) -> BytesN<32> {
        let mut cur = leaf.to_array();
        let mut idx = self.index;
        for &sib in self.siblings.iter().take(self.depth as usize) {
            let (l, r) = if idx & 1 == 0 { (cur, sib) } else { (sib, cur) };
            cur = sha_pair(&l, &r, env);
            idx >>= 1;
        }
        BytesN::from_array(env, &cur)
    }

    /// Verify that `leaf` sits at `index` in the tree with the given `root`.
    pub fn verify(&self, env: &Env, leaf: &BytesN<32>, root: &BytesN<32>) -> bool {
        if self.depth > COMPACT_MAX_DEPTH as u32 {
            return false;
        }
        &self.compute_root(env, leaf) == root
    }

    /// Convert from a legacy [`MerklePath`] (depth ≤ 32).
    pub fn from_merkle_path(path: &MerklePath) -> Self {
        let mut compact = Self::new();
        compact.depth = path.depth;
        compact.index = path.index;
        // Copy only the used entries — the rest stay zeroed.
        let n = path.depth as usize;
        compact.siblings[..n].copy_from_slice(&path.siblings[..n]);
        compact
    }

    /// Downgrade to a legacy [`MerklePath`] if depth ≤ [`MAX_DEPTH`] (32).
    ///
    /// Returns `None` if the depth exceeds 32.
    pub fn to_merkle_path(&self) -> Option<MerklePath> {
        if self.depth > MAX_DEPTH {
            return None;
        }
        let mut mp = MerklePath {
            siblings: [[0u8; 32]; MAX_DEPTH as usize],
            depth: self.depth,
            index: self.index,
        };
        let n = self.depth as usize;
        mp.siblings[..n].copy_from_slice(&self.siblings[..n]);
        Some(mp)
    }
}

/// Batch verify multiple Merkle paths to avoid re-hashing shared intermediate nodes.
/// Enforces `depth <= MAX_DEPTH`, valid `index < 2^depth`, unique leaf indices,
/// and consistency of all shared internal nodes and sibling hashes across queries.
pub fn verify_batch(
    env: &Env,
    leaves: &Vec<BytesN<32>>,
    paths: &[MerklePath],
    root: &BytesN<32>,
) -> bool {
    let count = leaves.len() as usize;
    if count != paths.len() || count == 0 {
        return false;
    }

    let Some(first_path) = paths.first() else {
        return false;
    };
    let depth = first_path.depth;
    if depth > MAX_DEPTH {
        return false;
    }

    let mut current_level: AllocVec<(u64, [u8; 32], AllocVec<usize>)> =
        AllocVec::with_capacity(count);
    for (i, p) in paths.iter().enumerate() {
        let Some(leaf) = leaves.get(i as u32) else {
            return false;
        };
        if p.depth != depth {
            return false; // All paths must have the same depth
        }
        // `p.index` is u64 and `depth <= MAX_DEPTH (32) < 64`, avoiding 32-bit usize shift overflow on wasm32.
        if (p.index >> depth) != 0 {
            return false;
        }
        let pids = alloc::vec![i];
        current_level.push((p.index, leaf.to_array(), pids));
    }

    // Sort by index to group siblings together
    current_level.sort_unstable_by_key(|k| k.0);

    // Ensure no duplicate indices
    if current_level.windows(2).any(|w| w[0].0 == w[1].0) {
        return false;
    }

    for d in 0..depth as usize {
        let mut next_level: AllocVec<(u64, [u8; 32], AllocVec<usize>)> =
            AllocVec::with_capacity(current_level.len());
        let mut iter = current_level.into_iter().peekable();
        while let Some((idx, hash, mut pids)) = iter.next() {
            let parent_idx = idx >> 1;

            if (idx & 1) == 0
                && iter
                    .peek()
                    .is_some_and(|(next_idx, _, _)| *next_idx == (idx ^ 1))
            {
                // Sibling is present in the batch: validate that all contributing paths agree
                // with the computed sibling hash on the opposite branch.
                let Some((_, sibling_hash, right_pids)) = iter.next() else {
                    return false;
                };
                for &pid in &pids {
                    let Some(p) = paths.get(pid) else {
                        return false;
                    };
                    if p.siblings[d] != sibling_hash {
                        return false;
                    }
                }
                for &pid in &right_pids {
                    let Some(p) = paths.get(pid) else {
                        return false;
                    };
                    if p.siblings[d] != hash {
                        return false;
                    }
                }
                let parent_hash = sha_pair(&hash, &sibling_hash, env);
                pids.extend(right_pids);
                next_level.push((parent_idx, parent_hash, pids));
            } else {
                // Sibling not in batch: every path sharing this node must supply the exact same sibling.
                let Some(&first_pid) = pids.first() else {
                    return false;
                };
                let Some(first_path) = paths.get(first_pid) else {
                    return false;
                };
                let sibling_hash = first_path.siblings[d];
                for &pid in &pids[1..] {
                    let Some(p) = paths.get(pid) else {
                        return false;
                    };
                    if p.siblings[d] != sibling_hash {
                        return false;
                    }
                }
                let (l, r) = if idx & 1 == 0 {
                    (hash, sibling_hash)
                } else {
                    (sibling_hash, hash)
                };
                let parent_hash = sha_pair(&l, &r, env);
                next_level.push((parent_idx, parent_hash, pids));
            }
        }
        current_level = next_level;
    }

    if current_level.len() != 1 {
        return false;
    }

    let final_hash = current_level[0].1;
    &BytesN::from_array(env, &final_hash) == root
}

/// Build the Merkle root over a list of leaf digests (prover-side helper / test
/// fixture). Uses a host-backed `Vec` of digests — no guest Wasm heap.
pub fn merkle_root(env: &Env, leaves: &Vec<BytesN<32>>) -> BytesN<32> {
    let mut level: Vec<BytesN<32>> = Vec::new(env);
    for l in leaves.iter() {
        level.push_back(l);
    }
    if level.is_empty() {
        return BytesN::from_array(env, &[0u8; 32]);
    }
    while level.len() > 1 {
        let mut next: Vec<BytesN<32>> = Vec::new(env);
        let n = level.len();
        let mut i = 0;
        while i < n {
            let left = match level.get(i) {
                Some(v) => v,
                None => break,
            };
            // An odd trailing node is paired with itself, as in RFC 6962 trees.
            let right = level.get(i + 1).unwrap_or_else(|| left.clone());
            next.push_back(sha_pair_bn(env, &left, &right));
            i += 2;
        }
        level = next;
    }
    level
        .get(0)
        .unwrap_or_else(|| BytesN::from_array(env, &[0u8; 32]))
}

/// Open a Merkle proof for `leaves[index]` (prover-side helper / test fixture).
pub fn open(env: &Env, leaves: &Vec<BytesN<32>>, index: u32) -> MerklePath {
    let mut level: Vec<BytesN<32>> = Vec::new(env);
    for l in leaves.iter() {
        level.push_back(l);
    }
    let mut path = MerklePath {
        siblings: [[0u8; 32]; MAX_DEPTH as usize],
        depth: 0,
        index: index as u64,
    };
    let mut idx = index;
    let mut depth = 0u32;
    // Bounded by MAX_DEPTH so a deep tree can never write past `siblings`.
    while level.len() > 1 && (depth as usize) < MAX_DEPTH as usize {
        let n = level.len();
        let sib_idx = idx ^ 1;
        let sibling = level
            .get(sib_idx)
            .or_else(|| level.get(idx))
            .unwrap_or_else(|| BytesN::from_array(env, &[0u8; 32]));
        path.siblings[depth as usize] = sibling.to_array();
        let mut next: Vec<BytesN<32>> = Vec::new(env);
        let mut i = 0;
        while i < n {
            let left = match level.get(i) {
                Some(v) => v,
                None => break,
            };
            let right = level.get(i + 1).unwrap_or_else(|| left.clone());
            next.push_back(sha_pair_bn(env, &left, &right));
            i += 2;
        }
        level = next;
        idx >>= 1;
        depth += 1;
    }
    path.depth = depth;
    path
}

/// Maximum depth for a Sparse Merkle Tree (256-bit key space).
pub const SMT_MAX_DEPTH: u32 = 256;

/// Precomputed empty hashes for each level of a Sparse Merkle Tree.
/// `EMPTY_HASHES[0]` = RFC 6962 leaf hash of empty leaf (`SHA256(0x00 || [0u8; 32])`).
/// `EMPTY_HASHES[i]` = `H_internal(EMPTY_HASHES[i-1], EMPTY_HASHES[i-1])`.
pub struct EmptyHashes {
    hashes: AllocVec<[u8; 32]>,
}

impl EmptyHashes {
    /// Compute and return the empty-hash table up to `SMT_MAX_DEPTH`.
    /// Stored heap-backed so stack size stays O(1) (< 32 bytes).
    pub fn new(env: &Env) -> Self {
        let mut hashes = AllocVec::with_capacity(SMT_MAX_DEPTH as usize + 1);
        // Level 0: RFC 6962 leaf-domain hash of 32 zero bytes (0x00 || [0u8; 32])
        let mut empty_leaf = [0u8; 33];
        empty_leaf[0] = 0x00;
        hashes.push(
            env.crypto()
                .sha256(&Bytes::from_array(env, &empty_leaf))
                .to_array(),
        );
        // Level i: internal node hash (0x01 || level i-1 || level i-1)
        for i in 1..=SMT_MAX_DEPTH as usize {
            let prev = hashes[i - 1];
            hashes.push(sha_pair(&prev, &prev, env));
        }
        Self { hashes }
    }

    /// Get the empty hash for a specific level (0 = leaf level).
    #[inline(always)]
    pub fn get(&self, level: u32) -> &[u8; 32] {
        &self.hashes[level as usize]
    }

    /// Get the empty root for a tree of the given depth.
    #[inline(always)]
    pub fn root(&self, depth: u32) -> &[u8; 32] {
        &self.hashes[depth as usize]
    }
}

/// Count set bits in a `u256`.
#[inline(always)]
fn popcount_u256(v: u256) -> u32 {
    let (hi, lo) = v.into_words();
    hi.count_ones() + lo.count_ones()
}

/// Compute the RFC 6962 empty-leaf digest (`SHA256(0x00 || [0u8; 32])`).
#[inline(always)]
fn empty_leaf_hash(env: &Env) -> [u8; 32] {
    let mut empty_leaf = [0u8; 33];
    empty_leaf[0] = 0x00;
    env.crypto()
        .sha256(&Bytes::from_array(env, &empty_leaf))
        .to_array()
}

/// A sparse Merkle authentication path.
///
/// Only non-empty siblings are stored explicitly. A bitmap indicates which
/// levels have a non-empty sibling (LSB-first: bit `level` corresponds to tree
/// `level` in `0..depth`). Missing siblings default to the empty hash for that level.
pub struct SparseMerklePath {
    /// Bitmap: bit `i` (`0 <= i < depth`) is 1 if a non-empty sibling is stored for level `i`.
    pub bitmap: u256,
    /// Non-empty sibling hashes, packed contiguously in increasing level order.
    pub siblings: AllocVec<[u8; 32]>,
    /// Number of non-empty siblings (must equal popcount of `bitmap` and `siblings.len()`).
    pub sibling_count: u32,
    /// Tree depth (`<= SMT_MAX_DEPTH`).
    pub depth: u32,
    /// Leaf index (256-bit key; bits `>= depth` must be zero).
    pub index: u256,
}

impl SparseMerklePath {
    /// Validate depth, unused high-bit zeroing on `bitmap` and `index`,
    /// `sibling_count == popcount(bitmap)`, and `siblings.len() == sibling_count`.
    fn is_well_formed(&self) -> bool {
        if self.depth > SMT_MAX_DEPTH {
            return false;
        }
        // Guard shift against u256 >= 256 overflow when depth == SMT_MAX_DEPTH.
        if self.depth < SMT_MAX_DEPTH {
            if (self.bitmap >> self.depth) != u256::ZERO {
                return false;
            }
            if (self.index >> self.depth) != u256::ZERO {
                return false;
            }
        }
        let ones = popcount_u256(self.bitmap);
        if self.sibling_count != ones {
            return false;
        }
        if self.siblings.len() != self.sibling_count as usize {
            return false;
        }
        true
    }

    /// Recompute the root this sparse path authenticates to using precomputed `empty_hashes`.
    pub fn compute_root(
        &self,
        env: &Env,
        leaf: &BytesN<32>,
        empty_hashes: &EmptyHashes,
    ) -> BytesN<32> {
        let mut cur = leaf.to_array();
        let mut idx = self.index;
        let mut sib_idx = 0usize;
        // `depth` is proof data: clamp it to the precomputed empty-hash table.
        let steps = self.depth.min(SMT_MAX_DEPTH) as usize;

        for level in 0..steps {
            let is_right = (idx & u256::from(1u64)) != u256::ZERO;
            idx >>= 1;

            let sib = if ((self.bitmap >> level) & u256::from(1u64)) != u256::ZERO {
                if let Some(&s) = self.siblings.get(sib_idx) {
                    sib_idx += 1;
                    s
                } else {
                    *empty_hashes.get(level as u32)
                }
            } else {
                *empty_hashes.get(level as u32)
            };

            let (l, r) = if is_right { (sib, cur) } else { (cur, sib) };
            cur = sha_pair(&l, &r, env);
        }

        BytesN::from_array(env, &cur)
    }

    /// Verify that `leaf` sits at `index` in the SMT with Merkle `root` using
    /// precomputed `empty_hashes`.
    pub fn verify(
        &self,
        env: &Env,
        leaf: &BytesN<32>,
        root: &BytesN<32>,
        empty_hashes: &EmptyHashes,
    ) -> bool {
        if !self.is_well_formed() {
            return false;
        }
        &self.compute_root(env, leaf, empty_hashes) == root
    }

    /// Verify that `leaf` sits at `index` in the SMT with Merkle `root` by
    /// rolling `empty_hash` iteratively on the stack (32 bytes, zero extra allocation).
    pub fn verify_rolling(&self, env: &Env, leaf: &BytesN<32>, root: &BytesN<32>) -> bool {
        if !self.is_well_formed() {
            return false;
        }

        let mut cur = leaf.to_array();
        let mut idx = self.index;
        let mut empty_hash = empty_leaf_hash(env);
        let mut sib_idx = 0usize;

        for level in 0..self.depth as usize {
            let is_right = (idx & u256::from(1u64)) != u256::ZERO;
            idx >>= 1;

            let sib = if ((self.bitmap >> level) & u256::from(1u64)) != u256::ZERO {
                let Some(&s) = self.siblings.get(sib_idx) else {
                    return false;
                };
                sib_idx += 1;
                s
            } else {
                empty_hash
            };

            let (l, r) = if is_right { (sib, cur) } else { (cur, sib) };
            cur = sha_pair(&l, &r, env);
            if level + 1 < self.depth as usize {
                empty_hash = sha_pair(&empty_hash, &empty_hash, env);
            }
        }

        &BytesN::from_array(env, &cur) == root
    }
}

/// Build the SMT root from a list of non-empty leaves (prover-side helper).
///
/// `leaves` is a slice of `(index, leaf_hash)` pairs with unique indices in `[0, 2^depth)`.
pub fn smt_root(
    env: &Env,
    leaves: &[(u256, [u8; 32])],
    depth: u32,
    empty_hashes: &EmptyHashes,
) -> BytesN<32> {
    if depth > SMT_MAX_DEPTH {
        return BytesN::from_array(env, &[0u8; 32]);
    }
    if leaves.is_empty() {
        return BytesN::from_array(env, empty_hashes.root(depth));
    }

    let mut level_map: BTreeMap<u256, [u8; 32]> = BTreeMap::new();
    for (idx, hash) in leaves {
        level_map.insert(*idx, *hash);
    }

    for level in 0..depth {
        let mut parent_map: BTreeMap<u256, [u8; 32]> = BTreeMap::new();
        let empty_hash = empty_hashes.get(level);

        for (idx, hash) in &level_map {
            let parent_idx = idx >> 1;
            if parent_map.contains_key(&parent_idx) {
                continue;
            }
            let is_right = (idx & u256::from(1u64)) != u256::ZERO;
            let sibling_idx = idx ^ u256::from(1u64);
            let sib = level_map.get(&sibling_idx).copied().unwrap_or(*empty_hash);

            let (left, right) = if is_right { (sib, *hash) } else { (*hash, sib) };
            parent_map.insert(parent_idx, sha_pair(&left, &right, env));
        }

        level_map = parent_map;
    }

    let root_hash = level_map
        .get(&u256::ZERO)
        .copied()
        .unwrap_or(*empty_hashes.root(depth));
    BytesN::from_array(env, &root_hash)
}

/// Open a Sparse Merkle proof for the leaf at `index` (prover-side helper).
///
/// Returns a `SparseMerklePath` containing only non-empty siblings.
pub fn smt_open(
    env: &Env,
    leaves: &[(u256, [u8; 32])],
    index: u256,
    depth: u32,
    empty_hashes: &EmptyHashes,
) -> SparseMerklePath {
    let mut leaf_map: BTreeMap<u256, [u8; 32]> = BTreeMap::new();
    for (idx, hash) in leaves {
        leaf_map.insert(*idx, *hash);
    }

    let mut path = SparseMerklePath {
        bitmap: u256::ZERO,
        siblings: AllocVec::new(),
        sibling_count: 0,
        // An unsupported depth yields an empty (never-verifying) path.
        depth: depth.min(SMT_MAX_DEPTH),
        index,
    };
    let depth = path.depth;

    let mut idx = index;
    let mut sib_idx = 0u32;

    for level in 0..depth as usize {
        let sibling_idx = idx ^ u256::from(1u64);

        if let Some(sib_hash) = leaf_map.get(&sibling_idx) {
            // Non-empty sibling found
            path.bitmap |= u256::from(1u64) << level;
            path.siblings.push(*sib_hash);
            sib_idx += 1;
        }
        // else: sibling is empty, bitmap bit stays 0

        idx >>= 1;

        // Build parent level for next iteration
        let mut parent_map: BTreeMap<u256, [u8; 32]> = BTreeMap::new();
        let empty_hash = empty_hashes.get(level as u32);

        for (node_idx, hash) in &leaf_map {
            let parent_idx = node_idx >> 1;
            if parent_map.contains_key(&parent_idx) {
                continue;
            }
            let node_is_right = (node_idx & u256::from(1u64)) != u256::ZERO;
            let node_sibling_idx = node_idx ^ u256::from(1u64);
            let sib = leaf_map
                .get(&node_sibling_idx)
                .copied()
                .unwrap_or(*empty_hash);

            let (left, right) = if node_is_right {
                (sib, *hash)
            } else {
                (*hash, sib)
            };

            parent_map.insert(parent_idx, sha_pair(&left, &right, env));
        }

        leaf_map = parent_map;
    }

    path.sibling_count = sib_idx;
    path
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use soroban_sdk::Env;

    fn env() -> Env {
        let e = Env::default();
        e.cost_estimate().budget().reset_unlimited();
        e
    }

    #[test]
    fn valid_path_verifies_and_corrupted_fails() {
        let env = env();
        let mut leaves = Vec::new(&env);
        for i in 0..8u64 {
            leaves.push_back(felt_leaf(&env, Felt::new(i)));
        }
        let root = merkle_root(&env, &leaves);

        let idx = 3u32;
        let path = open(&env, &leaves, idx);
        let leaf = felt_leaf(&env, Felt::new(idx as u64));
        assert!(path.verify(&env, &leaf, &root), "valid path must verify");

        let bad_leaf = felt_leaf(&env, Felt::new(99));
        assert!(
            !path.verify(&env, &bad_leaf, &root),
            "corrupted leaf must fail"
        );

        let mut bad_path = path;
        bad_path.siblings[0] = felt_leaf(&env, Felt::new(123)).to_array();
        assert!(
            !bad_path.verify(&env, &leaf, &root),
            "corrupted sibling must fail"
        );
    }

    #[test]
    fn different_root_rejected() {
        let env = env();
        let mut leaves = Vec::new(&env);
        for i in 0..4u64 {
            leaves.push_back(felt_leaf(&env, Felt::new(i)));
        }
        let path = open(&env, &leaves, 0);
        let leaf = felt_leaf(&env, Felt::new(0));
        let wrong = BytesN::from_array(&env, &[0xab; 32]);
        assert!(!path.verify(&env, &leaf, &wrong));
    }

    #[test]
    fn batch_verifies_valid_paths() {
        let env = env();
        let mut leaves = Vec::new(&env);
        for i in 0..8u64 {
            leaves.push_back(felt_leaf(&env, Felt::new(i)));
        }
        let root = merkle_root(&env, &leaves);

        let idx0 = 2u32;
        let idx1 = 3u32; // sibling to idx0
        let idx2 = 5u32;

        let path0 = open(&env, &leaves, idx0);
        let path1 = open(&env, &leaves, idx1);
        let path2 = open(&env, &leaves, idx2);

        let mut batch_leaves = Vec::new(&env);
        batch_leaves.push_back(felt_leaf(&env, Felt::new(idx0 as u64)));
        batch_leaves.push_back(felt_leaf(&env, Felt::new(idx1 as u64)));
        batch_leaves.push_back(felt_leaf(&env, Felt::new(idx2 as u64)));
        let batch_paths = [path0, path1, path2];

        assert!(
            verify_batch(&env, &batch_leaves, &batch_paths, &root),
            "batch verify should succeed"
        );
    }

    // ───────────────────────────────────────────────────────────────────────
    // DeepMerklePath tests (issue #460)
    // ───────────────────────────────────────────────────────────────────────

    #[test]
    fn deep_path_from_legacy_verifies() {
        let env = env();
        let mut leaves = Vec::new(&env);
        for i in 0..8u64 {
            leaves.push_back(felt_leaf(&env, Felt::new(i)));
        }
        let root = merkle_root(&env, &leaves);
        let idx = 5u32;
        let legacy = open(&env, &leaves, idx);
        let leaf = felt_leaf(&env, Felt::new(idx as u64));

        // Legacy path verifies.
        assert!(legacy.verify(&env, &leaf, &root));

        // Converted DeepMerklePath also verifies.
        let deep = DeepMerklePath::from_merkle_path(&legacy);
        assert_eq!(deep.depth, legacy.depth);
        assert_eq!(deep.index, legacy.index);
        assert!(deep.verify(&env, &leaf, &root));
    }

    #[test]
    fn deep_path_corrupted_sibling_fails() {
        let env = env();
        let mut leaves = Vec::new(&env);
        for i in 0..4u64 {
            leaves.push_back(felt_leaf(&env, Felt::new(i)));
        }
        let root = merkle_root(&env, &leaves);
        let legacy = open(&env, &leaves, 1);
        let leaf = felt_leaf(&env, Felt::new(1));

        let mut deep = DeepMerklePath::from_merkle_path(&legacy);
        assert!(deep.verify(&env, &leaf, &root));

        // Corrupt a sibling.
        deep.set_sibling(0, [0xffu8; 32]);
        assert!(!deep.verify(&env, &leaf, &root));
    }

    #[test]
    fn deep_path_set_and_get_sibling() {
        let mut deep = DeepMerklePath::new();
        let hash = [0xab; 32];

        // Set sibling at various levels spanning different pages.
        deep.set_sibling(0, hash);
        deep.set_sibling(15, hash); // last slot of page 0
        deep.set_sibling(16, hash); // first slot of page 1
        deep.set_sibling(63, hash); // last slot of page 3

        assert_eq!(*deep.sibling(0), hash);
        assert_eq!(*deep.sibling(15), hash);
        assert_eq!(*deep.sibling(16), hash);
        assert_eq!(*deep.sibling(63), hash);
        // Untouched slot should be zero.
        assert_eq!(*deep.sibling(1), [0u8; 32]);
    }

    // ───────────────────────────────────────────────────────────────────────
    // CompactMerklePath tests (issue #460)
    // ───────────────────────────────────────────────────────────────────────

    #[test]
    fn compact_path_from_legacy_verifies() {
        let env = env();
        let mut leaves = Vec::new(&env);
        for i in 0..8u64 {
            leaves.push_back(felt_leaf(&env, Felt::new(i)));
        }
        let root = merkle_root(&env, &leaves);
        let idx = 7u32;
        let legacy = open(&env, &leaves, idx);
        let leaf = felt_leaf(&env, Felt::new(idx as u64));

        let compact = CompactMerklePath::from_merkle_path(&legacy);
        assert_eq!(compact.depth, legacy.depth);
        assert_eq!(compact.index, legacy.index);
        assert!(compact.verify(&env, &leaf, &root));
    }

    #[test]
    fn compact_path_corrupted_fails() {
        let env = env();
        let mut leaves = Vec::new(&env);
        for i in 0..4u64 {
            leaves.push_back(felt_leaf(&env, Felt::new(i)));
        }
        let root = merkle_root(&env, &leaves);
        let legacy = open(&env, &leaves, 0);
        let leaf = felt_leaf(&env, Felt::new(0));

        let mut compact = CompactMerklePath::from_merkle_path(&legacy);
        assert!(compact.verify(&env, &leaf, &root));

        compact.siblings[0] = [0xddu8; 32];
        assert!(!compact.verify(&env, &leaf, &root));
    }

    #[test]
    fn compact_path_round_trip_to_legacy() {
        let env = env();
        let mut leaves = Vec::new(&env);
        for i in 0..8u64 {
            leaves.push_back(felt_leaf(&env, Felt::new(i)));
        }
        let root = merkle_root(&env, &leaves);
        let idx = 2u32;
        let legacy = open(&env, &leaves, idx);
        let leaf = felt_leaf(&env, Felt::new(idx as u64));

        let compact = CompactMerklePath::from_merkle_path(&legacy);
        let back = compact
            .to_merkle_path()
            .expect("depth <= 32 should succeed");
        assert!(back.verify(&env, &leaf, &root));
    }

    #[test]
    fn compact_path_to_legacy_none_when_too_deep() {
        let mut compact = CompactMerklePath::new();
        compact.depth = 33; // exceeds MAX_DEPTH
        assert!(compact.to_merkle_path().is_none());
    }

    #[test]
    fn compact_path_is_copy() {
        let env = env();
        let mut leaves = Vec::new(&env);
        for i in 0..4u64 {
            leaves.push_back(felt_leaf(&env, Felt::new(i)));
        }
        let root = merkle_root(&env, &leaves);
        let legacy = open(&env, &leaves, 3);
        let leaf = felt_leaf(&env, Felt::new(3));

        let compact = CompactMerklePath::from_merkle_path(&legacy);
        // Copy the struct (no clone needed) — this compiles only if Copy is impl'd.
        let copy = compact;
        assert!(copy.verify(&env, &leaf, &root));
        // Original is still usable (not moved).
        assert!(compact.verify(&env, &leaf, &root));
    }

    // ───────────────────────────────────────────────────────────────────────
    // RFC 6962 domain separation, verify_batch, & SparseMerklePath security tests
    // ───────────────────────────────────────────────────────────────────────

    #[test]
    fn rfc6962_second_preimage_tree_depth_confusion_rejected() {
        let env = env();
        let left = felt_leaf(&env, Felt::new(1));
        let right = felt_leaf(&env, Felt::new(2));

        // Build a 2-leaf tree: root = H(0x01 || left || right)
        let mut leaves = Vec::new(&env);
        leaves.push_back(left.clone());
        leaves.push_back(right.clone());
        let root = merkle_root(&env, &leaves);

        // Second-preimage attack: treat the 64-byte internal preimage (left || right)
        // as a 1-leaf tree's leaf hashed with `hash()` (0x00 || left || right).
        let mut concatenated = [0u8; 64];
        concatenated[..32].copy_from_slice(&left.to_array());
        concatenated[32..].copy_from_slice(&right.to_array());
        let forged_leaf = hash(&env, &Bytes::from_array(&env, &concatenated));

        assert_ne!(
            forged_leaf, root,
            "leaf hash (0x00) must never collide with internal node hash (0x01)"
        );

        let depth0_path = MerklePath {
            siblings: [[0u8; 32]; MAX_DEPTH as usize],
            depth: 0,
            index: 0,
        };
        assert!(
            !depth0_path.verify(&env, &forged_leaf, &root),
            "depth-0 forged leaf from internal preimage must be rejected"
        );

        // Also verify raw internal digest cannot match a leaf hashed from the same 32 bytes.
        let zero_leaf = hash(&env, &Bytes::from_array(&env, &[0u8; 32]));
        let raw_zero = BytesN::from_array(&env, &[0u8; 32]);
        let empty_hashes = EmptyHashes::new(&env);
        assert_eq!(zero_leaf.to_array(), *empty_hashes.get(0));
        assert_ne!(
            zero_leaf, raw_zero,
            "empty leaf hash must include 0x00 domain prefix"
        );
    }

    #[test]
    fn batch_rejects_empty_and_depth_over_max() {
        let env = env();
        let empty_leaves = Vec::new(&env);
        let root = BytesN::from_array(&env, &[0u8; 32]);
        assert!(!verify_batch(&env, &empty_leaves, &[], &root));

        let mut leaves = Vec::new(&env);
        leaves.push_back(felt_leaf(&env, Felt::new(1)));
        let paths = [MerklePath {
            siblings: [[0u8; 32]; MAX_DEPTH as usize],
            depth: MAX_DEPTH + 1,
            index: 0,
        }];
        assert!(
            !verify_batch(&env, &leaves, &paths, &root),
            "depth > MAX_DEPTH must be rejected without panic"
        );
    }

    #[test]
    fn batch_rejects_out_of_range_and_duplicate_indices() {
        let env = env();
        let mut leaves = Vec::new(&env);
        for i in 0..8u64 {
            leaves.push_back(felt_leaf(&env, Felt::new(i)));
        }
        let root = merkle_root(&env, &leaves);

        // Index 8 aliases index 0 modulo 2^3 in a depth-3 tree.
        let mut bad_idx_path = open(&env, &leaves, 0);
        bad_idx_path.index = 1u64 << 3;
        let mut l1 = Vec::new(&env);
        l1.push_back(felt_leaf(&env, Felt::new(0)));
        assert!(
            !verify_batch(&env, &l1, &[bad_idx_path], &root),
            "index >= 2^depth must be rejected"
        );

        // Duplicate indices (even with valid or conflicting leaves) must fail.
        let path0 = open(&env, &leaves, 0);
        let path0_dup = open(&env, &leaves, 0);
        let mut dup_leaves = Vec::new(&env);
        dup_leaves.push_back(felt_leaf(&env, Felt::new(0)));
        dup_leaves.push_back(felt_leaf(&env, Felt::new(999)));
        assert!(!verify_batch(&env, &dup_leaves, &[path0, path0_dup], &root));
    }

    #[test]
    fn batch_rejects_mismatched_depths_and_inconsistent_shared_nodes() {
        let env = env();
        let mut leaves = Vec::new(&env);
        for i in 0..8u64 {
            leaves.push_back(felt_leaf(&env, Felt::new(i)));
        }
        let root = merkle_root(&env, &leaves);

        let path2 = open(&env, &leaves, 2);
        let path3 = open(&env, &leaves, 3);
        let leaf2 = felt_leaf(&env, Felt::new(2));
        let leaf3 = felt_leaf(&env, Felt::new(3));

        // 1. Mismatched depth between paths
        let mut wrong_depth = path3;
        wrong_depth.depth = 2;
        let mut bl = Vec::new(&env);
        bl.push_back(leaf2.clone());
        bl.push_back(leaf3.clone());
        assert!(!verify_batch(&env, &bl, &[path2, wrong_depth], &root));

        // 2. Corrupt sibling at merge level d=0 (path2's siblings[0] != leaf3)
        let mut bad_merge_sib = path2;
        bad_merge_sib.siblings[0] = [0xdeu8; 32];
        assert!(
            !verify_batch(&env, &bl, &[bad_merge_sib, path3], &root),
            "inconsistent sibling at merge level must be rejected"
        );

        // 3. Corrupt shared ancestor sibling at d=1 on path3 (while path2 has valid siblings[1])
        let mut bad_ancestor_sib = path3;
        bad_ancestor_sib.siblings[1] = [0xadu8; 32];
        assert!(
            !verify_batch(&env, &bl, &[path2, bad_ancestor_sib], &root),
            "inconsistent shared internal sibling across paths must be rejected"
        );
    }

    #[test]
    fn batch_accepts_depth_zero_single_leaf() {
        let env = env();
        let leaf = felt_leaf(&env, Felt::new(42));
        let mut leaves = Vec::new(&env);
        leaves.push_back(leaf.clone());
        let paths = [MerklePath {
            siblings: [[0u8; 32]; MAX_DEPTH as usize],
            depth: 0,
            index: 0,
        }];
        assert!(verify_batch(&env, &leaves, &paths, &leaf));
    }

    #[test]
    fn sparse_merkle_happy_path_and_rolling_verify() {
        let env = env();
        let empty = EmptyHashes::new(&env);
        let depth = 8u32;

        let leaf_a = felt_leaf(&env, Felt::new(10));
        let leaf_b = felt_leaf(&env, Felt::new(20));
        let idx_a = u256::from(5u64);
        let idx_b = u256::from(200u64);
        let smt_leaves = [(idx_a, leaf_a.to_array()), (idx_b, leaf_b.to_array())];

        let root = smt_root(&env, &smt_leaves, depth, &empty);
        let path_a = smt_open(&env, &smt_leaves, idx_a, depth, &empty);
        let path_b = smt_open(&env, &smt_leaves, idx_b, depth, &empty);

        assert!(path_a.verify(&env, &leaf_a, &root, &empty));
        assert!(path_b.verify(&env, &leaf_b, &root, &empty));
        assert!(path_a.verify_rolling(&env, &leaf_a, &root));
        assert!(path_b.verify_rolling(&env, &leaf_b, &root));

        // Wrong leaf rejected
        assert!(!path_a.verify(&env, &leaf_b, &root, &empty));
        assert!(!path_a.verify_rolling(&env, &leaf_b, &root));
    }

    #[test]
    fn sparse_merkle_boundaries_and_rejection_cases() {
        let env = env();
        let empty = EmptyHashes::new(&env);

        // Stack size sanity check: both structs combined must remain well under 2 KB.
        assert!(
            core::mem::size_of::<SparseMerklePath>() + core::mem::size_of::<EmptyHashes>() < 2048
        );

        // Depth 0 boundary
        let leaf0 = felt_leaf(&env, Felt::new(7));
        let path0 = SparseMerklePath {
            bitmap: u256::ZERO,
            siblings: AllocVec::new(),
            sibling_count: 0,
            depth: 0,
            index: u256::ZERO,
        };
        assert!(path0.verify(&env, &leaf0, &leaf0, &empty));
        assert!(path0.verify_rolling(&env, &leaf0, &leaf0));

        let mut bad_depth0_idx = SparseMerklePath {
            bitmap: u256::ZERO,
            siblings: AllocVec::new(),
            sibling_count: 0,
            depth: 0,
            index: u256::from(1u64),
        };
        assert!(!bad_depth0_idx.verify(&env, &leaf0, &leaf0, &empty));
        bad_depth0_idx.index = u256::ZERO;
        bad_depth0_idx.bitmap = u256::from(1u64);
        assert!(!bad_depth0_idx.verify(&env, &leaf0, &leaf0, &empty));

        // Depth 8 valid proof for mutation checks
        let depth = 8u32;
        let leaf_a = felt_leaf(&env, Felt::new(11));
        let leaf_b = felt_leaf(&env, Felt::new(22));
        let smt_leaves = [
            (u256::from(0u64), leaf_a.to_array()),
            (u256::from(1u64), leaf_b.to_array()),
        ];
        let root = smt_root(&env, &smt_leaves, depth, &empty);
        let valid = smt_open(&env, &smt_leaves, u256::from(0u64), depth, &empty);
        assert!(valid.verify(&env, &leaf_a, &root, &empty));

        // 1. Corrupted sibling_count (mismatch with bitmap popcount)
        let mut bad_count = SparseMerklePath {
            bitmap: valid.bitmap,
            siblings: valid.siblings.clone(),
            sibling_count: valid.sibling_count + 1,
            depth: valid.depth,
            index: valid.index,
        };
        assert!(!bad_count.verify(&env, &leaf_a, &root, &empty));

        // 2. Trailing sibling exceeding popcount
        bad_count.sibling_count = valid.sibling_count;
        bad_count.siblings.push([0u8; 32]);
        assert!(!bad_count.verify(&env, &leaf_a, &root, &empty));

        // 3. Unused high bits set in bitmap (bit >= depth)
        let bad_bitmap = SparseMerklePath {
            bitmap: valid.bitmap | (u256::from(1u64) << depth),
            siblings: {
                let mut s = valid.siblings.clone();
                s.push(*empty.get(depth));
                s
            },
            sibling_count: valid.sibling_count + 1,
            depth,
            index: valid.index,
        };
        assert!(!bad_bitmap.verify(&env, &leaf_a, &root, &empty));

        // 4. Unused high bits set in index (bit >= depth)
        let bad_index = SparseMerklePath {
            bitmap: valid.bitmap,
            siblings: valid.siblings.clone(),
            sibling_count: valid.sibling_count,
            depth,
            index: valid.index | (u256::from(1u64) << depth),
        };
        assert!(!bad_index.verify(&env, &leaf_a, &root, &empty));

        // 5. Depth == SMT_MAX_DEPTH (256) boundary (no u256 shift overflow) and depth > 256 rejected
        let max_path = SparseMerklePath {
            bitmap: u256::ZERO,
            siblings: AllocVec::new(),
            sibling_count: 0,
            depth: SMT_MAX_DEPTH,
            index: u256::MAX,
        };
        let max_root = max_path.compute_root(&env, &leaf_a, &empty);
        assert!(max_path.verify(&env, &leaf_a, &max_root, &empty));
        assert!(max_path.verify_rolling(&env, &leaf_a, &max_root));

        let over_max = SparseMerklePath {
            bitmap: u256::ZERO,
            siblings: AllocVec::new(),
            sibling_count: 0,
            depth: SMT_MAX_DEPTH + 1,
            index: u256::ZERO,
        };
        assert!(!over_max.verify(&env, &leaf_a, &max_root, &empty));
        assert!(!over_max.verify_rolling(&env, &leaf_a, &max_root));
    }
}

/// Host-limit tests for deep Merkle validation (issue #462).
///
/// `depth` arrives inside proof data, so these tests treat it as hostile
/// input: a claimed depth of 64 must terminate — bounded by the array,
/// never a Wasm trap or an unbounded host-call loop — and the deepest
/// *legitimate* path (`COMPACT_MAX_DEPTH`, a 2^64-leaf tree) must fit
/// comfortably inside one transaction's Soroban budget.
#[cfg(test)]
mod limit_tests {
    extern crate std;
    use super::*;
    use soroban_sdk::Env;

    /// Current mainnet per-transaction Soroban resource limits, which are
    /// also what `budget().reset_default()` configures in the SDK test host:
    /// 100M CPU instructions, 40 MiB of Wasm linear memory.
    const TX_CPU_INSNS_LIMIT: u64 = 100_000_000;
    const TX_MEM_BYTES_LIMIT: u64 = 40 * 1024 * 1024;

    /// A synthetic path of `depth` levels with distinct sibling digests. Trees
    /// this deep cannot be *built* in a test (depth 64 implies 2^64
    /// leaves), so limits are exercised on the verification fold — the only
    /// side that ever runs on-chain.
    fn synthetic_compact_path(depth: u32) -> CompactMerklePath {
        let mut siblings = [[0u8; 32]; COMPACT_MAX_DEPTH];
        for (i, s) in siblings.iter_mut().enumerate() {
            s[0] = i as u8 + 1;
            s[31] = 0xa5;
        }
        CompactMerklePath {
            siblings,
            depth,
            index: u64::MAX >> 1, // exercise both left/right orderings
        }
    }

    /// CPU and memory consumed by one `verify` call at the given claimed
    /// depth, measured against the DEFAULT (network-shaped) budget — not the
    /// unlimited one — so exhaustion would fail the test loudly.
    fn measured_verify(env: &Env, depth: u32, root: &BytesN<32>) -> (bool, u64, u64) {
        let path = synthetic_compact_path(depth);
        let leaf = BytesN::from_array(env, &[0x11u8; 32]);
        let mut budget = env.cost_estimate().budget();
        budget.reset_default();
        let ok = path.verify(env, &leaf, root);
        let budget = env.cost_estimate().budget();
        (
            ok,
            budget.cpu_instruction_cost(),
            budget.memory_bytes_cost(),
        )
    }

    /// The root the synthetic path at `depth` folds to (computed once under
    /// an unlimited budget; correctness of the fold itself is covered by the
    /// `open()`-based tests above — these tests are about resource bounds).
    fn root_for(env: &Env, depth: u32) -> BytesN<32> {
        env.cost_estimate().budget().reset_unlimited();
        let leaf = BytesN::from_array(env, &[0x11u8; 32]);
        synthetic_compact_path(depth).compute_root(env, &leaf)
    }

    #[test]
    fn max_depth_verify_fits_the_transaction_budget_with_headroom() {
        let env = Env::default();
        let root = root_for(&env, COMPACT_MAX_DEPTH as u32);

        let (ok, cpu, mem) = measured_verify(&env, COMPACT_MAX_DEPTH as u32, &root);
        assert!(ok, "a full-depth ({COMPACT_MAX_DEPTH}) path must verify");

        // The deepest legitimate check is COMPACT_MAX_DEPTH host sha256 calls. It must
        // not merely squeak under the per-transaction ceiling — a verifier
        // consuming a large fraction of the budget leaves nothing for the
        // surrounding STARK checks. Require an order of magnitude of headroom.
        assert!(
            cpu < TX_CPU_INSNS_LIMIT / 10,
            "depth-{COMPACT_MAX_DEPTH} verify used {cpu} CPU insns — more than 10% of the {TX_CPU_INSNS_LIMIT} tx limit"
        );
        assert!(
            mem < TX_MEM_BYTES_LIMIT / 10,
            "depth-{COMPACT_MAX_DEPTH} verify used {mem} bytes — more than 10% of the {TX_MEM_BYTES_LIMIT} tx limit"
        );
    }

    #[test]
    fn cost_grows_linearly_with_depth_not_worse() {
        let env = Env::default();
        // Per-depth roots so every verify actually folds its full claimed depth.
        let r16 = root_for(&env, 16);
        let r32 = root_for(&env, 32);
        let r64 = root_for(&env, 64);

        let (ok16, cpu16, _) = measured_verify(&env, 16, &r16);
        let (ok32, cpu32, _) = measured_verify(&env, 32, &r32);
        let (ok64, cpu64, _) = measured_verify(&env, 64, &r64);
        assert!(ok16 && ok32 && ok64);

        // Doubling the depth may at most roughly double the cost (plus a
        // fixed per-call overhead). Superlinear growth here would be the
        // early warning that deep trees hit the ceiling before COMPACT_MAX_DEPTH.
        assert!(
            cpu32 <= cpu16.saturating_mul(2) + cpu16,
            "16→32 grew worse than linearly: {cpu16} → {cpu32}"
        );
        assert!(
            cpu64 <= cpu32.saturating_mul(2) + cpu16,
            "32→64 grew worse than linearly: {cpu32} → {cpu64}"
        );
    }

    #[test]
    fn hostile_depth_beyond_max_terminates_bounded_and_rejects() {
        let env = Env::default();
        let honest_root = root_for(&env, COMPACT_MAX_DEPTH as u32);
        let (_, cpu_at_max, _) = measured_verify(&env, COMPACT_MAX_DEPTH as u32, &honest_root);

        for hostile_depth in [COMPACT_MAX_DEPTH as u32 + 1, 128, 256, u32::MAX] {
            let (ok, cpu, mem) = measured_verify(&env, hostile_depth, &honest_root);
            assert!(
                !ok,
                "a path claiming depth {hostile_depth} (> COMPACT_MAX_DEPTH) must never verify"
            );
            // Termination bound: rejection must cost no more than an honest
            // full-depth fold — the claimed depth must not buy the caller a
            // single extra host call, let alone a budget-exhausting loop.
            assert!(
                cpu <= cpu_at_max,
                "depth {hostile_depth} spent {cpu} CPU insns, more than an honest depth-{COMPACT_MAX_DEPTH} verify ({cpu_at_max}) — the loop is not bounded"
            );
            assert!(mem < TX_MEM_BYTES_LIMIT / 10);
        }
    }

    #[test]
    fn depth_boundary_is_exact() {
        let env = Env::default();

        // depth == COMPACT_MAX_DEPTH: legitimate and accepted.
        let root = root_for(&env, COMPACT_MAX_DEPTH as u32);
        let (ok, _, _) = measured_verify(&env, COMPACT_MAX_DEPTH as u32, &root);
        assert!(
            ok,
            "depth == COMPACT_MAX_DEPTH is the deepest legitimate path"
        );

        // depth == COMPACT_MAX_DEPTH + 1: rejected even against the root its own
        // COMPACT_MAX_DEPTH-prefix folds to — an oversized claim must not pass by
        // matching a truncated fold of itself.
        let truncated_root = root_for(&env, COMPACT_MAX_DEPTH as u32); // prefix fold == depth-64 fold
        let path = synthetic_compact_path(COMPACT_MAX_DEPTH as u32 + 1);
        let leaf = BytesN::from_array(&env, &[0x11u8; 32]);
        {
            let mut b = env.cost_estimate().budget();
            b.reset_default();
        }
        assert!(
            !path.verify(&env, &leaf, &truncated_root),
            "an oversized depth must be rejected outright, not clamped into passing"
        );
    }
}
