//! STARK verifier & FRI proximity-testing primitives (Issue #366, Issue #571).
//!
//! This module implements the verifier-side building blocks for STARK proofs,
//! plus a unified [`verify_stark_proof`] entry point:
//!
//! * [`field`] — the Goldilocks prime field (`p = 2^64 − 2^32 + 1`) with high
//!   2-adicity, used for the FRI Reed–Solomon domain.
//! * [`aet`] — Algebraic Execution Trace configuration and boundary/transition
//!   constraint checks.
//! * [`fri`] — FRI folding loops, layer commitment, and deep-FRI composition.
//! * [`merkle`] — Soroban-optimized Merkle authentication over the native
//!   SHA-256 host binding.
//! * [`transcript`] — Fiat-Shamir transcript over SHA-256.
//!
//! # The verified protocol
//!
//! A proof attests that a length-`N = 2^log_n`, width-`W` execution trace
//! satisfies an AIR described by an [`Air`] implementation. The prover commits
//! to the trace's low-degree extension (LDE) over a coset of size
//! `M = 4N` (blowup 4), and the verifier checks:
//!
//! 1. **Transcript binding** — the AIR dimensions, constraint counts and the
//!    trace root are absorbed; every challenge (constraint weights `α`, DEEP
//!    point `ζ`, folding challenges `β_l`, query indices) is squeezed from that
//!    running SHA-256 state, so a prover cannot pick them after the fact.
//! 2. **Constraint composition** — with `Z(x) = x^N − c^N` the vanishing
//!    polynomial of the trace domain `{c·ω_N^j}` and `sel(x) = x − x_{N−1}`
//!    the "last transition row" selector,
//!    `C(x) = Σ_k α_k·t_k(x)·sel(x)/Z(x) + Σ_j α_j·(T_{c_j}(x) − v_j)/(x − x_j)`.
//!    For an honest trace every `t_k` vanishes on the first `N−1` trace rows,
//!    so `C` is a polynomial of degree `< 2N`; a violated boundary constraint
//!    or transition leaves a pole in the trace domain, which makes `C` a
//!    non-low-degree function and is rejected by the FRI test.
//! 3. **DEEP quotient** — `D(x) = (C(x) − C(ζ))/(x − ζ)` is evaluated on the
//!    LDE coset, committed, and folded `log_n + 1` times with Fiat-Shamir `β_l`.
//!    `C(ζ)` is recomputed by the verifier from the out-of-domain frame
//!    `(T(ζ), T(ω_N·ζ))`, so a wrong out-of-domain claim changes `C(ζ)` and
//!    makes `D` non-polynomial (hence non-low-degree).
//! 4. **Query phase** — for each sampled index the verifier authenticates the
//!    trace row against the trace root, recomputes `C(z_i)` from the revealed
//!    `T(z_i), T(ω_N·z_i)`, checks `D(z_i) = (C(z_i) − C(ζ))/(z_i − ζ)` against
//!    the layer-0 opening, and then walks every committed FRI layer: both
//!    `(x, −x)` openings are Merkle-authenticated against that layer's root,
//!    folded with `β_l`, and compared with the next layer's opening. The final
//!    two-element layer must be constant, which is exactly the `deg(C) < 2N`
//!    degree bound (blowup 4, `log_n + 1` folds).
//!
//! Every check returns `Result<(), ZkError>`; the verifier never panics on
//! hostile input (out-of-range widths, depths, indices or layer counts are
//! rejected before any indexing).

pub mod aet;
pub mod field;
pub mod fri;
pub mod merkle;
pub mod transcript;

/// Test-only prover used by the end-to-end STARK tests. Kept out of the
/// contract build so no prover code is ever linked into a verifier's WASM.
#[cfg(test)]
mod prover;

use aet::{row_leaf, trace_domain_point, TRACE_COSET_OFFSET};
use core::ops::{Add, Mul, Sub};
use field::Felt;
use fri::fold_value;
use merkle::felt_leaf;
use transcript::Transcript;

use soroban_sdk::{Bytes, BytesN, Env};

use soroban_zk_core::ZkError;

// ===========================================================================
// Protocol parameters
// ===========================================================================

/// Largest supported trace log-size (the trace has at most `2^8 = 256` rows).
pub const STARK_MAX_LOG_N: u32 = 8;

/// FRI/LDE blowup: the LDE coset holds `2^STARK_BLOWUP_LOG` times as many
/// points as the trace domain.
pub const STARK_BLOWUP_LOG: u32 = 2;

/// Maximum number of query positions sampled per proof.
pub const STARK_MAX_QUERIES: u32 = 4;

/// Maximum number of trace columns.
pub const STARK_MAX_WIDTH: usize = 4;

/// Maximum number of boundary constraints.
pub const STARK_MAX_BOUNDARY: u32 = 4;

/// Maximum number of transition constraints.
pub const STARK_MAX_TRANSITIONS: u32 = 4;

/// Maximum number of constraint weights (`α`) squeezed per proof.
pub const STARK_MAX_CONSTRAINTS: usize =
    STARK_MAX_BOUNDARY as usize + STARK_MAX_TRANSITIONS as usize;

/// Maximum Merkle path length: the LDE layer has `2^(log_n + blowup)` leaves.
pub const STARK_MAX_PATH: usize = STARK_MAX_LOG_N as usize + STARK_BLOWUP_LOG as usize;

/// Number of committed FRI layers (`log_n + 1`), excluding the final constant.
pub const STARK_MAX_COMMITTED_LAYERS: usize = STARK_MAX_LOG_N as usize + 1;

/// Length of the explicitly transmitted final FRI layer.
pub const STARK_FINAL_LAYER: usize = 2;

// ===========================================================================
// AIR description
// ===========================================================================

/// A minimal AIR (Algebraic Intermediate Representation) description.
///
/// The verifier only needs the constraint *residuals* — polynomials that
/// evaluate to zero exactly when the constraint holds — so arbitrary AIRs can be
/// verified without this crate hard-coding a particular circuit.
///
/// Implementations must be pure: the same inputs always give the same residual,
/// and no method may panic on the indices the verifier passes (all indices are
/// range-checked against `width()` / `num_*()` before use).
pub trait Air {
    /// Number of columns (registers) per trace row.
    fn width(&self) -> u32;

    /// Log-size of the trace: it has `2^log_trace_length` rows.
    fn log_trace_length(&self) -> u32;

    /// Number of boundary constraints.
    fn num_boundary(&self) -> u32;

    /// Boundary constraint `i` as `(row, column, value)`: the cell must equal
    /// `value`.
    fn boundary(&self, i: u32) -> (u32, u32, Felt);

    /// Number of transition constraints.
    fn num_transitions(&self) -> u32;

    /// Residual of transition constraint `k` between `cur` (row `j`) and `next`
    /// (row `j+1`). Zero iff the constraint holds.
    fn transition(&self, k: u32, cur: &[Felt], next: &[Felt]) -> Felt;
}

// ===========================================================================
// Proof structures
// ===========================================================================

/// One FRI layer opening: the `(x, −x)` pair at `index` and `index + 2^(log−1)`.
#[derive(Clone)]
pub struct FriLayerOpening {
    /// Normalised index (`< 2^(log−1)`) of the first element of the pair.
    pub index: u32,
    /// Value at `index`.
    pub value: Felt,
    /// Value at `index + 2^(log−1)` (the point `−x`).
    pub pair_value: Felt,
    /// Authentication path for `value` (depth = the layer log-size).
    pub path: [[u8; 32]; STARK_MAX_PATH],
    /// Authentication path for `pair_value`.
    pub pair_path: [[u8; 32]; STARK_MAX_PATH],
}

/// One FRI query: the revealed trace rows plus every layer opening.
#[derive(Clone)]
pub struct QueryOpening {
    /// Layer-0 query index (the verifier re-derives it from the transcript).
    pub index: u32,
    /// `T(z_i)` — the LDE row at the query point.
    pub trace_row: [Felt; STARK_MAX_WIDTH],
    /// `T(ω_N·z_i)` — the LDE row one trace-domain step ahead.
    pub trace_next: [Felt; STARK_MAX_WIDTH],
    /// Authentication path for `trace_row` against the trace root.
    pub trace_path: [[u8; 32]; STARK_MAX_PATH],
    /// Authentication path for `trace_next` against the trace root.
    pub next_path: [[u8; 32]; STARK_MAX_PATH],
    /// Per committed FRI layer openings, from the composition layer down.
    pub layers: [FriLayerOpening; STARK_MAX_COMMITTED_LAYERS],
}

/// A multi-layer FRI-STARK proof.
#[derive(Clone)]
pub struct StarkProof {
    /// Trace log-size (`N = 2^log_trace_length`).
    pub log_trace_length: u32,
    /// Trace width.
    pub width: u32,
    /// Number of query positions.
    pub num_queries: u32,
    /// Merkle root of the trace LDE rows.
    pub trace_root: BytesN<32>,
    /// Merkle roots of the committed FRI layers, starting with the composition
    /// layer `D` and ending with the four-element layer.
    pub layer_roots: [BytesN<32>; STARK_MAX_COMMITTED_LAYERS],
    /// The final two-element FRI layer; both entries must be equal.
    pub final_layer: [Felt; STARK_FINAL_LAYER],
    /// Out-of-domain frame `T(ζ)`.
    pub ood_current: [Felt; STARK_MAX_WIDTH],
    /// Out-of-domain frame `T(ω_N·ζ)`.
    pub ood_next: [Felt; STARK_MAX_WIDTH],
    /// Query openings.
    pub queries: [QueryOpening; STARK_MAX_QUERIES as usize],
}

// ===========================================================================
// Shared Fiat-Shamir schedule (prover and verifier must agree exactly)
// ===========================================================================

/// Start the transcript: absorb the protocol tag, the AIR shape and the trace
/// commitment.
pub(crate) fn start_transcript(
    env: &Env,
    log_n: u32,
    width: u32,
    num_boundary: u32,
    num_transitions: u32,
    trace_root: &BytesN<32>,
) -> Transcript {
    let mut tr = Transcript::new();
    tr.absorb(env, &Bytes::from_slice(env, b"stark-fri-v1"));
    tr.absorb_felt(env, Felt::new(log_n as u64));
    tr.absorb_felt(env, Felt::new(width as u64));
    tr.absorb_felt(env, Felt::new(num_boundary as u64));
    tr.absorb_felt(env, Felt::new(num_transitions as u64));
    tr.absorb_digest(env, trace_root);
    tr
}

/// Squeeze the `count` constraint weights `α`.
pub(crate) fn squeeze_alphas(
    tr: &mut Transcript,
    env: &Env,
    count: usize,
) -> [Felt; STARK_MAX_CONSTRAINTS] {
    let mut alphas = [Felt::ZERO; STARK_MAX_CONSTRAINTS];
    for slot in alphas.iter_mut().take(count) {
        *slot = tr.squeeze_felt(env);
    }
    alphas
}

/// Squeeze the DEEP point `ζ`, rejecting draws inside the trace domain (where
/// the vanishing polynomial `Z` — and hence the composition — is undefined).
pub(crate) fn squeeze_zeta(
    tr: &mut Transcript,
    env: &Env,
    n: u64,
    c_n: Felt,
) -> Result<Felt, ZkError> {
    let mut zeta = tr.squeeze_felt(env);
    let mut guard = 0u32;
    while zeta.pow(n) == c_n {
        zeta = tr.squeeze_felt(env);
        guard += 1;
        if guard > 32 {
            return Err(ZkError::InvalidInput);
        }
    }
    Ok(zeta)
}

// ===========================================================================
// Composition polynomial
// ===========================================================================

/// Evaluate the constraint composition polynomial at `z`, given the trace
/// values `cur = T(z)` and `next = T(ω_N·z)`.
///
/// `C(z) = Σ_k α_k·t_k(cur,next)·(z − x_last)/(z^N − c^N)
///        + Σ_j α_{nt+j}·(cur[c_j] − v_j)/(z − x_j)`
///
/// Returns [`ZkError::InvalidInput`] when `z` is a root of `Z` or equals a
/// boundary-constraint point (the composition is undefined there).
fn composition_at<A: Air>(
    air: &A,
    alphas: &[Felt],
    cur: &[Felt],
    next: &[Felt],
    z: Felt,
    log_n: u32,
    n: u64,
) -> Result<Felt, ZkError> {
    let c_n = Felt::new(TRACE_COSET_OFFSET).pow(n);
    let z_van = z.pow(n).sub(c_n);
    if z_van.is_zero() {
        return Err(ZkError::InvalidInput);
    }
    let z_van_inv = z_van.inv();
    let selector = z.sub(trace_domain_point(log_n, n - 1));

    let mut acc = Felt::ZERO;
    let nt = air.num_transitions();
    for k in 0..nt {
        let residual = air.transition(k, cur, next);
        acc = acc.add(
            alphas[k as usize]
                .mul(residual)
                .mul(selector)
                .mul(z_van_inv),
        );
    }
    let nb = air.num_boundary();
    for j in 0..nb {
        let (row, column, value) = air.boundary(j);
        let x_j = trace_domain_point(log_n, row as u64);
        let diff = z.sub(x_j);
        if diff.is_zero() {
            return Err(ZkError::InvalidInput);
        }
        acc = acc.add(
            alphas[(nt + j) as usize]
                .mul(cur[column as usize].sub(value))
                .mul(diff.inv()),
        );
    }
    Ok(acc)
}

// ===========================================================================
// Unified verifier
// ===========================================================================

/// Verify a [`StarkProof`] against the AIR `air` (Issue #571).
///
/// Runs the full commit/query FRI phase over the composition polynomial,
/// including DEEP-FRI out-of-domain composition, boundary and transition
/// constraint enforcement, and multi-layer Merkle authentication.
///
/// # Errors
///
/// * [`ZkError::InvalidInput`] — malformed dimensions, a proof that does not
///   match the AIR shape, or an out-of-domain point that collides with the
///   evaluation domain.
/// * [`ZkError::MerkleVerificationFailed`] — an authentication path does not
///   reconstruct its root.
/// * [`ZkError::FriVerificationFailed`] — the DEEP quotient, a fold, or the
///   final constant layer is inconsistent (the trace does not satisfy the AIR
///   or the proof was tampered with).
pub fn verify_stark_proof<A: Air>(env: &Env, air: &A, proof: &StarkProof) -> Result<(), ZkError> {
    let log_n = proof.log_trace_length;
    let width = proof.width;
    if log_n == 0 || log_n > STARK_MAX_LOG_N {
        return Err(ZkError::InvalidInput);
    }
    if width == 0 || width as usize > STARK_MAX_WIDTH {
        return Err(ZkError::InvalidInput);
    }
    if proof.num_queries == 0 || proof.num_queries > STARK_MAX_QUERIES {
        return Err(ZkError::InvalidInput);
    }
    if air.width() != width || air.log_trace_length() != log_n {
        return Err(ZkError::InvalidInput);
    }
    let nb = air.num_boundary();
    let nt = air.num_transitions();
    if nb > STARK_MAX_BOUNDARY
        || nt > STARK_MAX_TRANSITIONS
        || (nb + nt) as usize > STARK_MAX_CONSTRAINTS
    {
        return Err(ZkError::InvalidInput);
    }

    let n = 1u64 << log_n;
    let log_m = log_n + STARK_BLOWUP_LOG;
    let m = 1u64 << log_m;
    let layers = (log_n + 1) as usize; // committed FRI layers
    let width = width as usize;

    for j in 0..nb {
        let (row, column, _) = air.boundary(j);
        if row as u64 >= n || column >= width as u32 {
            return Err(ZkError::InvalidInput);
        }
    }

    // ---- Fiat-Shamir ------------------------------------------------------
    let mut tr = start_transcript(env, log_n, proof.width, nb, nt, &proof.trace_root);
    let alphas = squeeze_alphas(&mut tr, env, (nb + nt) as usize);
    let c_n = Felt::new(TRACE_COSET_OFFSET).pow(n);
    let zeta = squeeze_zeta(&mut tr, env, n, c_n)?;

    tr.absorb_digest(env, &proof.layer_roots[0]);
    let mut betas = [Felt::ZERO; STARK_MAX_COMMITTED_LAYERS];
    for l in 0..layers {
        betas[l] = tr.squeeze_felt(env);
        if l + 1 < layers {
            tr.absorb_digest(env, &proof.layer_roots[l + 1]);
        }
    }
    let mut query_index = [0u32; STARK_MAX_QUERIES as usize];
    for slot in query_index.iter_mut().take(proof.num_queries as usize) {
        *slot = (tr.squeeze_felt(env).as_u64() % m) as u32;
    }

    // ---- Final layer must be constant (the deg < 2N degree bound) ---------
    if proof.final_layer[0] != proof.final_layer[1] {
        return Err(ZkError::FriVerificationFailed);
    }
    let final_value = proof.final_layer[0];

    // ---- DEEP composition at the out-of-domain point ----------------------
    let c_zeta = composition_at(
        air,
        &alphas,
        &proof.ood_current[..width],
        &proof.ood_next[..width],
        zeta,
        log_n,
        n,
    )?;

    // ---- Query phase ------------------------------------------------------
    for q in 0..proof.num_queries as usize {
        let opening = &proof.queries[q];
        let index0 = query_index[q];
        if opening.index != index0 {
            return Err(ZkError::InvalidInput);
        }

        // Trace LDE row at z_i.
        let trace_leaf = row_leaf(env, &opening.trace_row[..width])?;
        if !merkle::verify_path_at(
            env,
            &trace_leaf,
            &proof.trace_root,
            &opening.trace_path,
            log_m,
            index0 as u64,
        ) {
            return Err(ZkError::MerkleVerificationFailed);
        }

        // Trace LDE row at ω_N·z_i (the "next row" for transition constraints).
        let next_index = (index0 as u64 + (1u64 << STARK_BLOWUP_LOG)) % m;
        let next_leaf = row_leaf(env, &opening.trace_next[..width])?;
        if !merkle::verify_path_at(
            env,
            &next_leaf,
            &proof.trace_root,
            &opening.next_path,
            log_m,
            next_index,
        ) {
            return Err(ZkError::MerkleVerificationFailed);
        }

        let z = Felt::domain_point(log_m, index0 as u64);
        let c_z = composition_at(
            air,
            &alphas,
            &opening.trace_row[..width],
            &opening.trace_next[..width],
            z,
            log_n,
            n,
        )?;
        let denom = z.sub(zeta);
        if denom.is_zero() {
            return Err(ZkError::InvalidInput);
        }
        let d_expected = c_z.sub(c_zeta).mul(denom.inv());

        // Walk the FRI commit/query chain.
        let mut idx = index0;
        let mut current = Felt::ZERO;
        for l in 0..layers {
            let log_l = log_m - l as u32;
            let half = 1u32 << (log_l - 1);
            let m_idx = idx & (half - 1);
            let layer = &opening.layers[l];
            if layer.index != m_idx {
                return Err(ZkError::InvalidInput);
            }

            if !merkle::verify_path_at(
                env,
                &felt_leaf(env, layer.value),
                &proof.layer_roots[l],
                &layer.path,
                log_l,
                m_idx as u64,
            ) {
                return Err(ZkError::MerkleVerificationFailed);
            }
            if !merkle::verify_path_at(
                env,
                &felt_leaf(env, layer.pair_value),
                &proof.layer_roots[l],
                &layer.pair_path,
                log_l,
                (m_idx + half) as u64,
            ) {
                return Err(ZkError::MerkleVerificationFailed);
            }

            // The value the chain is checking sits at `idx`, which is either
            // the low (`value`) or high (`pair_value`) element of the pair.
            let at_idx = if idx == m_idx {
                layer.value
            } else {
                layer.pair_value
            };
            if l == 0 {
                // Layer 0 must equal the DEEP quotient at the queried point.
                if at_idx != d_expected {
                    return Err(ZkError::FriVerificationFailed);
                }
            } else if at_idx != current {
                return Err(ZkError::FriVerificationFailed);
            }

            let x = Felt::domain_point(log_l, m_idx as u64);
            current = fold_value(layer.value, layer.pair_value, x, betas[l]);
            idx = m_idx;
        }

        if current != final_value {
            return Err(ZkError::FriVerificationFailed);
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests;
