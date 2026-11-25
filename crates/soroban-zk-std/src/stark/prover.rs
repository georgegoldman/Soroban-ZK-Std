//! Test-only STARK prover for the end-to-end FRI-STARK tests (Issue #571).
//!
//! This module is compiled **only** under `#[cfg(test)]`, so no prover code is
//! ever linked into a contract build. It implements the honest side of the
//! protocol described in [`super`]:
//!
//! 1. interpolate every trace column on the trace domain `{c·ω_N^j}` and
//!    evaluate it on the FRI coset of size `M = 4N` (the LDE);
//! 2. Merkle-commit the LDE rows;
//! 3. absorb the commitments and squeeze `α`, `ζ`, `β_l` and the query indices
//!    with the same Fiat-Shamir schedule as the verifier;
//! 4. evaluate the constraint composition `C`, the DEEP quotient
//!    `D = (C − C(ζ))/(x − ζ)` and its FRI folds, committing each layer;
//! 5. open the trace rows and every FRI layer at the sampled indices.
//!
//! The prover deliberately does **not** check the AIR: it must be able to
//! produce a proof for an invalid trace so the negative tests can confirm the
//! verifier rejects it.

extern crate alloc;

use alloc::vec::Vec as AllocVec;
use core::ops::{Add, Mul, Sub};

use soroban_sdk::{BytesN, Env, Vec};

use super::{
    composition_at, squeeze_alphas, squeeze_zeta, start_transcript, trace_domain_point, Air,
    FriLayerOpening, QueryOpening, StarkProof, STARK_BLOWUP_LOG, STARK_FINAL_LAYER,
    STARK_MAX_COMMITTED_LAYERS, STARK_MAX_LOG_N, STARK_MAX_PATH, STARK_MAX_QUERIES,
    STARK_MAX_WIDTH, TRACE_COSET_OFFSET,
};
use crate::stark::field::Felt;
use crate::stark::merkle;
use soroban_zk_core::ZkError;

/// A commitment plus the leaf digests needed to open it.
struct Committed {
    root: BytesN<32>,
    leaves: Vec<BytesN<32>>,
}

fn commit(env: &Env, data: &[Felt]) -> Committed {
    let mut leaves: Vec<BytesN<32>> = Vec::new(env);
    for f in data {
        leaves.push_back(merkle::felt_leaf(env, *f));
    }
    let root = merkle::merkle_root(env, &leaves);
    Committed { root, leaves }
}

fn commit_rows(env: &Env, rows: &[AllocVec<Felt>]) -> Result<Committed, ZkError> {
    let mut leaves: Vec<BytesN<32>> = Vec::new(env);
    for row in rows {
        leaves.push_back(super::row_leaf(env, row)?);
    }
    let root = merkle::merkle_root(env, &leaves);
    Ok(Committed { root, leaves })
}

/// Lagrange weights `L_j(y)` for the nodes `x_j` of the trace domain.
///
/// Uses the closed form `L_j(y) = (y^N − c^N) / ((y − x_j)·N·x_j^{N−1})`,
/// which needs one field inversion per node and no polynomial coefficients.
fn lagrange_weights(
    nodes: &[Felt],
    nodes_n1: &[Felt],
    y: Felt,
    c_n: Felt,
    n: u64,
) -> Result<AllocVec<Felt>, ZkError> {
    let num = y.pow(n).sub(c_n);
    if num.is_zero() {
        // `y` is a trace-domain point: the closed form is singular.
        return Err(ZkError::InvalidInput);
    }
    let n_felt = Felt::new(n);
    let mut weights = AllocVec::with_capacity(nodes.len());
    for (j, x_j) in nodes.iter().enumerate() {
        let diff = y.sub(*x_j);
        if diff.is_zero() {
            return Err(ZkError::InvalidInput);
        }
        weights.push(num.mul(diff.mul(n_felt).mul(nodes_n1[j]).inv()));
    }
    Ok(weights)
}

fn dot(weights: &[Felt], values: &[Felt]) -> Felt {
    let mut acc = Felt::ZERO;
    for (w, v) in weights.iter().zip(values.iter()) {
        acc = acc.add(w.mul(*v));
    }
    acc
}

fn fill_path(
    env: &Env,
    leaves: &Vec<BytesN<32>>,
    index: u32,
    out: &mut [[u8; 32]; STARK_MAX_PATH],
) -> Result<(), ZkError> {
    let path = merkle::open(env, leaves, index);
    let depth = path.depth as usize;
    if depth > STARK_MAX_PATH {
        return Err(ZkError::InvalidInput);
    }
    out[..depth].copy_from_slice(&path.siblings[..depth]);
    Ok(())
}

fn empty_fri_layer() -> FriLayerOpening {
    FriLayerOpening {
        index: 0,
        value: Felt::ZERO,
        pair_value: Felt::ZERO,
        path: [[0u8; 32]; STARK_MAX_PATH],
        pair_path: [[0u8; 32]; STARK_MAX_PATH],
    }
}

fn empty_query() -> QueryOpening {
    QueryOpening {
        index: 0,
        trace_row: [Felt::ZERO; STARK_MAX_WIDTH],
        trace_next: [Felt::ZERO; STARK_MAX_WIDTH],
        trace_path: [[0u8; 32]; STARK_MAX_PATH],
        next_path: [[0u8; 32]; STARK_MAX_PATH],
        layers: core::array::from_fn(|_| empty_fri_layer()),
    }
}

/// Produce a STARK proof for `trace` (`2^log_n` rows of `air.width()` columns).
///
/// The trace is interpolated on the trace coset and evaluated on the FRI coset;
/// no constraint check is performed here (see the module docs).
pub fn prove_stark<A: Air>(env: &Env, air: &A, trace: &[&[Felt]]) -> Result<StarkProof, ZkError> {
    let log_n = air.log_trace_length();
    let width = air.width() as usize;
    if log_n == 0 || log_n > STARK_MAX_LOG_N {
        return Err(ZkError::InvalidInput);
    }
    if width == 0 || width > STARK_MAX_WIDTH {
        return Err(ZkError::InvalidInput);
    }
    let n = 1u64 << log_n;
    if trace.len() as u64 != n {
        return Err(ZkError::InvalidInput);
    }
    if trace.iter().any(|row| row.len() != width) {
        return Err(ZkError::InvalidInput);
    }

    let log_m = log_n + STARK_BLOWUP_LOG;
    let m = 1u64 << log_m;
    let layers = (log_n + 1) as usize;
    let step = 1u64 << STARK_BLOWUP_LOG; // ω_N shift on the LDE coset

    // ---- Interpolate the trace and evaluate it on the LDE coset ----------
    let nodes: AllocVec<Felt> = (0..n).map(|j| trace_domain_point(log_n, j)).collect();
    let nodes_n1: AllocVec<Felt> = nodes.iter().map(|x| x.pow(n - 1)).collect();
    let c_n = Felt::new(TRACE_COSET_OFFSET).pow(n);
    let mut columns: AllocVec<AllocVec<Felt>> = AllocVec::with_capacity(width);
    for c in 0..width {
        columns.push(trace.iter().map(|row| row[c]).collect());
    }

    let mut lde: AllocVec<AllocVec<Felt>> = AllocVec::with_capacity(m as usize);
    for i in 0..m {
        let z = Felt::domain_point(log_m, i);
        let weights = lagrange_weights(&nodes, &nodes_n1, z, c_n, n)?;
        let mut row = AllocVec::with_capacity(width);
        for column in columns.iter() {
            row.push(dot(&weights, column));
        }
        lde.push(row);
    }

    let trace_commit = commit_rows(env, &lde)?;

    // ---- Fiat-Shamir: α, ζ ------------------------------------------------
    let nb = air.num_boundary();
    let nt = air.num_transitions();
    let mut tr = start_transcript(env, log_n, width as u32, nb, nt, &trace_commit.root);
    let alphas = squeeze_alphas(&mut tr, env, (nb + nt) as usize);
    let zeta = squeeze_zeta(&mut tr, env, n, c_n)?;

    // ---- Out-of-domain frame: T(ζ) and T(ω_N·ζ) ---------------------------
    let root_n = Felt::layer_root(log_n);
    let mut ood_current = [Felt::ZERO; STARK_MAX_WIDTH];
    let mut ood_next = [Felt::ZERO; STARK_MAX_WIDTH];
    let w_zeta = lagrange_weights(&nodes, &nodes_n1, zeta, c_n, n)?;
    let w_zeta_shift = lagrange_weights(&nodes, &nodes_n1, zeta.mul(root_n), c_n, n)?;
    for c in 0..width {
        ood_current[c] = dot(&w_zeta, &columns[c]);
        ood_next[c] = dot(&w_zeta_shift, &columns[c]);
    }
    let c_zeta = composition_at(
        air,
        &alphas,
        &ood_current[..width],
        &ood_next[..width],
        zeta,
        log_n,
        n,
    )?;

    // ---- Composition and DEEP quotient over the LDE coset -----------------
    let mut deep: AllocVec<Felt> = AllocVec::with_capacity(m as usize);
    for i in 0..m {
        let z = Felt::domain_point(log_m, i);
        let cur = &lde[i as usize];
        let next = &lde[((i + step) % m) as usize];
        let c = composition_at(air, &alphas, cur, next, z, log_n, n)?;
        let diff = z.sub(zeta);
        if diff.is_zero() {
            return Err(ZkError::InvalidInput);
        }
        deep.push(c.sub(c_zeta).mul(diff.inv()));
    }

    // ---- FRI commit phase -------------------------------------------------
    let mut layer_data: AllocVec<AllocVec<Felt>> = AllocVec::new();
    let mut layer_commit: AllocVec<Committed> = AllocVec::new();
    let mut layer_roots: [BytesN<32>; STARK_MAX_COMMITTED_LAYERS] =
        core::array::from_fn(|_| BytesN::from_array(env, &[0u8; 32]));

    layer_data.push(deep);
    layer_commit.push(commit(env, &layer_data[0]));
    layer_roots[0] = layer_commit[0].root.clone();
    tr.absorb_digest(env, &layer_roots[0]);

    for l in 0..layers - 1 {
        let beta = tr.squeeze_felt(env);
        let log_l = log_m - l as u32;
        let half = 1usize << (log_l - 1);
        let mut next: AllocVec<Felt> = AllocVec::new();
        next.resize(half, Felt::ZERO);
        crate::stark::fri::fold_layer_into(&layer_data[l], &mut next, beta, log_l);
        layer_commit.push(commit(env, &next));
        layer_roots[l + 1] = layer_commit[l + 1].root.clone();
        tr.absorb_digest(env, &layer_roots[l + 1]);
        layer_data.push(next);
    }

    let beta_last = tr.squeeze_felt(env);
    let log_last = log_m - (layers as u32 - 1);
    let half_last = 1usize << (log_last - 1);
    let mut final_layer = [Felt::ZERO; STARK_FINAL_LAYER];
    crate::stark::fri::fold_layer_into(
        &layer_data[layers - 1],
        &mut final_layer,
        beta_last,
        log_last,
    );
    debug_assert_eq!(half_last, STARK_FINAL_LAYER);

    // ---- Query phase ------------------------------------------------------
    let mut queries: [QueryOpening; STARK_MAX_QUERIES as usize] =
        core::array::from_fn(|_| empty_query());
    for slot in queries.iter_mut() {
        let index0 = (tr.squeeze_felt(env).as_u64() % m) as u32;
        let mut opening = empty_query();
        opening.index = index0;

        // Trace openings: z_i and ω_N·z_i.
        opening.trace_row[..width].copy_from_slice(&lde[index0 as usize]);
        let next_index = ((index0 as u64 + step) % m) as u32;
        opening.trace_next[..width].copy_from_slice(&lde[next_index as usize]);
        fill_path(env, &trace_commit.leaves, index0, &mut opening.trace_path)?;
        fill_path(
            env,
            &trace_commit.leaves,
            next_index,
            &mut opening.next_path,
        )?;

        // FRI layer openings.
        let mut idx = index0;
        for l in 0..layers {
            let log_l = log_m - l as u32;
            let half = 1u32 << (log_l - 1);
            let m_idx = idx & (half - 1);
            let layer = &layer_data[l];
            let mut fri = empty_fri_layer();
            fri.index = m_idx;
            fri.value = layer[m_idx as usize];
            fri.pair_value = layer[(m_idx + half) as usize];
            fill_path(env, &layer_commit[l].leaves, m_idx, &mut fri.path)?;
            fill_path(
                env,
                &layer_commit[l].leaves,
                m_idx + half,
                &mut fri.pair_path,
            )?;
            opening.layers[l] = fri;
            idx = m_idx;
        }

        *slot = opening;
    }

    Ok(StarkProof {
        log_trace_length: log_n,
        width: width as u32,
        num_queries: super::STARK_MAX_QUERIES,
        trace_root: trace_commit.root,
        layer_roots,
        final_layer,
        ood_current,
        ood_next,
        queries,
    })
}
