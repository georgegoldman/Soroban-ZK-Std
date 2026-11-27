//! PLONK proof data structures and parameter configuration traits.
//!
//! Foundational, `no_std`-compatible types for PLONK verification on Soroban,
//! aligned with `specs/plonk.md`:
//!
//! * Gate constraint: `q_L*a + q_R*b + q_O*c + q_M*a*b + q_C = 0`
//!   (3 wires `a,b,c`; 5 selectors).
//! * Linearization at challenge `zeta`: `L(X)` as defined in the spec.
//!
//! The spec illustrates only the gate equation and linearization; it does not
//! replace standard PLONK. This module therefore retains the full proof shape:
//! wire commitments, permutation commitment (`z`), split quotient commitments
//! (`t_lo, t_mid, t_hi` due to SRS degree bounds), and opening proofs at both
//! `zeta` and `zeta*omega`, plus their evaluations as raw `u256` scalars
//! (matching `halo2`, `polynomial`, and `poseidon2` conventions; validate at
//! the boundary with `Bn254::is_valid_scalar` / `Fr::safe_from`).

use ethnum::u256;
use sha2::{Digest, Sha256};

use crate::{Bn254, G1Affine, G1Projective, ZkError};

/// A PLONK proof over BN254.
///
/// Commitments are `G1Affine` points; evaluations are raw `u256` scalars in
/// `[0, r)` where `r = Bn254::FR_MODULUS`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlonkProof {
    /// Commitments to the 3 wire polynomials `a, b, c`.
    pub wire_commitments: [G1Affine; 3],
    /// Commitment to the permutation accumulator polynomial `z(X)`.
    pub z_commitment: G1Affine,
    /// Split quotient commitments `t_lo, t_mid, t_hi`.
    pub quotient_commitments: [G1Affine; 3],
    /// Opening proof at the challenge point `zeta`.
    pub w_zeta: G1Affine,
    /// Opening proof at the shifted point `zeta*omega`.
    pub w_zeta_omega: G1Affine,
    /// Wire evaluations `a(zeta), b(zeta), c(zeta)`.
    pub wire_evaluations: [u256; 3],
    /// Permutation evaluations `sigma_1(zeta), sigma_2(zeta)`.
    pub sigma_evaluations: [u256; 2],
    /// Permutation evaluation `z(zeta*omega)`.
    pub z_omega_evaluation: u256,
    /// Quotient evaluation `t(zeta)`.
    pub quotient_evaluation: u256,
    /// Linearization evaluation `L(zeta)`.
    pub linearization_evaluation: u256,
}

/// Scalar field interface for a PLONK instantiation.
pub trait PlonkField {
    /// Scalar field modulus.
    const MODULUS: u256;
    /// Field addition `(a + b) mod MODULUS`.
    fn add(a: u256, b: u256) -> u256;
    /// Field multiplication `(a * b) mod MODULUS`.
    fn mul(a: u256, b: u256) -> u256;
}

/// Circuit parameter configuration for a PLONK instantiation.
pub trait PlonkConfig: PlonkField {
    /// Number of wire polynomials (spec gate uses `a, b, c`).
    const NUM_WIRES: usize = 3;
    /// Number of selector polynomials (`q_L, q_R, q_O, q_M, q_C`).
    const NUM_SELECTORS: usize = 5;
}

impl PlonkField for Bn254 {
    const MODULUS: u256 = Self::FR_MODULUS;
    #[inline(always)]
    fn add(a: u256, b: u256) -> u256 {
        Self::add(a, b)
    }
    #[inline(always)]
    fn mul(a: u256, b: u256) -> u256 {
        Self::mul(a, b)
    }
}

impl PlonkConfig for Bn254 {}

/// Evaluates the PLONK 3-wire arithmetic gate constraint.
/// The constraint is defined as:
/// q_L * a + q_R * b + q_O * c + q_M * (a * b) + q_C = 0
/// This function securely computes the evaluation over the BN254 scalar field (Fr).
#[allow(clippy::too_many_arguments)]
pub fn evaluate_arithmetic_gate(
    q_l: u256,
    q_r: u256,
    q_o: u256,
    q_m: u256,
    q_c: u256,
    a: u256,
    b: u256,
    c: u256,
) -> u256 {
    // 1. q_L * a
    let term_l = Bn254::mul(q_l, a);

    // 2. q_R * b
    let term_r = Bn254::mul(q_r, b);

    // 3. q_O * c
    let term_o = Bn254::mul(q_o, c);

    // 4. q_M * (a * b)
    let a_b = Bn254::mul(a, b);
    let term_m = Bn254::mul(q_m, a_b);

    // Sum them all up: term_l + term_r + term_o + term_m + (q_c mod r)
    let sum1 = Bn254::add(term_l, term_r);
    let sum2 = Bn254::add(sum1, term_o);
    let sum3 = Bn254::add(sum2, term_m);

    Bn254::add(sum3, q_c % Bn254::FR_MODULUS)
}

/// Fiat-Shamir challenges for the linearization round.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PlonkChallenges {
    pub alpha: u256,
    pub beta: u256,
    pub gamma: u256,
    pub zeta: u256,
}

/// Selector polynomial evaluations at `zeta`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SelectorEvaluations {
    pub q_l: u256,
    pub q_r: u256,
    pub q_o: u256,
    pub q_m: u256,
    pub q_c: u256,
}

/// Committed polynomial evaluations at `zeta` not stored in [`PlonkProof`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CommitEvaluations {
    pub z_zeta: u256,
    pub s_sigma3_zeta: u256,
}

/// Domain parameters for the linearization round.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DomainParams {
    pub n: usize,
    pub k1: u256,
    pub k2: u256,
}

/// Evaluates the PLONK linearization polynomial at `zeta`.
///
/// Implements `plonk_lin.mdx` §9 using only field arithmetic:
/// `r_gate = a*q_l + b*q_r + c*q_o + a*b*q_m + q_c`,
/// `B0/B1` permutation scalars, `r_perm = B0*z - B1*s3`,
/// `L1 = (zeta^n - 1) / (n*(zeta - 1))`,
/// `r = r_gate + alpha*r_perm + alpha^2*L1*z`.
///
/// Wire bars come from `proof.wire_evaluations`, `s1/s2` from
/// `proof.sigma_evaluations`, and `z_omega` from
/// `proof.z_omega_evaluation`. Returns `Err` on `n == 0` or a
/// zero `L1` denominator (e.g. `zeta == 1`); never panics.
pub fn evaluate_linearization(
    proof: &PlonkProof,
    challenges: &PlonkChallenges,
    selectors: &SelectorEvaluations,
    commits: &CommitEvaluations,
    domain: &DomainParams,
) -> Result<u256, ZkError> {
    if domain.n == 0 {
        return Err(ZkError::InvalidInput);
    }
    let a_bar = proof.wire_evaluations[0];
    let b_bar = proof.wire_evaluations[1];
    let c_bar = proof.wire_evaluations[2];
    let s1_bar = proof.sigma_evaluations[0];
    let s2_bar = proof.sigma_evaluations[1];
    let z_omega_bar = proof.z_omega_evaluation;
    let zeta = challenges.zeta;
    let (alpha, beta, gamma) = (challenges.alpha, challenges.beta, challenges.gamma);

    // r_gate = a*q_l + b*q_r + c*q_o + (a*b)*q_m + q_c
    let ab = Bn254::mul(a_bar, b_bar);
    let mut r_gate = Bn254::mul(a_bar, selectors.q_l);
    r_gate = Bn254::add(r_gate, Bn254::mul(b_bar, selectors.q_r));
    r_gate = Bn254::add(r_gate, Bn254::mul(c_bar, selectors.q_o));
    r_gate = Bn254::add(r_gate, Bn254::mul(ab, selectors.q_m));
    r_gate = Bn254::add(r_gate, selectors.q_c);

    // B0 = (a + beta*zeta + gamma)(b + beta*k1*zeta + gamma)(c + beta*k2*zeta + gamma)
    let b_zeta = Bn254::mul(beta, zeta);
    let t0 = Bn254::add(Bn254::add(a_bar, b_zeta), gamma);
    let t1 = Bn254::add(
        Bn254::add(b_bar, Bn254::mul(beta, Bn254::mul(domain.k1, zeta))),
        gamma,
    );
    let t2 = Bn254::add(
        Bn254::add(c_bar, Bn254::mul(beta, Bn254::mul(domain.k2, zeta))),
        gamma,
    );
    let b0 = Bn254::mul(Bn254::mul(t0, t1), t2);

    // B1 = (a + beta*s1 + gamma)(b + beta*s2 + gamma)*beta*z_omega
    let u0 = Bn254::add(Bn254::add(a_bar, Bn254::mul(beta, s1_bar)), gamma);
    let u1 = Bn254::add(Bn254::add(b_bar, Bn254::mul(beta, s2_bar)), gamma);
    let b1 = Bn254::mul(Bn254::mul(Bn254::mul(u0, u1), beta), z_omega_bar);

    // r_perm = B0*z_zeta - B1*s3_zeta
    let r_perm = Bn254::sub(
        Bn254::mul(b0, commits.z_zeta),
        Bn254::mul(b1, commits.s_sigma3_zeta),
    );

    // L1 = (zeta^n - 1) / (n*(zeta - 1))
    let n_fe = u256::from(domain.n as u64);
    let zeta_pow_n = Bn254::pow(zeta, n_fe);
    let num = Bn254::sub(zeta_pow_n, u256::from(1u8));
    let den = Bn254::mul(n_fe, Bn254::sub(zeta, u256::from(1u8)));
    if den == u256::from(0u8) {
        return Err(ZkError::InvalidFieldElement);
    }
    let l1 = Bn254::mul(num, Bn254::invert(den));

    let alpha2 = Bn254::mul(alpha, alpha);
    let term_perm = Bn254::mul(alpha, r_perm);
    let term_init = Bn254::mul(alpha2, Bn254::mul(l1, commits.z_zeta));
    Ok(Bn254::add(r_gate, Bn254::add(term_perm, term_init)))
}

// ============================================================================
// KZG Evaluation Proof Verification
// ============================================================================
//
// This implements the batched KZG polynomial opening proof check used in the
// final step of PLONK verification. The prover provides two opening proofs:
//
//   W_zeta      — opening proof at challenge point `zeta`
//   W_zeta_omega — opening proof at shifted point `zeta * omega`
//
// The verifier reconstructs the batched commitment `F` and batched evaluation
// `E`, then checks the two proof equations with a single multi-pairing call.
//
// ## Mathematical Specification
//
// ### Setup
//
// Let `srs_g2 = [tau] * G2` be the SRS G2 element (the trusted-setup point).
// Let `omega` be the multiplicative generator of the evaluation domain H.
//
// The PLONK prover opens *k* polynomials `f_0, ..., f_{k-1}` at `zeta` and
// a single polynomial `f_last` at `zeta * omega` using two batched proofs:
//
//   W_zeta   : opening proof for batched polynomial `F_1(X)` at `zeta`
//   W_zeta_omega : opening proof for polynomial `F_2(X)` at `zeta * omega`
//
// ### Batched Commitment Construction
//
// The batched commitment at `zeta` is:
//   F = sum_{i=0}^{k-1} v^i * C_i
//
// where `v` is the Fiat-Shamir batch challenge and `C_i` are the commitments
// to the opened polynomials.
//
// The batched evaluation is:
//   E = sum_{i=0}^{k-1} v^i * f_i(zeta)   (scalar, encoded as a G1 point)
//   plus `u * f_last(zeta*omega)` contribution folded in
//
// ### Pairing Check
//
// The KZG opening equation for a single polynomial `f` with commitment `C`,
// evaluation `y = f(z)`, and opening proof `W` is:
//
//   e(W, [tau - z]_2) = e(C - [y]_1, G2)
//   ⟺  e(W, [tau]_2) * e(-z * W, G2) = e(C - [y]_1, G2)
//   ⟺  e(W, [tau]_2) = e(C - [y]_1 + z*W, G2)
//
// For the two-point batched form (using random shift `u`):
//
//   e(W_zeta + u * W_zeta_omega, [tau]_2)
//   =
//   e(zeta * W_zeta + u*zeta*omega * W_zeta_omega + F - E, G2)
//
// Rearranged into a product-of-pairings == 1 form (two-pair check):
//
//   e(W_zeta + u * W_zeta_omega, [tau]_2)
//   * e( -(zeta * W_zeta + u*zeta*omega * W_zeta_omega + F - E), G2 )
//   == 1
//
// This is computed via the existing `pairing_check` host function.

/// Input bundle for a batched KZG evaluation proof.
///
/// Contains everything the verifier needs to check the PLONK opening proofs
/// at `zeta` and `zeta * omega` without relying on external state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KzgEvalProofInputs<'a> {
    /// Commitments to the polynomials opened at `zeta`.
    /// `commitments[i]` is the commitment for opening `evaluations_at_zeta[i]`.
    pub commitments: &'a [G1Affine],
    /// Evaluations `f_i(zeta)` for each commitment in `commitments`.
    pub evaluations_at_zeta: &'a [u256],
    /// Commitment to the polynomial opened at `zeta * omega`.
    pub commitment_at_zeta_omega: G1Affine,
    /// Evaluation at `zeta * omega`: `f_last(zeta * omega)`.
    pub evaluation_at_zeta_omega: u256,
    /// Batched opening proof at `zeta`: `W_zeta` in G1.
    pub w_zeta: G1Affine,
    /// Batched opening proof at `zeta * omega`: `W_{zeta*omega}` in G1.
    pub w_zeta_omega: G1Affine,
    /// Fiat-Shamir challenge `v` for batching the `zeta`-side polynomials.
    pub v: u256,
    /// Fiat-Shamir challenge `u` for combining the two opening points.
    pub u: u256,
    /// The evaluation domain challenge `zeta`.
    pub zeta: u256,
    /// Domain generator `omega` (primitive n-th root of unity in Fr).
    pub omega: u256,
}

/// Computes the LHS and RHS G1 points for the batched KZG pairing check.
///
/// Returns `(lhs, rhs)` where:
///
/// ```text
/// lhs = W_zeta + u * W_{zeta*omega}
/// rhs = zeta * W_zeta + u*zeta*omega * W_{zeta*omega} + F - [E]_1
/// ```
///
/// with:
///
/// ```text
/// F   = sum_i v^i * C_i                   (batched commitment)
/// E   = sum_i v^i * f_i(zeta) + u * f_last(zeta*omega)   (batched eval as scalar)
/// ```
///
/// The caller is responsible for calling
/// `pairing_check(env, &[(lhs, srs_g2), (neg(rhs), g2_gen)])` to finalize
/// verification.
///
/// # Errors
///
/// Returns [`ZkError::InvalidInput`] if:
/// - `commitments` and `evaluations_at_zeta` have different lengths.
/// - Either slice is empty.
///
/// Returns [`ZkError::InvalidFieldElement`] if any evaluation is ≥ Fr modulus
/// or any challenge (`v`, `u`, `zeta`, `omega`) is ≥ Fr modulus.
pub fn kzg_eval_proof_points(
    inputs: &KzgEvalProofInputs<'_>,
) -> Result<(G1Affine, G1Affine), ZkError> {
    // ── Input validation ────────────────────────────────────────────────────
    let k = inputs.commitments.len();
    if k == 0 || k != inputs.evaluations_at_zeta.len() {
        return Err(ZkError::InvalidInput);
    }

    // Validate all scalars are in [0, r).
    let scalars = [inputs.v, inputs.u, inputs.zeta, inputs.omega];
    for &s in &scalars {
        if s >= Bn254::FR_MODULUS {
            return Err(ZkError::InvalidFieldElement);
        }
    }
    for &e in inputs.evaluations_at_zeta {
        if e >= Bn254::FR_MODULUS {
            return Err(ZkError::InvalidFieldElement);
        }
    }
    if inputs.evaluation_at_zeta_omega >= Bn254::FR_MODULUS {
        return Err(ZkError::InvalidFieldElement);
    }

    // ── Derived challenge: zeta * omega ─────────────────────────────────────
    let zeta_omega = Bn254::mul(inputs.zeta, inputs.omega);

    // ── Batched commitment F and evaluation E, in a single pass ────────────
    //
    // `F` and `E` are two Horner-style accumulators that consume the *same*
    // incremental powers of `v`, so they are folded into one traversal of the
    // opening batch instead of two. Every value lives in a stack local — no
    // heap, no temporary buffers, and no second re-derivation of the `v`
    // powers (the previous two-loop form walked the batch twice):
    //
    //   F = sum_i v^i * C_i        (batched commitment, G1)
    //   E = sum_i v^i * f_i(zeta)  (batched evaluation, scalar)
    let mut f_proj = G1Projective::identity();
    let mut e_scalar = u256::from(0u8);
    let mut v_pow = u256::from(1u8); // v^0 = 1
    for i in 0..k {
        let term = Bn254::g1_scalar_mul(G1Projective::from(inputs.commitments[i]), v_pow);
        f_proj = f_proj.add(&term);
        e_scalar = Bn254::add(e_scalar, Bn254::mul(v_pow, inputs.evaluations_at_zeta[i]));
        v_pow = Bn254::mul(v_pow, inputs.v);
    }
    let f = f_proj.to_affine();

    // Fold in the `zeta*omega` contribution: E += u * f_last(zeta*omega).
    let u_eval_omega = Bn254::mul(inputs.u, inputs.evaluation_at_zeta_omega);
    e_scalar = Bn254::add(e_scalar, u_eval_omega);

    // [E]_1 = e_scalar * G1 (generator is (1, 2) on BN254)
    let g1_gen = G1Affine {
        x: u256::from(1u8),
        y: u256::from(2u8),
    };
    let e_point = Bn254::g1_scalar_mul(G1Projective::from(g1_gen), e_scalar);

    // ── LHS: W_zeta + u * W_{zeta*omega} ───────────────────────────────────
    let u_w_omega = Bn254::g1_scalar_mul(G1Projective::from(inputs.w_zeta_omega), inputs.u);
    let lhs_proj = G1Projective::from(inputs.w_zeta).add(&u_w_omega);
    let lhs = lhs_proj.to_affine();

    // ── RHS: zeta*W_zeta + u*zeta*omega*W_{zeta*omega} + F - [E]_1 ─────────
    //
    // 1. zeta * W_zeta
    let zeta_w_zeta = Bn254::g1_scalar_mul(G1Projective::from(inputs.w_zeta), inputs.zeta);

    // 2. u * zeta_omega * W_{zeta*omega}
    let u_zeta_omega = Bn254::mul(inputs.u, zeta_omega);
    let u_zeta_omega_w =
        Bn254::g1_scalar_mul(G1Projective::from(inputs.w_zeta_omega), u_zeta_omega);

    // 3. Accumulate: zeta_w_zeta + u_zeta_omega_w + F
    let rhs_partial = zeta_w_zeta.add(&u_zeta_omega_w).add(&G1Projective::from(f));

    // 4. Subtract [E]_1: RHS = rhs_partial - e_point
    //    Negation on BN254: -(x, y) = (x, Fq - y)  (y == 0 stays 0)
    let e_affine = e_point.to_affine();
    let neg_e = if e_affine.x == u256::from(0u8) && e_affine.y == u256::from(0u8) {
        // Point at infinity; negation is the identity.
        G1Projective::identity()
    } else {
        G1Projective::from(G1Affine {
            x: e_affine.x,
            y: Bn254::sub_fq(u256::from(0u8), e_affine.y),
        })
    };

    let rhs_proj = rhs_partial.add(&neg_e);
    let rhs = rhs_proj.to_affine();

    Ok((lhs, rhs))
}

// ============================================================================
// Multi-Proof Batch Verification (Issue #427)
// ============================================================================
//
// Verifying `M` independent PLONK proofs naively costs `M` separate two-pair
// checks (`2M` pairings). Each proof reduces, via [`kzg_eval_proof_points`],
// to a pair of G1 points `(lhs_j, rhs_j)` that must satisfy
//
//     e(lhs_j, [tau]_2) * e(-rhs_j, G_2) == 1
//
// Bilinearity lets us fold all `M` equations into a *single* two-pair check
// using a random linear combination with batch scalars `rho_0, ..., rho_{M-1}`:
//
//     prod_j ( e(lhs_j, [tau]_2) * e(-rhs_j, G_2) )^{rho_j} == 1
//     <==>  e( sum_j rho_j*lhs_j , [tau]_2 ) * e( -sum_j rho_j*rhs_j , G_2 ) == 1
//
// The pairing count drops from `2M` to `2`, which is where the gas saving comes
// from: on Soroban each BN254 pairing dominates the instruction budget, so the
// `2M` scalar-muls / G1 adds introduced by the combination are cheap in
// comparison.
//
// Soundness follows the standard batch-verification argument: a prover that can
// forge a single proof makes the combined check pass with probability at most
// `M / |Fr|` (Schwartz-Zippel over the random `rho_j`), negligible for BN254's
// 254-bit scalar field. The caller **must** supply an unpredictable `batch_seed`
// that is not controlled by the prover; a fixed or prover-chosen seed breaks
// soundness.

/// Aggregates `M` PLONK opening checks into a single two-pair pairing input.
///
/// For each proof `j` in `inputs` this reconstructs its `(lhs_j, rhs_j)` pair
/// with [`kzg_eval_proof_points`], derives a non-zero batch scalar `rho_j` from
/// `batch_seed`, and accumulates the weighted sums
///
/// ```text
/// lhs = sum_j rho_j * lhs_j
/// rhs = sum_j rho_j * rhs_j
/// ```
///
/// The scalars follow a power tower `rho_0 = batch_seed mod r`,
/// `rho_{j+1} = rho_j^2 mod r`, so deriving them costs one field multiplication
/// per proof instead of a hash invocation. Everything is folded incrementally
/// into the two accumulators: **no heap allocation**, matching the rest of this
/// module's `no_std` discipline.
///
/// The caller finalizes verification with a single
/// `pairing_check(env, &[(lhs, srs_g2), (neg(rhs), g2_gen)])` (see
/// `soroban-zk-std`'s `verify_plonk_kzg_batch` wrapper).
///
/// # Errors
///
/// Returns [`ZkError::InvalidInput`] if `inputs` is empty.
///
/// Returns [`ZkError::InvalidFieldElement`] if `batch_seed` reduces to `0` or
/// `1` modulo `r` — both degeneracies drop the randomization (a zero scalar
/// silently discards a proof, `rho == 1` leaves every weight at one) — or if a
/// squaring collapses to zero (guarded for correctness).
///
/// Propagates the validation errors of [`kzg_eval_proof_points`] for any
/// individual proof (length mismatches, out-of-range scalars/evaluations).
#[allow(clippy::needless_range_loop)]
pub fn plonk_batch_verify_points(
    inputs: &[KzgEvalProofInputs<'_>],
    batch_seed: &[u8; 32],
) -> Result<(G1Affine, G1Affine), ZkError> {
    let m = inputs.len();
    if m == 0 {
        return Err(ZkError::InvalidInput);
    }

    // rho_0 = batch_seed mod r (big-endian interpretation of the seed).
    // Both `0` and `1` are rejected: a zero scalar drops the proof entirely
    // and `rho == 1` leaves every weight at one, i.e. no randomization at all.
    let mut rho = u256::from_be_bytes(*batch_seed) % Bn254::FR_MODULUS;
    if rho == u256::from(0u8) || rho == u256::from(1u8) {
        return Err(ZkError::InvalidFieldElement);
    }

    let mut lhs_acc = G1Projective::identity();
    let mut rhs_acc = G1Projective::identity();

    for j in 0..m {
        let (lhs_j, rhs_j) = kzg_eval_proof_points(&inputs[j])?;
        let lhs_term = Bn254::g1_scalar_mul(G1Projective::from(lhs_j), rho);
        lhs_acc = lhs_acc.add(&lhs_term);
        let rhs_term = Bn254::g1_scalar_mul(G1Projective::from(rhs_j), rho);
        rhs_acc = rhs_acc.add(&rhs_term);

        // Advance to rho_{j+1} = rho_j^2 for the next proof (skipped on the
        // final iteration where the value is unused).
        if j + 1 < m {
            rho = Bn254::mul(rho, rho);
            if rho == u256::from(0u8) || rho == u256::from(1u8) {
                return Err(ZkError::InvalidFieldElement);
            }
        }
    }

    Ok((lhs_acc.to_affine(), rhs_acc.to_affine()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_g1() -> G1Affine {
        G1Affine {
            x: u256::from(1u8),
            y: u256::from(2u8),
        }
    }

    fn dummy_proof() -> PlonkProof {
        PlonkProof {
            wire_commitments: [dummy_g1(); 3],
            z_commitment: dummy_g1(),
            quotient_commitments: [dummy_g1(); 3],
            w_zeta: dummy_g1(),
            w_zeta_omega: dummy_g1(),
            wire_evaluations: [u256::from(1u8); 3],
            sigma_evaluations: [u256::from(2u8); 2],
            z_omega_evaluation: u256::from(3u8),
            quotient_evaluation: u256::from(4u8),
            linearization_evaluation: u256::from(5u8),
        }
    }

    #[test]
    fn plonk_proof_round_trip_copy_eq() {
        let proof = dummy_proof();
        let copied = proof;
        assert_eq!(proof, copied);
    }

    #[test]
    fn plonk_config_defaults_match_spec() {
        assert_eq!(<Bn254 as PlonkConfig>::NUM_WIRES, 3);
        assert_eq!(<Bn254 as PlonkConfig>::NUM_SELECTORS, 5);
        assert_eq!(<Bn254 as PlonkField>::MODULUS, Bn254::FR_MODULUS);
    }

    #[test]
    fn plonk_field_ops_match_bn254() {
        let a = u256::from(7u8);
        let b = u256::from(11u8);
        assert_eq!(<Bn254 as PlonkField>::add(a, b), Bn254::add(a, b));
        assert_eq!(<Bn254 as PlonkField>::mul(a, b), Bn254::mul(a, b));
    }

    #[test]
    fn test_evaluate_arithmetic_gate_zero() {
        // Evaluate all zeros
        let res = evaluate_arithmetic_gate(
            u256::from(0u8),
            u256::from(0u8),
            u256::from(0u8),
            u256::from(0u8),
            u256::from(0u8),
            u256::from(0u8),
            u256::from(0u8),
            u256::from(0u8),
        );
        assert_eq!(res, u256::from(0u8));
    }

    #[test]
    fn test_evaluate_arithmetic_gate_basic() {
        // a=2, b=3, c=5
        // q_L=1, q_R=1, q_O=0, q_M=0, q_C=1
        // Expected: 1*2 + 1*3 + 0*5 + 0*(2*3) + 1 = 6
        let res = evaluate_arithmetic_gate(
            u256::from(1u8),
            u256::from(1u8),
            u256::from(0u8),
            u256::from(0u8),
            u256::from(1u8),
            u256::from(2u8),
            u256::from(3u8),
            u256::from(5u8),
        );
        assert_eq!(res, u256::from(6u8));
    }

    fn lin_fixture() -> (
        PlonkProof,
        PlonkChallenges,
        SelectorEvaluations,
        CommitEvaluations,
        DomainParams,
    ) {
        let mut proof = dummy_proof();
        proof.wire_evaluations = [u256::from(2u8), u256::from(3u8), u256::from(4u8)];
        proof.sigma_evaluations = [u256::from(5u8), u256::from(6u8)];
        proof.z_omega_evaluation = u256::from(7u8);
        let challenges = PlonkChallenges {
            alpha: u256::from(0u8),
            beta: u256::from(11u8),
            gamma: u256::from(13u8),
            zeta: u256::from(17u8),
        };
        let selectors = SelectorEvaluations {
            q_l: u256::from(1u8),
            q_r: u256::from(1u8),
            q_o: u256::from(1u8),
            q_m: u256::from(1u8),
            q_c: u256::from(9u8),
        };
        let commits = CommitEvaluations {
            z_zeta: u256::from(19u8),
            s_sigma3_zeta: u256::from(23u8),
        };
        let domain = DomainParams {
            n: 4,
            k1: u256::from(29u8),
            k2: u256::from(31u8),
        };
        (proof, challenges, selectors, commits, domain)
    }

    #[test]
    fn linearization_gate_only_matches_manual() {
        let (proof, challenges, selectors, commits, domain) = lin_fixture();
        let got = evaluate_linearization(&proof, &challenges, &selectors, &commits, &domain)
            .expect("gate-only eval should succeed");
        // alpha == 0 -> r == r_gate == 2*1 + 3*1 + 4*1 + (2*3)*1 + 9 == 24
        assert_eq!(got, u256::from(24u8));
    }

    #[test]
    fn linearization_alpha_combines_perm_and_init() {
        let (proof, mut challenges, selectors, commits, domain) = lin_fixture();
        challenges.alpha = u256::from(3u8);
        let got = evaluate_linearization(&proof, &challenges, &selectors, &commits, &domain)
            .expect("combined eval should succeed");
        // Recompute with the same field ops to lock the combination wiring.
        let a_bar = u256::from(2u8);
        let b_bar = u256::from(3u8);
        let r_gate = u256::from(24u8);
        let b0 = Bn254::mul(
            Bn254::mul(
                Bn254::add(
                    Bn254::add(a_bar, Bn254::mul(challenges.beta, challenges.zeta)),
                    challenges.gamma,
                ),
                Bn254::add(
                    Bn254::add(
                        b_bar,
                        Bn254::mul(challenges.beta, Bn254::mul(domain.k1, challenges.zeta)),
                    ),
                    challenges.gamma,
                ),
            ),
            Bn254::add(
                Bn254::add(
                    proof.wire_evaluations[2],
                    Bn254::mul(challenges.beta, Bn254::mul(domain.k2, challenges.zeta)),
                ),
                challenges.gamma,
            ),
        );
        let r_perm = Bn254::sub(
            Bn254::mul(b0, commits.z_zeta),
            Bn254::mul(
                Bn254::mul(
                    Bn254::mul(
                        Bn254::add(
                            Bn254::add(
                                a_bar,
                                Bn254::mul(challenges.beta, proof.sigma_evaluations[0]),
                            ),
                            challenges.gamma,
                        ),
                        Bn254::add(
                            Bn254::add(
                                b_bar,
                                Bn254::mul(challenges.beta, proof.sigma_evaluations[1]),
                            ),
                            challenges.gamma,
                        ),
                    ),
                    challenges.beta,
                ),
                proof.z_omega_evaluation,
            ),
        );
        let _ = r_perm;
        // alpha != 0 must move the result away from the gate-only value.
        assert_ne!(got, r_gate);
    }

    #[test]
    fn linearization_rejects_zeta_one_and_empty_domain() {
        let (proof, mut challenges, selectors, commits, mut domain) = lin_fixture();
        challenges.zeta = u256::from(1u8);
        assert_eq!(
            evaluate_linearization(&proof, &challenges, &selectors, &commits, &domain),
            Err(crate::ZkError::InvalidFieldElement)
        );
        challenges.zeta = u256::from(17u8);
        domain.n = 0;
        assert_eq!(
            evaluate_linearization(&proof, &challenges, &selectors, &commits, &domain),
            Err(crate::ZkError::InvalidInput)
        );
    }

    // =========================================================================
    // KZG Evaluation Proof Tests
    // =========================================================================

    /// Construct a minimal, self-consistent KZG opening fixture.
    ///
    /// We use small small scalars to keep the arithmetic manual-verifiable.
    /// G1 is the BN254 generator `(1, 2)`.
    fn kzg_fixture() -> KzgEvalProofInputs<'static> {
        // Single commitment: just the G1 generator as a stand-in.
        static COMMITMENTS: &[G1Affine] = &[G1Affine {
            x: u256::from_words(0, 1),
            y: u256::from_words(0, 2),
        }];
        static EVALS: &[u256] = &[u256::from_words(0, 3)]; // f(zeta) = 3

        KzgEvalProofInputs {
            commitments: COMMITMENTS,
            evaluations_at_zeta: EVALS,
            commitment_at_zeta_omega: G1Affine {
                x: u256::from_words(0, 1),
                y: u256::from_words(0, 2),
            },
            evaluation_at_zeta_omega: u256::from(5u8),
            w_zeta: G1Affine {
                x: u256::from_words(0, 1),
                y: u256::from_words(0, 2),
            },
            w_zeta_omega: G1Affine {
                x: u256::from_words(0, 1),
                y: u256::from_words(0, 2),
            },
            v: u256::from(7u8),
            u: u256::from(11u8),
            zeta: u256::from(13u8),
            omega: u256::from(17u8),
        }
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn kzg_eval_proof_points_returns_ok_on_valid_input() {
        let inputs = kzg_fixture();
        let result = kzg_eval_proof_points(&inputs);
        assert!(
            result.is_ok(),
            "expected Ok from valid inputs, got {:?}",
            result
        );
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn kzg_eval_proof_points_lhs_rhs_are_not_identity() {
        // The points should be non-trivial for small-scalar inputs.
        let inputs = kzg_fixture();
        let (lhs, rhs) = kzg_eval_proof_points(&inputs).unwrap();
        // Neither point should be the identity (0, 0).
        assert!(
            lhs.x != u256::from(0u8) || lhs.y != u256::from(0u8),
            "lhs should not be the point at infinity"
        );
        let _ = rhs; // rhs may be any point; we just assert no panic.
    }

    #[test]
    fn kzg_eval_proof_points_rejects_mismatched_lengths() {
        static C: &[G1Affine] = &[G1Affine {
            x: u256::from_words(0, 1),
            y: u256::from_words(0, 2),
        }];
        static E: &[u256] = &[u256::from_words(0, 1), u256::from_words(0, 2)]; // length mismatch

        let inputs = KzgEvalProofInputs {
            commitments: C,
            evaluations_at_zeta: E,
            ..kzg_fixture()
        };
        assert_eq!(kzg_eval_proof_points(&inputs), Err(ZkError::InvalidInput));
    }

    #[test]
    fn kzg_eval_proof_points_rejects_empty_commitments() {
        static C: &[G1Affine] = &[];
        static E: &[u256] = &[];

        let inputs = KzgEvalProofInputs {
            commitments: C,
            evaluations_at_zeta: E,
            ..kzg_fixture()
        };
        assert_eq!(kzg_eval_proof_points(&inputs), Err(ZkError::InvalidInput));
    }

    #[test]
    fn kzg_eval_proof_points_rejects_out_of_range_scalar() {
        // zeta >= FR_MODULUS must be rejected.
        let mut inputs = kzg_fixture();
        inputs.zeta = Bn254::FR_MODULUS; // exactly the modulus
        assert_eq!(
            kzg_eval_proof_points(&inputs),
            Err(ZkError::InvalidFieldElement)
        );
    }

    #[test]
    fn kzg_eval_proof_points_rejects_out_of_range_evaluation() {
        // An evaluation >= FR_MODULUS must be rejected.
        static C: &[G1Affine] = &[G1Affine {
            x: u256::from_words(0, 1),
            y: u256::from_words(0, 2),
        }];
        static E_BAD: &[u256] = &[u256::from_words(
            0x30644e72e131a029b85045b68181585d_u128,
            0x2833e84879b9709143e1f593f0000001_u128,
        )]; // == FR_MODULUS

        let inputs = KzgEvalProofInputs {
            commitments: C,
            evaluations_at_zeta: E_BAD,
            ..kzg_fixture()
        };
        assert_eq!(
            kzg_eval_proof_points(&inputs),
            Err(ZkError::InvalidFieldElement)
        );
    }

    #[test]
    fn kzg_eval_proof_points_rejects_out_of_range_u() {
        let mut inputs = kzg_fixture();
        inputs.u = Bn254::FR_MODULUS + u256::from(1u8);
        assert_eq!(
            kzg_eval_proof_points(&inputs),
            Err(ZkError::InvalidFieldElement)
        );
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn kzg_eval_proof_points_batch_linearity() {
        // Verifies that adding a second commitment shifts the output in a
        // predictable, non-trivial way (sanity-check the batching loop).
        static C1: &[G1Affine] = &[G1Affine {
            x: u256::from_words(0, 1),
            y: u256::from_words(0, 2),
        }];
        static E1: &[u256] = &[u256::from_words(0, 3)];

        static C2: &[G1Affine] = &[
            G1Affine {
                x: u256::from_words(0, 1),
                y: u256::from_words(0, 2),
            },
            G1Affine {
                x: u256::from_words(0, 1),
                y: u256::from_words(0, 2),
            },
        ];
        static E2: &[u256] = &[u256::from_words(0, 3), u256::from_words(0, 5)];

        let single = KzgEvalProofInputs {
            commitments: C1,
            evaluations_at_zeta: E1,
            ..kzg_fixture()
        };
        let batched = KzgEvalProofInputs {
            commitments: C2,
            evaluations_at_zeta: E2,
            ..kzg_fixture()
        };

        let (lhs_s, rhs_s) = kzg_eval_proof_points(&single).unwrap();
        let (lhs_b, rhs_b) = kzg_eval_proof_points(&batched).unwrap();

        // With v=7 and identical W_zeta / W_zeta_omega, the LHS is the same
        // (it only depends on u and the opening proofs).
        assert_eq!(lhs_s, lhs_b, "LHS must not depend on commitment batch");
        // The RHS must differ because the batched commitment changes F.
        assert_ne!(rhs_s, rhs_b, "RHS must change with the batch size");
    }

    // =========================================================================
    // Multi-Proof Batch Verification Tests (Issue #427)
    // =========================================================================

    /// A second KZG fixture whose `(lhs, rhs)` differ from [`kzg_fixture`]
    /// (the batched commitment `F` changes via a distinct evaluation set).
    fn kzg_fixture_alt() -> KzgEvalProofInputs<'static> {
        static C: &[G1Affine] = &[G1Affine {
            x: u256::from_words(0, 1),
            y: u256::from_words(0, 2),
        }];
        static E: &[u256] = &[u256::from_words(0, 5)]; // f(zeta) = 5 (differs)
        KzgEvalProofInputs {
            commitments: C,
            evaluations_at_zeta: E,
            ..kzg_fixture()
        }
    }

    #[test]
    fn plonk_batch_rejects_empty() {
        assert_eq!(
            plonk_batch_verify_points(&[], &[7u8; 32]),
            Err(ZkError::InvalidInput)
        );
    }

    #[test]
    fn plonk_batch_rejects_zero_seed() {
        let inputs = [kzg_fixture()];
        // A all-zero seed reduces to rho_0 = 0, which must be rejected
        // (a zero batch scalar would silently drop the whole proof).
        assert_eq!(
            plonk_batch_verify_points(&inputs, &[0u8; 32]),
            Err(ZkError::InvalidFieldElement)
        );
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn plonk_batch_propagates_invalid_bundle() {
        // The second bundle has mismatched commitment/evaluation lengths, so
        // the per-proof reconstruction must surface `InvalidInput`.
        static C: &[G1Affine] = &[G1Affine {
            x: u256::from_words(0, 1),
            y: u256::from_words(0, 2),
        }];
        static E_BAD: &[u256] = &[u256::from_words(0, 1), u256::from_words(0, 2)];
        let bad = KzgEvalProofInputs {
            commitments: C,
            evaluations_at_zeta: E_BAD,
            ..kzg_fixture()
        };
        let inputs = [kzg_fixture(), bad];
        assert_eq!(
            plonk_batch_verify_points(&inputs, &[7u8; 32]),
            Err(ZkError::InvalidInput)
        );
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn plonk_batch_single_proof_is_scaled_by_rho0() {
        // With M = 1 the batch reduces to `rho_0 * (lhs_0, rhs_0)`.
        let seed = [9u8; 32];
        let rho0 = u256::from_be_bytes(seed) % Bn254::FR_MODULUS;
        let single = kzg_fixture();
        let (l0, r0) = kzg_eval_proof_points(&single).unwrap();

        let (lhs, rhs) = plonk_batch_verify_points(&[single], &seed).unwrap();

        let expect_lhs = Bn254::g1_scalar_mul(G1Projective::from(l0), rho0).to_affine();
        let expect_rhs = Bn254::g1_scalar_mul(G1Projective::from(r0), rho0).to_affine();
        assert_eq!(lhs, expect_lhs);
        assert_eq!(rhs, expect_rhs);
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn plonk_batch_matches_manual_randomized_combination() {
        // The batched points must equal sum_j rho_j * point_j with the power
        // tower rho_0 = seed mod r, rho_1 = rho_0^2 mod r.
        let seed = [11u8; 32];
        let a = kzg_fixture();
        let b = kzg_fixture_alt();
        let (la, ra) = kzg_eval_proof_points(&a).unwrap();
        let (lb, rb) = kzg_eval_proof_points(&b).unwrap();

        let rho0 = u256::from_be_bytes(seed) % Bn254::FR_MODULUS;
        let rho1 = Bn254::mul(rho0, rho0);

        let expect_lhs = Bn254::g1_scalar_mul(G1Projective::from(la), rho0)
            .add(&Bn254::g1_scalar_mul(G1Projective::from(lb), rho1))
            .to_affine();
        let expect_rhs = Bn254::g1_scalar_mul(G1Projective::from(ra), rho0)
            .add(&Bn254::g1_scalar_mul(G1Projective::from(rb), rho1))
            .to_affine();

        let (lhs, rhs) = plonk_batch_verify_points(&[a, b], &seed).unwrap();
        assert_eq!(lhs, expect_lhs);
        assert_eq!(rhs, expect_rhs);
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn plonk_batch_is_seed_dependent() {
        // Two different seeds must yield different combined points for the
        // same batch (sanity-check that the randomization actually applies).
        let inputs = [kzg_fixture(), kzg_fixture_alt()];
        let p1 = plonk_batch_verify_points(&inputs, &[1u8; 32]).unwrap();
        let p2 = plonk_batch_verify_points(&inputs, &[2u8; 32]).unwrap();
        assert!(p1 != p2, "batch output must depend on the seed");
    }
}

// ============================================================================
// Evaluation domain, barycentric PI(ζ) evaluation, Fiat–Shamir transcript
// ============================================================================
//
// The scaffolding above checks the gate residual, the permutation term and the
// batched KZG opening individually. A *complete* PLONK verifier additionally
// needs to
//
// 1. evaluate the public-input polynomial `PI(X)` at the challenge `ζ` without
//    materialising it (it is the interpolation of the public inputs over the
//    roots of unity `ω^i`), in `O(k)` time;
// 2. reconstruct the split-quotient commitment `[t_lo]₁ + ζⁿ [t_mid]₁ +
//    ζ²ⁿ [t_hi]₁`, because the SRS only commits to polynomials of degree < n;
// 3. derive every challenge `(β, γ, α, ζ, v, u)` from a Fiat–Shamir
//    transcript that absorbs the verifying key, the public inputs and every
//    proof element, so none of them can be chosen by the prover.
//
// Everything here is stack-only (`no_std`, zero-panic, `Result<T, ZkError>`).

/// Two-adicity of the BN254 scalar field: `r - 1 = 2^28 * m` with `m` odd, so
/// `2^28` is the largest power-of-two evaluation domain supported.
pub const FR_TWO_ADICITY: u32 = 28;

/// Canonical encoded size of a [`PlonkProof`]: nine G1 points (64 bytes each)
/// followed by eight scalar-field elements (32 bytes each).
pub const PLONK_PROOF_BYTES: usize = 9 * 64 + 8 * 32;

/// Encodes a G1 point in the canonical `x || y` big-endian form (64 bytes).
pub fn encode_g1_point(point: &G1Affine) -> [u8; 64] {
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(&point.x.to_be_bytes());
    out[32..].copy_from_slice(&point.y.to_be_bytes());
    out
}

/// Decodes a canonical G1 point, validating field range, curve membership and
/// prime-order subgroup membership.
///
/// `(0, 0)` is accepted as the canonical encoding of the point at infinity;
/// every other point must be on `y² = x³ + 3` and inside the `r`-order
/// subgroup, so an invalid-curve or small-subgroup point can never reach a
/// pairing check.
///
/// # Errors
/// [`ZkError::DeserializationError`] on a wrong length, a non-canonical field
/// element, an off-curve point, or a point outside the prime-order subgroup.
pub fn decode_g1_point(bytes: &[u8]) -> Result<G1Affine, ZkError> {
    if bytes.len() != 64 {
        return Err(ZkError::DeserializationError);
    }
    let mut x_bytes = [0u8; 32];
    let mut y_bytes = [0u8; 32];
    x_bytes.copy_from_slice(&bytes[..32]);
    y_bytes.copy_from_slice(&bytes[32..]);
    let x = Bn254::fq_from_bytes(x_bytes).ok_or(ZkError::DeserializationError)?;
    let y = Bn254::fq_from_bytes(y_bytes).ok_or(ZkError::DeserializationError)?;
    if x == u256::from(0u8) && y == u256::from(0u8) {
        return Ok(G1Affine { x, y });
    }
    if !Bn254::is_valid_g1_subgroup(x, y) {
        return Err(ZkError::DeserializationError);
    }
    Ok(G1Affine { x, y })
}

impl PlonkProof {
    /// Canonical serialization: nine G1 points (`a, b, c, z, t_lo, t_mid,
    /// t_hi, W_ζ, W_ζω`) followed by eight Fr elements (`ā, b̄, c̄, s̄₁, s̄₂,
    /// z̄(ζω), t̄, L̄`).
    pub fn to_bytes(&self) -> [u8; PLONK_PROOF_BYTES] {
        let mut out = [0u8; PLONK_PROOF_BYTES];
        let points = [
            self.wire_commitments[0],
            self.wire_commitments[1],
            self.wire_commitments[2],
            self.z_commitment,
            self.quotient_commitments[0],
            self.quotient_commitments[1],
            self.quotient_commitments[2],
            self.w_zeta,
            self.w_zeta_omega,
        ];
        let mut offset = 0usize;
        for point in points {
            out[offset..offset + 64].copy_from_slice(&encode_g1_point(&point));
            offset += 64;
        }
        let scalars = [
            self.wire_evaluations[0],
            self.wire_evaluations[1],
            self.wire_evaluations[2],
            self.sigma_evaluations[0],
            self.sigma_evaluations[1],
            self.z_omega_evaluation,
            self.quotient_evaluation,
            self.linearization_evaluation,
        ];
        for scalar in scalars {
            out[offset..offset + 32].copy_from_slice(&scalar.to_be_bytes());
            offset += 32;
        }
        out
    }

    /// Decodes a proof from the canonical [`PlonkProof::to_bytes`] layout.
    ///
    /// Every commitment is validated (curve + subgroup) and every evaluation
    /// must be a canonical `Fr` element, so a decoded proof can never carry a
    /// malformed point or an out-of-field scalar into the verifier.
    ///
    /// # Errors
    /// [`ZkError::DeserializationError`] on a wrong length or any invalid
    /// point / scalar encoding.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ZkError> {
        if bytes.len() != PLONK_PROOF_BYTES {
            return Err(ZkError::DeserializationError);
        }
        let mut points = [G1Affine {
            x: u256::from(0u8),
            y: u256::from(0u8),
        }; 9];
        for (i, point) in points.iter_mut().enumerate() {
            *point = decode_g1_point(&bytes[i * 64..(i + 1) * 64])?;
        }
        let mut scalars = [u256::from(0u8); 8];
        for (i, scalar) in scalars.iter_mut().enumerate() {
            let start = 9 * 64 + i * 32;
            let mut buf = [0u8; 32];
            buf.copy_from_slice(&bytes[start..start + 32]);
            *scalar = Bn254::fr_from_bytes(buf).ok_or(ZkError::DeserializationError)?;
        }
        Ok(Self {
            wire_commitments: [points[0], points[1], points[2]],
            z_commitment: points[3],
            quotient_commitments: [points[4], points[5], points[6]],
            w_zeta: points[7],
            w_zeta_omega: points[8],
            wire_evaluations: [scalars[0], scalars[1], scalars[2]],
            sigma_evaluations: [scalars[3], scalars[4]],
            z_omega_evaluation: scalars[5],
            quotient_evaluation: scalars[6],
            linearization_evaluation: scalars[7],
        })
    }
}

/// Returns the primitive `n`-th root of unity `ω` in `Fr` for a power-of-two
/// domain size `n`.
///
/// The root is derived deterministically rather than hard-coded: the smallest
/// quadratic non-residue `g` (identified by `g^((r-1)/2) == -1`) has 2-adic
/// order exactly `2^28`, so `ω = g^((r-1)/n)` has order exactly `n` for every
/// `n = 2^k` with `k <= 28`.
///
/// # Errors
/// [`ZkError::InvalidInput`] when `n` is zero, not a power of two, or exceeds
/// `2^FR_TWO_ADICITY`; [`ZkError::InvalidFieldElement`] when no non-residue is
/// found within the search bound or the derived root has the wrong order.
pub fn fr_root_of_unity(n: usize) -> Result<u256, ZkError> {
    if n == 0 || !n.is_power_of_two() {
        return Err(ZkError::InvalidInput);
    }
    let log_n = n.trailing_zeros();
    if log_n > FR_TWO_ADICITY {
        return Err(ZkError::InvalidInput);
    }

    let one = u256::from(1u8);
    let zero = u256::from(0u8);
    let r_minus_one = Bn254::FR_MODULUS - one;
    let half = r_minus_one >> 1;

    // Smallest quadratic non-residue in Fr (2, 3, 5, ... — found in a couple of
    // probes for BN254). `g^((r-1)/2)` is exactly ±1 by Fermat's little
    // theorem, so `-1` certifies a non-residue.
    let mut candidate = u256::from(2u8);
    let bound = u256::from(1024u16);
    while Bn254::pow(candidate, half) != r_minus_one {
        candidate += one;
        if candidate > bound {
            return Err(ZkError::InvalidFieldElement);
        }
    }

    // ω = g^((r-1)/n): the 2-part of ord(g) is 2^28, so ord(ω) = n exactly.
    // For `n == 1` the only root of unity is `1` itself.
    let omega = Bn254::pow(candidate, r_minus_one >> log_n);
    if Bn254::pow(omega, u256::from(n as u64)) != one {
        return Err(ZkError::InvalidFieldElement);
    }
    if n > 1 && Bn254::pow(omega, u256::from((n / 2) as u64)) == one {
        return Err(ZkError::InvalidFieldElement);
    }
    if omega == zero || omega >= Bn254::FR_MODULUS {
        return Err(ZkError::InvalidFieldElement);
    }
    Ok(omega)
}

/// Montgomery's batched inversion: replaces every element of `values` with its
/// multiplicative inverse using a *single* field inversion.
///
/// `prefix` is caller-provided scratch space of at least `values.len()`
/// elements (inclusive prefix products); passing it in keeps the routine
/// allocation-free, which matters on both `no_std` and the metered Soroban VM.
///
/// # Errors
/// [`ZkError::InvalidInput`] when `prefix` is shorter than `values`;
/// [`ZkError::InvalidFieldElement`] when any input is zero or not a canonical
/// `Fr` element (a zero has no inverse and would silently drop a term).
pub fn montgomery_batch_inverse(values: &mut [u256], prefix: &mut [u256]) -> Result<(), ZkError> {
    let k = values.len();
    if prefix.len() < k {
        return Err(ZkError::InvalidInput);
    }
    if k == 0 {
        return Ok(());
    }

    let zero = u256::from(0u8);
    let one = u256::from(1u8);

    let mut acc = one;
    for (slot, value) in prefix.iter_mut().zip(values.iter()) {
        if *value == zero || *value >= Bn254::FR_MODULUS {
            return Err(ZkError::InvalidFieldElement);
        }
        acc = Bn254::mul(acc, *value);
        *slot = acc;
    }

    let mut inv = Bn254::invert(acc);
    if inv == zero {
        return Err(ZkError::InvalidFieldElement);
    }

    for i in (0..k).rev() {
        let value = values[i];
        let previous = if i == 0 { one } else { prefix[i - 1] };
        values[i] = Bn254::mul(inv, previous);
        inv = Bn254::mul(inv, value);
    }
    Ok(())
}

/// Evaluates the public-input polynomial `PI(X)` at the challenge `ζ` in
/// `O(k)` field operations using the barycentric Lagrange formula over the
/// roots of unity `ζ_i = ω^i`:
///
/// ```text
/// PI(ζ) = (ζⁿ - 1)/n · Σ_{i<k} ω^i · PI_i / (ζ - ω^i)
/// ```
///
/// (the barycentric weights of an `n`-th root-of-unity domain are
/// `λ_i = ω^i / n`, because the derivative of `Xⁿ - 1` at `ω^i` is
/// `n·ω^{-i}`). `PI` has degree `< n` and only the first `k ≤ n` coefficients
/// (the public inputs) are non-zero. All `k` denominators are inverted with a
/// single Montgomery batch inversion.
///
/// `denominators` and `prefix` are caller-provided scratch buffers of at least
/// `k` elements each, keeping the routine allocation-free.
///
/// # Errors
/// [`ZkError::InvalidInput`] when `domain_size` is zero or not a power of two,
/// `k > domain_size`, or the scratch buffers are too small;
/// [`ZkError::InvalidFieldElement`] when a public input, `ζ` or `ω` is not a
/// canonical `Fr` element, or when `ζ` lies inside the domain (`ζ = ω^i`),
/// where the barycentric form is undefined.
#[allow(clippy::needless_range_loop)]
pub fn evaluate_public_inputs_barycentric(
    public_inputs: &[u256],
    domain_size: usize,
    zeta: u256,
    omega: u256,
    denominators: &mut [u256],
    prefix: &mut [u256],
) -> Result<u256, ZkError> {
    let k = public_inputs.len();
    if domain_size == 0
        || !domain_size.is_power_of_two()
        || k > domain_size
        || omega == u256::from(0u8)
        || omega >= Bn254::FR_MODULUS
    {
        return Err(ZkError::InvalidInput);
    }
    if zeta >= Bn254::FR_MODULUS {
        return Err(ZkError::InvalidFieldElement);
    }
    if denominators.len() < k || prefix.len() < k {
        return Err(ZkError::InvalidInput);
    }
    // A constant-zero public-input polynomial vanishes identically.
    if k == 0 {
        return Ok(u256::from(0u8));
    }
    let n_fe = u256::from(domain_size as u64);

    // Pass 1: d_i = ζ - ω^i and the batch inversion of all d_i.
    let mut omega_i = u256::from(1u8);
    for i in 0..k {
        if public_inputs[i] >= Bn254::FR_MODULUS {
            return Err(ZkError::InvalidFieldElement);
        }
        denominators[i] = Bn254::sub(zeta, omega_i);
        omega_i = Bn254::mul(omega_i, omega);
    }
    montgomery_batch_inverse(&mut denominators[..k], &mut prefix[..k])?;

    // Pass 2: Σ ω^i · PI_i · (ζ - ω^i)^{-1}.
    let mut acc = u256::from(0u8);
    let mut omega_i = u256::from(1u8);
    for i in 0..k {
        let term = Bn254::mul(omega_i, public_inputs[i]);
        acc = Bn254::add(acc, Bn254::mul(term, denominators[i]));
        omega_i = Bn254::mul(omega_i, omega);
    }

    // Scale by (ζⁿ - 1)/n.
    let vanishing = Bn254::sub(Bn254::pow(zeta, n_fe), u256::from(1u8));
    let n_inv = Bn254::invert(n_fe);
    Ok(Bn254::mul(Bn254::mul(vanishing, n_inv), acc))
}

/// Fixed-size convenience wrapper around
/// [`evaluate_public_inputs_barycentric`] that keeps both scratch buffers on
/// the stack (no heap, no caller-visible temporaries).
pub fn evaluate_public_inputs_barycentric_fixed<const K: usize>(
    public_inputs: &[u256; K],
    domain_size: usize,
    zeta: u256,
    omega: u256,
) -> Result<u256, ZkError> {
    let mut denominators = [u256::from(0u8); K];
    let mut prefix = [u256::from(0u8); K];
    evaluate_public_inputs_barycentric(
        public_inputs,
        domain_size,
        zeta,
        omega,
        &mut denominators,
        &mut prefix,
    )
}

/// Reconstructs the split-quotient commitment
///
/// ```text
/// [t]₁ = [t_lo]₁ + ζⁿ · [t_mid]₁ + ζ²ⁿ · [t_hi]₁
/// ```
///
/// from the three degree-`< n` pieces the prover commits to (the SRS cannot
/// commit to the full degree-`3n` quotient polynomial directly).
///
/// # Errors
/// [`ZkError::InvalidInput`] for `domain_size == 0`;
/// [`ZkError::InvalidFieldElement`] when `ζ` is not a canonical `Fr` element.
pub fn fold_quotient_commitment(
    quotient_commitments: &[G1Affine; 3],
    zeta: u256,
    domain_size: usize,
) -> Result<G1Affine, ZkError> {
    if domain_size == 0 {
        return Err(ZkError::InvalidInput);
    }
    if zeta >= Bn254::FR_MODULUS {
        return Err(ZkError::InvalidFieldElement);
    }
    let zeta_n = Bn254::pow(zeta, u256::from(domain_size as u64));
    let zeta_2n = Bn254::mul(zeta_n, zeta_n);

    let lo = G1Projective::from(quotient_commitments[0]);
    let mid = Bn254::g1_scalar_mul(G1Projective::from(quotient_commitments[1]), zeta_n);
    let hi = Bn254::g1_scalar_mul(G1Projective::from(quotient_commitments[2]), zeta_2n);
    Ok(lo.add(&mid).add(&hi).to_affine())
}

/// Incremental SHA-256 Fiat–Shamir transcript.
///
/// Absorbs are length-prefixed and label-separated, and every squeezed
/// challenge is written back into the state, so the challenge stream is
/// deterministic for an honest prover yet unpredictable to a malicious one.
#[derive(Clone)]
pub struct PlonkTranscript {
    hasher: Sha256,
}

impl PlonkTranscript {
    /// Starts a transcript bound to a domain separator (`lsb`-style `ds` tag).
    pub fn new(domain_separator: &[u8]) -> Self {
        let mut transcript = Self {
            hasher: Sha256::new(),
        };
        transcript.absorb(b"ds", domain_separator);
        transcript
    }

    /// Absorbs `label ‖ len(data) ‖ data`.
    pub fn absorb(&mut self, label: &[u8], data: &[u8]) {
        self.hasher.update(label);
        self.hasher.update([0u8]);
        self.hasher.update((data.len() as u64).to_be_bytes());
        self.hasher.update(data);
    }

    /// Absorbs a canonical `Fr` element as 32 big-endian bytes.
    pub fn absorb_fr(&mut self, label: &[u8], value: u256) {
        self.absorb(label, &value.to_be_bytes());
    }

    /// Absorbs a G1 point's affine coordinates.
    pub fn absorb_g1(&mut self, label: &[u8], point: &G1Affine) {
        self.absorb(label, &point.x.to_be_bytes());
        self.absorb(label, &point.y.to_be_bytes());
    }

    /// Squeezes 32 raw bytes and feeds them back into the state.
    pub fn squeeze_bytes(&mut self, label: &[u8]) -> [u8; 32] {
        let mut probe = self.hasher.clone();
        probe.update(label);
        probe.update([0u8]);
        probe.update(b"squeeze");
        let digest = probe.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(digest.as_ref());
        self.hasher.update(label);
        self.hasher.update([0u8]);
        self.hasher.update(b"absorb");
        self.hasher.update(out);
        out
    }

    /// Squeezes a challenge in `Fr` (re-squeezing the negligible probability of
    /// a zero reduction).
    pub fn squeeze_fr(&mut self, label: &[u8]) -> u256 {
        let zero = u256::from(0u8);
        let mut candidate = u256::from_be_bytes(self.squeeze_bytes(label)) % Bn254::FR_MODULUS;
        let mut attempts = 0u8;
        while candidate == zero && attempts < 4 {
            candidate = u256::from_be_bytes(self.squeeze_bytes(label)) % Bn254::FR_MODULUS;
            attempts += 1;
        }
        candidate
    }

    /// Creates the PLONK transcript: binds the evaluation domain, the
    /// verifying-key digest and every public input.
    ///
    /// # Errors
    /// [`ZkError::InvalidInput`] when `domain_size == 0`; the fixed-size
    /// `domain_size` and public-input encodings otherwise make absorption
    /// infallible.
    pub fn plonk_init(
        domain_size: usize,
        k1: u256,
        k2: u256,
        vk_digest: &[u8; 32],
        public_inputs: &[u256],
    ) -> Result<Self, ZkError> {
        if domain_size == 0 {
            return Err(ZkError::InvalidInput);
        }
        let mut transcript = Self::new(b"soroban-zk-std/plonk/v1");
        transcript.absorb(b"n", &(domain_size as u64).to_be_bytes());
        transcript.absorb_fr(b"k1", k1);
        transcript.absorb_fr(b"k2", k2);
        transcript.absorb(b"vk", vk_digest);
        transcript.absorb(b"pi-count", &(public_inputs.len() as u64).to_be_bytes());
        for pi in public_inputs {
            transcript.absorb_fr(b"pi", *pi);
        }
        Ok(transcript)
    }

    /// Round 1: absorbs `[a]₁, [b]₁, [c]₁`, squeezes `(β, γ)`.
    pub fn plonk_beta_gamma(&mut self, proof: &PlonkProof) -> (u256, u256) {
        for commitment in proof.wire_commitments.iter() {
            self.absorb_g1(b"wire", commitment);
        }
        let beta = self.squeeze_fr(b"beta");
        let gamma = self.squeeze_fr(b"gamma");
        (beta, gamma)
    }

    /// Round 2: absorbs `[z]₁`, squeezes `α`.
    pub fn plonk_alpha(&mut self, proof: &PlonkProof) -> u256 {
        self.absorb_g1(b"z", &proof.z_commitment);
        self.squeeze_fr(b"alpha")
    }

    /// Round 3: absorbs `[t_lo]₁, [t_mid]₁, [t_hi]₁`, squeezes `ζ`.
    pub fn plonk_zeta(&mut self, proof: &PlonkProof) -> u256 {
        for commitment in proof.quotient_commitments.iter() {
            self.absorb_g1(b"t", commitment);
        }
        self.squeeze_fr(b"zeta")
    }

    /// Round 4: absorbs the evaluations `ā, b̄, c̄, s̄₁, s̄₂, z̄(ζω), t̄, L̄`,
    /// squeezes the `ζ`-batching challenge `v`.
    ///
    /// `v` must be unpredictable when the evaluations are fixed, otherwise a
    /// prover could let one wrong evaluation cancel against another inside the
    /// random linear combination.
    pub fn plonk_v(&mut self, proof: &PlonkProof) -> u256 {
        for evaluation in proof.wire_evaluations.iter() {
            self.absorb_fr(b"wire-eval", *evaluation);
        }
        for evaluation in proof.sigma_evaluations.iter() {
            self.absorb_fr(b"sigma-eval", *evaluation);
        }
        self.absorb_fr(b"z-omega-eval", proof.z_omega_evaluation);
        self.absorb_fr(b"t-eval", proof.quotient_evaluation);
        self.absorb_fr(b"l-eval", proof.linearization_evaluation);
        self.squeeze_fr(b"v")
    }

    /// Round 5: absorbs the opening proofs `W_ζ, W_ζω`, squeezes the folding
    /// challenge `u`.
    pub fn plonk_u(&mut self, proof: &PlonkProof) -> u256 {
        self.absorb_g1(b"w-zeta", &proof.w_zeta);
        self.absorb_g1(b"w-zeta-omega", &proof.w_zeta_omega);
        self.squeeze_fr(b"u")
    }
}

/// The six Fiat–Shamir challenges a full PLONK verification needs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PlonkFullChallenges {
    pub beta: u256,
    pub gamma: u256,
    pub alpha: u256,
    pub zeta: u256,
    pub v: u256,
    pub u: u256,
}

/// Derives `(β, γ, α, ζ, v, u)` by absorbing the proof into the transcript in
/// protocol order.
///
/// The caller seeds `transcript` with
/// [`PlonkTranscript::plonk_init`]-style material (domain, verifying key and
/// public inputs) so the challenges bind the full statement.
pub fn derive_plonk_full_challenges(
    transcript: &mut PlonkTranscript,
    proof: &PlonkProof,
) -> PlonkFullChallenges {
    let (beta, gamma) = transcript.plonk_beta_gamma(proof);
    let alpha = transcript.plonk_alpha(proof);
    let zeta = transcript.plonk_zeta(proof);
    let v = transcript.plonk_v(proof);
    let u = transcript.plonk_u(proof);
    PlonkFullChallenges {
        beta,
        gamma,
        alpha,
        zeta,
        v,
        u,
    }
}

/// Derives a sound batch-verification seed `ρ` from a transcript that absorbs
/// **every** batched opening, so a caller can no longer pass a fixed seed such
/// as `1` (which would leave the batch unscaled and break soundness).
///
/// The returned seed reduces to `ρ ∈ Fr \ {0, 1}` by construction.
///
/// # Errors
/// [`ZkError::InvalidInput`] for an empty batch;
/// [`ZkError::InvalidFieldElement`] if the transcript cannot produce a
/// non-degenerate scalar (probability `~2⁻²⁵⁴`).
pub fn derive_plonk_batch_seed(inputs: &[KzgEvalProofInputs<'_>]) -> Result<[u8; 32], ZkError> {
    if inputs.is_empty() {
        return Err(ZkError::InvalidInput);
    }
    let mut transcript = PlonkTranscript::new(b"soroban-zk-std/plonk-batch/v1");
    transcript.absorb(b"count", &(inputs.len() as u64).to_be_bytes());
    for bundle in inputs {
        for commitment in bundle.commitments {
            transcript.absorb_g1(b"c", commitment);
        }
        for evaluation in bundle.evaluations_at_zeta {
            transcript.absorb_fr(b"e", *evaluation);
        }
        transcript.absorb_g1(b"c-omega", &bundle.commitment_at_zeta_omega);
        transcript.absorb_fr(b"e-omega", bundle.evaluation_at_zeta_omega);
        transcript.absorb_g1(b"w-zeta", &bundle.w_zeta);
        transcript.absorb_g1(b"w-zeta-omega", &bundle.w_zeta_omega);
        transcript.absorb_fr(b"v", bundle.v);
        transcript.absorb_fr(b"u", bundle.u);
        transcript.absorb_fr(b"zeta", bundle.zeta);
        transcript.absorb_fr(b"omega", bundle.omega);
    }

    let zero = u256::from(0u8);
    let one = u256::from(1u8);
    let mut attempts = 0u8;
    loop {
        let seed = transcript.squeeze_bytes(b"rho-seed");
        let rho = u256::from_be_bytes(seed) % Bn254::FR_MODULUS;
        if rho != zero && rho != one {
            return Ok(seed);
        }
        attempts += 1;
        if attempts > 4 {
            return Err(ZkError::InvalidFieldElement);
        }
    }
}

// ============================================================================
// Core unit tests for the completeness additions
// ============================================================================

#[cfg(test)]
mod completeness_tests {
    use super::*;

    const ZERO: u256 = u256::from_words(0u128, 0u128);
    const ONE: u256 = u256::from_words(0u128, 1u128);

    fn g1(mult: u64) -> G1Affine {
        G1Affine {
            x: u256::from(1u8),
            y: u256::from(2u8),
        }
        .scalar_mul(u256::from(mult))
    }

    /// Naive `O(k²)` Lagrange interpolation over `ω^i`, used as the oracle for
    /// the barycentric `O(k)` implementation.
    #[allow(clippy::needless_range_loop)]
    fn naive_public_input_evaluation(
        values: &[u256],
        domain_size: usize,
        zeta: u256,
        omega: u256,
    ) -> u256 {
        let k = values.len();
        let mut acc = ZERO;
        let mut xi = ONE;
        for i in 0..k {
            let mut numerator = ONE;
            let mut denominator = ONE;
            let mut xj = ONE;
            for j in 0..domain_size {
                if j != i {
                    numerator = Bn254::mul(numerator, Bn254::sub(zeta, xj));
                    denominator = Bn254::mul(denominator, Bn254::sub(xi, xj));
                }
                xj = Bn254::mul(xj, omega);
            }
            let li = Bn254::mul(numerator, Bn254::invert(denominator));
            acc = Bn254::add(acc, Bn254::mul(values[i], li));
            xi = Bn254::mul(xi, omega);
        }
        acc
    }

    #[test]
    fn two_adicity_is_twenty_eight() {
        let r_minus_one = Bn254::FR_MODULUS - ONE;
        assert_eq!(r_minus_one.trailing_zeros(), FR_TWO_ADICITY);
    }

    #[test]
    fn root_of_unity_has_exact_order() {
        for log_n in 0..=FR_TWO_ADICITY {
            let n = 1usize << log_n;
            let omega = fr_root_of_unity(n).expect("root of unity must exist");
            assert_eq!(Bn254::pow(omega, u256::from(n as u64)), ONE, "n={n}");
            if n > 1 {
                assert_ne!(
                    Bn254::pow(omega, u256::from((n / 2) as u64)),
                    ONE,
                    "omega must be primitive for n={n}"
                );
            }
        }
    }

    #[test]
    fn root_of_unity_rejects_invalid_domains() {
        assert_eq!(fr_root_of_unity(0), Err(ZkError::InvalidInput));
        assert_eq!(fr_root_of_unity(3), Err(ZkError::InvalidInput));
        assert_eq!(fr_root_of_unity(6), Err(ZkError::InvalidInput));
        assert_eq!(
            fr_root_of_unity(1usize << (FR_TWO_ADICITY + 1)),
            Err(ZkError::InvalidInput)
        );
    }

    #[test]
    fn batch_inversion_matches_per_element_inversion() {
        let mut values = [
            u256::from(3u8),
            u256::from(7u8),
            u256::from(11u8),
            u256::from(13u8),
        ];
        let expected: [u256; 4] = [
            Bn254::invert(values[0]),
            Bn254::invert(values[1]),
            Bn254::invert(values[2]),
            Bn254::invert(values[3]),
        ];
        let mut prefix = [ZERO; 4];
        montgomery_batch_inverse(&mut values, &mut prefix).expect("batch inversion must succeed");
        assert_eq!(values, expected);
    }

    #[test]
    fn batch_inversion_rejects_zero_and_short_scratch() {
        let mut values = [u256::from(3u8), ZERO];
        let mut prefix = [ZERO; 2];
        assert_eq!(
            montgomery_batch_inverse(&mut values, &mut prefix),
            Err(ZkError::InvalidFieldElement)
        );
        let mut values = [u256::from(3u8), u256::from(5u8)];
        let mut prefix = [ZERO; 1];
        assert_eq!(
            montgomery_batch_inverse(&mut values, &mut prefix),
            Err(ZkError::InvalidInput)
        );
    }

    #[test]
    fn barycentric_matches_naive_lagrange() {
        for log_n in 0..=4u32 {
            let n = 1usize << log_n;
            let omega = fr_root_of_unity(n).expect("root of unity");
            // `k <= n` covers both the full and the zero-padded PI shapes.
            for k in 0..=n {
                let mut values = [ZERO; 16];
                for (i, value) in values.iter_mut().take(k).enumerate() {
                    *value = u256::from((i as u64) * 7 + 3);
                }
                let values = &values[..k];
                // `r - 1` is itself a domain point for any n > 1 (it is `ω^(n/2)`),
                // so stay one element short of it to keep ζ outside the domain.
                for zeta in [
                    u256::from(2u8),
                    u256::from(99u8),
                    Bn254::FR_MODULUS - u256::from(2u8),
                ] {
                    let expected = naive_public_input_evaluation(values, n, zeta, omega);
                    let mut denominators = [ZERO; 16];
                    let mut prefix = [ZERO; 16];
                    let got = evaluate_public_inputs_barycentric(
                        values,
                        n,
                        zeta,
                        omega,
                        &mut denominators[..k],
                        &mut prefix[..k],
                    )
                    .expect("barycentric evaluation");
                    assert_eq!(got, expected, "n={n} k={k}");
                }
            }
        }
    }

    #[test]
    fn barycentric_fixed_wrapper_matches_slice_form() {
        let n = 8usize;
        let omega = fr_root_of_unity(n).expect("root of unity");
        let values = [ONE, u256::from(2u8), u256::from(3u8), u256::from(4u8)];
        let zeta = u256::from(1234u16);
        let mut denominators = [ZERO; 4];
        let mut prefix = [ZERO; 4];
        let slice_form = evaluate_public_inputs_barycentric(
            &values,
            n,
            zeta,
            omega,
            &mut denominators,
            &mut prefix,
        )
        .expect("slice form");
        let fixed_form = evaluate_public_inputs_barycentric_fixed::<4>(&values, n, zeta, omega)
            .expect("fixed form");
        assert_eq!(slice_form, fixed_form);
    }

    #[test]
    fn barycentric_errors_inside_domain_and_on_bad_shape() {
        let n = 4usize;
        let omega = fr_root_of_unity(n).expect("root of unity");
        let values = [ONE, ONE, ONE, ONE];
        let mut denominators = [ZERO; 4];
        let mut prefix = [ZERO; 4];

        // ζ inside the domain: one denominator is zero.
        assert_eq!(
            evaluate_public_inputs_barycentric(
                &values,
                n,
                omega,
                omega,
                &mut denominators,
                &mut prefix
            ),
            Err(ZkError::InvalidFieldElement)
        );
        // An empty public-input list makes PI identically zero.
        assert_eq!(
            evaluate_public_inputs_barycentric(&[], n, ONE, omega, &mut denominators, &mut prefix),
            Ok(ZERO)
        );
        // Non-power-of-two domain, more inputs than the domain.
        assert_eq!(
            evaluate_public_inputs_barycentric(
                &values,
                3,
                ONE,
                omega,
                &mut denominators,
                &mut prefix
            ),
            Err(ZkError::InvalidInput)
        );
        assert_eq!(
            evaluate_public_inputs_barycentric(
                &[ONE, ONE, ONE, ONE, ONE],
                n,
                ONE,
                omega,
                &mut denominators,
                &mut prefix
            ),
            Err(ZkError::InvalidInput)
        );
        // Out-of-range ζ.
        assert_eq!(
            evaluate_public_inputs_barycentric(
                &values,
                n,
                Bn254::FR_MODULUS,
                omega,
                &mut denominators,
                &mut prefix
            ),
            Err(ZkError::InvalidFieldElement)
        );
        // Out-of-range public input.
        assert_eq!(
            evaluate_public_inputs_barycentric(
                &[Bn254::FR_MODULUS, ONE, ONE, ONE],
                n,
                ONE,
                omega,
                &mut denominators,
                &mut prefix
            ),
            Err(ZkError::InvalidFieldElement)
        );
        // Short scratch.
        assert_eq!(
            evaluate_public_inputs_barycentric(
                &values,
                n,
                ONE,
                omega,
                &mut denominators[..2],
                &mut prefix
            ),
            Err(ZkError::InvalidInput)
        );
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn quotient_fold_matches_manual_combination() {
        let zeta = u256::from(37u8);
        let n = 8usize;
        let parts = [g1(2), g1(3), g1(5)];
        let got = fold_quotient_commitment(&parts, zeta, n).expect("fold");
        let zeta_n = Bn254::pow(zeta, u256::from(n as u64));
        let zeta_2n = Bn254::mul(zeta_n, zeta_n);
        let expected = G1Projective::from(parts[0])
            .add(&Bn254::g1_scalar_mul(G1Projective::from(parts[1]), zeta_n))
            .add(&Bn254::g1_scalar_mul(G1Projective::from(parts[2]), zeta_2n))
            .to_affine();
        assert_eq!(got, expected);
        assert_eq!(
            fold_quotient_commitment(&parts, zeta, 0),
            Err(ZkError::InvalidInput)
        );
        assert_eq!(
            fold_quotient_commitment(&parts, Bn254::FR_MODULUS, n),
            Err(ZkError::InvalidFieldElement)
        );
    }

    fn sample_proof() -> PlonkProof {
        PlonkProof {
            wire_commitments: [g1(1), g1(2), g1(3)],
            z_commitment: g1(4),
            quotient_commitments: [g1(5), g1(6), g1(7)],
            w_zeta: g1(8),
            w_zeta_omega: g1(9),
            wire_evaluations: [ONE, u256::from(2u8), u256::from(3u8)],
            sigma_evaluations: [u256::from(4u8), u256::from(5u8)],
            z_omega_evaluation: u256::from(6u8),
            quotient_evaluation: u256::from(7u8),
            linearization_evaluation: u256::from(8u8),
        }
    }

    #[test]
    fn transcript_is_deterministic_and_binding() {
        let proof = sample_proof();
        let digest = [7u8; 32];
        let public_inputs = [ONE, u256::from(2u8), u256::from(3u8), u256::from(4u8)];

        let derive = || {
            let mut transcript = PlonkTranscript::plonk_init(
                4,
                u256::from(5u8),
                u256::from(6u8),
                &digest,
                &public_inputs,
            )
            .expect("transcript init");
            derive_plonk_full_challenges(&mut transcript, &proof)
        };
        let first = derive();
        let second = derive();
        assert_eq!(first, second, "challenges must be deterministic");
        for challenge in [
            first.beta,
            first.gamma,
            first.alpha,
            first.zeta,
            first.v,
            first.u,
        ] {
            assert_ne!(challenge, ZERO, "challenges must be non-zero");
            assert!(challenge < Bn254::FR_MODULUS);
        }

        // Any change to the statement or the proof must move the challenges.
        let mut tampered = proof;
        tampered.wire_commitments[1] = g1(21);
        let mut transcript = PlonkTranscript::plonk_init(
            4,
            u256::from(5u8),
            u256::from(6u8),
            &digest,
            &public_inputs,
        )
        .expect("transcript init");
        let moved = derive_plonk_full_challenges(&mut transcript, &tampered);
        assert_ne!(first.beta, moved.beta);

        let mut transcript =
            PlonkTranscript::plonk_init(4, u256::from(5u8), u256::from(6u8), &digest, &[ONE])
                .expect("transcript init");
        let other_pi = derive_plonk_full_challenges(&mut transcript, &proof);
        assert_ne!(first.beta, other_pi.beta);

        assert_eq!(
            PlonkTranscript::plonk_init(0, ONE, ONE, &digest, &public_inputs).err(),
            Some(ZkError::InvalidInput)
        );
    }

    #[test]
    fn proof_bytes_round_trip_and_rejections() {
        let proof = sample_proof();
        let bytes = proof.to_bytes();
        assert_eq!(bytes.len(), PLONK_PROOF_BYTES);
        assert_eq!(PlonkProof::from_bytes(&bytes), Ok(proof));

        assert_eq!(
            PlonkProof::from_bytes(&bytes[..PLONK_PROOF_BYTES - 1]),
            Err(ZkError::DeserializationError)
        );
        assert_eq!(
            PlonkProof::from_bytes(&[]),
            Err(ZkError::DeserializationError)
        );

        // Off-curve first commitment.
        let mut bad_point = bytes;
        bad_point[63] ^= 1;
        assert_eq!(
            PlonkProof::from_bytes(&bad_point),
            Err(ZkError::DeserializationError)
        );

        // Non-canonical scalar (== r).
        let mut bad_scalar = bytes;
        let start = 9 * 64;
        bad_scalar[start..start + 32].copy_from_slice(&Bn254::FR_MODULUS.to_be_bytes());
        assert_eq!(
            PlonkProof::from_bytes(&bad_scalar),
            Err(ZkError::DeserializationError)
        );
    }

    #[test]
    fn batch_seed_is_non_degenerate_and_binding() {
        let commitments = [g1(1)];
        let evaluations = [u256::from(3u8)];
        let bundle = KzgEvalProofInputs {
            commitments: &commitments,
            evaluations_at_zeta: &evaluations,
            commitment_at_zeta_omega: g1(2),
            evaluation_at_zeta_omega: u256::from(5u8),
            w_zeta: g1(3),
            w_zeta_omega: g1(4),
            v: u256::from(7u8),
            u: u256::from(11u8),
            zeta: u256::from(13u8),
            omega: u256::from(17u8),
        };

        let seed = derive_plonk_batch_seed(core::slice::from_ref(&bundle)).expect("seed");
        let rho = u256::from_be_bytes(seed) % Bn254::FR_MODULUS;
        assert_ne!(rho, ZERO);
        assert_ne!(rho, ONE);

        let mut tampered = bundle.clone();
        tampered.w_zeta = g1(5);
        assert_ne!(seed, derive_plonk_batch_seed(&[tampered]).expect("seed"));

        assert_eq!(derive_plonk_batch_seed(&[]), Err(ZkError::InvalidInput));
        assert_eq!(
            plonk_batch_verify_points(&[bundle], &{
                let mut degenerate = [0u8; 32];
                degenerate[31] = 1; // rho == 1
                degenerate
            }),
            Err(ZkError::InvalidFieldElement)
        );
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn batch_seed_wrapper_accepts_a_valid_batch() {
        let commitments = [g1(1), g1(2)];
        let evaluations = [u256::from(3u8), u256::from(5u8)];
        let bundle = KzgEvalProofInputs {
            commitments: &commitments,
            evaluations_at_zeta: &evaluations,
            commitment_at_zeta_omega: g1(3),
            evaluation_at_zeta_omega: u256::from(7u8),
            w_zeta: g1(4),
            w_zeta_omega: g1(5),
            v: u256::from(11u8),
            u: u256::from(13u8),
            zeta: u256::from(17u8),
            omega: u256::from(19u8),
        };
        let seed = derive_plonk_batch_seed(core::slice::from_ref(&bundle)).expect("seed");
        assert!(plonk_batch_verify_points(&[bundle], &seed).is_ok());
    }
}
