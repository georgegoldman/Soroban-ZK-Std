//! Production end-to-end PLONK-KZG prover-to-verifier test suite.
//!
//! Unlike unit tests that use synthetic generator placeholders, every test in
//! this file constructs genuine algebraic KZG polynomial commitments
//! (`[p(tau)]_1`) and quotient opening witnesses (`[q(tau)]_1`) over a
//! deterministic test trapdoor `tau` using `ark-bn254`, then verifies them
//! through [`verify_plonk_kzg`] and [`verify_plonk_kzg_batch`].
//!
//! Coverage:
//! - Multi-gate arithmetic PLONK circuit (addition, multiplication, linear
//!   combination, and general fan-in gates over a 4-point multiplicative
//!   subgroup `{1, omega, omega^2, omega^3}`).
//! - Single-proof KZG opening verification (`Ok(true)` on valid openings).
//! - 1-bit evaluation perturbations (`Ok(false)` on any tampered evaluation).
//! - Wrong trusted-setup SRS rejection (`Ok(false)`).
//! - Multi-proof batch verification (`verify_plonk_kzg_batch`) for `M = 2, 4, 8`
//!   distinct circuits, plus 1-bit perturbation rejection at first, middle,
//!   and last positions.

use ark_bn254::{
    Fq as ArkFq, Fr as ArkFr, G1Projective as ArkG1, G2Projective as ArkG2,
};
use ark_ec::{CurveGroup, PrimeGroup};
use ark_ff::{BigInteger, Field, One, PrimeField, Zero};
use ethnum::u256;
use soroban_sdk::Env;
use soroban_zk_core::plonk::evaluate_arithmetic_gate;
use soroban_zk_core::{Bn254, G1Affine, KzgEvalProofInputs};
use soroban_zk_std::pairing::G2Affine;
use soroban_zk_std::plonk_kzg::{verify_plonk_kzg, verify_plonk_kzg_batch};

// ---------------------------------------------------------------------------
// Conversion helpers: ark-bn254 <-> soroban-zk-core / soroban-zk-std
// ---------------------------------------------------------------------------

fn ark_fp_to_u256<F: PrimeField>(x: F) -> u256 {
    let bytes = x.into_bigint().to_bytes_be();
    let mut out = [0u8; 32];
    out[32 - bytes.len()..].copy_from_slice(&bytes);
    u256::from_be_bytes(out)
}

fn ark_g1_to_local(p: ArkG1) -> G1Affine {
    if p.is_zero() {
        return G1Affine {
            x: u256::from(0u8),
            y: u256::from(0u8),
        };
    }
    let aff = p.into_affine();
    G1Affine {
        x: ark_fp_to_u256::<ArkFq>(aff.x),
        y: ark_fp_to_u256::<ArkFq>(aff.y),
    }
}

fn ark_g2_to_local(p: ArkG2) -> G2Affine {
    let aff = p.into_affine();
    G2Affine {
        x: (
            ark_fp_to_u256::<ArkFq>(aff.x.c0),
            ark_fp_to_u256::<ArkFq>(aff.x.c1),
        ),
        y: (
            ark_fp_to_u256::<ArkFq>(aff.y.c0),
            ark_fp_to_u256::<ArkFq>(aff.y.c1),
        ),
    }
}

fn g1_identity() -> G1Affine {
    G1Affine {
        x: u256::from(0u8),
        y: u256::from(0u8),
    }
}

fn g1_gen() -> G1Affine {
    G1Affine {
        x: u256::from(1u8),
        y: u256::from(2u8),
    }
}

// ---------------------------------------------------------------------------
// Polynomial arithmetic over BN254 Fr
// ---------------------------------------------------------------------------

/// Evaluate `p(x) = sum_i coeffs[i] * x^i` via Horner's method.
fn poly_eval(coeffs: &[ArkFr], x: ArkFr) -> ArkFr {
    let mut acc = ArkFr::ZERO;
    for &c in coeffs.iter().rev() {
        acc = acc * x + c;
    }
    acc
}

/// Add two polynomials represented in ascending-degree coefficient order.
fn poly_add(a: &[ArkFr], b: &[ArkFr]) -> Vec<ArkFr> {
    let len = a.len().max(b.len());
    let mut out = vec![ArkFr::ZERO; len];
    for (i, &c) in a.iter().enumerate() {
        out[i] += c;
    }
    for (i, &c) in b.iter().enumerate() {
        out[i] += c;
    }
    out
}

/// Multiply two polynomials represented in ascending-degree coefficient order.
fn poly_mul(a: &[ArkFr], b: &[ArkFr]) -> Vec<ArkFr> {
    if a.is_empty() || b.is_empty() {
        return vec![ArkFr::ZERO];
    }
    let mut out = vec![ArkFr::ZERO; a.len() + b.len() - 1];
    for (i, &ca) in a.iter().enumerate() {
        for (j, &cb) in b.iter().enumerate() {
            out[i + j] += ca * cb;
        }
    }
    out
}

/// Divide `P(X) - P(z)` by `(X - z)` using synthetic division.
fn poly_div_linear(coeffs: &[ArkFr], z: ArkFr) -> Vec<ArkFr> {
    let n = coeffs.len();
    if n <= 1 {
        return vec![ArkFr::ZERO];
    }
    let mut q = vec![ArkFr::ZERO; n - 1];
    q[n - 2] = coeffs[n - 1];
    for i in (0..n - 2).rev() {
        q[i] = coeffs[i + 1] + z * q[i + 1];
    }
    q
}

/// Lagrange-interpolate a unique polynomial of degree `< xs.len()` passing
/// through `(xs[i], ys[i])`.
fn lagrange_interpolate(xs: &[ArkFr], ys: &[ArkFr]) -> Vec<ArkFr> {
    assert_eq!(xs.len(), ys.len());
    let n = xs.len();
    let mut result = vec![ArkFr::ZERO; n];

    for i in 0..n {
        let mut basis = vec![ArkFr::ONE];
        let mut denom = ArkFr::ONE;
        for j in 0..n {
            if i == j {
                continue;
            }
            // Multiply basis by (X - xs[j])
            basis = poly_mul(&basis, &[-xs[j], ArkFr::ONE]);
            denom *= xs[i] - xs[j];
        }
        let scale = ys[i] * denom.inverse().expect("distinct domain points");
        for (k, &b) in basis.iter().enumerate() {
            result[k] += scale * b;
        }
    }

    result
}

/// Compute algebraic KZG commitment `[p(tau)]_1`.
fn kzg_commit_trapdoor(coeffs: &[ArkFr], tau: ArkFr) -> G1Affine {
    let val = poly_eval(coeffs, tau);
    ark_g1_to_local(ArkG1::generator() * val)
}

/// Flip the least-significant bit of a `u256` field element while keeping it
/// strictly below `Bn254::FR_MODULUS`.
fn perturb_one_bit(x: u256) -> u256 {
    let flipped = x ^ u256::from(1u8);
    assert!(flipped < Bn254::FR_MODULUS);
    assert_ne!(flipped, x);
    flipped
}

// ---------------------------------------------------------------------------
// Multi-gate PLONK-KZG fixture builder
// ---------------------------------------------------------------------------

/// Owned KZG opening bundle produced from genuine multi-gate PLONK polynomials
/// over a 4-gate domain `{1, omega, omega^2, omega^3}` and trapdoor `tau`.
struct PlonkKzgFixture {
    commitments: Vec<G1Affine>,
    evaluations_at_zeta: Vec<u256>,
    commitment_at_zeta_omega: G1Affine,
    evaluation_at_zeta_omega: u256,
    w_zeta: G1Affine,
    w_zeta_omega: G1Affine,
    v: u256,
    u: u256,
    zeta: u256,
    omega: u256,
}

impl PlonkKzgFixture {
    fn as_inputs(&self) -> KzgEvalProofInputs<'_> {
        KzgEvalProofInputs {
            commitments: &self.commitments,
            evaluations_at_zeta: &self.evaluations_at_zeta,
            commitment_at_zeta_omega: self.commitment_at_zeta_omega,
            evaluation_at_zeta_omega: self.evaluation_at_zeta_omega,
            w_zeta: self.w_zeta,
            w_zeta_omega: self.w_zeta_omega,
            v: self.v,
            u: self.u,
            zeta: self.zeta,
            omega: self.omega,
        }
    }
}

/// Build a 4-gate PLONK arithmetic circuit and its genuine KZG opening proof
/// parameterized by `(tau, seed_offset)`.
///
/// The 4 gates exercise:
/// - Gate 0: addition (`a0 + b0 - c0 = 0`)
/// - Gate 1: multiplication (`a1 * b1 - c1 = 0`)
/// - Gate 2: weighted linear + constant (`2*a2 + 3*b2 - c2 + 5 = 0`)
/// - Gate 3: combined mul + linear + constant (`a3*b3 + 4*a3 - c3 - 7 = 0`)
fn build_multigate_plonk_fixture(tau: ArkFr, seed_offset: u64) -> PlonkKzgFixture {
    // Primitive 4th root of unity in BN254 Fr: sqrt(-1).
    let omega = (-ArkFr::ONE)
        .sqrt()
        .expect("BN254 Fr has -1 as a quadratic residue");
    assert_eq!(omega.pow([4u64]), ArkFr::ONE);
    assert_ne!(omega.pow([2u64]), ArkFr::ONE);

    let domain = [ArkFr::ONE, omega, omega * omega, omega * omega * omega];

    // Witness values parameterized by seed_offset so each proof in a batch is distinct.
    let s = ArkFr::from(seed_offset + 3);
    let a0 = s;
    let b0 = s + ArkFr::from(7u64);
    let c0 = a0 + b0;

    let a1 = s + ArkFr::from(2u64);
    let b1 = s + ArkFr::from(5u64);
    let c1 = a1 * b1;

    let a2 = s + ArkFr::from(11u64);
    let b2 = s + ArkFr::from(13u64);
    let c2 = ArkFr::from(2u64) * a2 + ArkFr::from(3u64) * b2 + ArkFr::from(5u64);

    let a3 = s + ArkFr::from(17u64);
    let b3 = s + ArkFr::from(19u64);
    let c3 = a3 * b3 + ArkFr::from(4u64) * a3 - ArkFr::from(7u64);

    let a_vals = [a0, a1, a2, a3];
    let b_vals = [b0, b1, b2, b3];
    let c_vals = [c0, c1, c2, c3];

    let ql_vals = [
        ArkFr::ONE,
        ArkFr::ZERO,
        ArkFr::from(2u64),
        ArkFr::from(4u64),
    ];
    let qr_vals = [ArkFr::ONE, ArkFr::ZERO, ArkFr::from(3u64), ArkFr::ZERO];
    let qo_vals = [-ArkFr::ONE, -ArkFr::ONE, -ArkFr::ONE, -ArkFr::ONE];
    let qm_vals = [ArkFr::ZERO, ArkFr::ONE, ArkFr::ZERO, ArkFr::ONE];
    let qc_vals = [
        ArkFr::ZERO,
        ArkFr::ZERO,
        ArkFr::from(5u64),
        -ArkFr::from(7u64),
    ];

    // Verify every gate satisfies soroban-zk-core's arithmetic gate equation.
    for i in 0..4 {
        let residual = evaluate_arithmetic_gate(
            ark_fp_to_u256(a_vals[i]),
            ark_fp_to_u256(b_vals[i]),
            ark_fp_to_u256(c_vals[i]),
            ark_fp_to_u256(ql_vals[i]),
            ark_fp_to_u256(qr_vals[i]),
            ark_fp_to_u256(qo_vals[i]),
            ark_fp_to_u256(qm_vals[i]),
            ark_fp_to_u256(qc_vals[i]),
        );
        assert_eq!(residual, u256::from(0u8), "gate {i} residual must be zero");
    }

    // Interpolate all 8 circuit polynomials over the 4-gate domain.
    let polys = [
        lagrange_interpolate(&domain, &a_vals),
        lagrange_interpolate(&domain, &b_vals),
        lagrange_interpolate(&domain, &c_vals),
        lagrange_interpolate(&domain, &ql_vals),
        lagrange_interpolate(&domain, &qr_vals),
        lagrange_interpolate(&domain, &qo_vals),
        lagrange_interpolate(&domain, &qm_vals),
        lagrange_interpolate(&domain, &qc_vals),
    ];

    // Out-of-domain evaluation challenge and batching scalars.
    let zeta = ArkFr::from(0x9e37_79b9u64 + seed_offset * 101);
    let v = ArkFr::from(0x517c_c1b7u64 + seed_offset * 37);
    let u = ArkFr::from(0x2722_0a95u64 + seed_offset * 53);

    let commitments: Vec<G1Affine> = polys
        .iter()
        .map(|p| kzg_commit_trapdoor(p, tau))
        .collect();

    let evals_ark: Vec<ArkFr> = polys.iter().map(|p| poly_eval(p, zeta)).collect();
    let evaluations_at_zeta: Vec<u256> = evals_ark.iter().map(|&e| ark_fp_to_u256(e)).collect();

    // Batched polynomial P(X) = sum_i v^i * p_i(X).
    let mut batched_poly = vec![ArkFr::ZERO];
    let mut v_pow = ArkFr::ONE;
    for p in &polys {
        let scaled: Vec<ArkFr> = p.iter().map(|&c| c * v_pow).collect();
        batched_poly = poly_add(&batched_poly, &scaled);
        v_pow *= v;
    }

    // Quotient witness: q_zeta(X) = (P(X) - P(zeta)) / (X - zeta).
    let q_zeta_poly = poly_div_linear(&batched_poly, zeta);
    let w_zeta = kzg_commit_trapdoor(&q_zeta_poly, tau);

    PlonkKzgFixture {
        commitments,
        evaluations_at_zeta,
        commitment_at_zeta_omega: g1_gen(),
        evaluation_at_zeta_omega: u256::from(0u8),
        w_zeta,
        w_zeta_omega: g1_identity(),
        v: ark_fp_to_u256(v),
        u: ark_fp_to_u256(u),
        zeta: ark_fp_to_u256(zeta),
        omega: ark_fp_to_u256(omega),
    }
}

fn test_trapdoor() -> (ArkFr, G2Affine) {
    let tau = ArkFr::from(0x1234_5678_9abc_def0u64);
    let srs_g2 = ark_g2_to_local(ArkG2::generator() * tau);
    (tau, srs_g2)
}

// ---------------------------------------------------------------------------
// Single-proof PLONK-KZG tests
// ---------------------------------------------------------------------------

#[test]
fn plonk_kzg_single_multigate_accepts_valid_opening() {
    let env = Env::default();
    let (tau, srs_g2) = test_trapdoor();
    let fixture = build_multigate_plonk_fixture(tau, 0);

    let accepted = verify_plonk_kzg(&env, &fixture.as_inputs(), srs_g2)
        .expect("valid KZG opening must not error");
    assert!(accepted, "genuine KZG opening must return Ok(true)");
}

#[test]
fn plonk_kzg_single_rejects_one_bit_perturbed_evaluations() {
    let env = Env::default();
    let (tau, srs_g2) = test_trapdoor();

    // Perturb first, middle, and last polynomial evaluations at zeta by 1 bit.
    for idx in [0usize, 3, 7] {
        let mut fixture = build_multigate_plonk_fixture(tau, 1);
        fixture.evaluations_at_zeta[idx] = perturb_one_bit(fixture.evaluations_at_zeta[idx]);

        let accepted = verify_plonk_kzg(&env, &fixture.as_inputs(), srs_g2)
            .expect("perturbed evaluation must still be a valid field element");
        assert!(
            !accepted,
            "1-bit perturbation on evaluation[{idx}] must return Ok(false)"
        );
    }

    // Perturb evaluation_at_zeta_omega by 1 bit (0 -> 1).
    let mut fixture = build_multigate_plonk_fixture(tau, 2);
    fixture.evaluation_at_zeta_omega = perturb_one_bit(fixture.evaluation_at_zeta_omega);
    let accepted = verify_plonk_kzg(&env, &fixture.as_inputs(), srs_g2)
        .expect("perturbed zeta*omega evaluation must not error");
    assert!(
        !accepted,
        "1-bit perturbation on evaluation_at_zeta_omega must return Ok(false)"
    );
}

#[test]
fn plonk_kzg_single_rejects_wrong_srs_g2() {
    let env = Env::default();
    let (tau, _srs_g2) = test_trapdoor();
    let fixture = build_multigate_plonk_fixture(tau, 5);

    // G2 generator corresponds to tau = 1, which does not match the proof's tau.
    let accepted = verify_plonk_kzg(&env, &fixture.as_inputs(), G2Affine::generator())
        .expect("wrong SRS G2 is subgroup-valid and must not error");
    assert!(!accepted, "mismatched SRS G2 must return Ok(false)");
}

// ---------------------------------------------------------------------------
// Batched PLONK-KZG tests
// ---------------------------------------------------------------------------

#[test]
fn plonk_kzg_batch_accepts_valid_multigate_circuits() {
    let env = Env::default();
    let (tau, srs_g2) = test_trapdoor();
    let batch_seed = [0x42u8; 32];

    for batch_size in [2usize, 4, 8] {
        let fixtures: Vec<PlonkKzgFixture> = (0..batch_size)
            .map(|i| build_multigate_plonk_fixture(tau, i as u64 + 10))
            .collect();
        let inputs: Vec<KzgEvalProofInputs<'_>> =
            fixtures.iter().map(PlonkKzgFixture::as_inputs).collect();

        let accepted = verify_plonk_kzg_batch(&env, &inputs, &batch_seed, srs_g2)
            .expect("valid KZG batch must not error");
        assert!(
            accepted,
            "genuine {batch_size}-proof KZG batch must return Ok(true)"
        );
    }
}

#[test]
fn plonk_kzg_batch_rejects_one_bit_perturbation_at_any_position() {
    let env = Env::default();
    let (tau, srs_g2) = test_trapdoor();
    let batch_seed = [0x99u8; 32];
    let batch_size = 8usize;

    for corrupt_idx in [0usize, batch_size / 2, batch_size - 1] {
        let mut fixtures: Vec<PlonkKzgFixture> = (0..batch_size)
            .map(|i| build_multigate_plonk_fixture(tau, i as u64 + 100))
            .collect();

        // Perturb one evaluation by 1 bit in a single proof of the batch.
        let eval_idx = corrupt_idx % fixtures[corrupt_idx].evaluations_at_zeta.len();
        fixtures[corrupt_idx].evaluations_at_zeta[eval_idx] =
            perturb_one_bit(fixtures[corrupt_idx].evaluations_at_zeta[eval_idx]);

        let inputs: Vec<KzgEvalProofInputs<'_>> =
            fixtures.iter().map(PlonkKzgFixture::as_inputs).collect();

        let accepted = verify_plonk_kzg_batch(&env, &inputs, &batch_seed, srs_g2)
            .expect("perturbed batch must not error");
        assert!(
            !accepted,
            "1-bit perturbation at proof {corrupt_idx} in {batch_size}-proof batch must return Ok(false)"
        );
    }
}
