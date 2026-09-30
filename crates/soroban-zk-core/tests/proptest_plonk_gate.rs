//! Issue #428 — Property-based (fuzz) tests for the PLONK gate evaluator.
//!
//! These tests stress [`soroban_zk_core::plonk`]'s constraint logic with
//! randomly generated field elements to prove three things:
//!
//! 1. **Algebraic correctness** — `evaluate_arithmetic_gate` computes exactly
//!    `q_L·a + q_R·b + q_O·c + q_M·(a·b) + q_C` over `Fr`.
//! 2. **Malformed-trace rejection** — the residual is `0` for a trace that
//!    satisfies the gate and provably non-zero (equal to `q_O·δ`) the instant a
//!    satisfying wire is perturbed by `δ ≠ 0`. This is the accept/reject
//!    signal a verifier relies on.
//! 3. **Edge-case robustness** — the evaluator and the linearization routine
//!    *never panic*, whatever they are fed: zero, `r − 1`, values at/above the
//!    modulus, empty domains, or `ζ == 1`. Off-field inputs are reduced, and
//!    structurally invalid inputs surface as a typed [`ZkError`] rather than a
//!    crash.
//!
//! A cross-check ties the two evaluators together: with `α == 0` the
//! linearization collapses to the pure gate residual, so the gate and the
//! linearization must agree bit-for-bit.
//!
//! [`soroban_zk_core::plonk`]: soroban_zk_core::plonk
//! [`ZkError`]: soroban_zk_core::ZkError

use ethnum::u256;
use proptest::prelude::*;
use soroban_zk_core::plonk::{
    evaluate_arithmetic_gate, evaluate_linearization, CommitEvaluations, DomainParams, PlonkChallenges,
    PlonkProof, SelectorEvaluations,
};
use soroban_zk_core::{Bn254, G1Affine, ZkError};

const ZERO: u256 = u256::from_words(0u128, 0u128);
const ONE: u256 = u256::from_words(0u128, 1u128);

/// Interpret a random 32-byte blob as a canonical `Fr` element (`mod r`).
fn fr(bytes: [u8; 32]) -> u256 {
    u256::from_be_bytes(bytes) % Bn254::FR_MODULUS
}

/// A well-formed (but algebraically inert) G1 point used only to satisfy the
/// struct shape — neither evaluator touches the commitments.
fn dummy_g1() -> G1Affine {
    G1Affine {
        x: u256::from_words(0, 1),
        y: u256::from_words(0, 2),
    }
}

/// Assemble a `PlonkProof` whose *evaluations* are what the linearization
/// consumes; the commitments are filler.
fn proof_with_evals(
    wire: [u256; 3],
    sigma: [u256; 2],
    z_omega: u256,
) -> PlonkProof {
    PlonkProof {
        wire_commitments: [dummy_g1(); 3],
        z_commitment: dummy_g1(),
        quotient_commitments: [dummy_g1(); 3],
        w_zeta: dummy_g1(),
        w_zeta_omega: dummy_g1(),
        wire_evaluations: wire,
        sigma_evaluations: sigma,
        z_omega_evaluation: z_omega,
        quotient_evaluation: ZERO,
        linearization_evaluation: ZERO,
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1000))]

    // ── 1. Algebraic correctness of the gate ────────────────────────────────

    /// The gate evaluator must match a hand-computed reference exactly and
    /// always return a canonical element in `[0, r)`.
    #[test]
    fn gate_matches_reference_arithmetic(
        ql in any::<[u8; 32]>(), qr in any::<[u8; 32]>(), qo in any::<[u8; 32]>(),
        qm in any::<[u8; 32]>(), qc in any::<[u8; 32]>(),
        a in any::<[u8; 32]>(), b in any::<[u8; 32]>(), c in any::<[u8; 32]>(),
    ) {
        let (ql, qr, qo, qm, qc) = (fr(ql), fr(qr), fr(qo), fr(qm), fr(qc));
        let (a, b, c) = (fr(a), fr(b), fr(c));

        let got = evaluate_arithmetic_gate(ql, qr, qo, qm, qc, a, b, c);

        // Reference: q_L·a + q_R·b + q_O·c + q_M·(a·b) + q_C  (mod r).
        let expected = Bn254::add(
            Bn254::add(
                Bn254::add(Bn254::mul(ql, a), Bn254::mul(qr, b)),
                Bn254::add(Bn254::mul(qo, c), Bn254::mul(qm, Bn254::mul(a, b))),
            ),
            qc,
        );
        prop_assert_eq!(got, expected);
        prop_assert!(got < Bn254::FR_MODULUS, "gate residual escaped the field");
    }

    // ── 2. Malformed-trace rejection (the accept/reject signal) ─────────────

    /// A trace built to satisfy the gate must yield residual `0`.
    #[test]
    fn gate_accepts_satisfied_trace(
        ql in any::<[u8; 32]>(), qr in any::<[u8; 32]>(), qo in any::<[u8; 32]>(),
        qm in any::<[u8; 32]>(), qc in any::<[u8; 32]>(),
        a in any::<[u8; 32]>(), b in any::<[u8; 32]>(),
    ) {
        let (ql, qr, qo, qm, qc) = (fr(ql), fr(qr), fr(qo), fr(qm), fr(qc));
        let (a, b) = (fr(a), fr(b));
        prop_assume!(qo != ZERO);

        // Solve q_O·c = -(q_L·a + q_R·b + q_M·a·b + q_C) for c.
        let rest = Bn254::add(
            Bn254::add(Bn254::mul(ql, a), Bn254::mul(qr, b)),
            Bn254::add(Bn254::mul(qm, Bn254::mul(a, b)), qc),
        );
        let c = Bn254::mul(Bn254::sub(ZERO, rest), Bn254::invert(qo));

        let res = evaluate_arithmetic_gate(ql, qr, qo, qm, qc, a, b, c);
        prop_assert_eq!(res, ZERO, "satisfying trace must be accepted");
    }

    /// Perturbing the satisfying wire `c` by `δ ≠ 0` must be *rejected*, and
    /// the residual must equal exactly `q_O·δ` — proving rejection is not a
    /// coincidence but tracks the injected error.
    #[test]
    fn gate_rejects_malformed_trace(
        ql in any::<[u8; 32]>(), qr in any::<[u8; 32]>(), qo in any::<[u8; 32]>(),
        qm in any::<[u8; 32]>(), qc in any::<[u8; 32]>(),
        a in any::<[u8; 32]>(), b in any::<[u8; 32]>(), delta in any::<[u8; 32]>(),
    ) {
        let (ql, qr, qo, qm, qc) = (fr(ql), fr(qr), fr(qo), fr(qm), fr(qc));
        let (a, b) = (fr(a), fr(b));
        prop_assume!(qo != ZERO);

        let rest = Bn254::add(
            Bn254::add(Bn254::mul(ql, a), Bn254::mul(qr, b)),
            Bn254::add(Bn254::mul(qm, Bn254::mul(a, b)), qc),
        );
        let c_sat = Bn254::mul(Bn254::sub(ZERO, rest), Bn254::invert(qo));

        let d = fr(delta);
        prop_assume!(d != ZERO);
        let c_bad = Bn254::add(c_sat, d);

        let res = evaluate_arithmetic_gate(ql, qr, qo, qm, qc, a, b, c_bad);
        prop_assert_eq!(res, Bn254::mul(qo, d));
        prop_assert_ne!(res, ZERO, "malformed trace must be rejected");
    }

    // ── 3. Edge-case robustness (never panic) ───────────────────────────────

    /// Arbitrary `u256` inputs — including values at/above the modulus and the
    /// extreme corners — must reduce cleanly and never panic.
    #[test]
    fn gate_never_panics_on_arbitrary_inputs(
        ql in any::<[u8; 32]>(), qr in any::<[u8; 32]>(), qo in any::<[u8; 32]>(),
        qm in any::<[u8; 32]>(), qc in any::<[u8; 32]>(),
        a in any::<[u8; 32]>(), b in any::<[u8; 32]>(), c in any::<[u8; 32]>(),
    ) {
        // Deliberately NOT reduced mod r: raw blobs exercise out-of-range edges.
        let res = evaluate_arithmetic_gate(
            u256::from_be_bytes(ql), u256::from_be_bytes(qr),
            u256::from_be_bytes(qo), u256::from_be_bytes(qm),
            u256::from_be_bytes(qc), u256::from_be_bytes(a),
            u256::from_be_bytes(b), u256::from_be_bytes(c),
        );
        // If it returned, the result is field-canonical.
        prop_assert!(res < Bn254::FR_MODULUS);
    }

    /// All-zero selectors annihilate the trace: the residual is exactly `q_C`.
    #[test]
    fn gate_with_zero_selectors_reduces_to_constant(
        qc in any::<[u8; 32]>(), a in any::<[u8; 32]>(), b in any::<[u8; 32]>(), c in any::<[u8; 32]>(),
    ) {
        let res = evaluate_arithmetic_gate(
            ZERO, ZERO, ZERO, ZERO, fr(qc), fr(a), fr(b), fr(c),
        );
        prop_assert_eq!(res, fr(qc));
    }

    /// The evaluator is a pure function: identical inputs yield identical output.
    #[test]
    fn gate_is_deterministic(
        ql in any::<[u8; 32]>(), qr in any::<[u8; 32]>(), qo in any::<[u8; 32]>(),
        qm in any::<[u8; 32]>(), qc in any::<[u8; 32]>(),
        a in any::<[u8; 32]>(), b in any::<[u8; 32]>(), c in any::<[u8; 32]>(),
    ) {
        let x1 = evaluate_arithmetic_gate(fr(ql), fr(qr), fr(qo), fr(qm), fr(qc), fr(a), fr(b), fr(c));
        let x2 = evaluate_arithmetic_gate(fr(ql), fr(qr), fr(qo), fr(qm), fr(qc), fr(a), fr(b), fr(c));
        prop_assert_eq!(x1, x2);
    }

    // ── 4. Linearization: robustness + gate cross-check ─────────────────────

    /// For `ζ ≠ 1` and `n ≥ 1`, the linearization returns `Ok` with a canonical
    /// element; for `ζ == 1` it must return the typed field-element error.
    /// Either way, never a panic.
    #[test]
    fn linearization_never_panics_and_is_field_canonical(
        wb0 in any::<[u8; 32]>(), wb1 in any::<[u8; 32]>(), wb2 in any::<[u8; 32]>(),
        s0 in any::<[u8; 32]>(), s1 in any::<[u8; 32]>(), zo in any::<[u8; 32]>(),
        alpha in any::<[u8; 32]>(), beta in any::<[u8; 32]>(), gamma in any::<[u8; 32]>(),
        zeta_bytes in any::<[u8; 32]>(),
        ql in any::<[u8; 32]>(), qr in any::<[u8; 32]>(), qo in any::<[u8; 32]>(),
        qm in any::<[u8; 32]>(), qc in any::<[u8; 32]>(),
        zz in any::<[u8; 32]>(), s3 in any::<[u8; 32]>(),
        k1 in any::<[u8; 32]>(), k2 in any::<[u8; 32]>(),
        n in 1usize..=64usize,
    ) {
        let proof = proof_with_evals([fr(wb0), fr(wb1), fr(wb2)], [fr(s0), fr(s1)], fr(zo));
        let zeta = fr(zeta_bytes);
        let challenges = PlonkChallenges { alpha: fr(alpha), beta: fr(beta), gamma: fr(gamma), zeta };
        let selectors = SelectorEvaluations {
            q_l: fr(ql), q_r: fr(qr), q_o: fr(qo), q_m: fr(qm), q_c: fr(qc),
        };
        let commits = CommitEvaluations { z_zeta: fr(zz), s_sigma3_zeta: fr(s3) };
        let domain = DomainParams { n, k1: fr(k1), k2: fr(k2) };

        let result = evaluate_linearization(&proof, &challenges, &selectors, &commits, &domain);
        if zeta == ONE {
            prop_assert_eq!(result.err(), Some(ZkError::InvalidFieldElement));
        } else {
            // `n >= 1` and `zeta != 1` rule out both error paths, so this must
            // succeed and land inside the field.
            prop_assert!(result.is_ok(), "linearization unexpectedly errored: {:?}", result);
            if let Ok(v) = result {
                prop_assert!(v < Bn254::FR_MODULUS, "linearization escaped the field");
            }
        }
    }

    /// An empty domain (`n == 0`) is always a structural `InvalidInput`,
    /// short-circuiting before any field work.
    #[test]
    fn linearization_rejects_empty_domain(
        wb0 in any::<[u8; 32]>(), zeta_bytes in any::<[u8; 32]>(),
    ) {
        let proof = proof_with_evals([fr(wb0), ZERO, ZERO], [ZERO, ZERO], ZERO);
        let challenges = PlonkChallenges {
            alpha: ZERO, beta: ZERO, gamma: ZERO, zeta: fr(zeta_bytes),
        };
        let selectors = SelectorEvaluations { q_l: ZERO, q_r: ZERO, q_o: ZERO, q_m: ZERO, q_c: ZERO };
        let commits = CommitEvaluations { z_zeta: ZERO, s_sigma3_zeta: ZERO };
        let domain = DomainParams { n: 0, k1: ZERO, k2: ZERO };

        prop_assert_eq!(
            evaluate_linearization(&proof, &challenges, &selectors, &commits, &domain).err(),
            Some(ZkError::InvalidInput)
        );
    }

    /// Cross-check linking the two evaluators: with `α == 0` the linearization
    /// collapses to the gate residual, so it must equal `evaluate_arithmetic_gate`
    /// exactly and therefore accept/reject the same traces.
    #[test]
    fn linearization_with_zero_alpha_equals_gate(
        ql in any::<[u8; 32]>(), qr in any::<[u8; 32]>(), qo in any::<[u8; 32]>(),
        qm in any::<[u8; 32]>(), qc in any::<[u8; 32]>(),
        a in any::<[u8; 32]>(), b in any::<[u8; 32]>(), c in any::<[u8; 32]>(),
        beta in any::<[u8; 32]>(), gamma in any::<[u8; 32]>(),
        zeta_bytes in any::<[u8; 32]>(), s0 in any::<[u8; 32]>(), s1 in any::<[u8; 32]>(),
        zo in any::<[u8; 32]>(), zz in any::<[u8; 32]>(), s3 in any::<[u8; 32]>(),
        k1 in any::<[u8; 32]>(), k2 in any::<[u8; 32]>(),
        n in 1usize..=64usize,
    ) {
        let (ql, qr, qo, qm, qc) = (fr(ql), fr(qr), fr(qo), fr(qm), fr(qc));
        let (a, b, c) = (fr(a), fr(b), fr(c));
        let zeta = fr(zeta_bytes);
        prop_assume!(zeta != ONE);

        let proof = proof_with_evals([a, b, c], [fr(s0), fr(s1)], fr(zo));
        let challenges = PlonkChallenges { alpha: ZERO, beta: fr(beta), gamma: fr(gamma), zeta };
        let selectors = SelectorEvaluations { q_l: ql, q_r: qr, q_o: qo, q_m: qm, q_c: qc };
        let commits = CommitEvaluations { z_zeta: fr(zz), s_sigma3_zeta: fr(s3) };
        let domain = DomainParams { n, k1: fr(k1), k2: fr(k2) };

        let lin_res = evaluate_linearization(&proof, &challenges, &selectors, &commits, &domain);
        prop_assert!(lin_res.is_ok(), "linearization errored with zeta != 1: {:?}", lin_res);
        if let Ok(lin) = lin_res {
            let gate = evaluate_arithmetic_gate(ql, qr, qo, qm, qc, a, b, c);
            prop_assert_eq!(lin, gate);
        }
    }

    /// Determinism: identical linearization inputs produce identical results.
    #[test]
    fn linearization_is_deterministic(
        wb0 in any::<[u8; 32]>(), wb1 in any::<[u8; 32]>(), wb2 in any::<[u8; 32]>(),
        s0 in any::<[u8; 32]>(), s1 in any::<[u8; 32]>(), zo in any::<[u8; 32]>(),
        alpha in any::<[u8; 32]>(), beta in any::<[u8; 32]>(), gamma in any::<[u8; 32]>(),
        zeta_bytes in any::<[u8; 32]>(),
        ql in any::<[u8; 32]>(), qr in any::<[u8; 32]>(), qo in any::<[u8; 32]>(),
        qm in any::<[u8; 32]>(), qc in any::<[u8; 32]>(),
        zz in any::<[u8; 32]>(), s3 in any::<[u8; 32]>(),
        k1 in any::<[u8; 32]>(), k2 in any::<[u8; 32]>(),
        n in 1usize..=64usize,
    ) {
        let build = || {
            let proof = proof_with_evals([fr(wb0), fr(wb1), fr(wb2)], [fr(s0), fr(s1)], fr(zo));
            let challenges = PlonkChallenges {
                alpha: fr(alpha), beta: fr(beta), gamma: fr(gamma), zeta: fr(zeta_bytes),
            };
            let selectors = SelectorEvaluations {
                q_l: fr(ql), q_r: fr(qr), q_o: fr(qo), q_m: fr(qm), q_c: fr(qc),
            };
            let commits = CommitEvaluations { z_zeta: fr(zz), s_sigma3_zeta: fr(s3) };
            let domain = DomainParams { n, k1: fr(k1), k2: fr(k2) };
            evaluate_linearization(&proof, &challenges, &selectors, &commits, &domain)
        };
        prop_assert_eq!(build(), build());
    }
}
