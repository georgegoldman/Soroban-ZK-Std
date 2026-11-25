//! Positive and negative Sumcheck vectors for `soroban_zk_core::sumcheck`.
//!
//! The positive vectors are generated with an honest prover helper built on the
//! same folding convention as the verifier, so they exercise the full protocol
//! (round chain plus the multilinear-evaluation oracle) rather than a
//! hand-tuned single round.

use ethnum::u256;
use soroban_zk_core::sumcheck::{
    verify_multilinear_sumcheck, verify_sumcheck, MultilinearPolynomial, RoundPolynomial,
    SumcheckReduction,
};
use soroban_zk_core::{Bn254, ZkError};

const TERMS: usize = 3;

fn fr(value: u64) -> u256 {
    u256::from(value)
}

/// Honest Sumcheck prover: folds the table round by round and emits the
/// degree-1 round polynomial `g_i(X) = Σ_j (t[j] + X·(t[j+half] - t[j]))`.
fn honest_rounds(evaluations: &[u256], challenges: &[u256]) -> Vec<RoundPolynomial<TERMS>> {
    let mut table = evaluations.to_vec();
    let mut rounds = Vec::with_capacity(challenges.len());

    for &challenge in challenges {
        let half = table.len() / 2;
        let mut at_zero = fr(0);
        let mut at_one = fr(0);
        for j in 0..half {
            at_zero = Bn254::add(at_zero, table[j]);
            at_one = Bn254::add(at_one, table[j + half]);
        }
        let slope = Bn254::sub(at_one, at_zero);
        let round = RoundPolynomial::<TERMS>::from_coefficients(&[at_zero, slope])
            .expect("honest round coefficients are canonical Fr elements");
        rounds.push(round);

        for j in 0..half {
            let lo = table[j];
            let hi = table[j + half];
            table[j] = Bn254::add(lo, Bn254::mul(challenge, Bn254::sub(hi, lo)));
        }
        table.truncate(half);
    }

    rounds
}

fn polynomial(evaluations: &[u256]) -> MultilinearPolynomial<16> {
    MultilinearPolynomial::<16>::from_evaluations(evaluations)
        .expect("valid multilinear polynomial fixture")
}

/// Small wrapper that pins the round bound so call sites stay readable.
fn verify<const MAX_EVALS: usize>(
    polynomial: &MultilinearPolynomial<MAX_EVALS>,
    claimed_sum: u256,
    rounds: &[RoundPolynomial<TERMS>],
    challenges: &[u256],
) -> Result<SumcheckReduction<24>, ZkError> {
    verify_multilinear_sumcheck::<MAX_EVALS, 24, TERMS>(polynomial, claimed_sum, rounds, challenges)
}

// ── positive vectors ────────────────────────────────────────────────────────

#[test]
fn two_variable_hand_computed_vector_is_accepted() {
    // p(0,0)=1, p(0,1)=2, p(1,0)=3, p(1,1)=4.
    // Round 0: g0(X) = 3 + 4X, g0(0)+g0(1) = 10.
    // r0 = 5 -> 23. Round 1: g1(X) = 11 + X, sum = 23.
    // r1 = 7 -> 18 = p(5, 7).
    let poly = polynomial(&[fr(1), fr(2), fr(3), fr(4)]);
    let round0 = RoundPolynomial::<TERMS>::from_coefficients(&[fr(3), fr(4)]).unwrap();
    let round1 = RoundPolynomial::<TERMS>::from_coefficients(&[fr(11), fr(1)]).unwrap();
    let rounds = [round0, round1];
    let challenges = [fr(5), fr(7)];

    assert_eq!(poly.hypercube_sum(), fr(10));
    assert_eq!(poly.evaluate(&challenges).unwrap(), fr(18));

    let reduction = verify(&poly, fr(10), &rounds, &challenges).expect("honest vector must verify");
    assert_eq!(reduction.final_evaluation, fr(18));
    assert_eq!(reduction.num_rounds, 2);
    assert_eq!(reduction.challenge_slice(), &challenges);
}

#[test]
fn single_variable_vector_is_accepted() {
    let poly = polynomial(&[fr(5), fr(9)]);
    let rounds = honest_rounds(poly.evaluations(), &[fr(2)]);
    let reduction = verify(&poly, poly.hypercube_sum(), &rounds, &[fr(2)])
        .expect("single-round vector must verify");
    assert_eq!(reduction.final_evaluation, fr(13));
    assert_eq!(poly.evaluate(&[fr(2)]).unwrap(), fr(13));
}

#[test]
fn three_variable_and_gate_vector_is_accepted() {
    // Three-way AND: only the all-ones corner is 1.
    let poly = polynomial(&[fr(0), fr(0), fr(0), fr(0), fr(0), fr(0), fr(0), fr(1)]);
    let challenges = [fr(3), fr(5), fr(11)];
    assert_eq!(poly.hypercube_sum(), fr(1));

    let rounds = honest_rounds(poly.evaluations(), &challenges);
    // Round 0 is the identity: g0(X) = X.
    assert_eq!(rounds[0].coefficients(), &[fr(0), fr(1)]);

    let reduction = verify(&poly, fr(1), &rounds, &challenges).expect("AND vector verifies");
    assert_eq!(reduction.final_evaluation, fr(3 * 5 * 11));
    assert_eq!(poly.evaluate(&challenges).unwrap(), fr(3 * 5 * 11));
}

#[test]
fn sixteen_variable_vector_is_accepted() {
    // Exercise the maximum supported variable count with a non-trivial table.
    // A 2¹⁶-entry table is 2 MiB and the MLE fold needs a second copy, so this
    // runs on a dedicated large stack (see `MultilinearPolynomial::evaluate`).
    std::thread::Builder::new()
        .stack_size(32 * 1024 * 1024)
        .spawn(|| {
            let evaluations: Vec<u256> = (0u64..(1 << 16))
                .map(|i| u256::from(i.wrapping_mul(0x9e37_79b9).wrapping_add(7) % 1_000_003))
                .collect();
            let poly = MultilinearPolynomial::<{ 1 << 16 }>::from_evaluations(&evaluations)
                .expect("2^16 table fits MAX_VARIABLES");
            assert_eq!(poly.num_variables(), 16);

            let challenges: Vec<u256> = (0u64..16).map(|i| fr(i * 17 + 3)).collect();
            let rounds = honest_rounds(poly.evaluations(), &challenges);
            let reduction = verify(&poly, poly.hypercube_sum(), &rounds, &challenges)
                .expect("16-variable vector verifies");
            assert_eq!(reduction.num_rounds, 16);
        })
        .expect("large-stack thread spawns")
        .join()
        .expect("16-variable test must not panic");
}

#[test]
fn zero_polynomial_vectors_are_accepted() {
    let poly = polynomial(&[fr(0), fr(0)]);
    let rounds = honest_rounds(poly.evaluations(), &[fr(9)]);
    assert!(rounds[0].is_zero());
    let reduction = verify(&poly, fr(0), &rounds, &[fr(9)]).expect("zero polynomial must verify");
    assert_eq!(reduction.final_evaluation, fr(0));
}

#[test]
fn round_degree_two_is_supported() {
    // A degree-2 round polynomial (the UltraHonk relation shape).
    let round = RoundPolynomial::<TERMS>::from_coefficients(&[fr(2), fr(3), fr(4)]).unwrap();
    // g(0)+g(1) = 2 + 9 = 11, g(2) = 2 + 6 + 16 = 24.
    let reduction = verify_sumcheck::<8, TERMS>(fr(11), &[round], &[fr(2)]).unwrap();
    assert_eq!(reduction.final_evaluation, fr(24));
}

// ── negative vectors ────────────────────────────────────────────────────────

#[test]
fn tampered_round_polynomial_is_rejected() {
    let poly = polynomial(&[fr(1), fr(2), fr(3), fr(4)]);
    let mut rounds = honest_rounds(poly.evaluations(), &[fr(5), fr(7)]);
    // g0(0) + g0(1) becomes 3 + 9 = 12 != 10.
    rounds[0] = RoundPolynomial::<TERMS>::from_coefficients(&[fr(3), fr(5)]).unwrap();

    assert_eq!(
        verify(&poly, fr(10), &rounds, &[fr(5), fr(7)]),
        Err(ZkError::ConstraintUnsatisfied)
    );
}

#[test]
fn tampered_final_evaluation_is_rejected() {
    let poly = polynomial(&[fr(1), fr(2), fr(3), fr(4)]);
    let mut rounds = honest_rounds(poly.evaluations(), &[fr(5), fr(7)]);
    // Keep every round-consistency check satisfied but shift the final claim.
    rounds[1] = RoundPolynomial::<TERMS>::from_coefficients(&[fr(11), fr(2)]).unwrap();
    // g1(0)+g1(1) = 11 + 13 = 24 != 23 follows from the previous round, so the
    // chain check itself must be the one that fails.
    assert_eq!(
        verify(&poly, fr(10), &rounds, &[fr(5), fr(7)]),
        Err(ZkError::ConstraintUnsatisfied)
    );
}

#[test]
fn oracle_mismatch_is_rejected() {
    // The round chain is internally consistent but describes a different
    // polynomial than the one supplied to the verifier.
    let honest = polynomial(&[fr(1), fr(2), fr(3), fr(4)]);
    let other = polynomial(&[fr(1), fr(2), fr(3), fr(5)]);
    let rounds = honest_rounds(honest.evaluations(), &[fr(5), fr(7)]);

    assert_eq!(
        verify(&other, fr(10), &rounds, &[fr(5), fr(7)]),
        Err(ZkError::ConstraintUnsatisfied)
    );
}

#[test]
fn wrong_claimed_sum_is_rejected() {
    let poly = polynomial(&[fr(1), fr(2), fr(3), fr(4)]);
    let rounds = honest_rounds(poly.evaluations(), &[fr(5), fr(7)]);
    assert_eq!(
        verify_sumcheck::<8, TERMS>(fr(11), &rounds, &[fr(5), fr(7)]),
        Err(ZkError::ConstraintUnsatisfied)
    );
}

#[test]
fn out_of_range_challenge_is_rejected() {
    let poly = polynomial(&[fr(1), fr(2)]);
    let rounds = honest_rounds(poly.evaluations(), &[fr(5)]);
    assert_eq!(
        verify(&poly, fr(3), &rounds, &[Bn254::FR_MODULUS]),
        Err(ZkError::InvalidFieldElement)
    );
}

#[test]
fn mismatched_round_and_challenge_counts_are_rejected() {
    let poly = polynomial(&[fr(1), fr(2), fr(3), fr(4)]);
    let rounds = honest_rounds(poly.evaluations(), &[fr(5), fr(7)]);
    assert_eq!(
        verify_sumcheck::<8, TERMS>(fr(10), &rounds, &[fr(5)]),
        Err(ZkError::InvalidInput)
    );
}

#[test]
fn empty_round_chain_is_rejected() {
    assert_eq!(
        verify_sumcheck::<8, TERMS>(fr(0), &[], &[]),
        Err(ZkError::InvalidInput)
    );
}

#[test]
fn too_many_rounds_are_rejected() {
    let rounds = honest_rounds(&[fr(1), fr(2), fr(3), fr(4)], &[fr(5), fr(7)]);
    assert_eq!(
        verify_sumcheck::<1, TERMS>(fr(10), &rounds, &[fr(5), fr(7)]),
        Err(ZkError::InvalidInput)
    );
}

#[test]
fn too_many_round_terms_are_rejected() {
    let coefficients = [fr(1), fr(2), fr(3), fr(4), fr(5)];
    assert_eq!(
        RoundPolynomial::<TERMS>::from_coefficients(&coefficients),
        Err(ZkError::InvalidInput)
    );
}

#[test]
fn invalid_polynomial_tables_are_rejected() {
    // Empty.
    assert_eq!(
        MultilinearPolynomial::<16>::from_evaluations(&[]),
        Err(ZkError::InvalidInput)
    );
    // Not a power of two.
    assert_eq!(
        MultilinearPolynomial::<16>::from_evaluations(&[fr(1), fr(2), fr(3)]),
        Err(ZkError::InvalidInput)
    );
    // Exceeds capacity.
    let eight = [fr(1); 8];
    assert_eq!(
        MultilinearPolynomial::<4>::from_evaluations(&eight),
        Err(ZkError::InvalidInput)
    );
    // Out-of-range evaluation.
    assert_eq!(
        MultilinearPolynomial::<16>::from_evaluations(&[fr(1), Bn254::FR_MODULUS]),
        Err(ZkError::InvalidFieldElement)
    );
}

#[test]
fn evaluate_rejects_wrong_point_shape_and_bad_coordinates() {
    let poly = polynomial(&[fr(1), fr(2), fr(3), fr(4)]);
    assert_eq!(poly.evaluate(&[fr(1)]), Err(ZkError::InvalidInput));
    assert_eq!(
        poly.evaluate(&[fr(1), Bn254::FR_MODULUS]),
        Err(ZkError::InvalidFieldElement)
    );
    assert_eq!(
        RoundPolynomial::<TERMS>::from_coefficients(&[fr(1)])
            .unwrap()
            .evaluate(Bn254::FR_MODULUS),
        Err(ZkError::InvalidFieldElement)
    );
}

#[test]
fn round_count_must_match_variable_count() {
    let poly = polynomial(&[fr(1), fr(2), fr(3), fr(4)]);
    let rounds = honest_rounds(poly.evaluations(), &[fr(5)]);
    assert_eq!(
        verify(&poly, fr(10), &rounds, &[fr(5)]),
        Err(ZkError::InvalidInput)
    );
}
