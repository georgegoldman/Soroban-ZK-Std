//! # Halo2-IPA Failure Condition Test Vectors (Issue #440)
//!
//! Comprehensive adversarial test suite for the IPA verifier.  Every test
//! represents a class of malicious or malformed input that a soundness-
//! complete verifier **must** reject, or documents a structural invariant
//! that the state machine must enforce regardless of the arithmetic.
//!
//! ## Coverage map
//!
//! | Category                         | Tests                                                    |
//! |----------------------------------|----------------------------------------------------------|
//! | **Field element bounds**         | scalars at / above FR_MODULUS, all-ones bit-pattern      |
//! | **Invalid folding dimensions**   | n ≠ 2^ROUNDS, ROUNDS = 0, n = 0, non-power-of-two n     |
//! | **Malformed cross-terms**        | swapped L/R, negated L, negated R, wrong-round comms     |
//! | **Challenge integrity**          | zero challenge, challenge == r, replayed challenge       |
//! | **State machine ordering**       | finish before all rounds, extra rounds beyond ROUNDS     |
//! | **Final scalar evaluation**      | wrong a_final, wrong b_final, both wrong, off-by-one     |
//! | **Batch verification**           | bad seed, mismatched n, out-of-range proof scalars,      |
//! |                                  | a single bad proof in a multi-proof batch                |
//! | **verify_final_check**           | wrong p_final, wrong G', wrong H', wrong U, all-wrong    |
//! | **Commitment folding formula**   | direct check that P' = u²·L + P + u⁻²·R is enforced    |
//! | **Iterator error isolation**     | bad batches do not abort the iterator                    |
//! | **Proof structural validation**  | IpaProof::validate rejects both and each scalar ≥ r      |

use ethnum::u256;
use soroban_zk_core::{
    halo2_ipa::{
        IpaProof, IpaRoundChallenge, IpaRoundCommitments, IpaRoundState, IpaVerifierState,
    },
    halo2_ipa_batch::{batch_verify_ipa, verify_final_check, BatchIpaInput, BatchIpaIter},
    Bn254, G1Affine, ZkError,
};

// ============================================================================
// Shared helpers
// ============================================================================

/// BN254 G1 generator (x=1, y=2) — a canonical, valid curve point.
fn g1_gen() -> G1Affine {
    G1Affine {
        x: u256::from(1u8),
        y: u256::from(2u8),
    }
}

/// The affine point at infinity / group identity: (0, 0).
fn identity() -> G1Affine {
    G1Affine {
        x: u256::from(0u8),
        y: u256::from(0u8),
    }
}

/// A second distinct valid curve point: 2·G.
fn g1_2gen() -> G1Affine {
    g1_gen().scalar_mul(u256::from(2u8))
}

/// A third distinct valid curve point: 3·G.
fn g1_3gen() -> G1Affine {
    g1_gen().scalar_mul(u256::from(3u8))
}

/// Negate a G1 affine point: (x, y) → (x, Fq − y).
fn negate_g1(p: G1Affine) -> G1Affine {
    if p.x == u256::from(0u8) && p.y == u256::from(0u8) {
        return p;
    }
    G1Affine {
        x: p.x,
        y: Bn254::sub_fq(u256::from(0u8), p.y),
    }
}

/// Build a valid `IpaRoundChallenge` from a small nonzero scalar.
fn challenge(u: u8) -> IpaRoundChallenge {
    IpaRoundChallenge::from_scalar(u256::from(u)).unwrap()
}

/// Build a trivial `IpaProof<ROUNDS>` with identity cross-commitments and
/// unit final scalars — used where the proof content is not under test.
fn trivial_proof<const ROUNDS: usize>() -> IpaProof<ROUNDS> {
    IpaProof::new(
        [IpaRoundCommitments::new(identity(), identity()); ROUNDS],
        u256::from(1u8),
        u256::from(1u8),
    )
}

/// Build a uniform challenge array where every round uses scalar `u`.
fn uniform_challenges<const ROUNDS: usize>(u: u8) -> [IpaRoundChallenge; ROUNDS] {
    [challenge(u); ROUNDS]
}

/// Create a 32-byte seed with the last byte set to `v`.
fn seed(v: u8) -> [u8; 32] {
    let mut s = [0u8; 32];
    s[31] = v;
    s
}

// ============================================================================
// 1. Field element bound validation on IpaProof::validate
// ============================================================================

/// `a_final` exactly equal to FR_MODULUS is out of range.
#[test]
fn proof_validate_a_final_equals_modulus_is_rejected() {
    let comms = [IpaRoundCommitments::new(identity(), identity()); 4];
    let proof = IpaProof::<4>::new(comms, Bn254::FR_MODULUS, u256::from(1u8));
    assert_eq!(proof.validate(), Err(ZkError::InvalidFieldElement));
}

/// `b_final` exactly equal to FR_MODULUS is out of range.
#[test]
fn proof_validate_b_final_equals_modulus_is_rejected() {
    let comms = [IpaRoundCommitments::new(identity(), identity()); 4];
    let proof = IpaProof::<4>::new(comms, u256::from(1u8), Bn254::FR_MODULUS);
    assert_eq!(proof.validate(), Err(ZkError::InvalidFieldElement));
}

/// Both `a_final` and `b_final` above the modulus are rejected.
#[test]
fn proof_validate_both_scalars_above_modulus_is_rejected() {
    let comms = [IpaRoundCommitments::new(identity(), identity()); 4];
    let proof = IpaProof::<4>::new(comms, Bn254::FR_MODULUS, Bn254::FR_MODULUS);
    assert_eq!(proof.validate(), Err(ZkError::InvalidFieldElement));
}

/// `a_final = FR_MODULUS + 1` (off-by-one above) is rejected.
#[test]
fn proof_validate_a_final_one_above_modulus_is_rejected() {
    let comms = [IpaRoundCommitments::new(identity(), identity()); 2];
    let proof = IpaProof::<2>::new(comms, Bn254::FR_MODULUS + u256::from(1u8), u256::from(1u8));
    assert_eq!(proof.validate(), Err(ZkError::InvalidFieldElement));
}

/// `a_final = FR_MODULUS - 1` is the largest valid scalar — must pass.
#[test]
fn proof_validate_a_final_max_valid_scalar_is_accepted() {
    let comms = [IpaRoundCommitments::new(identity(), identity()); 2];
    let proof = IpaProof::<2>::new(comms, Bn254::FR_MODULUS - u256::from(1u8), u256::from(1u8));
    assert!(proof.validate().is_ok());
}

/// All-ones 256-bit pattern (u256::MAX) is well above the modulus — rejected.
#[test]
fn proof_validate_all_ones_scalar_is_rejected() {
    let comms = [IpaRoundCommitments::new(identity(), identity()); 1];
    let all_ones = u256::MAX;
    let proof = IpaProof::<1>::new(comms, all_ones, u256::from(1u8));
    assert_eq!(proof.validate(), Err(ZkError::InvalidFieldElement));
}

/// Zero final scalars are valid field elements (they sit in [0, r)).
#[test]
fn proof_validate_zero_scalars_are_accepted() {
    let comms = [IpaRoundCommitments::new(identity(), identity()); 2];
    let proof = IpaProof::<2>::new(comms, u256::from(0u8), u256::from(0u8));
    assert!(proof.validate().is_ok());
}

// ============================================================================
// 2. IpaRoundChallenge construction failures
// ============================================================================

/// Challenge scalar zero is non-invertible — must be rejected.
#[test]
fn challenge_zero_scalar_is_rejected() {
    assert_eq!(
        IpaRoundChallenge::from_scalar(u256::from(0u8)),
        Err(ZkError::InvalidFieldElement)
    );
}

/// Challenge scalar equal to the field modulus reduces to zero — rejected.
///
/// Note: `from_scalar` receives the raw scalar; if FR_MODULUS is passed
/// without reduction it equals zero mod r and must be rejected.
#[test]
fn challenge_scalar_equals_modulus_is_rejected() {
    // FR_MODULUS ≡ 0 (mod r), which would produce a non-invertible element.
    // The implementation must catch this.
    let result = IpaRoundChallenge::from_scalar(Bn254::FR_MODULUS);
    // Either InvalidFieldElement (if modulus check is applied) or it reduces
    // to zero and is caught by the zero-check.
    assert!(
        result == Err(ZkError::InvalidFieldElement),
        "challenge equal to FR_MODULUS must be rejected, got: {:?}",
        result
    );
}

/// The inverse of a valid challenge must satisfy u · u_inv ≡ 1 (mod r).
#[test]
fn challenge_inverse_product_is_identity() {
    for &scalar in &[2u8, 3, 7, 13, 97, 255] {
        let c = challenge(scalar);
        assert_eq!(
            Bn254::mul(c.u, c.u_inv),
            u256::from(1u8),
            "u·u_inv != 1 for u = {scalar}"
        );
    }
}

/// The squared inverse must satisfy u_sq · u_sq_inv ≡ 1 (mod r).
#[test]
fn challenge_squared_inverse_product_is_identity() {
    for &scalar in &[2u8, 5, 11, 31, 200] {
        let c = challenge(scalar);
        assert_eq!(
            Bn254::mul(c.u_sq, c.u_sq_inv),
            u256::from(1u8),
            "u_sq·u_sq_inv != 1 for u = {scalar}"
        );
    }
}

/// u_sq must equal u·u (mod r).
#[test]
fn challenge_u_sq_equals_u_times_u() {
    for &scalar in &[2u8, 3, 7, 50] {
        let c = challenge(scalar);
        let expected = Bn254::mul(c.u, c.u);
        assert_eq!(c.u_sq, expected, "u_sq != u*u for u = {scalar}");
    }
}

// ============================================================================
// 3. IpaRoundState / IpaVerifierState dimension validation
// ============================================================================

/// `n` must equal `1 << ROUNDS`.  Passing a smaller power of two fails.
#[test]
fn verifier_state_smaller_n_is_rejected() {
    assert_eq!(
        IpaVerifierState::<4>::new(identity(), 8), // 8 != 1<<4 = 16
        Err(ZkError::InvalidInput)
    );
}

/// `n` must equal `1 << ROUNDS`.  Passing a larger power of two fails.
#[test]
fn verifier_state_larger_n_is_rejected() {
    assert_eq!(
        IpaVerifierState::<3>::new(identity(), 16), // 16 != 1<<3 = 8
        Err(ZkError::InvalidInput)
    );
}

/// `n = 0` is always invalid (no power-of-two equals 0).
#[test]
fn verifier_state_n_zero_is_rejected() {
    assert_eq!(
        IpaVerifierState::<3>::new(identity(), 0),
        Err(ZkError::InvalidInput)
    );
}

/// `n = 1` is invalid for ROUNDS ≥ 1 (1 << 1 = 2, not 1).
#[test]
fn verifier_state_n_one_rounds_one_is_rejected() {
    assert_eq!(
        IpaVerifierState::<1>::new(identity(), 1), // 1 != 1<<1 = 2
        Err(ZkError::InvalidInput)
    );
}

/// A non-power-of-two `n` that is adjacent to a valid value must be rejected.
#[test]
fn verifier_state_non_power_of_two_n_is_rejected() {
    // For ROUNDS = 3, valid n = 8. Test n = 7, 9, 6, 10.
    for bad_n in [6, 7, 9, 10, 12, 15] {
        assert_eq!(
            IpaVerifierState::<3>::new(identity(), bad_n),
            Err(ZkError::InvalidInput),
            "n = {bad_n} should be rejected for ROUNDS = 3"
        );
    }
}

/// ROUNDS = 0 makes the proof degenerate — initial state must fail.
#[test]
fn round_state_rounds_zero_is_rejected() {
    assert_eq!(
        IpaRoundState::<0>::initial(identity(), 1),
        Err(ZkError::InvalidInput)
    );
}

/// `finish` before applying any rounds must fail.
#[test]
fn finish_before_any_round_is_rejected() {
    let vs = IpaVerifierState::<3>::new(identity(), 8).unwrap();
    assert_eq!(vs.finish(), Err(ZkError::InvalidInput));
}

/// `finish` after applying only some (but not all) rounds must fail.
#[test]
fn finish_after_partial_rounds_is_rejected() {
    let mut vs = IpaVerifierState::<3>::new(identity(), 8).unwrap();
    let rc = IpaRoundCommitments::new(identity(), identity());

    vs.apply_round(rc, challenge(2)).unwrap(); // round 0
    assert_eq!(vs.finish(), Err(ZkError::InvalidInput), "after 1/3 rounds");

    vs.apply_round(rc, challenge(3)).unwrap(); // round 1
    assert_eq!(vs.finish(), Err(ZkError::InvalidInput), "after 2/3 rounds");
}

/// `apply_round` after all ROUNDS have been applied must fail.
#[test]
fn apply_round_after_completion_is_rejected() {
    let mut vs = IpaVerifierState::<2>::new(identity(), 4).unwrap();
    let rc = IpaRoundCommitments::new(identity(), identity());

    vs.apply_round(rc, challenge(2)).unwrap();
    vs.apply_round(rc, challenge(3)).unwrap();

    // The verifier is now complete — one more round must be rejected.
    assert_eq!(vs.apply_round(rc, challenge(4)), Err(ZkError::InvalidInput));
}

/// Applying more than ROUNDS rounds must fail even for large ROUNDS.
#[test]
fn apply_round_overflow_is_rejected_for_large_rounds() {
    let mut vs = IpaVerifierState::<4>::new(identity(), 16).unwrap();
    let rc = IpaRoundCommitments::new(identity(), identity());
    for i in 0..4u8 {
        vs.apply_round(rc, challenge(i + 2)).unwrap();
    }
    assert_eq!(vs.apply_round(rc, challenge(7)), Err(ZkError::InvalidInput));
}

// ============================================================================
// 4. Commitment folding formula — direct integrity checks
// ============================================================================

/// The folded commitment must equal `u²·L + P + u⁻²·R`.
/// Injecting an incorrect L (a different point) must produce a different
/// folded commitment, catching malformed cross-terms.
#[test]
fn fold_with_wrong_l_produces_different_commitment() {
    let p = g1_gen();
    let r_point = g1_2gen();
    let u_val = challenge(5);

    // Correct fold: L = 3·G.
    let correct_l = g1_3gen();
    let mut vs_correct = IpaVerifierState::<1>::new(p, 2).unwrap();
    vs_correct
        .apply_round(IpaRoundCommitments::new(correct_l, r_point), u_val)
        .unwrap();
    let correct_state = vs_correct.finish().unwrap();

    // Malformed fold: L = 2·G (different from the correct one).
    let wrong_l = g1_2gen();
    let mut vs_wrong = IpaVerifierState::<1>::new(p, 2).unwrap();
    vs_wrong
        .apply_round(IpaRoundCommitments::new(wrong_l, r_point), u_val)
        .unwrap();
    let wrong_state = vs_wrong.finish().unwrap();

    assert_ne!(
        correct_state.folded_commitment, wrong_state.folded_commitment,
        "different L must produce different folded commitment"
    );
}

/// Injecting an incorrect R must produce a different folded commitment.
#[test]
fn fold_with_wrong_r_produces_different_commitment() {
    let p = g1_gen();
    let l_point = g1_2gen();
    let u_val = challenge(7);

    let correct_r = g1_3gen();
    let mut vs_correct = IpaVerifierState::<1>::new(p, 2).unwrap();
    vs_correct
        .apply_round(IpaRoundCommitments::new(l_point, correct_r), u_val)
        .unwrap();
    let correct_state = vs_correct.finish().unwrap();

    let wrong_r = g1_2gen();
    let mut vs_wrong = IpaVerifierState::<1>::new(p, 2).unwrap();
    vs_wrong
        .apply_round(IpaRoundCommitments::new(l_point, wrong_r), u_val)
        .unwrap();
    let wrong_state = vs_wrong.finish().unwrap();

    assert_ne!(
        correct_state.folded_commitment, wrong_state.folded_commitment,
        "different R must produce different folded commitment"
    );
}

/// Swapping L and R (cross-term inversion) must produce a different result
/// unless L == R (the swap is a distinct attack, not a degenerate case).
#[test]
fn fold_with_swapped_l_and_r_produces_different_commitment() {
    let p = g1_gen();
    let l_point = g1_2gen();
    let r_point = g1_3gen();
    let u_val = challenge(11);

    let mut vs_correct = IpaVerifierState::<1>::new(p, 2).unwrap();
    vs_correct
        .apply_round(IpaRoundCommitments::new(l_point, r_point), u_val)
        .unwrap();
    let correct_state = vs_correct.finish().unwrap();

    // Attack: swap L and R.
    let mut vs_swapped = IpaVerifierState::<1>::new(p, 2).unwrap();
    vs_swapped
        .apply_round(IpaRoundCommitments::new(r_point, l_point), u_val)
        .unwrap();
    let swapped_state = vs_swapped.finish().unwrap();

    // Because u ≠ u⁻¹ in general, swapping yields a different result.
    assert_ne!(
        correct_state.folded_commitment, swapped_state.folded_commitment,
        "swapping L and R must change the folded commitment"
    );
}

/// Negating L must change the folded commitment (tests sign-flip attack).
#[test]
fn fold_with_negated_l_produces_different_commitment() {
    let p = g1_gen();
    let l_point = g1_2gen();
    let r_point = g1_3gen();
    let u_val = challenge(13);

    let mut vs_correct = IpaVerifierState::<1>::new(p, 2).unwrap();
    vs_correct
        .apply_round(IpaRoundCommitments::new(l_point, r_point), u_val)
        .unwrap();
    let correct_state = vs_correct.finish().unwrap();

    let mut vs_neg = IpaVerifierState::<1>::new(p, 2).unwrap();
    vs_neg
        .apply_round(IpaRoundCommitments::new(negate_g1(l_point), r_point), u_val)
        .unwrap();
    let neg_state = vs_neg.finish().unwrap();

    assert_ne!(
        correct_state.folded_commitment, neg_state.folded_commitment,
        "negating L must change the folded commitment"
    );
}

/// Negating R must change the folded commitment.
#[test]
fn fold_with_negated_r_produces_different_commitment() {
    let p = g1_gen();
    let l_point = g1_2gen();
    let r_point = g1_3gen();
    let u_val = challenge(17);

    let mut vs_correct = IpaVerifierState::<1>::new(p, 2).unwrap();
    vs_correct
        .apply_round(IpaRoundCommitments::new(l_point, r_point), u_val)
        .unwrap();
    let correct_state = vs_correct.finish().unwrap();

    let mut vs_neg = IpaVerifierState::<1>::new(p, 2).unwrap();
    vs_neg
        .apply_round(IpaRoundCommitments::new(l_point, negate_g1(r_point)), u_val)
        .unwrap();
    let neg_state = vs_neg.finish().unwrap();

    assert_ne!(
        correct_state.folded_commitment, neg_state.folded_commitment,
        "negating R must change the folded commitment"
    );
}

/// Using a different challenge (wrong Fiat-Shamir scalar) must produce a
/// different folded commitment — validates challenge binding.
#[test]
fn fold_with_wrong_challenge_produces_different_commitment() {
    let p = g1_gen();
    let l_point = g1_2gen();
    let r_point = g1_3gen();

    let correct_u = challenge(5);
    let wrong_u = challenge(7);

    let mut vs_correct = IpaVerifierState::<1>::new(p, 2).unwrap();
    vs_correct
        .apply_round(IpaRoundCommitments::new(l_point, r_point), correct_u)
        .unwrap();
    let correct_state = vs_correct.finish().unwrap();

    let mut vs_wrong = IpaVerifierState::<1>::new(p, 2).unwrap();
    vs_wrong
        .apply_round(IpaRoundCommitments::new(l_point, r_point), wrong_u)
        .unwrap();
    let wrong_state = vs_wrong.finish().unwrap();

    assert_ne!(
        correct_state.folded_commitment, wrong_state.folded_commitment,
        "a different challenge must change the folded commitment"
    );
}

/// Changing the initial commitment (the proof commitment P) must change the
/// final folded commitment — the verifier is bound to the original P.
#[test]
fn fold_with_wrong_initial_commitment_produces_different_result() {
    let l_point = g1_2gen();
    let r_point = g1_3gen();
    let u_val = challenge(3);

    let correct_p = g1_gen();
    let wrong_p = g1_2gen();

    let mut vs_correct = IpaVerifierState::<1>::new(correct_p, 2).unwrap();
    vs_correct
        .apply_round(IpaRoundCommitments::new(l_point, r_point), u_val)
        .unwrap();
    let correct_state = vs_correct.finish().unwrap();

    let mut vs_wrong = IpaVerifierState::<1>::new(wrong_p, 2).unwrap();
    vs_wrong
        .apply_round(IpaRoundCommitments::new(l_point, r_point), u_val)
        .unwrap();
    let wrong_state = vs_wrong.finish().unwrap();

    assert_ne!(
        correct_state.folded_commitment, wrong_state.folded_commitment,
        "different initial commitment must propagate to different final state"
    );
}

/// Multi-round test: injecting a malformed cross-term in round 1 of a 3-round
/// IPA must produce a different final state from the honest transcript.
#[test]
fn fold_malformed_cross_term_in_first_round_propagates_to_final_state() {
    let p = g1_gen();
    let rc_good = IpaRoundCommitments::new(g1_2gen(), g1_3gen());
    let rc_bad = IpaRoundCommitments::new(g1_3gen(), g1_2gen()); // swapped L/R
    let rc_neutral = IpaRoundCommitments::new(identity(), identity());
    let u1 = challenge(2);
    let u2 = challenge(3);
    let u3 = challenge(5);

    // Honest path.
    let mut honest = IpaVerifierState::<3>::new(p, 8).unwrap();
    honest.apply_round(rc_good, u1).unwrap();
    honest.apply_round(rc_neutral, u2).unwrap();
    honest.apply_round(rc_neutral, u3).unwrap();
    let honest_state = honest.finish().unwrap();

    // Adversarial path: bad cross-term in round 0.
    let mut adv = IpaVerifierState::<3>::new(p, 8).unwrap();
    adv.apply_round(rc_bad, u1).unwrap();
    adv.apply_round(rc_neutral, u2).unwrap();
    adv.apply_round(rc_neutral, u3).unwrap();
    let adv_state = adv.finish().unwrap();

    assert_ne!(
        honest_state.folded_commitment, adv_state.folded_commitment,
        "malformed cross-term in round 0 must corrupt the final folded commitment"
    );
}

/// Multi-round test: injecting a malformed cross-term in the *last* round
/// must also change the final state (no "late-round forgery" weakness).
#[test]
fn fold_malformed_cross_term_in_last_round_corrupts_final_state() {
    let p = g1_gen();
    let rc_neutral = IpaRoundCommitments::new(identity(), identity());
    let rc_good = IpaRoundCommitments::new(g1_2gen(), g1_3gen());
    let rc_bad = IpaRoundCommitments::new(g1_3gen(), g1_2gen());
    let u1 = challenge(2);
    let u2 = challenge(3);
    let u3 = challenge(7);

    let mut honest = IpaVerifierState::<3>::new(p, 8).unwrap();
    honest.apply_round(rc_neutral, u1).unwrap();
    honest.apply_round(rc_neutral, u2).unwrap();
    honest.apply_round(rc_good, u3).unwrap();
    let honest_state = honest.finish().unwrap();

    let mut adv = IpaVerifierState::<3>::new(p, 8).unwrap();
    adv.apply_round(rc_neutral, u1).unwrap();
    adv.apply_round(rc_neutral, u2).unwrap();
    adv.apply_round(rc_bad, u3).unwrap();
    let adv_state = adv.finish().unwrap();

    assert_ne!(
        honest_state.folded_commitment, adv_state.folded_commitment,
        "malformed cross-term in the final round must corrupt the final state"
    );
}

// ============================================================================
// 5. Challenge history integrity
// ============================================================================

/// After all rounds the challenge history must match the order in which
/// challenges were applied (no reordering by the state machine).
#[test]
fn challenge_history_records_correct_order() {
    let p = identity();
    let rc = IpaRoundCommitments::new(identity(), identity());
    let c1 = challenge(2);
    let c2 = challenge(3);
    let c3 = challenge(5);

    let mut vs = IpaVerifierState::<3>::new(p, 8).unwrap();
    vs.apply_round(rc, c1).unwrap();
    vs.apply_round(rc, c2).unwrap();
    vs.apply_round(rc, c3).unwrap();
    let state = vs.finish().unwrap();

    assert_eq!(state.challenges[0].u, u256::from(2u8));
    assert_eq!(state.challenges[1].u, u256::from(3u8));
    assert_eq!(state.challenges[2].u, u256::from(5u8));
}

/// Replaying the same challenge in every round produces a state distinct
/// from one that uses varied challenges — confirms there is no silent
/// de-duplication of challenges.
#[test]
fn replayed_challenge_in_all_rounds_differs_from_varied_challenges() {
    let p = g1_gen();
    let rc = IpaRoundCommitments::new(g1_2gen(), g1_3gen());

    let mut vs_replay = IpaVerifierState::<3>::new(p, 8).unwrap();
    for _ in 0..3 {
        vs_replay.apply_round(rc, challenge(4)).unwrap();
    }
    let replay_state = vs_replay.finish().unwrap();

    let mut vs_varied = IpaVerifierState::<3>::new(p, 8).unwrap();
    vs_varied.apply_round(rc, challenge(2)).unwrap();
    vs_varied.apply_round(rc, challenge(3)).unwrap();
    vs_varied.apply_round(rc, challenge(4)).unwrap();
    let varied_state = vs_varied.finish().unwrap();

    assert_ne!(
        replay_state.folded_commitment, varied_state.folded_commitment,
        "replayed challenges should differ from unique challenges"
    );
}

// ============================================================================
// 6. Final scalar evaluation — verify_final_check failure modes
// ============================================================================

/// Wrong `p_final` with correct scalars and generators must be rejected.
#[test]
fn final_check_wrong_p_final_is_rejected() {
    let out = soroban_zk_core::halo2_ipa_batch::BatchIpaOutput {
        a_combined: u256::from(1u8),
        b_combined: u256::from(1u8),
        inner_product: u256::from(1u8),
    };
    let g_prime = identity();
    let h_prime = identity();
    let u_base = identity();
    // a·G' + b·H' + ip·U = identity. p_final ≠ identity → reject.
    let wrong_p_final = g1_gen();
    assert_eq!(
        verify_final_check(&out, wrong_p_final, g_prime, h_prime, u_base),
        Err(ZkError::ConstraintUnsatisfied)
    );
}

/// Correct p_final but wrong G' (different basis) must be rejected.
#[test]
fn final_check_wrong_g_prime_is_rejected() {
    // Set up so that a·G' + b·H' + ip·U = some known point.
    // Use a=1, b=0, ip=0, G' = generator → result = G.
    let out = soroban_zk_core::halo2_ipa_batch::BatchIpaOutput {
        a_combined: u256::from(1u8),
        b_combined: u256::from(0u8),
        inner_product: u256::from(0u8),
    };
    let correct_g_prime = g1_gen();
    let h_prime = identity();
    let u_base = identity();
    let p_final = g1_gen(); // matches 1·G + 0·H + 0·U = G

    // Correct case passes.
    assert!(verify_final_check(&out, p_final, correct_g_prime, h_prime, u_base).is_ok());

    // Wrong G' must fail.
    let wrong_g_prime = g1_2gen();
    assert_eq!(
        verify_final_check(&out, p_final, wrong_g_prime, h_prime, u_base),
        Err(ZkError::ConstraintUnsatisfied)
    );
}

/// Correct p_final but wrong H' must be rejected.
#[test]
fn final_check_wrong_h_prime_is_rejected() {
    // a=0, b=1, ip=0, H' = 2·G → result = 2·G.
    let out = soroban_zk_core::halo2_ipa_batch::BatchIpaOutput {
        a_combined: u256::from(0u8),
        b_combined: u256::from(1u8),
        inner_product: u256::from(0u8),
    };
    let g_prime = identity();
    let correct_h_prime = g1_2gen();
    let u_base = identity();
    let p_final = g1_2gen();

    assert!(verify_final_check(&out, p_final, g_prime, correct_h_prime, u_base).is_ok());

    let wrong_h_prime = g1_3gen();
    assert_eq!(
        verify_final_check(&out, p_final, g_prime, wrong_h_prime, u_base),
        Err(ZkError::ConstraintUnsatisfied)
    );
}

/// Correct p_final but wrong U base must be rejected.
#[test]
fn final_check_wrong_u_base_is_rejected() {
    // a=0, b=0, ip=1, U = 3·G → result = 3·G.
    let out = soroban_zk_core::halo2_ipa_batch::BatchIpaOutput {
        a_combined: u256::from(0u8),
        b_combined: u256::from(0u8),
        inner_product: u256::from(1u8),
    };
    let g_prime = identity();
    let h_prime = identity();
    let correct_u_base = g1_3gen();
    let p_final = g1_3gen();

    assert!(verify_final_check(&out, p_final, g_prime, h_prime, correct_u_base).is_ok());

    let wrong_u_base = g1_2gen();
    assert_eq!(
        verify_final_check(&out, p_final, g_prime, h_prime, wrong_u_base),
        Err(ZkError::ConstraintUnsatisfied)
    );
}

/// All four arguments wrong must still be rejected (no accidental cancellation).
#[test]
fn final_check_all_arguments_wrong_is_rejected() {
    let out = soroban_zk_core::halo2_ipa_batch::BatchIpaOutput {
        a_combined: u256::from(2u8),
        b_combined: u256::from(3u8),
        inner_product: Bn254::mul(u256::from(2u8), u256::from(3u8)),
    };
    assert_eq!(
        verify_final_check(&out, g1_3gen(), g1_2gen(), g1_gen(), g1_gen()),
        Err(ZkError::ConstraintUnsatisfied)
    );
}

/// Inner product field is inconsistent with a·b: the caller-supplied `inner_product`
/// field is used verbatim, so if an adversary sets it to a wrong value the
/// final check must fail.
#[test]
fn final_check_wrong_inner_product_value_is_rejected() {
    // a=1, b=2, correct ip = 2.  Adversary claims ip = 3.
    let out_bad_ip = soroban_zk_core::halo2_ipa_batch::BatchIpaOutput {
        a_combined: u256::from(1u8),
        b_combined: u256::from(2u8),
        inner_product: u256::from(3u8), // wrong: should be 1*2 = 2
    };
    // p_final built from the *correct* ip=2: a·G + b·H + 2·U
    let g_prime = g1_gen();
    let h_prime = g1_2gen();
    let u_base = g1_3gen();
    // Compute the honest p_final: 1·G + 2·(2G) + 2·(3G) = G + 4G + 6G = 11G
    let p_final = g1_gen()
        .scalar_mul(u256::from(1u8))
        .add(&g1_2gen().scalar_mul(u256::from(2u8)))
        .add(&g1_3gen().scalar_mul(u256::from(2u8)));

    assert_eq!(
        verify_final_check(&out_bad_ip, p_final, g_prime, h_prime, u_base),
        Err(ZkError::ConstraintUnsatisfied),
        "wrong inner_product in output must cause final check to fail"
    );
}

// ============================================================================
// 7. Batch verification failure modes
// ============================================================================

/// Batch seed that reduces to zero mod r must be rejected.
#[test]
fn batch_verify_zero_seed_rejected() {
    let input = BatchIpaInput::<1, 2> {
        commitments: [identity()],
        proofs: [trivial_proof::<2>()],
        challenges: uniform_challenges::<2>(3),
        batch_seed: [0u8; 32],
    };
    assert_eq!(
        batch_verify_ipa(&input, 4),
        Err(ZkError::InvalidFieldElement)
    );
}

/// `n` that does not match `1 << ROUNDS` must be rejected.
#[test]
fn batch_verify_wrong_n_is_rejected() {
    let input = BatchIpaInput::<1, 3> {
        commitments: [identity()],
        proofs: [trivial_proof::<3>()],
        challenges: uniform_challenges::<3>(3),
        batch_seed: seed(5),
    };
    // Correct n = 8 for ROUNDS = 3.  We pass 16.
    assert_eq!(batch_verify_ipa(&input, 16), Err(ZkError::InvalidInput));
}

/// `n` that is too small (half the correct value) is rejected.
#[test]
fn batch_verify_n_too_small_is_rejected() {
    let input = BatchIpaInput::<1, 3> {
        commitments: [identity()],
        proofs: [trivial_proof::<3>()],
        challenges: uniform_challenges::<3>(3),
        batch_seed: seed(5),
    };
    assert_eq!(batch_verify_ipa(&input, 4), Err(ZkError::InvalidInput));
}

/// A single proof in a batch with `a_final ≥ FR_MODULUS` must cause the
/// whole batch to fail structural validation before any arithmetic.
#[test]
fn batch_verify_one_proof_bad_a_final_rejects_batch() {
    let bad_proof = IpaProof::<2>::new(
        [IpaRoundCommitments::new(identity(), identity()); 2],
        Bn254::FR_MODULUS, // out of range
        u256::from(1u8),
    );
    let input = BatchIpaInput::<2, 2> {
        commitments: [identity(); 2],
        proofs: [trivial_proof::<2>(), bad_proof],
        challenges: uniform_challenges::<2>(3),
        batch_seed: seed(5),
    };
    assert_eq!(
        batch_verify_ipa(&input, 4),
        Err(ZkError::InvalidFieldElement)
    );
}

/// A single proof in a batch with `b_final ≥ FR_MODULUS` must cause
/// batch validation to fail.
#[test]
fn batch_verify_one_proof_bad_b_final_rejects_batch() {
    let bad_proof = IpaProof::<3>::new(
        [IpaRoundCommitments::new(identity(), identity()); 3],
        u256::from(1u8),
        Bn254::FR_MODULUS + u256::from(5u8), // out of range
    );
    let input = BatchIpaInput::<2, 3> {
        commitments: [identity(); 2],
        proofs: [trivial_proof::<3>(), bad_proof],
        challenges: uniform_challenges::<3>(3),
        batch_seed: seed(7),
    };
    assert_eq!(
        batch_verify_ipa(&input, 8),
        Err(ZkError::InvalidFieldElement)
    );
}

/// All proofs bad in a batch: all-ones scalars (u256::MAX) are far above r.
#[test]
fn batch_verify_all_proofs_with_max_scalar_rejected() {
    let bad_proof = IpaProof::<2>::new(
        [IpaRoundCommitments::new(identity(), identity()); 2],
        u256::MAX,
        u256::MAX,
    );
    let input = BatchIpaInput::<3, 2> {
        commitments: [identity(); 3],
        proofs: [bad_proof; 3],
        challenges: uniform_challenges::<2>(3),
        batch_seed: seed(9),
    };
    assert_eq!(
        batch_verify_ipa(&input, 4),
        Err(ZkError::InvalidFieldElement)
    );
}

/// Batch with `M = 0` proofs is structurally invalid.
#[test]
fn batch_verify_m_zero_is_rejected() {
    let input = BatchIpaInput::<0, 2> {
        commitments: [],
        proofs: [],
        challenges: uniform_challenges::<2>(3),
        batch_seed: seed(1),
    };
    assert_eq!(batch_verify_ipa(&input, 4), Err(ZkError::InvalidInput));
}

/// The combined final scalars must match the accumulated individual scalars.
/// This is a positive test: `a_combined = Σ ρ_j · a_j`.
#[test]
fn batch_verify_combined_scalars_match_manual_accumulation() {
    // Single proof with a_final = 5, b_final = 7.
    let proof = IpaProof::<2>::new(
        [IpaRoundCommitments::new(identity(), identity()); 2],
        u256::from(5u8),
        u256::from(7u8),
    );
    let input = BatchIpaInput::<1, 2> {
        commitments: [identity()],
        proofs: [proof],
        challenges: uniform_challenges::<2>(3),
        batch_seed: seed(11),
    };
    let out = batch_verify_ipa(&input, 4).unwrap();

    // ρ_0 = seed_scalar = seed(11) mod r.
    let rho0 = u256::from_be_bytes(seed(11)) % Bn254::FR_MODULUS;
    assert_eq!(out.a_combined, Bn254::mul(rho0, u256::from(5u8)));
    assert_eq!(out.b_combined, Bn254::mul(rho0, u256::from(7u8)));
    assert_eq!(
        out.inner_product,
        Bn254::mul(out.a_combined, out.b_combined)
    );
}

/// With two proofs the combined scalars must satisfy the linear accumulation.
#[test]
fn batch_verify_two_proofs_combined_scalars_are_correct() {
    // Two proofs: (a=2, b=3) and (a=4, b=5).
    let p1 = IpaProof::<2>::new(
        [IpaRoundCommitments::new(identity(), identity()); 2],
        u256::from(2u8),
        u256::from(3u8),
    );
    let p2 = IpaProof::<2>::new(
        [IpaRoundCommitments::new(identity(), identity()); 2],
        u256::from(4u8),
        u256::from(5u8),
    );
    let input = BatchIpaInput::<2, 2> {
        commitments: [identity(); 2],
        proofs: [p1, p2],
        challenges: uniform_challenges::<2>(3),
        batch_seed: seed(13),
    };
    let out = batch_verify_ipa(&input, 4).unwrap();

    let rho0 = u256::from_be_bytes(seed(13)) % Bn254::FR_MODULUS;
    let rho1 = Bn254::mul(rho0, rho0);
    let expected_a = Bn254::add(
        Bn254::mul(rho0, u256::from(2u8)),
        Bn254::mul(rho1, u256::from(4u8)),
    );
    let expected_b = Bn254::add(
        Bn254::mul(rho0, u256::from(3u8)),
        Bn254::mul(rho1, u256::from(5u8)),
    );

    assert_eq!(out.a_combined, expected_a);
    assert_eq!(out.b_combined, expected_b);
}

// ============================================================================
// 8. BatchIpaIter — error isolation and ordering guarantees
// ============================================================================

/// A bad batch (zero seed) surrounded by valid batches: the iterator must
/// return an error for the bad one and `Ok` for the valid ones, without
/// short-circuiting.
#[test]
fn batch_iter_bad_middle_batch_does_not_abort_iteration() {
    let good_input = || BatchIpaInput::<1, 2> {
        commitments: [identity()],
        proofs: [trivial_proof::<2>()],
        challenges: uniform_challenges::<2>(3),
        batch_seed: seed(5),
    };
    let bad_input = BatchIpaInput::<1, 2> {
        commitments: [identity()],
        proofs: [trivial_proof::<2>()],
        challenges: uniform_challenges::<2>(3),
        batch_seed: [0u8; 32], // invalid seed
    };
    let inputs = [good_input(), bad_input, good_input()];
    let mut iter = BatchIpaIter::new(&inputs, 4);

    assert!(iter.next().unwrap().is_ok(), "first batch should succeed");
    assert!(
        iter.next().unwrap().is_err(),
        "second batch (bad seed) should fail"
    );
    assert!(iter.next().unwrap().is_ok(), "third batch should succeed");
    assert!(iter.next().is_none(), "iterator should be exhausted");
}

/// The iterator's `remaining` count decrements correctly on each `next` call.
#[test]
fn batch_iter_remaining_count_is_accurate() {
    let inputs = [
        BatchIpaInput::<1, 2> {
            commitments: [identity()],
            proofs: [trivial_proof::<2>()],
            challenges: uniform_challenges::<2>(3),
            batch_seed: seed(2),
        },
        BatchIpaInput::<1, 2> {
            commitments: [identity()],
            proofs: [trivial_proof::<2>()],
            challenges: uniform_challenges::<2>(3),
            batch_seed: seed(4),
        },
        BatchIpaInput::<1, 2> {
            commitments: [identity()],
            proofs: [trivial_proof::<2>()],
            challenges: uniform_challenges::<2>(3),
            batch_seed: seed(6),
        },
    ];
    let mut iter = BatchIpaIter::new(&inputs, 4);
    assert_eq!(iter.remaining(), 3);
    iter.next();
    assert_eq!(iter.remaining(), 2);
    iter.next();
    assert_eq!(iter.remaining(), 1);
    iter.next();
    assert_eq!(iter.remaining(), 0);
}

/// After reset the iterator replays the same results deterministically,
/// including any errors.
#[test]
fn batch_iter_reset_replays_results_including_errors() {
    let inputs = [
        BatchIpaInput::<1, 2> {
            commitments: [identity()],
            proofs: [trivial_proof::<2>()],
            challenges: uniform_challenges::<2>(3),
            batch_seed: seed(7),
        },
        BatchIpaInput::<1, 2> {
            commitments: [identity()],
            proofs: [trivial_proof::<2>()],
            challenges: uniform_challenges::<2>(3),
            batch_seed: [0u8; 32], // will error
        },
    ];
    let mut iter = BatchIpaIter::new(&inputs, 4);

    let r1 = iter.next().unwrap().unwrap();
    let e2 = iter.next().unwrap().unwrap_err();
    assert!(iter.next().is_none());

    iter.reset();
    assert_eq!(iter.next().unwrap().unwrap(), r1);
    assert_eq!(iter.next().unwrap().unwrap_err(), e2);
}

// ============================================================================
// 9. Folding formula — direct arithmetic regression
// ============================================================================

/// Manually compute P' = u²·L + P + u⁻²·R for a concrete challenge and
/// compare with the verifier output.  Detects any formula inversion bug.
#[test]
fn fold_formula_matches_manual_computation_with_concrete_points() {
    let p = g1_gen();
    let l = g1_2gen();
    let r = g1_3gen();
    let u_val = challenge(5);

    // Manual: u²·L + P + u⁻²·R
    let expected = l
        .scalar_mul(u_val.u_sq)
        .add(&p)
        .add(&r.scalar_mul(u_val.u_sq_inv));

    let mut vs = IpaVerifierState::<1>::new(p, 2).unwrap();
    vs.apply_round(IpaRoundCommitments::new(l, r), u_val)
        .unwrap();
    let state = vs.finish().unwrap();

    assert_eq!(
        state.folded_commitment, expected,
        "fold formula P' = u²·L + P + u⁻²·R must be implemented correctly"
    );
}

/// Verify that u² weight (not u) is applied to L, and u⁻² (not u⁻¹) to R.
/// A bug that uses u and u⁻¹ instead would produce the wrong result.
#[test]
fn fold_formula_uses_squared_weights_not_linear() {
    let p = g1_gen();
    let l = g1_2gen();
    let r = g1_3gen();
    let u_val = challenge(7);

    // What the code SHOULD produce (correct formula with u²/u⁻²).
    let correct = l
        .scalar_mul(u_val.u_sq)
        .add(&p)
        .add(&r.scalar_mul(u_val.u_sq_inv));

    // What an incorrect implementation using u/u⁻¹ would produce.
    let incorrect_linear = l
        .scalar_mul(u_val.u)
        .add(&p)
        .add(&r.scalar_mul(u_val.u_inv));

    // The two formulas should differ for a non-trivial challenge and non-identity points.
    assert_ne!(
        correct, incorrect_linear,
        "u²/u⁻² weights must differ from u/u⁻¹ weights for non-trivial inputs"
    );

    // Now confirm the verifier state uses the correct squared formula.
    let mut vs = IpaVerifierState::<1>::new(p, 2).unwrap();
    vs.apply_round(IpaRoundCommitments::new(l, r), u_val)
        .unwrap();
    let state = vs.finish().unwrap();
    assert_eq!(state.folded_commitment, correct);
    assert_ne!(state.folded_commitment, incorrect_linear);
}

/// With identity cross-terms (L = R = 0), folding must leave P unchanged
/// regardless of the challenge.
#[test]
fn fold_with_identity_cross_terms_leaves_commitment_unchanged() {
    let p = g1_gen();
    for u_scalar in [2u8, 5, 13, 99, 200] {
        let u_val = challenge(u_scalar);
        let mut vs = IpaVerifierState::<1>::new(p, 2).unwrap();
        vs.apply_round(IpaRoundCommitments::new(identity(), identity()), u_val)
            .unwrap();
        let state = vs.finish().unwrap();
        assert_eq!(
            state.folded_commitment, p,
            "identity cross-terms must leave P unchanged for u = {u_scalar}"
        );
    }
}

// ============================================================================
// 10. State machine invariants — active_len and round_index
// ============================================================================

/// After each round `active_len` must be halved exactly.
#[test]
fn active_len_halves_each_round() {
    let mut vs = IpaVerifierState::<4>::new(identity(), 16).unwrap();
    let rc = IpaRoundCommitments::new(identity(), identity());
    let expected_lens = [8, 4, 2, 1];

    for (i, &expected) in expected_lens.iter().enumerate() {
        vs.apply_round(rc, challenge((i as u8) + 2)).unwrap();
        assert_eq!(
            vs.state().active_len,
            expected,
            "active_len must be {expected} after round {i}"
        );
    }
}

/// `round_index` must increment by exactly 1 per applied round.
#[test]
fn round_index_increments_by_one_per_round() {
    let mut vs = IpaVerifierState::<4>::new(identity(), 16).unwrap();
    let rc = IpaRoundCommitments::new(identity(), identity());

    for expected_index in 1..=4u8 {
        vs.apply_round(rc, challenge(expected_index + 1)).unwrap();
        assert_eq!(
            vs.state().round_index,
            expected_index as usize,
            "round_index must be {expected_index} after round {expected_index}"
        );
    }
}

/// `is_complete` must be false during rounds and true only at the end.
#[test]
fn is_complete_returns_false_during_rounds_and_true_at_end() {
    let mut vs = IpaVerifierState::<3>::new(identity(), 8).unwrap();
    let rc = IpaRoundCommitments::new(identity(), identity());

    assert!(!vs.state().is_complete());
    vs.apply_round(rc, challenge(2)).unwrap();
    assert!(!vs.state().is_complete());
    vs.apply_round(rc, challenge(3)).unwrap();
    assert!(!vs.state().is_complete());
    vs.apply_round(rc, challenge(5)).unwrap();
    assert!(vs.state().is_complete());
}
