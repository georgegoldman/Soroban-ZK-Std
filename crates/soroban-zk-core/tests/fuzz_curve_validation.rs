//! Phase 3 — Fuzzing the curve-validation components (G1 & G2 point parsing).
//!
//! The contract never trusts externally supplied curve points: every point is
//! run through `is_valid_g1` / `is_valid_g1_subgroup` (G1) and `is_on_curve` /
//! `is_in_correct_subgroup` (G2) before being used. This suite bombards those
//! validators with randomised, malformed, and out-of-bounds 32-byte coordinate
//! inputs to guarantee they *never panic* and that an invalid point is always
//! rejected (subgroup membership implies on-curve validity, and any coordinate
//! outside `Fq` can never be a valid point).
//!
//! `proptest` acts as the fuzzing engine: on the first failure it prints the
//! PRNG seed and the minimal counterexample, satisfying the determinism
//! requirement so the edge case can be frozen as a regression test.

use ethnum::u256;
use proptest::prelude::*;
use soroban_zk_core::Bn254;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1024))]

    #[test]
    fn fuzz_g1_validation_no_panic(xb in any::<[u8; 32]>(), yb in any::<[u8; 32]>()) {
        let x = u256::from_be_bytes(xb);
        let y = u256::from_be_bytes(yb);

        // These must never panic regardless of input.
        let valid = Bn254::is_valid_g1(x, y);
        let in_subgroup = Bn254::is_valid_g1_subgroup(x, y);

        // Invariant: subgroup membership strictly implies on-curve validity.
        prop_assert!(!in_subgroup || valid);

        // Any coordinate outside the base field can never be a valid point.
        if x >= Bn254::FQ_MODULUS || y >= Bn254::FQ_MODULUS {
            prop_assert!(!valid, "coordinate outside Fq must be rejected");
        }
    }

    #[test]
    fn fuzz_g1_byte_decoding_no_panic(b in any::<[u8; 32]>()) {
        // Raw Fr/Fq decoding must always return an Option, never panic.
        let _ = Bn254::fr_from_bytes(b);
        let _ = Bn254::fq_from_bytes(b);
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn fuzz_g2_validation_no_panic(
        x0b in any::<[u8; 32]>(),
        x1b in any::<[u8; 32]>(),
        y0b in any::<[u8; 32]>(),
        y1b in any::<[u8; 32]>(),
    ) {
        let x = (u256::from_be_bytes(x0b), u256::from_be_bytes(x1b));
        let y = (u256::from_be_bytes(y0b), u256::from_be_bytes(y1b));

        // Never panic — the subgroup check runs the ψ endomorphism test.
        let on_curve = Bn254::is_on_curve(x, y);
        let in_subgroup = Bn254::is_in_correct_subgroup(x, y);

        // Invariant: subgroup membership implies on-curve validity.
        prop_assert!(!in_subgroup || on_curve);

        // Any Fq² coefficient outside the base field can never be on-curve.
        if x.0 >= Bn254::FQ_MODULUS
            || x.1 >= Bn254::FQ_MODULUS
            || y.0 >= Bn254::FQ_MODULUS
            || y.1 >= Bn254::FQ_MODULUS
        {
            prop_assert!(!on_curve, "Fq² coefficient outside Fq must be rejected");
        }
    }
}

// ----------------------------------------------------------------------------
// Differential cross-check of the fast subgroup tests (issue #577).
//
// `is_in_correct_subgroup` uses the endomorphism test ψ(Q) == [6x₀²]Q and
// `is_valid_g1_subgroup` relies on the G1 cofactor being 1. Both are compared
// against the 254-bit `[r]P == O` reference and against arkworks on random
// on-curve points: 250 cases × 2 G2 points (a raw random curve point, almost
// surely off-subgroup, and the same point with its cofactor cleared) = 500.
// ----------------------------------------------------------------------------

use ark_bn254::{Fq as ArkFq, Fq2 as ArkFq2, G1Affine as ArkG1Affine, G2Affine as ArkG2Affine};
use ark_ec::AffineRepr;
use ark_ff::{BigInteger, PrimeField};

fn ark_fq_to_u256(x: ArkFq) -> u256 {
    let bytes: [u8; 32] = x
        .into_bigint()
        .to_bytes_be()
        .try_into()
        .expect("BN254 Fq elements are 32 bytes");
    u256::from_be_bytes(bytes)
}

fn ark_g2_coords(p: &ArkG2Affine) -> ((u256, u256), (u256, u256)) {
    (
        (ark_fq_to_u256(p.x.c0), ark_fq_to_u256(p.x.c1)),
        (ark_fq_to_u256(p.y.c0), ark_fq_to_u256(p.y.c1)),
    )
}

/// Deterministically finds an on-curve G2 point by walking x upward from a
/// random start until x³ + b' is a square.
fn random_g2_point(x0b: [u8; 32], x1b: [u8; 32], greatest: bool) -> ArkG2Affine {
    let mut x = ArkFq2::new(
        ArkFq::from_be_bytes_mod_order(&x0b),
        ArkFq::from_be_bytes_mod_order(&x1b),
    );
    loop {
        if let Some(p) = ArkG2Affine::get_point_from_x_unchecked(x, greatest) {
            return p;
        }
        x += ArkFq2::from(1u64);
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(250))]

    #[test]
    #[cfg_attr(miri, ignore)]
    fn g2_endomorphism_subgroup_check_matches_scalar_mul(
        x0b in any::<[u8; 32]>(),
        x1b in any::<[u8; 32]>(),
        greatest in any::<bool>(),
    ) {
        let raw = random_g2_point(x0b, x1b, greatest);
        let cleared = raw.clear_cofactor();

        for point in [raw, cleared] {
            if point.is_zero() {
                continue;
            }
            let (x, y) = ark_g2_coords(&point);
            prop_assert!(Bn254::is_on_curve(x, y));

            let fast = Bn254::is_in_correct_subgroup(x, y);
            let naive = Bn254::is_in_correct_subgroup_naive(x, y);
            let reference = point.is_in_correct_subgroup_assuming_on_curve();
            prop_assert_eq!(fast, naive, "ψ test disagrees with [r]Q == O");
            prop_assert_eq!(fast, reference, "ψ test disagrees with arkworks");
        }

        // A cofactor-cleared point is always in the subgroup.
        if !cleared.is_zero() {
            let (x, y) = ark_g2_coords(&cleared);
            prop_assert!(Bn254::is_in_correct_subgroup(x, y));
        }
    }

    #[test]
    fn g1_cofactor_one_fast_path_matches_scalar_mul(
        xb in any::<[u8; 32]>(),
        greatest in any::<bool>(),
    ) {
        let mut x = ArkFq::from_be_bytes_mod_order(&xb);
        let point = loop {
            if let Some(p) = ArkG1Affine::get_point_from_x_unchecked(x, greatest) {
                break p;
            }
            x += ArkFq::from(1u64);
        };
        let (px, py) = (ark_fq_to_u256(point.x), ark_fq_to_u256(point.y));

        // h₁ = 1: every finite on-curve G1 point is in the subgroup.
        prop_assert!(Bn254::is_valid_g1_subgroup(px, py));
        prop_assert!(Bn254::is_valid_g1_subgroup_naive(px, py));
        prop_assert!(point.is_in_correct_subgroup_assuming_on_curve());
    }
}

/// Off-subgroup G2 points are rejected by every check (negative cases).
#[test]
#[cfg_attr(miri, ignore)]
fn g2_off_subgroup_points_are_rejected() {
    let mut rejected = 0;
    for seed in 0u8..16 {
        let point = random_g2_point([seed; 32], [seed.wrapping_add(1); 32], seed % 2 == 0);
        let (x, y) = ark_g2_coords(&point);
        if !point.is_in_correct_subgroup_assuming_on_curve() {
            assert!(!Bn254::is_in_correct_subgroup(x, y));
            assert!(!Bn254::is_in_correct_subgroup_naive(x, y));
            rejected += 1;
        }
    }
    assert!(
        rejected > 0,
        "expected random curve points off the subgroup"
    );
}
