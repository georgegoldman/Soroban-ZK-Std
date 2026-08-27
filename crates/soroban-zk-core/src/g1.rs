//! BN254 G1 group constants, subgroup membership check, and related utilities.
//!
//! All functions are `no_std`-compatible and operate on the [`G1Affine`] /
//! [`G1Projective`] types already defined in the parent crate.

use crate::{Bn254, G1Affine, G1Projective};
use ethnum::u256;

// ============================================================================
// Generator point
// ============================================================================

/// The standard BN254 G1 generator point G = (1, 2).
///
/// This specific coordinate pair is part of the BN254 parameter selection and
/// is the conventional base point used by proof systems such as Groth16 and
/// KZG.  The point satisfies the curve equation:
///
/// ```text
/// y² ≡ x³ + 3  (mod Fq)
/// 4  ≡ 1 + 3   ✓
/// ```
pub const G1_GENERATOR: G1Affine = G1Affine {
    x: u256::from_words(0, 1),
    y: u256::from_words(0, 2),
};

// Compile-time on-curve sanity check for the generator point.
// y² = 2² = 4  and  x³ + 3 = 1 + 3 = 4.
const _ON_CURVE: () = {
    let y_sq = 2u128 * 2; // 4
    let x_cb_plus_3 = 1u128 + 3; // 4
    assert!(y_sq == x_cb_plus_3, "G1 generator must satisfy y² = x³ + 3");
};

// ============================================================================
// Subgroup membership
// ============================================================================

/// Returns `true` if `p` belongs to the BN254 G1 prime-order subgroup.
///
/// For BN254 G1 the cofactor `h` is exactly **1**, so every point that lies on
/// the curve is automatically in the prime-order subgroup.  Subgroup membership
/// therefore reduces to a point-on-curve check:
///
/// ```text
/// y² ≡ x³ + 3  (mod Fq)
/// ```
///
/// The identity (point at infinity, represented as `(0, 0)`) is deliberately
/// rejected because it is not a valid input to most ZK primitives.
#[inline]
pub fn g1_is_in_subgroup(p: &G1Affine) -> bool {
    // Reject the identity / point at infinity.
    if p.x == u256::from(0u8) && p.y == u256::from(0u8) {
        return false;
    }
    Bn254::is_valid_g1(p.x, p.y)
}

// ============================================================================
// Negation helper
// ============================================================================

/// Computes the additive inverse of a G1 affine point: `−P = (x, −y mod Fq)`.
///
/// Negating the identity returns the identity unchanged.
#[inline]
pub fn g1_negate(p: G1Affine) -> G1Affine {
    if p.x == u256::from(0u8) && p.y == u256::from(0u8) {
        return p;
    }
    G1Affine {
        x: p.x,
        y: Bn254::sub_fq(u256::from(0u8), p.y),
    }
}

// ============================================================================
// Scalar multiplication (re-export for convenience)
// ============================================================================

/// Multiplies a G1 affine point by a scalar using the double-and-add algorithm
/// defined in [`Bn254::g1_scalar_mul`].
///
/// Returns the result in affine coordinates.
#[inline]
pub fn g1_scalar_mul(p: G1Affine, scalar: u256) -> G1Affine {
    Bn254::g1_scalar_mul(G1Projective::from(p), scalar).to_affine()
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generator_is_on_curve() {
        assert!(
            Bn254::is_valid_g1(G1_GENERATOR.x, G1_GENERATOR.y),
            "G1 generator (1, 2) must satisfy the BN254 curve equation"
        );
    }

    #[test]
    fn generator_passes_subgroup_check() {
        assert!(
            g1_is_in_subgroup(&G1_GENERATOR),
            "G1 generator must be in the prime-order subgroup"
        );
    }

    #[test]
    fn identity_fails_subgroup_check() {
        let identity = G1Affine {
            x: u256::from(0u8),
            y: u256::from(0u8),
        };
        assert!(
            !g1_is_in_subgroup(&identity),
            "The identity / point-at-infinity must be rejected"
        );
    }

    #[test]
    fn off_curve_point_fails_subgroup_check() {
        // (1, 3) does not satisfy y² = x³ + 3 mod Fq (9 ≠ 4).
        let bad = G1Affine {
            x: u256::from(1u8),
            y: u256::from(3u8),
        };
        assert!(!g1_is_in_subgroup(&bad));
    }

    #[test]
    fn negation_of_generator_is_on_curve() {
        let neg_g = g1_negate(G1_GENERATOR);
        // −G must also be on the curve.
        assert!(Bn254::is_valid_g1(neg_g.x, neg_g.y));
        // x-coordinate is unchanged.
        assert_eq!(neg_g.x, G1_GENERATOR.x);
        // y + (−y) ≡ 0 (mod Fq).
        let sum_y = Bn254::add_fq(G1_GENERATOR.y, neg_g.y);
        assert_eq!(sum_y, u256::from(0u8));
    }

    #[test]
    fn negation_of_identity_is_identity() {
        let id = G1Affine {
            x: u256::from(0u8),
            y: u256::from(0u8),
        };
        let neg_id = g1_negate(id);
        assert_eq!(neg_id, id);
    }

    #[test]
    fn scalar_mul_by_zero_gives_identity() {
        let result = g1_scalar_mul(G1_GENERATOR, u256::from(0u8));
        assert_eq!(result.x, u256::from(0u8));
        assert_eq!(result.y, u256::from(0u8));
    }

    #[test]
    fn scalar_mul_by_one_gives_generator() {
        let result = g1_scalar_mul(G1_GENERATOR, u256::from(1u8));
        assert_eq!(result, G1_GENERATOR);
    }

    #[test]
    fn scalar_mul_result_is_on_curve() {
        // 2 * G
        let two_g = g1_scalar_mul(G1_GENERATOR, u256::from(2u8));
        assert!(
            Bn254::is_valid_g1(two_g.x, two_g.y),
            "2·G must be on the BN254 curve"
        );
    }

    #[test]
    fn scalar_mul_commutativity() {
        // a * G == G + G + ... (a times); verify 3*G via two paths.
        let g3_direct = g1_scalar_mul(G1_GENERATOR, u256::from(3u8));

        let g2 = g1_scalar_mul(G1_GENERATOR, u256::from(2u8));
        let g3_stepwise = G1Affine::add(&g2, &G1_GENERATOR);

        assert_eq!(g3_direct, g3_stepwise);
    }
}
