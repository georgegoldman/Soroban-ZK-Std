use ethnum::u256;
use soroban_zk_core::{Bn254, G1Affine};

/// A BN254 G2 point in affine coordinates (X, Y).
/// Coordinates are elements of the degree-2 extension field Fq²,
/// represented as `a + b*u`, where `0` is the real part and `1` is the imaginary part.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct G2Affine {
    pub x: (u256, u256),
    pub y: (u256, u256),
}

impl G2Affine {
    /// Serializes the G2 point into a 128-byte array according to CAP-0074 §3.2 / EIP-197.
    ///
    /// ## Byte Layout
    /// The 128 bytes are structured as:
    /// - Bytes 0..32:   `x.1` (X imaginary / c1)
    /// - Bytes 32..64:  `x.0` (X real / c0)
    /// - Bytes 64..96:  `y.1` (Y imaginary / c1)
    /// - Bytes 96..128: `y.0` (Y real / c0)
    ///
    /// All 32-byte chunks are encoded in Big-Endian format.
    pub fn to_bytes(&self) -> [u8; 128] {
        let mut bytes = [0u8; 128];
        // EIP-197 / CAP-0074: c1 (imaginary) precedes c0 (real)
        bytes[0..32].copy_from_slice(&self.x.1.to_be_bytes()); // X c1
        bytes[32..64].copy_from_slice(&self.x.0.to_be_bytes()); // X c0
        bytes[64..96].copy_from_slice(&self.y.1.to_be_bytes()); // Y c1
        bytes[96..128].copy_from_slice(&self.y.0.to_be_bytes()); // Y c0
        bytes
    }

    pub fn generator() -> Self {
        Self {
            x: (
                u256::from_str_radix(
                    "1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed",
                    16,
                )
                .unwrap(),
                u256::from_str_radix(
                    "198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2",
                    16,
                )
                .unwrap(),
            ),
            y: (
                u256::from_str_radix(
                    "12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa",
                    16,
                )
                .unwrap(),
                u256::from_str_radix(
                    "090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b",
                    16,
                )
                .unwrap(),
            ),
        }
    }
}
/// Serializes a G1Affine point into a 64-byte array.
///
/// ## Byte Layout
/// - Bytes 0..32:  `x` (Big-Endian)
/// - Bytes 32..64: `y` (Big-Endian)
pub(crate) fn g1_to_bytes(g1: &G1Affine) -> [u8; 64] {
    let mut bytes = [0u8; 64];
    bytes[0..32].copy_from_slice(&g1.x.to_be_bytes());
    bytes[32..64].copy_from_slice(&g1.y.to_be_bytes());
    bytes
}

pub(crate) fn validate_g2_coords(g2: &G2Affine) -> bool {
    let (x0, x1) = g2.x;
    let (y0, y1) = g2.y;

    // is_on_curve also enforces field-element membership of the coordinates.
    Bn254::is_on_curve((x0, x1), (y0, y1)) && Bn254::is_in_correct_subgroup((x0, x1), (y0, y1))
}

/// Validates that a G2 point is both on the BN254 curve and in the prime-order subgroup.
///
/// This function performs two essential security checks:
///
/// 1. **Curve membership (on-curve check):** Verifies that the point (x, y) satisfies
///    the BN254 G2 curve equation: y² = x³ + β over Fq², where β = 3/(u + 9).
///    
///    **Why this matters:** Without this check, a malicious prover could submit
///    a point with valid field-element coordinates that does NOT lie on the curve.
///    Such an "invalid-curve" point passed to the pairing function could allow
///    forge attacks that bypass the proof system's soundness.
///
/// 2. **Subgroup membership (order check):** Verifies that the point belongs to
///    the prime-order subgroup G₂ (of order r), not just the full curve group
///    (of order r * h₂, where h₂ ≈ 2.18e34 is the cofactor).
///    
///    **Why this matters:** A "small-subgroup" or "cofactor" attack uses a point
///    that is on-curve but has order dividing h₂ (not prime order r). Such a point
///    reveals information about the prover's witness through bilinear pairing maps.
///    Subgroup validation ensures we only accept points of order r.
///
/// **Return value:**
/// - `true` if both curve and subgroup checks pass.
/// - `false` if either check fails (invalid G2 point).
///
/// **Special cases:**
/// - Returns `false` for (0, 0), which is not a valid affine point.
/// - Returns `true` for the identity element (point at infinity) if it is
///   properly encoded, but currently (0, 0) fails the affine check.
///
/// Evaluates the BN254 pairing check `e(A₁, B₁) · … · e(Aₙ, Bₙ) == 1`.
///
/// This delegates to the CAP-0075 host translation layer in [`crate::host`],
/// which performs strict input validation, invokes the native
/// `bn254_multi_pairing_check` host function, and transparently falls back to a
/// software pairing when the host is unavailable (off-chain tests).
pub use crate::host::pairing_check;

#[cfg(test)]
mod tests {
    use super::*;
    use ethnum::u256;
    use soroban_sdk::Env;
    use soroban_zk_core::ZkError;

    fn g1_generator() -> G1Affine {
        G1Affine {
            x: u256::from(1u8),
            y: u256::from(2u8),
        }
    }

    fn g1_generator_neg() -> G1Affine {
        G1Affine {
            x: u256::from(1u8),
            y: u256::from_str_radix(
                "30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd45",
                16,
            )
            .unwrap(),
        }
    }

    fn g2_generator() -> G2Affine {
        G2Affine {
            x: (
                // c0 (real) — FIRST in tuple -> x.0
                u256::from_str_radix(
                    "1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed",
                    16,
                )
                .unwrap(),
                // c1 (imaginary) — SECOND in tuple -> x.1
                u256::from_str_radix(
                    "198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2",
                    16,
                )
                .unwrap(),
            ),
            y: (
                // c0 (real) — FIRST in tuple -> y.0
                u256::from_str_radix(
                    "12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa",
                    16,
                )
                .unwrap(),
                // c1 (imaginary) — SECOND in tuple -> y.1
                u256::from_str_radix(
                    "090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b",
                    16,
                )
                .unwrap(),
            ),
        }
    }

    #[test]
    fn test_pairing_check_rejects_empty_input() {
        let env = Env::default();
        assert_eq!(pairing_check(&env, &[]), Err(ZkError::InvalidInput));
    }

    /// Verifies the bilinearity identity: e(G1, G2) * e(-G1, G2) == 1.
    /// This holds because -G1 = negation over G1, so e(G1, G2) * e(-G1, G2)
    /// = e(G1 - G1, G2) = e(O, G2) = 1.
    #[test]
    fn test_pairing_g1_neg_g1_same_g2_equals_one() {
        let env = Env::default();
        let result = pairing_check(
            &env,
            &[
                (g1_generator(), g2_generator()),
                (g1_generator_neg(), g2_generator()),
            ],
        );
        assert!(result.unwrap(), "e(G1, G2) * e(-G1, G2) should equal 1");
    }

    /// Verifies that a single valid pairing pair e(G1, G2) alone does NOT equal 1
    /// (i.e. the result is non-trivial when the product is not the identity).
    #[test]
    fn test_pairing_single_pair_is_not_one() {
        let env = Env::default();
        let result = pairing_check(&env, &[(g1_generator(), g2_generator())]);
        assert!(!result.unwrap(), "e(G1, G2) alone should not equal 1");
    }

    #[test]
    fn test_pairing_rejects_invalid_g1_point() {
        let env = Env::default();
        let invalid_g1 = G1Affine {
            x: u256::from(0u8),
            y: u256::from(0u8),
        };
        let result = pairing_check(&env, &[(invalid_g1, g2_generator())]);
        assert_eq!(result, Err(ZkError::InvalidInput));
    }

    #[test]
    fn test_pairing_rejects_invalid_g2_points() {
        let env = Env::default();
        let mut invalid_g2 = g2_generator();

        // Perturb the y-coordinate to make it not on the curve
        invalid_g2.y.0 = Bn254::add_fq(invalid_g2.y.0, u256::from(1u8));

        let result = pairing_check(&env, &[(g1_generator(), invalid_g2)]);
        assert_eq!(
            result,
            Err(ZkError::InvalidInput),
            "pairing_check should reject G2 points not on the curve"
        );
    }

    #[test]
    fn test_pairing_rejects_g2_at_zero() {
        let env = Env::default();
        let zero_g2 = G2Affine {
            x: (u256::from(0u8), u256::from(0u8)),
            y: (u256::from(0u8), u256::from(0u8)),
        };

        let result = pairing_check(&env, &[(g1_generator(), zero_g2)]);
        assert_eq!(
            result,
            Err(ZkError::InvalidInput),
            "pairing_check should reject (0, 0) as invalid G2 point"
        );
    }
}
