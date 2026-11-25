use ethnum::u256;
use soroban_zk_core::{Bn254, G1Affine, ZkError};

/// Compressed point flag: bit 6 indicates the point at infinity (Arkworks `SWFlags::PointAtInfinity`).
const COMPRESSED_FLAG_INFINITY: u8 = 1 << 6;
/// Compressed point flag: bit 7 indicates the lexicographically largest `y` (Arkworks `SWFlags::YIsNegative`).
const COMPRESSED_FLAG_Y_NEG: u8 = 1 << 7;
/// Mask for the top two flag bits in the final byte of a compressed point encoding.
const COMPRESSED_FLAGS_MASK: u8 = COMPRESSED_FLAG_INFINITY | COMPRESSED_FLAG_Y_NEG;

/// Returns `true` if `y` is strictly greater than `-y` in Arkworks'
/// lexicographic ordering on `Fq²` (compare `c1` first, then `c0`).
fn fq2_is_lex_largest(y: (u256, u256)) -> bool {
    let zero = u256::from(0u8);
    if y.1 != zero {
        y.1 > Bn254::sub_fq(zero, y.1)
    } else {
        y.0 > Bn254::sub_fq(zero, y.0)
    }
}

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

    /// Serializes this G2 point into the 64-byte Arkworks compressed
    /// representation (`x.c0 || x.c1` in little-endian), with the top two bits
    /// of byte 63 carrying the infinity (`0x40`) and lexicographic sign (`0x80`)
    /// flags, matching `ark-bn254` `CanonicalSerialize`.
    pub fn to_compressed_bytes(&self) -> [u8; 64] {
        let zero = u256::from(0u8);
        if self.x == (zero, zero) && self.y == (zero, zero) {
            let mut out = [0u8; 64];
            out[63] = COMPRESSED_FLAG_INFINITY;
            return out;
        }
        let mut out = [0u8; 64];
        out[0..32].copy_from_slice(&self.x.0.to_le_bytes());
        out[32..64].copy_from_slice(&self.x.1.to_le_bytes());
        if fq2_is_lex_largest(self.y) {
            out[63] |= COMPRESSED_FLAG_Y_NEG;
        }
        out
    }

    /// Deserializes a 64-byte Arkworks-compressed G2 point, validating field
    /// bounds, flag consistency, curve membership (`y² = x³ + β`), and
    /// prime-order subgroup membership.
    ///
    /// Returns the affine infinity encoding `((0, 0), (0, 0))` when the
    /// infinity flag is set and all remaining bits are zero.
    pub fn from_compressed_bytes(bytes: &[u8; 64]) -> Result<Self, ZkError> {
        let flags = bytes[63] & COMPRESSED_FLAGS_MASK;
        if flags == COMPRESSED_FLAGS_MASK {
            return Err(ZkError::DeserializationError);
        }

        let mut x0_bytes = [0u8; 32];
        let mut x1_bytes = [0u8; 32];
        x0_bytes.copy_from_slice(&bytes[0..32]);
        x1_bytes.copy_from_slice(&bytes[32..64]);
        x1_bytes[31] &= !COMPRESSED_FLAGS_MASK;

        let zero = u256::from(0u8);
        if flags == COMPRESSED_FLAG_INFINITY {
            if x0_bytes.iter().any(|&b| b != 0) || x1_bytes.iter().any(|&b| b != 0) {
                return Err(ZkError::DeserializationError);
            }
            return Ok(Self {
                x: (zero, zero),
                y: (zero, zero),
            });
        }

        let x0 = u256::from_le_bytes(x0_bytes);
        let x1 = u256::from_le_bytes(x1_bytes);
        if !Bn254::is_valid_fq(x0) || !Bn254::is_valid_fq(x1) {
            return Err(ZkError::DeserializationError);
        }

        let x = (x0, x1);
        let x2 = Bn254::fq2_sq(x);
        let x3 = Bn254::fq2_mul(x2, x);
        let rhs = Bn254::fq2_add(x3, (Bn254::G2_B_REAL, Bn254::G2_B_IMAG));

        let y_cand = Bn254::fq2_sqrt(rhs).ok_or(ZkError::DeserializationError)?;
        let neg_y = Bn254::fq2_neg(y_cand);
        let y_is_neg = fq2_is_lex_largest(y_cand);
        let want_neg = flags == COMPRESSED_FLAG_Y_NEG;
        let y = if y_is_neg == want_neg { y_cand } else { neg_y };

        if !Bn254::is_in_correct_subgroup(x, y) {
            return Err(ZkError::DeserializationError);
        }

        Ok(Self { x, y })
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

    #[test]
    fn test_g2_generator_matches_vk_constant() {
        assert_eq!(G2Affine::generator(), crate::vk::G2_GENERATOR);
    }

    #[test]
    fn test_g2_compressed_differential_against_arkworks() {
        use ark_ec::AffineRepr;
        use ark_ff::{BigInteger, PrimeField};
        use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

        let to_u256 = |f: ark_bn254::Fq| {
            let b = f.into_bigint().to_bytes_be();
            let mut arr = [0u8; 32];
            arr[32 - b.len()..].copy_from_slice(&b);
            u256::from_be_bytes(arr)
        };
        let ark_to_local = |p: ark_bn254::G2Affine| -> G2Affine {
            if p.is_zero() {
                let z = u256::from(0u8);
                return G2Affine {
                    x: (z, z),
                    y: (z, z),
                };
            }
            G2Affine {
                x: (to_u256(p.x.c0), to_u256(p.x.c1)),
                y: (to_u256(p.y.c0), to_u256(p.y.c1)),
            }
        };

        let gen = ark_bn254::G2Affine::generator();
        let test_points = [
            ark_bn254::G2Affine::zero(),
            gen,
            -gen,
            (gen * ark_bn254::Fr::from(2u64)).into(),
            (gen * ark_bn254::Fr::from(5u64)).into(),
            (-(gen * ark_bn254::Fr::from(987654321u64))).into(),
        ];

        for ark_p in test_points {
            let local_p = ark_to_local(ark_p);
            let mut ark_buf = [0u8; 64];
            ark_p
                .serialize_compressed(&mut ark_buf[..])
                .expect("ark G2 serialize_compressed");

            let local_buf = local_p.to_compressed_bytes();
            assert_eq!(
                local_buf, ark_buf,
                "G2 compressed bytes must match ark-bn254"
            );

            let decoded = G2Affine::from_compressed_bytes(&ark_buf)
                .expect("local G2 deserialize must succeed");
            assert_eq!(decoded, local_p);

            let ark_decoded = ark_bn254::G2Affine::deserialize_compressed(&local_buf[..])
                .expect("ark G2 deserialize must succeed");
            assert_eq!(ark_decoded, ark_p);
        }
    }

    #[test]
    fn test_g2_compressed_rejects_invalid_inputs() {
        // Both flags set (0xC0)
        let mut both_flags = [0u8; 64];
        both_flags[63] = 0xC0;
        assert_eq!(
            G2Affine::from_compressed_bytes(&both_flags),
            Err(ZkError::DeserializationError)
        );

        // Infinity flag with non-zero payload
        let mut bad_inf = [0u8; 64];
        bad_inf[63] = 0x40;
        bad_inf[0] = 1;
        assert_eq!(
            G2Affine::from_compressed_bytes(&bad_inf),
            Err(ZkError::DeserializationError)
        );

        // x0 >= FQ_MODULUS
        let mut bad_x0 = [0u8; 64];
        bad_x0[0..32].copy_from_slice(&Bn254::FQ_MODULUS.to_le_bytes());
        assert_eq!(
            G2Affine::from_compressed_bytes(&bad_x0),
            Err(ZkError::DeserializationError)
        );

        // On-curve but off-subgroup G2 point must be rejected
        let beta = (Bn254::G2_B_REAL, Bn254::G2_B_IMAG);
        let mut x_re = u256::from(1u8);
        loop {
            let x = (x_re, u256::from(0u8));
            let rhs = Bn254::fq2_add(Bn254::fq2_mul(Bn254::fq2_sq(x), x), beta);
            if let Some(y) = Bn254::fq2_sqrt(rhs) {
                if !Bn254::is_in_correct_subgroup(x, y) {
                    let off_subgroup = G2Affine { x, y };
                    let compressed = off_subgroup.to_compressed_bytes();
                    assert_eq!(
                        G2Affine::from_compressed_bytes(&compressed),
                        Err(ZkError::DeserializationError)
                    );
                    break;
                }
            }
            x_re = Bn254::add_fq(x_re, u256::from(1u8));
        }
    }
}
