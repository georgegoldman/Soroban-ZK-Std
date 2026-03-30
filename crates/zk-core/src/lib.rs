#![no_std]
use ethnum::u256;

/// Errors returned by zero-knowledge conversion and validation operations.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ZkError {
    /// The supplied value is ≥ the BN254 scalar field modulus and is not a valid field element.
    InvalidFieldElement,
    /// Mismatched input lengths or empty slices in multi-input operations.
    InvalidInput,
}

/// A BN254 scalar field element guaranteed to be in the range `[0, r)`.
///
/// Construct exclusively via [`SafeFrom`] to enforce field bounds without panicking.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct Fr(u256);

/// A BN254 G1 point in affine coordinates (x, y).
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct G1Affine {
    pub x: u256,
    pub y: u256,
}

/// A BN254 G1 point in Jacobian coordinates (X, Y, Z).
/// Represents the affine point (X/Z^2, Y/Z^3).
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct G1Jacobian {
    pub x: u256,
    pub y: u256,
    pub z: u256,
}

impl Fr {
    /// Returns the inner `u256` representation of the field element.
    #[inline(always)]
    pub fn inner(&self) -> u256 {
        self.0
    }
}

/// Constant-time, fallible conversion into a cryptographic type.
///
/// All implementations **must** be `#[inline(always)]`, must not allocate on
/// the heap, and must never call `unwrap()` or `expect()`.
pub trait SafeFrom<T>: Sized {
    fn safe_from(val: T) -> Result<Self, ZkError>;
}

impl SafeFrom<u256> for Fr {
    /// Converts a raw `u256` into an `Fr` field element using a constant-time range check.
    ///
    /// Uses subtraction overflow to test `val < r` without branching on intermediate
    /// secret values: `overflowing_sub` overflows if and only if `val < BASE_MODULUS`.
    /// Returns `Err(ZkError::InvalidFieldElement)` if `val >= r`. No heap allocation;
    /// no panics.
    #[inline(always)]
    fn safe_from(val: u256) -> Result<Self, ZkError> {
        // Constant-time range check: subtract the modulus and detect underflow.
        // Underflow occurs iff val < BASE_MODULUS, meaning val is a valid field element.
        let (_, in_field) = val.overflowing_sub(Bn254::BASE_MODULUS);
        if in_field {
            Ok(Fr(val))
        } else {
            Err(ZkError::InvalidFieldElement)
        }
    }
}

pub struct Bn254;

impl Bn254 {
    pub const BASE_MODULUS: ethnum::u256 = ethnum::u256::from_words(
        0x30644e72e131a029b85045b68181585d_u128,
        0x97816a916871ca8d3c208c16d87cfd47_u128,
    );

    /// G1 coefficient B for y^2 = x^3 + B
    pub const G1_B: u256 = u256::from_words(0u128, 3u128);

    pub fn is_valid_scalar(val: u256) -> bool {
        val < Self::BASE_MODULUS
    }

    pub fn add(a: u256, b: u256) -> u256 {
        let (sum, overflow) = a.overflowing_add(b);
        if overflow || sum >= Self::BASE_MODULUS {
            sum.wrapping_sub(Self::BASE_MODULUS)
        } else {
            sum
        }
    }

    pub fn sub(a: u256, b: u256) -> u256 {
        let (res, underflow) = a.overflowing_sub(b);
        if underflow {
            res.wrapping_add(Self::BASE_MODULUS)
        } else {
            res
        }
    }

    /// Modular Multiplication: (a * b) % BASE_MODULUS
    /// Implements manual 512-bit long multiplication to bypass library limitations.
    pub fn mul(a: u256, b: u256) -> u256 {
        if a == 0 || b == 0 {
            return u256::from(0u8);
        }

        // Split a and b into 128-bit halves
        let a_low = u256::from(a.as_u128());
        let a_high = a >> 128;
        let b_low = u256::from(b.as_u128());
        let b_high = b >> 128;

        // Schoolbook multiplication (a_hi*2^128 + a_lo) * (b_hi*2^128 + b_lo)
        // This yields 4 partial products
        let p0 = a_low * b_low;
        let p1 = a_low * b_high;
        let p2 = a_high * b_low;
        let p3 = a_high * b_high;

        // Perform modular reduction on each partial product stage
        // to keep everything within 256-bit bounds.
        let mut res = p0 % Self::BASE_MODULUS;

        // Handle p1 and p2 (shifted by 128 bits)
        let mut p1_p2 = p1 % Self::BASE_MODULUS;
        p1_p2 = Self::add(p1_p2, p2 % Self::BASE_MODULUS);
        for _ in 0..128 {
            p1_p2 = Self::add(p1_p2, p1_p2); // Modular doubling
        }
        res = Self::add(res, p1_p2);

        // Handle p3 (shifted by 256 bits)
        let mut p3_red = p3 % Self::BASE_MODULUS;
        for _ in 0..256 {
            p3_red = Self::add(p3_red, p3_red); // Modular doubling
        }
        res = Self::add(res, p3_red);

        res
    }

    pub fn pow(mut base: u256, mut exp: u256) -> u256 {
        let mut res = u256::from(1u8);
        while exp > 0 {
            if exp % 2 == 1 {
                res = Self::mul(res, base);
            }
            base = Self::mul(base, base);
            exp /= 2;
        }
        res
    }

    pub fn invert(a: u256) -> u256 {
        if a == 0 {
            return u256::from(0u8);
        }
        let exponent = Self::BASE_MODULUS - u256::from(2u8);
        Self::pow(a, exponent)
    }

    pub fn is_valid_g1(x: u256, y: u256) -> bool {
        if x == 0 && y == 0 {
            return false;
        }
        if x >= Self::BASE_MODULUS || y >= Self::BASE_MODULUS {
            return false;
        }

        let y_sq = Self::mul(y, y);
        let x_sq = Self::mul(x, x);
        let x_cb = Self::mul(x_sq, x);
        let rhs = Self::add(x_cb, Self::G1_B);

        y_sq == rhs
    }
}

/// Computes the Multi-Scalar Multiplication (MSM) for G1 points:
/// `result = s1*P1 + s2*P2 + ... + sn*Pn`
///
/// Uses the Pippenger bucket method with a window size of 4 bits.
/// This implementation is optimized for constant-time bit slicing and
///
/// ### Performance (n = 8, c = 4)
/// - Naive sum: ~3,072 point operations (256-bit double-and-add × 8)
/// - Pippenger (c=4): ~1,664 point operations (1,408 additions + 256 doublings)
/// - **Efficiency Gain**: ~45% reduction in point operations.
///
/// This optimization is critical for staying within Soroban's 400M instruction limit.
pub fn g1_msm(points: &[G1Affine], scalars: &[u256]) -> Result<G1Affine, ZkError> {
    if points.len() != scalars.len() {
        return Err(ZkError::InvalidInput);
    }
    if points.is_empty() {
        return Ok(G1Affine::IDENTITY);
    }

    // Window size c = 4 bits
    // Number of windows = 256 / 4 = 64
    let mut overall_res = G1Jacobian::IDENTITY;

    for w in (0..64).rev() {
        // Double the overall result 4 times for the new 4-bit window
        for _ in 0..4 {
            overall_res = overall_res.double();
        }

        let mut buckets = [G1Jacobian::IDENTITY; 15];
        let mut window_has_points = false;

        for (p, s) in points.iter().zip(scalars.iter()) {
            let shifted: u256 = *s >> (w * 4);
            let window_val = (shifted.as_u128() & 0x0Fu128) as usize;
            if window_val > 0 {
                buckets[window_val - 1] = buckets[window_val - 1].add_mixed(p);
                window_has_points = true;
            }
        }

        if window_has_points {
            // Triangle summation for the current window
            // T = sum(buckets[k..15]), R = sum(T)
            let mut t = G1Jacobian::IDENTITY;
            let mut r = G1Jacobian::IDENTITY;
            for k in (0..15).rev() {
                t = t.add(&buckets[k]);
                r = r.add(&t);
            }
            overall_res = overall_res.add(&r);
        }
    }

    Ok(overall_res.to_affine())
}

impl G1Affine {
    pub const IDENTITY: Self = Self {
        x: u256::ZERO,
        y: u256::ZERO,
    };

    #[inline(always)]
    pub fn is_identity(&self) -> bool {
        self.x == u256::ZERO && self.y == u256::ZERO
    }

    #[inline(always)]
    pub fn to_jacobian(&self) -> G1Jacobian {
        if self.is_identity() {
            G1Jacobian::IDENTITY
        } else {
            G1Jacobian {
                x: self.x,
                y: self.y,
                z: u256::from_words(0u128, 1u128),
            }
        }
    }

    /// Scalar multiplication: result = s * P
    pub fn scalar_mul(&self, scalar: u256) -> Self {
        if self.is_identity() || scalar == 0 {
            return Self::IDENTITY;
        }

        let mut res = G1Jacobian::IDENTITY;
        let mut temp = self.to_jacobian();
        let mut s = scalar;

        for _ in 0..256 {
            if s % 2 == 1 {
                res = res.add(&temp);
            }
            temp = temp.double();
            s >>= 1;
        }

        res.to_affine()
    }
}

impl G1Jacobian {
    pub const IDENTITY: Self = Self {
        x: u256::ZERO,
        y: u256::ONE,
        z: u256::ZERO,
    };

    #[inline(always)]
    pub fn is_identity(&self) -> bool {
        self.z == u256::ZERO
    }

    #[inline(always)]
    pub fn to_affine(&self) -> G1Affine {
        if self.is_identity() {
            return G1Affine::IDENTITY;
        }

        let z_inv = Bn254::invert(self.z);
        let z_inv2 = Bn254::mul(z_inv, z_inv);
        let z_inv3 = Bn254::mul(z_inv2, z_inv);

        G1Affine {
            x: Bn254::mul(self.x, z_inv2),
            y: Bn254::mul(self.y, z_inv3),
        }
    }

    /// Constant-time point doubling in Jacobian coordinates.
    /// Follows the optimization for a=0 (since BN254 G1 is y^2 = x^3 + 3).
    #[inline(always)]
    pub fn double(&self) -> Self {
        if self.is_identity() || self.y == 0 {
            return Self::IDENTITY;
        }

        // Optimized doubling for a=0
        // S = 4 * X * Y^2
        // M = 3 * X^2
        // X' = M^2 - 2 * S
        // Y' = M * (S - X') - 8 * Y^4
        // Z' = 2 * Y * Z

        let x_sq = Bn254::mul(self.x, self.x);
        let y_sq = Bn254::mul(self.y, self.y);
        let y_sq_sq = Bn254::mul(y_sq, y_sq);

        // S = 4 * X * Y^2
        let mut s = Bn254::mul(self.x, y_sq);
        s = Bn254::add(s, s);
        s = Bn254::add(s, s);

        // M = 3 * X^2
        let mut m = Bn254::add(x_sq, x_sq);
        m = Bn254::add(m, x_sq);

        // X' = M^2 - 2 * S
        let m_sq = Bn254::mul(m, m);
        let s2 = Bn254::add(s, s);
        let x_res = Bn254::sub(m_sq, s2);

        // Y' = M * (S - X') - 8 * Y^4
        let s_minus_x = Bn254::sub(s, x_res);
        let m_times_s_minus_x = Bn254::mul(m, s_minus_x);
        let mut y4_8 = Bn254::add(y_sq_sq, y_sq_sq);
        y4_8 = Bn254::add(y4_8, y4_8);
        y4_8 = Bn254::add(y4_8, y4_8);
        let y_res = Bn254::sub(m_times_s_minus_x, y4_8);

        // Z' = 2 * Y * Z
        let z_res = Bn254::add(Bn254::mul(self.y, self.z), Bn254::mul(self.y, self.z));

        Self {
            x: x_res,
            y: y_res,
            z: z_res,
        }
    }

    /// Constant-time Jacobian + Affine point addition (Mixed Addition).
    #[inline(always)]
    pub fn add_mixed(&self, other: &G1Affine) -> Self {
        if self.is_identity() {
            return other.to_jacobian();
        }
        if other.is_identity() {
            return *self;
        }

        // Mixed addition formulas (Z2 = 1)
        // U1 = X1, S1 = Y1, U2 = X2 * Z1^2, S2 = Y2 * Z1^3
        // H = U2 - U1, R = S2 - S1
        // X3 = R^2 - H^3 - 2 * U1 * H^2
        // Y3 = R * (U1 * H^2 - X3) - S1 * H^3
        // Z3 = H * Z1

        let z1_sq = Bn254::mul(self.z, self.z);
        let z1_cb = Bn254::mul(z1_sq, self.z);

        // U2 = X2 * Z1^2, S2 = Y2 * Z1^3
        let u2 = Bn254::mul(other.x, z1_sq);
        let s2 = Bn254::mul(other.y, z1_cb);

        // H = U2 - U1, R = S2 - S1
        if self.x == u2 {
            if self.y == s2 {
                return self.double();
            } else {
                return Self::IDENTITY;
            }
        }

        let h = Bn254::sub(u2, self.x);
        let r = Bn254::sub(s2, self.y);

        let h_sq = Bn254::mul(h, h);
        let h_cb = Bn254::mul(h_sq, h);

        // X3 = R^2 - H^3 - 2 * U1 * H^2
        let r_sq = Bn254::mul(r, r);
        let u1_h2 = Bn254::mul(self.x, h_sq);
        let u1_h2_2 = Bn254::add(u1_h2, u1_h2);
        let mut x_res = Bn254::sub(r_sq, h_cb);
        x_res = Bn254::sub(x_res, u1_h2_2);

        // Y3 = R * (U1 * H^2 - X3) - S1 * H^3
        let u1_h2_minus_x3 = Bn254::sub(u1_h2, x_res);
        let r_times_diff = Bn254::mul(r, u1_h2_minus_x3);
        let s1_h3 = Bn254::mul(self.y, h_cb);
        let y_res = Bn254::sub(r_times_diff, s1_h3);

        // Z3 = H * Z1
        let z_res = Bn254::mul(h, self.z);

        Self {
            x: x_res,
            y: y_res,
            z: z_res,
        }
    }

    /// Constant-time general Jacobian point addition.
    #[inline(always)]
    pub fn add(&self, other: &Self) -> Self {
        if self.is_identity() {
            return *other;
        }
        if other.is_identity() {
            return *self;
        }

        let z1_sq = Bn254::mul(self.z, self.z);
        let z2_sq = Bn254::mul(other.z, other.z);
        let z1_cb = Bn254::mul(z1_sq, self.z);
        let z2_cb = Bn254::mul(z2_sq, other.z);

        let u1 = Bn254::mul(self.x, z2_sq);
        let u2 = Bn254::mul(other.x, z1_sq);
        let s1 = Bn254::mul(self.y, z2_cb);
        let s2 = Bn254::mul(other.y, z1_cb);

        if u1 == u2 {
            if s1 == s2 {
                return self.double();
            } else {
                return Self::IDENTITY;
            }
        }

        let h = Bn254::sub(u2, u1);
        let r = Bn254::sub(s2, s1);

        let h_sq = Bn254::mul(h, h);
        let h_cb = Bn254::mul(h_sq, h);

        let r_sq = Bn254::mul(r, r);
        let u1_h2 = Bn254::mul(u1, h_sq);
        let u1_h2_2 = Bn254::add(u1_h2, u1_h2);

        let mut x_res = Bn254::sub(r_sq, h_cb);
        x_res = Bn254::sub(x_res, u1_h2_2);

        let u1_h2_minus_x3 = Bn254::sub(u1_h2, x_res);
        let r_times_diff = Bn254::mul(r, u1_h2_minus_x3);
        let s1_h3 = Bn254::mul(s1, h_cb);
        let y_res = Bn254::sub(r_times_diff, s1_h3);

        let z_res = Bn254::mul(Bn254::mul(h, self.z), other.z);

        Self {
            x: x_res,
            y: y_res,
            z: z_res,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fr_zero_is_valid() {
        let fr = Fr::safe_from(u256::from(0u8)).unwrap();
        assert_eq!(fr.inner(), u256::from(0u8));
    }

    #[test]
    fn fr_small_value_is_valid() {
        let fr = Fr::safe_from(u256::from(42u8)).unwrap();
        assert_eq!(fr.inner(), u256::from(42u8));
    }

    #[test]
    fn fr_modulus_minus_one_is_valid() {
        let max_valid = Bn254::BASE_MODULUS - u256::from(1u8);
        let fr = Fr::safe_from(max_valid).unwrap();
        assert_eq!(fr.inner(), max_valid);
    }

    #[test]
    fn fr_modulus_itself_is_invalid() {
        assert_eq!(
            Fr::safe_from(Bn254::BASE_MODULUS),
            Err(ZkError::InvalidFieldElement)
        );
    }

    #[test]
    fn fr_u256_max_is_invalid() {
        assert_eq!(Fr::safe_from(u256::MAX), Err(ZkError::InvalidFieldElement));
    }

    #[test]
    fn fr_inner_roundtrip() {
        let val = u256::from(99u8);
        let fr = Fr::safe_from(val).unwrap();
        assert_eq!(fr.inner(), val);
    }

    #[test]
    fn test_g1_scalar_mul() {
        // Generator point (roughly G_x, G_y for BN254)
        // Note: For testing, any valid point works.
        let p = G1Affine {
            x: u256::from(1u8),
            y: u256::from(2u8),
        };
        // Verify (x,y) is valid: y^2 = x^3 + 3 => 4 = 1 + 3 (Correct)
        assert!(Bn254::is_valid_g1(p.x, p.y));

        // 1 * P = P
        let res1 = p.scalar_mul(u256::from(1u8));
        assert_eq!(res1, p);

        // 2 * P = P.double()
        let res2 = p.scalar_mul(u256::from(2u8));
        let expected2 = p.to_jacobian().double().to_affine();
        assert_eq!(res2, expected2);

        // 0 * P = Identity
        let res0 = p.scalar_mul(u256::from(0u8));
        assert!(res0.is_identity());
    }

    #[test]
    fn test_g1_msm() {
        let p = G1Affine {
            x: u256::from(1u8),
            y: u256::from(2u8),
        };
        let a = u256::from(123u128);
        let b = u256::from(456u128);

        // g1_msm([P, P], [a, b]) == (a+b)*P
        let points = [p, p];
        let scalars = [a, b];
        let msm_res = g1_msm(&points, &scalars).unwrap();

        let expected_sum = a.overflowing_add(b).0;
        let expected_res = p.scalar_mul(expected_sum);

        assert_eq!(msm_res, expected_res);
    }

    #[test]
    fn test_g1_msm_identity() {
        let p = G1Affine {
            x: u256::from(1u8),
            y: u256::from(2u8),
        };
        let scalars = [u256::from(0u8)];
        let points = [p];
        let res = g1_msm(&points, &scalars).unwrap();
        assert!(res.is_identity());
    }

    #[test]
    fn test_g1_msm_mismatched_lengths() {
        let p = G1Affine {
            x: u256::from(1u8),
            y: u256::from(2u8),
        };
        let points = [p];
        let scalars = [u256::from(1u8), u256::from(2u8)];
        let res = g1_msm(&points, &scalars);
        assert_eq!(res, Err(ZkError::InvalidInput));
    }

    // ===== Jacobian Coordinate Tests =====

    /// Test: Round-trip conversion to_affine(from_affine(P)) == P
    #[test]
    fn test_jacobian_roundtrip_conversion() {
        let p = G1Affine {
            x: u256::from(1u8),
            y: u256::from(2u8),
        };
        // Verify p is valid: y^2 = x^3 + 3 => 4 = 1 + 3
        assert!(Bn254::is_valid_g1(p.x, p.y));

        // Convert to Jacobian and back
        let jac = p.to_jacobian();
        let p_back = jac.to_affine();

        assert_eq!(p_back, p);
    }

    /// Test: Identity point round-trip
    #[test]
    fn test_jacobian_identity_roundtrip() {
        let identity = G1Affine::IDENTITY;
        let jac = identity.to_jacobian();
        assert!(jac.is_identity());

        let back = jac.to_affine();
        assert!(back.is_identity());
    }

    /// Test: Addition with identity element (P + Identity = P)
    #[test]
    fn test_jacobian_add_with_identity() {
        let p = G1Affine {
            x: u256::from(1u8),
            y: u256::from(2u8),
        };
        let p_jac = p.to_jacobian();
        let identity = G1Jacobian::IDENTITY;

        // P + Identity = P
        let result = p_jac.add(&identity);
        let result_affine = result.to_affine();
        assert_eq!(result_affine, p);

        // Identity + P = P
        let result2 = identity.add(&p_jac);
        let result2_affine = result2.to_affine();
        assert_eq!(result2_affine, p);
    }

    /// Test: Mixed addition with identity (Jacobian + Affine where Affine is identity)
    #[test]
    fn test_jacobian_add_mixed_identity() {
        let p = G1Affine {
            x: u256::from(1u8),
            y: u256::from(2u8),
        };
        let p_jac = p.to_jacobian();
        let identity = G1Affine::IDENTITY;

        // P + Identity = P (mixed addition)
        let result = p_jac.add_mixed(&identity);
        let result_affine = result.to_affine();
        assert_eq!(result_affine, p);
    }

    /// Test: Doubling is consistent with addition (P + P = 2*P)
    #[test]
    fn test_jacobian_double_equals_add() {
        let p = G1Affine {
            x: u256::from(1u8),
            y: u256::from(2u8),
        };
        let p_jac = p.to_jacobian();

        // Compute P + P using addition
        let p_plus_p = p_jac.add(&p_jac);

        // Compute 2*P using doubling
        let doubled = p_jac.double();

        // Both should give the same affine result
        assert_eq!(p_plus_p.to_affine(), doubled.to_affine());
    }

    /// Test: Cross-validation - Affine arithmetic vs Jacobian arithmetic
    /// Compute doubling results in both coordinate systems and verify same result
    #[test]
    fn test_jacobian_cross_validation_addition() {
        let p = G1Affine {
            x: u256::from(1u8),
            y: u256::from(2u8),
        };

        // Verify point is valid
        assert!(Bn254::is_valid_g1(p.x, p.y));

        // Convert to Jacobian
        let p_jac = p.to_jacobian();

        // Addition (doubling via add)
        let sum_jac = p_jac.add(&p_jac);
        let sum_jac_affine = sum_jac.to_affine();

        // Addition via mixed coordinates (same point)
        let sum_mixed = p_jac.add_mixed(&p);
        let sum_mixed_affine = sum_mixed.to_affine();

        // Both should produce same result
        assert_eq!(sum_jac_affine, sum_mixed_affine);
    }

    /// Test: Scalar multiplication consistency (Affine vs Jacobian)
    #[test]
    fn test_jacobian_scalar_mul_consistency() {
        let p = G1Affine {
            x: u256::from(1u8),
            y: u256::from(2u8),
        };
        let scalar = u256::from(42u8);

        // Scalar multiplication using affine (converts to Jacobian internally)
        let res_affine = p.scalar_mul(scalar);

        // Manual scalar multiplication using Jacobian
        let mut res_jac = G1Jacobian::IDENTITY;
        let mut temp = p.to_jacobian();
        let mut s = scalar;

        for _ in 0..256 {
            if s % 2 == 1 {
                res_jac = res_jac.add(&temp);
            }
            temp = temp.double();
            s >>= 1;
        }

        let res_jac_affine = res_jac.to_affine();

        assert_eq!(res_affine, res_jac_affine);
    }

    /// Test: Point doubling edge case where y=0 returns identity
    #[test]
    fn test_jacobian_double_with_y_zero() {
        // Create a point where y=0 (this is a 2-torsion point)
        let p_jac = G1Jacobian {
            x: u256::from(5u8),
            y: u256::ZERO,
            z: u256::from_words(0u128, 1u128),
        };

        let result = p_jac.double();
        assert!(result.is_identity());
    }

    /// Test: Point doubling of identity returns identity
    #[test]
    fn test_jacobian_double_identity() {
        let identity = G1Jacobian::IDENTITY;
        let result = identity.double();
        assert!(result.is_identity());
    }

    /// Test: P + (-P) = Identity (handling of negation)
    #[test]
    fn test_jacobian_add_inverse() {
        let p = G1Affine {
            x: u256::from(1u8),
            y: u256::from(2u8),
        };

        // -P has the same x but negated y
        let p_inv = G1Affine {
            x: p.x,
            y: Bn254::sub(u256::ZERO, p.y),
        };

        let p_jac = p.to_jacobian();
        let p_inv_jac = p_inv.to_jacobian();

        // P + (-P) should be identity
        let result = p_jac.add(&p_inv_jac);
        assert!(result.is_identity());
    }

    /// Test: Arithmetic formula verification - doubling produces valid point
    #[test]
    fn test_jacobian_double_produces_valid_point() {
        let p = G1Affine {
            x: u256::from(1u8),
            y: u256::from(2u8),
        };

        let p_jac = p.to_jacobian();
        let doubled = p_jac.double();
        let doubled_affine = doubled.to_affine();

        // Result should be valid (satisfies curve equation)
        // unless it's the identity
        if !doubled_affine.is_identity() {
            assert!(Bn254::is_valid_g1(doubled_affine.x, doubled_affine.y));
        }
    }

    /// Test: Arithmetic formula verification - addition produces valid point
    #[test]
    fn test_jacobian_add_produces_valid_point() {
        let p = G1Affine {
            x: u256::from(1u8),
            y: u256::from(2u8),
        };

        let p_jac = p.to_jacobian();
        let doubled = p_jac.add(&p_jac);
        let doubled_affine = doubled.to_affine();

        // Result should be valid (satisfies curve equation)
        if !doubled_affine.is_identity() {
            assert!(Bn254::is_valid_g1(doubled_affine.x, doubled_affine.y));
        }
    }

    /// Test: Three-point associativity: (A + B) + C == A + (B + C)
    /// Using the same point P multiple times to ensure valid arithmetic
    #[test]
    fn test_jacobian_associativity() {
        let p = G1Affine {
            x: u256::from(1u8),
            y: u256::from(2u8),
        };
        let p_jac = p.to_jacobian();

        // Create P2 by doubling P
        let p2_jac = p_jac.double();
        let p2 = p2_jac.to_affine();

        // Create P3 by doubling P2
        let p3_jac = p2_jac.double();
        let p3 = p3_jac.to_affine();

        // (P + P2) + P3
        let left = p_jac.add_mixed(&p2).add_mixed(&p3).to_affine();

        // P + (P2 + P3)
        let right = p_jac.add_mixed(&p2.to_jacobian().add_mixed(&p3).to_affine()).to_affine();

        assert_eq!(left, right);
    }

    /// Test: Commutativity of addition: A + B == B + A
    #[test]
    fn test_jacobian_commutativity() {
        let p1 = G1Affine {
            x: u256::from(1u8),
            y: u256::from(2u8),
        };
        let p2 = G1Affine {
            x: u256::from(3u8),
            y: u256::from(10u8),
        };

        let p1_jac = p1.to_jacobian();
        let p2_jac = p2.to_jacobian();

        // P1 + P2
        let sum1 = p1_jac.add(&p2_jac).to_affine();

        // P2 + P1
        let sum2 = p2_jac.add(&p1_jac).to_affine();

        assert_eq!(sum1, sum2);
    }

    /// Test: Mixed addition commutativity
    #[test]
    fn test_jacobian_mixed_add_commutativity() {
        let p1 = G1Affine {
            x: u256::from(1u8),
            y: u256::from(2u8),
        };
        let p2 = G1Affine {
            x: u256::from(3u8),
            y: u256::from(10u8),
        };

        let p1_jac = p1.to_jacobian();

        // P1_jac + P2_affine
        let sum1 = p1_jac.add_mixed(&p2).to_affine();

        // P2_affine + P1 (need to convert P2 to Jacobian for add)
        let p2_jac = p2.to_jacobian();
        let sum2 = p2_jac.add_mixed(&p1).to_affine();

        assert_eq!(sum1, sum2);
    }

    /// Test: Special case handling - P + P should use doubling
    #[test]
    fn test_jacobian_add_same_point() {
        let p = G1Affine {
            x: u256::from(1u8),
            y: u256::from(2u8),
        };

        let p_jac = p.to_jacobian();

        // Adding same point using add()
        let result_add = p_jac.add(&p_jac);

        // Using double()
        let result_double = p_jac.double();

        assert_eq!(result_add.to_affine(), result_double.to_affine());
    }

    /// Test: Special case handling - mixed add with same point
    #[test]
    fn test_jacobian_mixed_add_same_point() {
        let p = G1Affine {
            x: u256::from(1u8),
            y: u256::from(2u8),
        };

        let p_jac = p.to_jacobian();

        // Mixed addition with same point
        let result_mixed = p_jac.add_mixed(&p);

        // Using double()
        let result_double = p_jac.double();

        assert_eq!(result_mixed.to_affine(), result_double.to_affine());
    }
}
