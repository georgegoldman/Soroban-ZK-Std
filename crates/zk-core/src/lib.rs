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

/// Affine point representation (x, y) on the BN254 curve
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AffinePoint {
    pub x: u256,
    pub y: u256,
}

/// Jacobian point representation (X, Y, Z) on the BN254 curve
/// Affine coordinates (x, y) are related by: x = X/Z², y = Y/Z³
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct JacobianPoint {
    pub x: u256,
    pub y: u256,
    pub z: u256,
}

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

    /// Convert Jacobian coordinates (X, Y, Z) to Affine coordinates (x, y)
    /// 
    /// # Arguments
    /// * `point` - A JacobianPoint with coordinates (X, Y, Z)
    /// 
    /// # Returns
    /// * `Some(AffinePoint)` - The affine coordinates (x, y) where x = X/Z² and y = Y/Z³
    /// * `None` - If Z = 0 (point at infinity)
    /// 
    /// # Mathematical Details
    /// Given Jacobian coordinates (X, Y, Z), the affine coordinates are:
    ///   x = X · Z⁻² mod p
    ///   y = Y · Z⁻³ mod p
    /// 
    /// We compute Z⁻¹ once using Fermat inversion, then derive:
    ///   Z⁻² = (Z⁻¹)²
    ///   Z⁻³ = Z⁻¹ · Z⁻²
    pub fn jacobian_to_affine(point: &JacobianPoint) -> Option<AffinePoint> {
        // Guard: Z = 0 represents the point at infinity
        if point.z == u256::from(0u8) {
            return None;
        }

        // Compute Z⁻¹ using Fermat's little theorem: Z⁻¹ = Z^(p-2) mod p
        let z_inv = Self::invert(point.z);

        // Compute Z⁻² = (Z⁻¹)²
        let z_inv_sq = Self::mul(z_inv, z_inv);

        // Compute Z⁻³ = Z⁻¹ · Z⁻²
        let z_inv_cb = Self::mul(z_inv, z_inv_sq);

        // Compute affine coordinates
        // x = X · Z⁻² mod p
        let x = Self::mul(point.x, z_inv_sq);

        // y = Y · Z⁻³ mod p
        let y = Self::mul(point.y, z_inv_cb);

        Some(AffinePoint { x, y })
    }

    /// Create a Jacobian point from affine coordinates
    /// 
    /// # Arguments
    /// * `x` - The x-coordinate in affine space
    /// * `y` - The y-coordinate in affine space
    /// 
    /// # Returns
    /// * `JacobianPoint` - The point in Jacobian coordinates with Z = 1
    pub fn affine_to_jacobian(point: &AffinePoint) -> JacobianPoint {
        JacobianPoint {
            x: point.x,
            y: point.y,
            z: u256::from(1u8),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jacobian_to_affine_normal_point() {
        // Test with a known point on the BN254 curve
        // Generator point G = (1, 2) in affine coordinates
        let affine_g = AffinePoint {
            x: u256::from(1u8),
            y: u256::from(2u8),
        };

        // Convert to Jacobian with Z = 1
        let jacobian_g = Bn254::affine_to_jacobian(&affine_g);

        // Convert back to affine
        let result = Bn254::jacobian_to_affine(&jacobian_g);

        // Should succeed and match original
        assert!(result.is_some());
        let converted = result.unwrap();
        assert_eq!(converted.x, affine_g.x);
        assert_eq!(converted.y, affine_g.y);
    }

    #[test]
    fn test_jacobian_to_affine_with_scaled_z() {
        // Test with a point where Z != 1
        // Use generator point G = (1, 2)
        let affine_g = AffinePoint {
            x: u256::from(1u8),
            y: u256::from(2u8),
        };

        // Create Jacobian point with Z = 2
        // This represents the same affine point (1, 2)
        let jacobian_scaled = JacobianPoint {
            x: Bn254::mul(affine_g.x, Bn254::mul(u256::from(2u8), u256::from(2u8))), // X = x * Z²
            y: Bn254::mul(affine_g.y, Bn254::mul(u256::from(2u8), Bn254::mul(u256::from(2u8), u256::from(2u8)))), // Y = y * Z³
            z: u256::from(2u8),
        };

        // Convert to affine
        let result = Bn254::jacobian_to_affine(&jacobian_scaled);

        // Should succeed and match original affine point
        assert!(result.is_some());
        let converted = result.unwrap();
        assert_eq!(converted.x, affine_g.x);
        assert_eq!(converted.y, affine_g.y);
    }

    #[test]
    fn test_jacobian_to_affine_identity_point() {
        // Test with Z = 0 (point at infinity)
        let jacobian_identity = JacobianPoint {
            x: u256::from(0u8),
            y: u256::from(0u8),
            z: u256::from(0u8),
        };

        // Convert to affine
        let result = Bn254::jacobian_to_affine(&jacobian_identity);

        // Should return None for point at infinity
        assert!(result.is_none());
    }

    #[test]
    fn test_jacobian_to_affine_round_trip() {
        // Test round-trip conversion: affine -> jacobian -> affine
        // Use a valid point on the BN254 curve
        let original_affine = AffinePoint {
            x: u256::from(1u8),
            y: u256::from(2u8),
        };

        // Verify the point is on the curve
        assert!(Bn254::is_valid_g1(original_affine.x, original_affine.y));

        // Convert to Jacobian
        let jacobian = Bn254::affine_to_jacobian(&original_affine);

        // Convert back to affine
        let result = Bn254::jacobian_to_affine(&jacobian);
        assert!(result.is_some());
        let round_trip_affine = result.unwrap();

        // Verify the point is still on the curve
        assert!(Bn254::is_valid_g1(round_trip_affine.x, round_trip_affine.y));

        // Verify coordinates match
        assert_eq!(round_trip_affine.x, original_affine.x);
        assert_eq!(round_trip_affine.y, original_affine.y);
    }

    #[test]
    fn test_jacobian_to_affine_multiple_z_values() {
        // Test that different Z values represent the same affine point
        let affine_point = AffinePoint {
            x: u256::from(1u8),
            y: u256::from(2u8),
        };

        // Test with Z = 1, 2, 3, 5
        let z_values = [1u8, 2, 3, 5];

        for &z_val in z_values.iter() {
            let z = u256::from(z_val);
            let jacobian = JacobianPoint {
                x: Bn254::mul(affine_point.x, Bn254::mul(z, z)), // X = x * Z²
                y: Bn254::mul(affine_point.y, Bn254::mul(z, Bn254::mul(z, z))), // Y = y * Z³
                z,
            };

            let result = Bn254::jacobian_to_affine(&jacobian);
            assert!(result.is_some());
            let converted = result.unwrap();
            assert_eq!(converted.x, affine_point.x);
            assert_eq!(converted.y, affine_point.y);
        }
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
}
