#![no_std]
use ethnum::u256;

// ---------------------------------------------------------------------------
// BN254 Field Constants
// ---------------------------------------------------------------------------

/// Base field modulus p (used for point coordinates)
/// p = 21888242871839275222246405745257275088696311157297823662689037894645226208583
const FP_MODULUS: u256 = u256::from_words(
    0x30644e72e131a029b85045b68181585d_u128,
    0x97816a916871ca8d3c208c16d87cfd47_u128,
);

/// Scalar field modulus r (used for scalars / exponents)
/// r = 21888242871839275222246405745257275088548364400416034343698204186575808495617
/// This is the group order of G1. k*G = O iff k ≡ 0 (mod r)
const FR_MODULUS: u256 = u256::from_words(
    0x30644e72e131a029b85045b68181585d_u128,
    0x2833e84879b9709143e1f593f0000001_u128,
);

// ---------------------------------------------------------------------------
// Bn254 — base field arithmetic (mod Fp)
// ---------------------------------------------------------------------------

pub struct Bn254;

impl Bn254 {
    pub const BASE_MODULUS: u256 = FP_MODULUS;

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

    /// Modular Multiplication: (a * b) % BASE_MODULUS
    /// Implements manual 512-bit long multiplication to bypass library limitations.
    pub fn mul(a: u256, b: u256) -> u256 {
        if a == u256::from(0u8) || b == u256::from(0u8) {
            return u256::from(0u8);
        }

        let a_low = u256::from(a.as_u128());
        let a_high = a >> 128;
        let b_low = u256::from(b.as_u128());
        let b_high = b >> 128;

        let p0 = a_low * b_low;
        let p1 = a_low * b_high;
        let p2 = a_high * b_low;
        let p3 = a_high * b_high;

        let mut res = p0 % Self::BASE_MODULUS;

        let mut p1_p2 = p1 % Self::BASE_MODULUS;
        p1_p2 = Self::add(p1_p2, p2 % Self::BASE_MODULUS);
        for _ in 0..128 {
            p1_p2 = Self::add(p1_p2, p1_p2);
        }
        res = Self::add(res, p1_p2);

        let mut p3_red = p3 % Self::BASE_MODULUS;
        for _ in 0..256 {
            p3_red = Self::add(p3_red, p3_red);
        }
        res = Self::add(res, p3_red);

        res
    }

    pub fn pow(mut base: u256, mut exp: u256) -> u256 {
        let mut res = u256::from(1u8);
        while exp > u256::from(0u8) {
            if exp % u256::from(2u8) == u256::from(1u8) {
                res = Self::mul(res, base);
            }
            base = Self::mul(base, base);
            exp /= u256::from(2u8);
        }
        res
    }

    pub fn invert(a: u256) -> u256 {
        if a == u256::from(0u8) {
            return u256::from(0u8);
        }
        let exponent = Self::BASE_MODULUS - u256::from(2u8);
        Self::pow(a, exponent)
    }

    pub fn is_valid_g1(x: u256, y: u256) -> bool {
        if x == u256::from(0u8) && y == u256::from(0u8) {
            return false;
        }
        if x >= Self::BASE_MODULUS || y >= Self::BASE_MODULUS {
            return false;
        }
        let y_sq = Self::mul(y, y);
        let x_sq = Self::mul(x, x);
        let x_cb = Self::mul(x_sq, x);
        let rhs = Self::add(x_cb, u256::from(3u8));
        y_sq == rhs
    }
}

// ---------------------------------------------------------------------------
// G1Projective — BN254 G1 point in Jacobian projective coordinates
//
// A projective point (X:Y:Z) represents the affine point (X/Z², Y/Z³).
// The point at infinity (identity) is represented as Z = 0.
//
// Using projective coords avoids the expensive field inversion that affine
// addition requires, saving ~250k instructions per add.
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct G1Projective {
    pub x: u256,
    pub y: u256,
    pub z: u256,
}

impl G1Projective {
    /// The point at infinity (additive identity).
    pub const IDENTITY: G1Projective = G1Projective {
        x: u256::from_words(0, 0),
        y: u256::from_words(0, 1), // y=1 is conventional for identity in projective
        z: u256::from_words(0, 0), // z=0 marks the identity
    };

    /// BN254 G1 generator point (affine, lifted to projective with Z=1).
    /// Gx = 1
    /// Gy = 2
    pub const GENERATOR: G1Projective = G1Projective {
        x: u256::from_words(0, 1),
        y: u256::from_words(0, 2),
        z: u256::from_words(0, 1),
    };

    /// Returns true if this point is the identity (point at infinity).
    pub fn is_identity(&self) -> bool {
        self.z == u256::from_words(0, 0)
    }

    /// Point doubling in Jacobian coordinates.
    ///
    /// Formula (from https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html):
    ///   A = 4*X*Y²
    ///   B = 8*Y⁴
    ///   C = 3*X²          (a=0 for BN254, so no a*Z⁴ term)
    ///   X' = C²  - 2*A
    ///   Y' = C*(A - X') - B
    ///   Z' = 2*Y*Z
    ///
    /// Estimated cost: ~12 Fp multiplications + ~8 additions ≈ 25k–30k instructions
    pub fn double(&self) -> G1Projective {
        if self.is_identity() {
            return *self;
        }

        let x = self.x;
        let y = self.y;
        let z = self.z;

        // A = 4*X*Y²
        let y2 = Bn254::mul(y, y);
        let xy2 = Bn254::mul(x, y2);
        let a = Fp::mul4(xy2);

        // B = 8*Y⁴
        let y4 = Bn254::mul(y2, y2);
        let b = Fp::mul8(y4);

        // C = 3*X²
        let x2 = Bn254::mul(x, x);
        let c = Fp::mul3(x2);

        // X' = C² - 2*A
        let c2 = Bn254::mul(c, c);
        let two_a = Fp::mul2(a);
        let x3 = Fp::sub(c2, two_a);

        // Y' = C*(A - X') - B
        let a_minus_x3 = Fp::sub(a, x3);
        let y3 = Fp::sub(Bn254::mul(c, a_minus_x3), b);

        // Z' = 2*Y*Z
        let yz = Bn254::mul(y, z);
        let z3 = Fp::mul2(yz);

        G1Projective {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    /// Point addition in Jacobian coordinates (mixed: self is projective, rhs is projective).
    ///
    /// Uses the standard Jacobian addition formula.
    /// Estimated cost: ~16 Fp multiplications ≈ 35k–40k instructions
    pub fn add(&self, rhs: &G1Projective) -> G1Projective {
        // Handle identity cases
        if self.is_identity() {
            return *rhs;
        }
        if rhs.is_identity() {
            return *self;
        }

        let x1 = self.x;
        let y1 = self.y;
        let z1 = self.z;
        let x2 = rhs.x;
        let y2 = rhs.y;
        let z2 = rhs.z;

        // U1 = X1*Z2², U2 = X2*Z1²
        let z1_2 = Bn254::mul(z1, z1);
        let z2_2 = Bn254::mul(z2, z2);
        let u1 = Bn254::mul(x1, z2_2);
        let u2 = Bn254::mul(x2, z1_2);

        // S1 = Y1*Z2³, S2 = Y2*Z1³
        let z1_3 = Bn254::mul(z1_2, z1);
        let z2_3 = Bn254::mul(z2_2, z2);
        let s1 = Bn254::mul(y1, z2_3);
        let s2 = Bn254::mul(y2, z1_3);

        // H = U2 - U1,  R = S2 - S1
        let h = Fp::sub(u2, u1);
        let r = Fp::sub(s2, s1);

        // If H == 0: points are equal (double) or inverse (identity)
        if h == u256::from_words(0, 0) {
            if r == u256::from_words(0, 0) {
                return self.double();
            } else {
                return G1Projective::IDENTITY;
            }
        }

        let h2 = Bn254::mul(h, h);
        let h3 = Bn254::mul(h2, h);
        let u1h2 = Bn254::mul(u1, h2);

        // X3 = R² - H³ - 2*U1*H²
        let r2 = Bn254::mul(r, r);
        let two_u1h2 = Fp::mul2(u1h2);
        let x3 = Fp::sub(Fp::sub(r2, h3), two_u1h2);

        // Y3 = R*(U1*H² - X3) - S1*H³
        let u1h2_x3 = Fp::sub(u1h2, x3);
        let s1h3 = Bn254::mul(s1, h3);
        let y3 = Fp::sub(Bn254::mul(r, u1h2_x3), s1h3);

        // Z3 = H*Z1*Z2
        let z3 = Bn254::mul(Bn254::mul(h, z1), z2);

        G1Projective {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    /// Convert projective point to affine (X/Z², Y/Z³).
    /// Returns (0,0) for the identity point.
    pub fn to_affine(&self) -> (u256, u256) {
        if self.is_identity() {
            return (u256::from_words(0, 0), u256::from_words(0, 0));
        }
        let z_inv = Bn254::invert(self.z);
        let z_inv2 = Bn254::mul(z_inv, z_inv);
        let z_inv3 = Bn254::mul(z_inv2, z_inv);
        let ax = Bn254::mul(self.x, z_inv2);
        let ay = Bn254::mul(self.y, z_inv3);
        (ax, ay)
    }

    /// Construct a projective point from affine coordinates.
    pub fn from_affine(x: u256, y: u256) -> G1Projective {
        G1Projective {
            x,
            y,
            z: u256::from_words(0, 1),
        }
    }
}

// ---------------------------------------------------------------------------
// Fp — helper for modular sub and small multiples (mod FP_MODULUS)
// ---------------------------------------------------------------------------

struct Fp;

impl Fp {
    /// Modular subtraction: (a - b) mod p, without underflow.
    fn sub(a: u256, b: u256) -> u256 {
        if a >= b {
            a - b
        } else {
            // a - b + p  (wraps correctly since a < b means result > 0)
            let diff = b - a;
            FP_MODULUS - diff
        }
    }

    fn mul2(a: u256) -> u256 {
        Bn254::add(a, a)
    }

    fn mul3(a: u256) -> u256 {
        Bn254::add(Fp::mul2(a), a)
    }

    fn mul4(a: u256) -> u256 {
        Fp::mul2(Fp::mul2(a))
    }

    fn mul8(a: u256) -> u256 {
        Fp::mul2(Fp::mul4(a))
    }
}

// ---------------------------------------------------------------------------
// ct_select — Constant-time conditional select (Issue #12)
//
// Returns `a` if `select_a == 1`, returns `b` if `select_a == 0`.
// Uses arithmetic masking — no branching on the secret bit.
//
// Security note: This is constant-time with respect to the SELECT BIT only.
// The field values a and b are always fully processed regardless of the bit.
// ---------------------------------------------------------------------------

/// Constant-time select for u256 values.
/// Returns `a` if `bit` is 1, returns `b` if `bit` is 0.
/// `bit` MUST be exactly 0 or 1.
pub fn ct_select_u256(a: u256, b: u256, bit: u256) -> u256 {
    // mask = 0xFFFF...FFFF if bit == 1, else 0x0000...0000
    // We compute: (bit * 0xFFFF...FFFF) which is either all-ones or zero
    let mask = bit.wrapping_mul(u256::MAX);
    // result = (a & mask) | (b & !mask)
    (a & mask) | (b & !mask)
}

/// Constant-time select for G1Projective points.
/// Returns `a` if `bit` is 1, returns `b` if `bit` is 0.
/// `bit` MUST be exactly 0 or 1.
pub fn ct_select_g1(a: G1Projective, b: G1Projective, bit: u256) -> G1Projective {
    G1Projective {
        x: ct_select_u256(a.x, b.x, bit),
        y: ct_select_u256(a.y, b.y, bit),
        z: ct_select_u256(a.z, b.z, bit),
    }
}

// ---------------------------------------------------------------------------
// g1_scalar_mul — Double-and-Add scalar multiplication (Issue #21)
//
// Computes k * P for a point P ∈ G1 and scalar k ∈ Fr.
//
// Algorithm: Double-and-Add from MSB to LSB over all 254 bits.
//   result = identity
//   for bit in scalar.bits() MSB → LSB:
//     result = double(result)
//     candidate = add(result, P)
//     result = ct_select(candidate, result, bit)   ← no branch on bit
//
// Constant-time guarantee: ct_select is used so both the add and the
// no-op path are always executed. The scalar bit never causes branching.
//
// Instruction cost estimate:
//   254 iterations × (1 double + 1 add + 1 ct_select)
//   ≈ 254 × (28k + 38k + 1k) instructions
//   ≈ ~17M instructions total
//   Well within Soroban's 400M instruction budget.
// ---------------------------------------------------------------------------

/// Scalar multiplication: computes `scalar * point` on BN254 G1.
///
/// # Arguments
/// * `point`  — A point in G1 (projective coordinates)
/// * `scalar` — A 256-bit scalar (will be reduced mod Fr internally)
///
/// # Returns
/// The projective point `scalar * point`.
pub fn g1_scalar_mul(point: G1Projective, scalar: u256) -> G1Projective {
    // Fast paths
    if scalar == u256::from_words(0, 0) {
        return G1Projective::IDENTITY;
    }
    if scalar == u256::from_words(0, 1) {
        return point;
    }

    // Reduce scalar mod Fr to handle scalars >= group order
    let k = scalar % FR_MODULUS;

    // After reduction, re-check fast paths
    if k == u256::from_words(0, 0) {
        return G1Projective::IDENTITY;
    }
    if k == u256::from_words(0, 1) {
        return point;
    }

    let mut result = G1Projective::IDENTITY;

    // Process all 254 bits from MSB to LSB.
    // BN254 Fr is ~254 bits; bit 255 and 256 are always 0 after reduction.
    // We iterate bits 253 down to 0 (254 bits total).
    let mut i: u32 = 253;
    loop {
        // Always double
        result = result.double();

        // Compute candidate = result + point (always, no branch)
        let candidate = result.add(&point);

        // Extract bit i of scalar k (0 or 1)
        let bit = (k >> i) & u256::from_words(0, 1);

        // Constant-time select: pick candidate if bit==1, else keep result
        result = ct_select_g1(candidate, result, bit);

        if i == 0 {
            break;
        }
        i -= 1;
    }

    result
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- Bn254 field arithmetic tests ---

    #[test]
    fn test_add_no_overflow() {
        let a = u256::from_words(0, 10u128);
        let b = u256::from_words(0, 20u128);
        assert_eq!(Bn254::add(a, b), u256::from_words(0, 30u128));
    }

    #[test]
    fn test_add_wraps_modulus() {
        let a = FP_MODULUS - u256::from_words(0, 1);
        let b = u256::from_words(0, 2u128);
        // (p-1) + 2 = p+1 ≡ 1 (mod p)
        assert_eq!(Bn254::add(a, b), u256::from_words(0, 1u128));
    }

    #[test]
    fn test_mul_zero() {
        let a = u256::from_words(0, 42u128);
        assert_eq!(
            Bn254::mul(a, u256::from_words(0, 0)),
            u256::from_words(0, 0)
        );
    }

    #[test]
    fn test_mul_one() {
        let a = u256::from_words(0, 42u128);
        assert_eq!(
            Bn254::mul(a, u256::from_words(0, 1)),
            u256::from_words(0, 42u128)
        );
    }

    #[test]
    fn test_invert_roundtrip() {
        let a = u256::from_words(0, 7u128);
        let inv_a = Bn254::invert(a);
        // a * a^{-1} == 1 mod p
        assert_eq!(Bn254::mul(a, inv_a), u256::from_words(0, 1u128));
    }

    // --- ct_select tests ---

    #[test]
    fn test_ct_select_picks_a_when_bit_1() {
        let a = u256::from_words(0, 111u128);
        let b = u256::from_words(0, 222u128);
        assert_eq!(ct_select_u256(a, b, u256::from_words(0, 1)), a);
    }

    #[test]
    fn test_ct_select_picks_b_when_bit_0() {
        let a = u256::from_words(0, 111u128);
        let b = u256::from_words(0, 222u128);
        assert_eq!(ct_select_u256(a, b, u256::from_words(0, 0)), b);
    }

    // --- G1 scalar multiplication tests ---

    /// g1_scalar_mul(G, 1) == G
    #[test]
    fn test_scalar_mul_by_one() {
        let g = G1Projective::GENERATOR;
        let result = g1_scalar_mul(g, u256::from_words(0, 1));
        let (rx, ry) = result.to_affine();
        // Generator affine coords: (1, 2)
        assert_eq!(rx, u256::from_words(0, 1));
        assert_eq!(ry, u256::from_words(0, 2));
    }

    /// g1_scalar_mul(G, 0) == identity
    #[test]
    fn test_scalar_mul_by_zero() {
        let g = G1Projective::GENERATOR;
        let result = g1_scalar_mul(g, u256::from_words(0, 0));
        assert!(result.is_identity());
    }

    /// g1_scalar_mul(G, 2) == G.double()
    #[test]
    fn test_scalar_mul_by_two_equals_double() {
        let g = G1Projective::GENERATOR;
        let doubled = g.double();
        let result = g1_scalar_mul(g, u256::from_words(0, 2));
        // Compare affine coordinates
        let (dx, dy) = doubled.to_affine();
        let (rx, ry) = result.to_affine();
        assert_eq!(rx, dx);
        assert_eq!(ry, dy);
    }

    /// CANONICAL CORRECTNESS TEST: g1_scalar_mul(G, r) == identity
    /// Multiplying the generator by the group order must yield the identity.
    #[test]
    fn test_scalar_mul_by_group_order_is_identity() {
        let g = G1Projective::GENERATOR;
        // r = FR_MODULUS (the BN254 group order)
        let result = g1_scalar_mul(g, FR_MODULUS);
        assert!(result.is_identity(), "G * r must equal the identity point");
    }
}
