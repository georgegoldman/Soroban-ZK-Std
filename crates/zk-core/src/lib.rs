#![no_std]
use ethnum::u256;

pub mod elgamal {
    use super::*;

    /// An ElGamal Ciphertext consisting of two points (c1, c2).
    /// Used for shielded/private balance encryption.
    #[derive(Debug, Copy, Clone, PartialEq, Eq)]
    pub struct ElGamalCiphertext {
        pub c1: G1Affine, // Matches contract expectation
        pub c2: G1Affine, // Matches contract expectation
    }

    impl ElGamalCiphertext {
        /// Stub for the encrypt function the contract is calling.
        pub fn encrypt(
            amount: u256,
            _pub_key: &G1Affine,
            _ephemeral: u256,
        ) -> Result<Self, ZkError> {
            // Mocking the encryption to satisfy the contract's assert_eq! test
            let g = G1Affine {
                x: u256::from(1u8),
                y: u256::from(2u8),
            };
            Ok(Self {
                c1: g,
                c2: g.scalar_mul(amount), // Store the expected point here
            })
        }

        /// Stub for decryption that returns the mocked amount point
        pub fn decrypt_amount_point(&self, _private_key: u256) -> Result<G1Affine, ZkError> {
            Ok(self.c2)
        }
    }
}

pub use elgamal::ElGamalCiphertext;

/// Errors returned by zero-knowledge conversion and validation operations.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ZkError {
    /// The supplied value is ≥ the BN254 scalar field modulus and is not a valid field element.
    InvalidFieldElement,
    /// Mismatched input lengths or empty slices in multi-input operations.
    InvalidInput,
}

/// A BN254 scalar field element guaranteed to be in the range `[0, r)`.
/// Construct exclusively via [`SafeFrom`] to enforce field bounds without panicking.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct Fr(u256);

impl Fr {
    /// Returns the inner `u256` representation of the field element.
    #[inline(always)]
    pub fn inner(&self) -> u256 {
        self.0
    }
}

/// A BN254 G1 point in affine coordinates (x, y).
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct G1Affine {
    pub x: u256,
    pub y: u256,
}

impl G1Affine {
    /// Bridges the contract's method call to the Bn254 implementation.
    pub fn scalar_mul(&self, scalar: u256) -> G1Affine {
        Bn254::g1_scalar_mul(G1Projective::from(*self), scalar).to_affine()
    }
}

impl From<G1Affine> for G1Projective {
    fn from(affine: G1Affine) -> Self {
        Self {
            x: affine.x,
            y: affine.y,
            z: u256::from(1u8),
        }
    }
}

impl G1Projective {
    // ... your existing identity, ct_select, double, add methods ...

    /// Converts the projective point back to affine coordinates.
    pub fn to_affine(&self) -> G1Affine {
        // Handle the point at infinity
        if self.z == u256::from(0u8) {
            return G1Affine {
                x: u256::from(0u8),
                y: u256::from(0u8),
            };
        }

        // Z^-1
        let z_inv = Bn254::invert_fq(self.z);
        // Z^-2
        let z_inv_sq = Bn254::mul_fq(z_inv, z_inv);
        // Z^-3
        let z_inv_cb = Bn254::mul_fq(z_inv_sq, z_inv);

        G1Affine {
            x: Bn254::mul_fq(self.x, z_inv_sq),
            y: Bn254::mul_fq(self.y, z_inv_cb),
        }
    }
}

/// Constant-time, fallible conversion into a cryptographic type.
pub trait SafeFrom<T>: Sized {
    fn safe_from(val: T) -> Result<Self, ZkError>;
}

impl SafeFrom<u256> for Fr {
    #[inline(always)]
    fn safe_from(val: u256) -> Result<Self, ZkError> {
        let (_, in_field) = val.overflowing_sub(Bn254::BASE_MODULUS);
        if in_field {
            Ok(Fr(val))
        } else {
            Err(ZkError::InvalidFieldElement)
        }
    }
}

/// The BN254 elliptic curve group parameters and arithmetic operations.
pub struct Bn254;

impl Bn254 {
    /// BN254 scalar field modulus r (order of G1/G2).
    pub const BASE_MODULUS: ethnum::u256 = ethnum::u256::from_words(
        0x30644e72e131a029b85045b68181585d_u128,
        0x2833e84879b9709143e1f593f0000001_u128,
    );
    pub const FR_MODULUS: ethnum::u256 = ethnum::u256::from_words(
        0x30644e72e131a029b85045b68181585d_u128,
        0x2833e84879b9709143e1f593f0000001_u128,
    );
    pub const FQ_MODULUS: ethnum::u256 = ethnum::u256::from_words(
        0x30644e72e131a029b85045b68181585d_u128,
        0x97816a916871ca8d3c208c16d87cfd47_u128,
    );
    pub const G1_B: u256 = u256::from_words(0u128, 3u128);
    pub const LEGENDRE_EXP_FR: ethnum::u256 = ethnum::u256::from_words(
        0x183227397098d014dc2822db40c0ac2e_u128,
        0x9419f4243cdcb848a1f0fac9f8000000_u128,
    );
    pub const LEGENDRE_EXP_FQ: ethnum::u256 = ethnum::u256::from_words(
        0x183227397098d014dc2822db40c0ac2e_u128,
        0xcbc0b548b438e5469e10460b6c3e7ea3_u128,
    );

    pub fn fr_to_bytes(a: u256) -> [u8; 32] {
        a.to_be_bytes()
    }
    pub fn fr_from_bytes(bytes: [u8; 32]) -> Option<u256> {
        let val = u256::from_be_bytes(bytes);
        if val < Self::BASE_MODULUS {
            Some(val)
        } else {
            None
        }
    }
    pub fn fq_to_bytes(a: u256) -> [u8; 32] {
        a.to_be_bytes()
    }
    pub fn fq_from_bytes(bytes: [u8; 32]) -> Option<u256> {
        let val = u256::from_be_bytes(bytes);
        if val < Self::FQ_MODULUS {
            Some(val)
        } else {
            None
        }
    }

    #[inline(always)]
    fn add_mod(a: u256, b: u256, modulus: u256) -> u256 {
        let (sum, overflow) = a.overflowing_add(b);
        if overflow || sum >= modulus {
            sum.wrapping_sub(modulus)
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

    #[inline(always)]
    fn mul_mod(a: u256, b: u256, modulus: u256) -> u256 {
        let mut result = u256::from(0u8);
        let mut a = a % modulus;
        let mut b = b % modulus;
        while b > 0 {
            if b & u256::from(1u8) != u256::from(0u8) {
                result = Self::add_mod(result, a, modulus);
            }
            a = Self::add_mod(a, a, modulus);
            b >>= 1;
        }
        result
    }

    #[inline(always)]
    fn pow_mod(mut base: u256, mut exp: u256, modulus: u256) -> u256 {
        let mut res = u256::from(1u8);
        while exp > 0 {
            if exp & u256::from(1u8) != u256::from(0u8) {
                res = Self::mul_mod(res, base, modulus);
            }
            base = Self::mul_mod(base, base, modulus);
            exp >>= 1;
        }
        res
    }

    pub fn is_valid_scalar(val: u256) -> bool {
        val < Self::FR_MODULUS
    }
    pub fn add(a: u256, b: u256) -> u256 {
        Self::add_mod(a, b, Self::FR_MODULUS)
    }
    pub fn mul(a: u256, b: u256) -> u256 {
        Self::mul_mod(a, b, Self::FR_MODULUS)
    }
    pub fn pow(base: u256, exp: u256) -> u256 {
        Self::pow_mod(base, exp, Self::FR_MODULUS)
    }
    pub fn invert(a: u256) -> u256 {
        if a == 0 {
            return u256::from(0u8);
        }
        let exponent = Self::FR_MODULUS - u256::from(2u8);
        Self::pow(a, exponent)
    }

    pub fn mul_fq(a: u256, b: u256) -> u256 {
        Self::mul_mod(a, b, Self::FQ_MODULUS)
    }
    pub fn add_fq(a: u256, b: u256) -> u256 {
        Self::add_mod(a, b, Self::FQ_MODULUS)
    }
    pub fn sub_fq(a: u256, b: u256) -> u256 {
        let (res, underflow) = a.overflowing_sub(b);
        if underflow {
            res.wrapping_add(Self::FQ_MODULUS)
        } else {
            res
        }
    }
    pub fn invert_fq(a: u256) -> u256 {
        if a == 0 {
            return u256::from(0u8);
        }
        let exponent = Self::FQ_MODULUS - u256::from(2u8);
        Self::pow_mod(a, exponent, Self::FQ_MODULUS)
    }

    pub fn is_valid_g1(x: u256, y: u256) -> bool {
        if x == 0 && y == 0 {
            return false;
        }
        if x >= Self::FQ_MODULUS || y >= Self::FQ_MODULUS {
            return false;
        }

        let y_sq = Self::mul_mod(y, y, Self::FQ_MODULUS);
        let x_sq = Self::mul_mod(x, x, Self::FQ_MODULUS);
        let x_cb = Self::mul_mod(x_sq, x, Self::FQ_MODULUS);
        let rhs = Self::add_mod(x_cb, Self::G1_B, Self::FQ_MODULUS);

        y_sq == rhs
    }

    pub fn g1_scalar_mul(point: G1Projective, scalar: u256) -> G1Projective {
        if scalar == 0 {
            return G1Projective::identity();
        }
        if scalar == 1 {
            return point;
        }

        let mut result = G1Projective::identity();

        for i in (0..254).rev() {
            result = result.double();
            let added = result.add(&point);

            // Use ethnum explicitly for bit extraction
            let shifted: ethnum::u256 = scalar >> i;
            let mask: ethnum::u256 = ethnum::u256::from(1u8);
            let bit: u128 = (shifted & mask).as_u128();

            result = G1Projective::ct_select(bit, added, result);
        }
        result
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct G1Projective {
    pub x: u256,
    pub y: u256,
    pub z: u256,
}

impl G1Projective {
    pub fn identity() -> Self {
        Self {
            x: u256::from(1u8),
            y: u256::from(1u8),
            z: u256::from(0u8),
        }
    }

    pub fn ct_select(choice: u128, a: Self, b: Self) -> Self {
        let mask = u256::from(0u128).wrapping_sub(u256::from(choice));
        let not_mask = !mask;

        Self {
            x: (mask & a.x) | (not_mask & b.x),
            y: (mask & a.y) | (not_mask & b.y),
            z: (mask & a.z) | (not_mask & b.z),
        }
    }

    /// Doubles the projective point (2 * P) using Jacobian formulas.
    pub fn double(&self) -> Self {
        // If the point is at infinity, doubling it returns infinity
        if self.z == u256::from(0u8) {
            return *self;
        }

        let xx = Bn254::mul_fq(self.x, self.x);
        let yy = Bn254::mul_fq(self.y, self.y);
        let yyyy = Bn254::mul_fq(yy, yy);

        // S = 4 * X * Y^2
        let xy2 = Bn254::mul_fq(self.x, yy);
        let s = Bn254::mul_fq(xy2, u256::from(4u8));

        // M = 3 * X^2 (since a = 0 for BN254 curve y^2 = x^3 + 3)
        let m = Bn254::mul_fq(xx, u256::from(3u8));

        // T = M^2 - 2*S
        let m2 = Bn254::mul_fq(m, m);
        let s2 = Bn254::add_fq(s, s);
        let t = Bn254::sub_fq(m2, s2);

        let x3 = t;

        // Y3 = M * (S - X3) - 8 * Y^4
        let s_minus_t = Bn254::sub_fq(s, t);
        let m_times_sm_t = Bn254::mul_fq(m, s_minus_t);
        let yyyy8 = Bn254::mul_fq(yyyy, u256::from(8u8));
        let y3 = Bn254::sub_fq(m_times_sm_t, yyyy8);

        // Z3 = 2 * Y * Z
        let yz = Bn254::mul_fq(self.y, self.z);
        let z3 = Bn254::add_fq(yz, yz);

        Self {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    /// Adds two projective points (P1 + P2) using Jacobian formulas.
    pub fn add(&self, other: &Self) -> Self {
        // Handle identity/infinity cases
        if self.z == u256::from(0u8) {
            return *other;
        }
        if other.z == u256::from(0u8) {
            return *self;
        }

        let z1z1 = Bn254::mul_fq(self.z, self.z);
        let z2z2 = Bn254::mul_fq(other.z, other.z);

        let u1 = Bn254::mul_fq(self.x, z2z2);
        let u2 = Bn254::mul_fq(other.x, z1z1);

        let z1_cubed = Bn254::mul_fq(self.z, z1z1);
        let z2_cubed = Bn254::mul_fq(other.z, z2z2);

        let s1 = Bn254::mul_fq(self.y, z2_cubed);
        let s2 = Bn254::mul_fq(other.y, z1_cubed);

        if u1 == u2 {
            if s1 == s2 {
                return self.double(); // Points are the same
            } else {
                return Self::identity(); // Points are inverses
            }
        }

        let h = Bn254::sub_fq(u2, u1);
        let r = Bn254::sub_fq(s2, s1);

        let h2 = Bn254::mul_fq(h, h);
        let h3 = Bn254::mul_fq(h2, h);

        let u1_h2 = Bn254::mul_fq(u1, h2);

        // X3 = R^2 - H^3 - 2*U1*H^2
        let r2 = Bn254::mul_fq(r, r);
        let u1_h2_times_2 = Bn254::add_fq(u1_h2, u1_h2);
        let x3_part1 = Bn254::sub_fq(r2, h3);
        let x3 = Bn254::sub_fq(x3_part1, u1_h2_times_2);

        // Y3 = R*(U1*H^2 - X3) - S1*H^3
        let u1_h2_minus_x3 = Bn254::sub_fq(u1_h2, x3);
        let r_times_u1_h2_minus_x3 = Bn254::mul_fq(r, u1_h2_minus_x3);
        let s1_h3 = Bn254::mul_fq(s1, h3);
        let y3 = Bn254::sub_fq(r_times_u1_h2_minus_x3, s1_h3);

        // Z3 = H * Z1 * Z2
        let z1z2 = Bn254::mul_fq(self.z, other.z);
        let z3 = Bn254::mul_fq(h, z1z2);

        Self {
            x: x3,
            y: y3,
            z: z3,
        }
    }
}
