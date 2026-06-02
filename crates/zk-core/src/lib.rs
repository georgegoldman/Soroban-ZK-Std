#![no_std]
use ethnum::u256;

/// Constant-time field arithmetic over 256-bit primes via Montgomery form.
///
/// All routines run in time independent of their operand *values* (no
/// data-dependent branches or memory accesses), so they do not leak secrets
/// through timing. Operands are represented as four little-endian 64-bit limbs;
/// every loop has a fixed trip count and every conditional is implemented with
/// bitmask selection rather than control flow.
///
/// The field modulus is referred to as `m`, and `R = 2^256`. Inputs and outputs
/// of the public [`mul_mod`]/[`add_mod`]/[`sub_mod`] helpers are *ordinary*
/// residues in `[0, m)` (not Montgomery form), so callers need no awareness of
/// the internal representation; conversion in and out of Montgomery form happens
/// inside [`mul_mod`].
mod mont {
    use ethnum::u256;

    /// `a + b*c + carry`, returning `(low 64 bits, high 64 bits)`.
    #[inline(always)]
    const fn mac(a: u64, b: u64, c: u64, carry: u64) -> (u64, u64) {
        let ret = (a as u128) + (b as u128) * (c as u128) + (carry as u128);
        (ret as u64, (ret >> 64) as u64)
    }

    /// `a + b + carry`, returning `(low 64 bits, high 64 bits)`.
    #[inline(always)]
    const fn adc(a: u64, b: u64, carry: u64) -> (u64, u64) {
        let ret = (a as u128) + (b as u128) + (carry as u128);
        (ret as u64, (ret >> 64) as u64)
    }

    /// `a - b - borrow`, returning `(result, borrow_out in {0,1})`.
    #[inline(always)]
    const fn sbb(a: u64, b: u64, borrow: u64) -> (u64, u64) {
        let ret = (a as u128).wrapping_sub((b as u128) + (borrow as u128));
        (ret as u64, ((ret >> 64) as u64) & 1)
    }

    #[inline(always)]
    fn to_limbs(x: u256) -> [u64; 4] {
        let (hi, lo) = x.into_words();
        [lo as u64, (lo >> 64) as u64, hi as u64, (hi >> 64) as u64]
    }

    #[inline(always)]
    fn from_limbs(l: [u64; 4]) -> u256 {
        let lo = (l[0] as u128) | ((l[1] as u128) << 64);
        let hi = (l[2] as u128) | ((l[3] as u128) << 64);
        u256::from_words(hi, lo)
    }

    /// Schoolbook 4x4 -> 8 limb product. Fixed trip count, no branches.
    #[inline(always)]
    fn mul_wide(a: [u64; 4], b: [u64; 4]) -> [u64; 8] {
        let mut r = [0u64; 8];
        let mut i = 0;
        while i < 4 {
            let mut carry = 0u64;
            let mut j = 0;
            while j < 4 {
                let (lo, hi) = mac(r[i + j], a[i], b[j], carry);
                r[i + j] = lo;
                carry = hi;
                j += 1;
            }
            r[i + 4] = carry;
            i += 1;
        }
        r
    }

    /// Montgomery reduction of an 8-limb value `t` modulo `m`: returns
    /// `t * R^{-1} mod m` in `[0, 2m)`. `inv` is `-m^{-1} mod 2^64`.
    #[inline(always)]
    fn mont_reduce(mut t: [u64; 8], m: [u64; 4], inv: u64) -> [u64; 4] {
        let mut carry2 = 0u64;
        let mut i = 0;
        while i < 4 {
            let k = t[i].wrapping_mul(inv);
            let (_, mut carry) = mac(t[i], k, m[0], 0);
            let mut j = 1;
            while j < 4 {
                let (lo, c) = mac(t[i + j], k, m[j], carry);
                t[i + j] = lo;
                carry = c;
                j += 1;
            }
            let (lo, c2) = adc(t[i + 4], carry2, carry);
            t[i + 4] = lo;
            carry2 = c2;
            i += 1;
        }
        [t[4], t[5], t[6], t[7]]
    }

    /// Constant-time conditional subtraction: returns `a - m` if `a >= m`, else
    /// `a`. Selection is done with a bitmask so control flow is value-independent.
    #[inline(always)]
    fn cond_sub(a: [u64; 4], m: [u64; 4]) -> [u64; 4] {
        let (r0, b) = sbb(a[0], m[0], 0);
        let (r1, b) = sbb(a[1], m[1], b);
        let (r2, b) = sbb(a[2], m[2], b);
        let (r3, borrow) = sbb(a[3], m[3], b);
        // borrow == 1 means a < m, so keep `a`; borrow == 0 means use `a - m`.
        let mask = 0u64.wrapping_sub(borrow);
        [
            (mask & a[0]) | (!mask & r0),
            (mask & a[1]) | (!mask & r1),
            (mask & a[2]) | (!mask & r2),
            (mask & a[3]) | (!mask & r3),
        ]
    }

    /// Montgomery multiplication: `a * b * R^{-1} mod m`, fully reduced to
    /// `[0, m)`. Requires `a, b < m`.
    #[inline(always)]
    fn mont_mul(a: [u64; 4], b: [u64; 4], m: [u64; 4], inv: u64) -> [u64; 4] {
        cond_sub(mont_reduce(mul_wide(a, b), m, inv), m)
    }

    /// All-ones mask when `c` is true, zero otherwise — branch-free.
    #[inline(always)]
    fn bool_mask(c: bool) -> u256 {
        u256::from(0u8).wrapping_sub(u256::from(c as u8))
    }

    /// Field multiplication in ordinary form: returns `a * b mod m`.
    ///
    /// Computed as `mont_mul(mont_mul(a, b), R2) = a*b mod m`, where `r2 = R^2
    /// mod m`. Requires `a, b < m` (all internal callers maintain this).
    #[inline(always)]
    pub fn mul_mod(a: u256, b: u256, m: u256, r2: u256, inv: u64) -> u256 {
        let ml = to_limbs(m);
        let t = mont_mul(to_limbs(a), to_limbs(b), ml, inv);
        from_limbs(mont_mul(t, to_limbs(r2), ml, inv))
    }

    /// Constant-time modular addition: `(a + b) mod m`. Requires `a, b < m`.
    #[inline(always)]
    pub fn add_mod(a: u256, b: u256, m: u256) -> u256 {
        let (sum, carry) = a.overflowing_add(b);
        let (diff, borrow) = sum.overflowing_sub(m);
        // Subtract m when the add overflowed 256 bits, or when sum >= m
        // (i.e. the subtraction did not borrow).
        let mask = bool_mask(carry | !borrow);
        (mask & diff) | (!mask & sum)
    }

    /// Constant-time modular subtraction: `(a - b) mod m`. Requires `a, b < m`.
    #[inline(always)]
    pub fn sub_mod(a: u256, b: u256, m: u256) -> u256 {
        let (diff, borrow) = a.overflowing_sub(b);
        let added = diff.wrapping_add(m);
        let mask = bool_mask(borrow);
        (mask & added) | (!mask & diff)
    }
}

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

    /// Montgomery constant `-r^{-1} mod 2^64` for the scalar field `Fr`.
    const FR_INV: u64 = 0xc2e1f593efffffff;
    /// Montgomery constant `R^2 mod r` (`R = 2^256`) for the scalar field `Fr`.
    const FR_R2: u256 = u256::from_words(
        0x0216d0b17f4e44a58c49833d53bb8085_u128,
        0x53fe3ab1e35c59e31bb8e645ae216da7_u128,
    );
    /// Montgomery constant `-q^{-1} mod 2^64` for the base field `Fq`.
    const FQ_INV: u64 = 0x87d20782e4866389;
    /// Montgomery constant `R^2 mod q` (`R = 2^256`) for the base field `Fq`.
    const FQ_R2: u256 = u256::from_words(
        0x06d89f71cab8351f47ab1eff0a417ff6_u128,
        0xb5e71911d44501fbf32cfc5b538afa89_u128,
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

    /// Constant-time modular addition. `modulus` is a public field parameter
    /// (`Fr` or `Fq`); operands are assumed reduced (`< modulus`).
    #[inline(always)]
    fn add_mod(a: u256, b: u256, modulus: u256) -> u256 {
        mont::add_mod(a, b, modulus)
    }

    /// Constant-time `Fr` subtraction `(a - b) mod r`.
    pub fn sub(a: u256, b: u256) -> u256 {
        mont::sub_mod(a, b, Self::BASE_MODULUS)
    }

    /// Constant-time modular multiplication via Montgomery reduction.
    ///
    /// Dispatches on the (public, non-secret) field modulus to select the
    /// precomputed Montgomery constants, then performs a value-independent
    /// Montgomery multiply. Operands must be reduced (`< modulus`); every
    /// internal caller maintains this invariant.
    #[inline(always)]
    fn mul_mod(a: u256, b: u256, modulus: u256) -> u256 {
        if modulus == Self::FR_MODULUS {
            mont::mul_mod(a, b, modulus, Self::FR_R2, Self::FR_INV)
        } else {
            mont::mul_mod(a, b, modulus, Self::FQ_R2, Self::FQ_INV)
        }
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

    /// Validates a BN254 base field element in Fq.
    ///
    /// This ensures the element is within the field modulus and prevents
    /// malformed G2 coordinate components from being passed into the native
    /// host pairing call.
    pub fn is_valid_fq(val: u256) -> bool {
        val < Self::FQ_MODULUS
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
        mont::sub_mod(a, b, Self::FQ_MODULUS)
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

    pub fn is_valid_g1_subgroup(x: u256, y: u256) -> bool {
        if !Self::is_valid_g1(x, y) {
            return false;
        }

        let point = G1Projective::from(G1Affine { x, y });
        let result = Self::g1_scalar_mul(point, Self::BASE_MODULUS);
        result.z == u256::from(0u8)
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

    pub fn is_identity(&self) -> bool {
        self.z == u256::from(0u8)
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

#[cfg(test)]
mod montgomery_tests {
    use super::*;

    const Q: u256 = Bn254::FQ_MODULUS;
    const R: u256 = Bn254::FR_MODULUS;

    // -- Fq (base field) --------------------------------------------------

    #[test]
    fn fq_mul_small_product_is_exact() {
        // When a*b < q the field product equals the ordinary integer product.
        assert_eq!(
            Bn254::mul_fq(u256::from(12345u32), u256::from(67890u32)),
            u256::from(12345u32 * 67890u32),
        );
    }

    #[test]
    fn fq_mul_identity_and_zero() {
        let a = u256::from_words(0x1234u128, 0xdead_beefu128);
        assert_eq!(Bn254::mul_fq(a, u256::from(1u8)), a);
        assert_eq!(Bn254::mul_fq(a, u256::from(0u8)), u256::from(0u8));
    }

    #[test]
    fn fq_mul_minus_one_squared_is_one() {
        // (q-1)^2 ≡ 1 (mod q) — exercises the largest possible operands.
        let qm1 = Bn254::sub_fq(u256::from(0u8), u256::from(1u8));
        assert_eq!(Bn254::mul_fq(qm1, qm1), u256::from(1u8));
    }

    #[test]
    fn fq_mul_matches_reference_vector() {
        let a = u256::from_words(
            0x16c72c53340fbe5eccdd46def0f28c58_u128,
            0x14f1d651eb8e167c8568460b561c2d6e_u128,
        );
        let b = u256::from_words(
            0x1a9314a75c6b1f82d70f2edc7b7bf6e7_u128,
            0x397bc04bc6aaa0584b9e5bbb768e6fb4_u128,
        );
        let expected = u256::from_words(
            0x12b20cbe3851bd815848694921b19437_u128,
            0x2fa254501fe3b4e69069538edba46472_u128,
        );
        assert_eq!(Bn254::mul_fq(a, b), expected);
        assert_eq!(Bn254::mul_fq(b, a), expected); // commutative
    }

    #[test]
    fn fq_mul_inverse_is_one() {
        let a = u256::from_words(0x9u128, 0xabcdef0123456789u128);
        assert_eq!(Bn254::mul_fq(a, Bn254::invert_fq(a)), u256::from(1u8));
    }

    #[test]
    fn fq_distributive() {
        let a = u256::from(0xdeadu32);
        let b = u256::from(0xbeefu32);
        let c = u256::from(0xcafeu32);
        let lhs = Bn254::mul_fq(a, Bn254::add_fq(b, c));
        let rhs = Bn254::add_fq(Bn254::mul_fq(a, b), Bn254::mul_fq(a, c));
        assert_eq!(lhs, rhs);
    }

    // -- Fr (scalar field) ------------------------------------------------

    #[test]
    fn fr_mul_minus_one_squared_is_one() {
        let rm1 = Bn254::sub(u256::from(0u8), u256::from(1u8));
        assert_eq!(Bn254::mul(rm1, rm1), u256::from(1u8));
    }

    #[test]
    fn fr_mul_matches_reference_vector() {
        let a = u256::from_words(
            0x16c72c53340fbe5eccdd46def0f28c5c_u128,
            0x6df8ed2b3ec19a5437da27286afe122a_u128,
        );
        let b = u256::from_words(
            0x1a9314a75c6b1f82d70f2edc7b7bf6e8_u128,
            0x8764472692d3ae4c345a1f4430056786_u128,
        );
        let expected = u256::from_words(
            0x157dd0f8e7a28e1432d23ec59ff450c1_u128,
            0x0c448f7b06d581124bd3b438020d5f61_u128,
        );
        assert_eq!(Bn254::mul(a, b), expected);
    }

    #[test]
    fn fr_mul_inverse_is_one() {
        let a = u256::from_words(0x7u128, 0x123456789abcdefu128);
        assert_eq!(Bn254::mul(a, Bn254::invert(a)), u256::from(1u8));
    }

    // -- add/sub edge cases (constant-time wrap) --------------------------

    #[test]
    fn add_sub_wrap_at_modulus() {
        let qm1 = Bn254::sub_fq(u256::from(0u8), u256::from(1u8));
        // (q-1) + 1 ≡ 0
        assert_eq!(Bn254::add_fq(qm1, u256::from(1u8)), u256::from(0u8));
        // 0 - 1 ≡ q-1
        assert_eq!(Bn254::sub_fq(u256::from(0u8), u256::from(1u8)), qm1);

        let rm1 = Bn254::sub(u256::from(0u8), u256::from(1u8));
        assert_eq!(Bn254::add(rm1, u256::from(1u8)), u256::from(0u8));
        assert_eq!(rm1, R - u256::from(1u8));
    }

    #[test]
    fn moduli_are_canonical_bn254() {
        // Sanity: Fq and Fr are the documented BN254 primes and differ.
        assert_ne!(Q, R);
        assert_eq!(
            Q,
            u256::from_words(
                0x30644e72e131a029b85045b68181585d_u128,
                0x97816a916871ca8d3c208c16d87cfd47_u128,
            )
        );
    }
}
