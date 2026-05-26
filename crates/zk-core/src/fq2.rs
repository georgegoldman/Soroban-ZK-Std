//! Fq2 — degree-2 extension field arithmetic for BN254.
//!
//! Elements are `(a0, a1)` representing `a0 + a1·u` where `u² = -1`.
//! All operations are constant-time modular arithmetic over Fq.
//!
//! Spec: docs/math/fq2.md

#![allow(dead_code)]

use crate::Bn254;
use ethnum::u256;

/// An element of Fq2 = Fq[u]/(u²+1).
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct Fq2 {
    /// Real part (coefficient of 1).
    pub c0: u256,
    /// Imaginary part (coefficient of u).
    pub c1: u256,
}

impl Fq2 {
    /// Additive identity.
    pub const ZERO: Self = Self {
        c0: u256::from_words(0, 0),
        c1: u256::from_words(0, 0),
    };

    /// Multiplicative identity.
    pub const ONE: Self = Self {
        c0: u256::from_words(0, 1),
        c1: u256::from_words(0, 0),
    };

    /// Returns `true` if this element is zero.
    #[inline(always)]
    pub fn is_zero(&self) -> bool {
        self.c0 == u256::from_words(0, 0) && self.c1 == u256::from_words(0, 0)
    }

    /// Component-wise addition mod q.
    #[inline(always)]
    pub fn add(&self, rhs: &Self) -> Self {
        Self {
            c0: Bn254::add_fq(self.c0, rhs.c0),
            c1: Bn254::add_fq(self.c1, rhs.c1),
        }
    }

    /// Component-wise subtraction mod q.
    #[inline(always)]
    pub fn sub(&self, rhs: &Self) -> Self {
        Self {
            c0: Bn254::sub_fq(self.c0, rhs.c0),
            c1: Bn254::sub_fq(self.c1, rhs.c1),
        }
    }

    /// Negation: `(-a0, -a1)`.
    #[inline(always)]
    pub fn neg(&self) -> Self {
        let zero = u256::from_words(0, 0);
        Self {
            c0: if self.c0 == zero {
                zero
            } else {
                Bn254::sub_fq(Bn254::FQ_MODULUS, self.c0)
            },
            c1: if self.c1 == zero {
                zero
            } else {
                Bn254::sub_fq(Bn254::FQ_MODULUS, self.c1)
            },
        }
    }

    /// Karatsuba multiplication.
    ///
    /// Cost: 3 Fq muls + 5 Fq adds.
    pub fn mul(&self, rhs: &Self) -> Self {
        // v0 = a0·b0,  v1 = a1·b1
        let v0 = Bn254::mul_fq(self.c0, rhs.c0);
        let v1 = Bn254::mul_fq(self.c1, rhs.c1);

        // c0 = v0 - v1   (u² = -1)
        let c0 = Bn254::sub_fq(v0, v1);

        // c1 = (a0+a1)(b0+b1) - v0 - v1
        let a_sum = Bn254::add_fq(self.c0, self.c1);
        let b_sum = Bn254::add_fq(rhs.c0, rhs.c1);
        let cross = Bn254::mul_fq(a_sum, b_sum);
        let c1 = Bn254::sub_fq(Bn254::sub_fq(cross, v0), v1);

        Self { c0, c1 }
    }

    /// Squaring — cheaper than `self.mul(self)`.
    ///
    /// Cost: 2 Fq muls + 3 Fq adds.
    pub fn square(&self) -> Self {
        // c0 = (a0-a1)(a0+a1)
        let c0 = Bn254::mul_fq(
            Bn254::sub_fq(self.c0, self.c1),
            Bn254::add_fq(self.c0, self.c1),
        );
        // c1 = 2·a0·a1
        let v = Bn254::mul_fq(self.c0, self.c1);
        let c1 = Bn254::add_fq(v, v);
        Self { c0, c1 }
    }

    /// Scalar multiplication by a base-field element.
    #[inline(always)]
    pub fn mul_fq(&self, scalar: u256) -> Self {
        Self {
            c0: Bn254::mul_fq(self.c0, scalar),
            c1: Bn254::mul_fq(self.c1, scalar),
        }
    }

    /// Frobenius / conjugate: `(a0, -a1)`.
    #[inline(always)]
    pub fn conjugate(&self) -> Self {
        let zero = u256::from_words(0, 0);
        Self {
            c0: self.c0,
            c1: if self.c1 == zero {
                zero
            } else {
                Bn254::sub_fq(Bn254::FQ_MODULUS, self.c1)
            },
        }
    }

    /// Inversion: `a⁻¹ = (a0, -a1) / (a0² + a1²)`.
    ///
    /// Returns `Fq2::ZERO` if `self` is zero (matches field convention).
    pub fn invert(&self) -> Self {
        if self.is_zero() {
            return Self::ZERO;
        }
        // norm = a0² + a1²
        let a0_sq = Bn254::mul_fq(self.c0, self.c0);
        let a1_sq = Bn254::mul_fq(self.c1, self.c1);
        let norm = Bn254::add_fq(a0_sq, a1_sq);
        let inv_norm = Bn254::invert_fq(norm);

        let zero = u256::from_words(0, 0);
        Self {
            c0: Bn254::mul_fq(self.c0, inv_norm),
            c1: if self.c1 == zero {
                zero
            } else {
                Bn254::mul_fq(Bn254::sub_fq(Bn254::FQ_MODULUS, self.c1), inv_norm)
            },
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn fq(lo: u128) -> u256 {
        u256::from_words(0, lo)
    }

    #[test]
    fn add_zero_identity() {
        let a = Fq2 { c0: fq(3), c1: fq(7) };
        assert_eq!(a.add(&Fq2::ZERO), a);
    }

    #[test]
    fn mul_one_identity() {
        let a = Fq2 { c0: fq(5), c1: fq(11) };
        assert_eq!(a.mul(&Fq2::ONE), a);
    }

    #[test]
    fn square_matches_mul_self() {
        let a = Fq2 { c0: fq(3), c1: fq(4) };
        assert_eq!(a.square(), a.mul(&a));
    }

    #[test]
    fn invert_roundtrip() {
        let a = Fq2 { c0: fq(7), c1: fq(13) };
        let inv = a.invert();
        let product = a.mul(&inv);
        assert_eq!(product, Fq2::ONE);
    }

    #[test]
    fn invert_zero_returns_zero() {
        assert_eq!(Fq2::ZERO.invert(), Fq2::ZERO);
    }

    #[test]
    fn conjugate_mul_equals_norm() {
        // a · conj(a) should be a real element (c1 == 0) equal to norm
        let a = Fq2 { c0: fq(5), c1: fq(3) };
        let product = a.mul(&a.conjugate());
        assert_eq!(product.c1, u256::from_words(0, 0));
        // norm = 5² + 3² = 34
        assert_eq!(product.c0, fq(34));
    }

    #[test]
    fn add_sub_roundtrip() {
        let a = Fq2 { c0: fq(100), c1: fq(200) };
        let b = Fq2 { c0: fq(50), c1: fq(75) };
        assert_eq!(a.add(&b).sub(&b), a);
    }

    #[test]
    fn neg_add_is_zero() {
        let a = Fq2 { c0: fq(42), c1: fq(99) };
        assert_eq!(a.add(&a.neg()), Fq2::ZERO);
    }
}
