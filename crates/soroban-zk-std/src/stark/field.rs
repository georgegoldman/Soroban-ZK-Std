//! Goldilocks field arithmetic (Issue #366, STARK primitives).
//!
//! The STARK FRI protocol needs a field with a *large* power-of-two subgroup
//! (high 2-adicity) for its Reed–Solomon domain. `Bn254`'s scalar field only
//! has 2-adicity ≈ 7, so we add the STARK-friendly **Goldilocks** field
//! `p = 2^64 − 2^32 + 1` (2-adicity 32). Elements fit in a single `u64` and all
//! arithmetic reduces through `u128`, so it is extremely cheap in the Soroban
//! WASM runtime and needs no heap allocation.
//!
//! # Reduction
//!
//! Writing `ε = 2^32 − 1` gives `p = 2^64 − ε`, hence `2^64 ≡ ε (mod p)`.
//! A 128-bit product `x = hi·2^64 + lo` therefore reduces as
//!
//! ```text
//! x ≡ lo + hi·ε   (mod p)
//!   ≡ lo + hi_lo·ε − hi_hi   (mod p)      hi = hi_hi·2^32 + hi_lo, 2^96 ≡ −1
//! ```
//!
//! which is a pair of shift-adds plus a single conditional subtraction — no
//! 128-bit division (`%`) and no data-dependent branches. `hi_lo·ε < 2^64` and
//! the wrapped intermediates keep the result below `2p`, so one masked
//! subtraction canonicalises it. This is the branchless shift-add reduction
//! used by production Goldilocks implementations.

use core::ops::{Add, Mul, Neg, Sub};

/// Goldilocks prime modulus `p = 2^64 − 2^32 + 1`.
pub const MODULUS: u64 = 0xFFFF_FFFF_0000_0001;

/// `ε = 2^32 − 1 = 2^64 mod p`.
const EPSILON: u64 = 0xFFFF_FFFF;

/// `2^(FRI_MAX_LOG)`-th primitive root of unity (generator `7` raised to
/// `(p−1)/2^32`). `ROOT_OF_UNITY^(2^32) == 1` and `ROOT_OF_UNITY^(2^31) == −1`.
pub const ROOT_OF_UNITY: u64 = 0x1856_29dc_da58_878c;

/// Coset offset used so the FRI evaluation domain never contains `0`.
pub const COSSET_OFFSET: u64 = 2;

/// Maximum FRI domain log-size. The domain has `2^FRI_MAX_LOG` points.
pub const FRI_MAX_LOG: u32 = 32;

/// `2⁻¹ mod p`, used in the FRI folding identity.
pub const INV2: u64 = 0x7FFF_FFFF_8000_0001; // (MODULUS + 1) / 2

/// A Goldilocks field element in `[0, p)`.
#[derive(Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct Felt {
    pub value: u64,
}

impl Felt {
    pub const ZERO: Felt = Felt { value: 0 };
    pub const ONE: Felt = Felt { value: 1 };

    /// Branchless shift-add reduction of a `u128` modulo `p`.
    ///
    /// Accepts any `u128`; the wrapped intermediate is always `< 2p`, so the
    /// final masked subtraction canonicalises the result into `[0, p)`.
    #[inline(always)]
    pub const fn reduce_u128(x: u128) -> u64 {
        let lo = x as u64;
        let hi = (x >> 64) as u64;
        let hi_hi = hi >> 32;
        let hi_lo = hi & EPSILON;
        // lo − hi_hi, borrowing one `2^64 ≡ ε` when it underflows.
        let (t0, borrow) = lo.overflowing_sub(hi_hi);
        let t0 = t0.wrapping_sub((borrow as u64) * EPSILON);
        // hi_lo · ε < 2^64, so this cannot overflow.
        let t1 = hi_lo * EPSILON;
        let (t2, carry) = t0.overflowing_add(t1);
        let t2 = t2.wrapping_add((carry as u64) * EPSILON);
        // Canonicalise: subtract p iff t2 ≥ p (branchless via a mask).
        let (r, under) = t2.overflowing_sub(MODULUS);
        let mask = (under as u64).wrapping_neg();
        (r & !mask) | (t2 & mask)
    }

    /// Wrap a `u64`, reducing modulo `p` (one masked subtraction).
    #[inline(always)]
    pub const fn new(v: u64) -> Felt {
        let (r, under) = v.overflowing_sub(MODULUS);
        let mask = (under as u64).wrapping_neg();
        Felt {
            value: (r & !mask) | (v & mask),
        }
    }

    #[inline]
    pub const fn from_u64(v: u64) -> Felt {
        Felt::new(v)
    }

    /// Reduce a `u128` intermediate to a field element.
    #[inline(always)]
    pub const fn reduce(x: u128) -> Felt {
        Felt {
            value: Felt::reduce_u128(x),
        }
    }

    #[inline(always)]
    pub const fn is_zero(self) -> bool {
        self.value == 0
    }

    #[inline(always)]
    pub fn square(self) -> Felt {
        self.mul(self)
    }

    /// Multiplicative inverse via Fermat's little theorem (`a^(p−2)`).
    ///
    /// Returns [`Felt::ZERO`] for zero (the inverse does not exist); callers
    /// that require an invertible element must check first.
    #[inline]
    pub fn inv(self) -> Felt {
        self.pow(MODULUS - 2)
    }

    /// Exponentiation by a `u64` exponent (square-and-multiply).
    #[inline]
    pub fn pow(self, mut e: u64) -> Felt {
        let mut r = Felt::ONE;
        let mut b = self;
        while e > 0 {
            if e & 1 == 1 {
                r = r.mul(b);
            }
            b = b.mul(b);
            e >>= 1;
        }
        r
    }

    /// `2⁻¹` as a field element.
    #[inline]
    pub const fn inv2() -> Felt {
        Felt { value: INV2 }
    }

    /// Returns the FRI domain root of unity of order `2^log`:
    /// `ROOT_OF_UNITY^(2^(FRI_MAX_LOG − log))`.
    ///
    /// `log` is clamped to `FRI_MAX_LOG`, so no shift can overflow.
    #[inline]
    pub fn layer_root(log: u32) -> Felt {
        let shift = FRI_MAX_LOG.saturating_sub(log);
        Felt::new(ROOT_OF_UNITY).pow(1u64 << shift)
    }

    /// Coset offset raised to `2^(FRI_MAX_LOG − log)` for the given layer.
    ///
    /// Layer `log − 1` is the set of squares of layer `log`, so
    /// `layer_offset(log).square() == layer_offset(log - 1)`.
    #[inline]
    pub fn layer_offset(log: u32) -> Felt {
        let shift = FRI_MAX_LOG.saturating_sub(log);
        Felt::new(COSSET_OFFSET).pow(1u64 << shift)
    }

    /// The `index`-th point of the coset evaluation domain for a layer of
    /// `2^log` points: `offset_log · root_log^index`.
    #[inline]
    pub fn domain_point(log: u32, index: u64) -> Felt {
        Felt::layer_offset(log).mul(Felt::layer_root(log).pow(index))
    }

    /// Evaluate a polynomial (coefficients low-to-high) at `x` via Horner.
    #[inline]
    pub fn poly_eval(coeffs: &[Felt], x: Felt) -> Felt {
        let mut acc = Felt::ZERO;
        for c in coeffs.iter().rev() {
            acc = acc.mul(x).add(*c);
        }
        acc
    }

    /// Canonical 8-byte big-endian encoding (used as Merkle leaf input).
    #[inline]
    pub const fn to_bytes(self) -> [u8; 8] {
        self.value.to_be_bytes()
    }

    /// Decode an 8-byte big-endian encoding, reducing into the field.
    #[inline]
    pub const fn from_bytes(b: &[u8; 8]) -> Felt {
        Felt::new(u64::from_be_bytes(*b))
    }

    /// Raw `u64` value.
    #[inline]
    pub const fn as_u64(self) -> u64 {
        self.value
    }
}

impl Add for Felt {
    type Output = Felt;
    /// `2^64 ≡ ε`, so a carry out of the `u64` addition folds back as `+ε`.
    #[inline]
    fn add(self, o: Felt) -> Felt {
        let (s, carry) = self.value.overflowing_add(o.value);
        let folded = if carry { s.wrapping_add(EPSILON) } else { s };
        Felt::new(folded)
    }
}
impl Sub for Felt {
    type Output = Felt;
    /// A borrow means we subtracted `2^64` too much; `2^64 ≡ ε`, so add it back.
    #[inline]
    fn sub(self, o: Felt) -> Felt {
        let (d, borrow) = self.value.overflowing_sub(o.value);
        let folded = if borrow { d.wrapping_sub(EPSILON) } else { d };
        Felt::new(folded)
    }
}
impl Mul for Felt {
    type Output = Felt;
    #[inline]
    fn mul(self, o: Felt) -> Felt {
        Felt::reduce(self.value as u128 * o.value as u128)
    }
}
impl Neg for Felt {
    type Output = Felt;
    #[inline]
    fn neg(self) -> Felt {
        Sub::sub(Felt::ZERO, self)
    }
}

impl From<u64> for Felt {
    #[inline]
    fn from(v: u64) -> Felt {
        Felt::new(v)
    }
}

impl core::fmt::Debug for Felt {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Felt({:#x})", self.value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arithmetic_identities() {
        let a = Felt::new(0x1234_5678);
        let b = Felt::new(0x9abc_def0);
        assert_eq!((a + b).sub(b), a);
        assert_eq!((a * b).mul(b.inv()), a);
        assert_eq!(a.add(Felt::ZERO), a);
        assert_eq!(a.sub(a), Felt::ZERO);
        assert_eq!(a.neg().neg(), a);
        // inv is its own inverse
        assert_eq!(a.inv().inv(), a);
    }

    #[test]
    fn reduction_matches_naive_modulo() {
        // Deterministic pseudo-random 128-bit values, including the extremes.
        let mut x: u128 = 0x9E37_79B9_7F4A_7C15_F39C_C060_5CED_C834;
        let mut samples = 0u32;
        while samples < 2_000 {
            let r = Felt::reduce_u128(x);
            assert_eq!(r as u128, x % MODULUS as u128, "mismatch for {x:#x}");
            assert!(r < MODULUS);
            x = x
                .wrapping_mul(0x2545_F491_4F6C_DD1D)
                .wrapping_add(0x0123_4567_89AB_CDEF);
            samples += 1;
        }
        // Extremes.
        for v in [
            0u128,
            1,
            MODULUS as u128 - 1,
            MODULUS as u128,
            u128::MAX,
            (MODULUS as u128 - 1) * (MODULUS as u128 - 1),
            (MODULUS as u128) << 64,
        ] {
            assert_eq!(Felt::reduce_u128(v) as u128, v % MODULUS as u128);
        }
    }

    #[test]
    fn boundary_values_reduce_canonically() {
        assert_eq!(Felt::new(MODULUS), Felt::ZERO);
        assert_eq!(Felt::new(MODULUS - 1).add(Felt::ONE), Felt::ZERO);
        assert_eq!(Felt::ZERO.sub(Felt::ONE), Felt::new(MODULUS - 1));
        assert_eq!(
            Felt::new(MODULUS - 1).mul(Felt::new(MODULUS - 1)),
            Felt::ONE
        );
        // (p-1) + (p-1) = -2
        assert_eq!(
            Felt::new(MODULUS - 1).add(Felt::new(MODULUS - 1)),
            Felt::new(MODULUS - 2)
        );
    }

    #[test]
    fn root_of_unity_properties() {
        let w = Felt::new(ROOT_OF_UNITY);
        assert_eq!(w.pow(1u64 << 32), Felt::ONE);
        assert_eq!(w.pow(1u64 << 31), Felt::new(MODULUS - 1)); // -1
                                                               // domain points are paired as x and -x
        let half = 1u64 << 7;
        for m in 0..4u64 {
            let x = Felt::domain_point(8, m);
            let nx = Felt::domain_point(8, m + half);
            assert_eq!(x.add(nx), Felt::ZERO);
        }
    }

    #[test]
    fn layer_domains_are_successive_squares() {
        for log in 2..10u32 {
            for m in 0..4u64 {
                assert_eq!(
                    Felt::domain_point(log, m).square(),
                    Felt::domain_point(log - 1, m)
                );
            }
        }
    }

    #[test]
    fn poly_eval_matches_manual() {
        // p(x) = 3 + 5x + 7x^2
        let coeffs = [Felt::new(3), Felt::new(5), Felt::new(7)];
        let x = Felt::new(11);
        let expected = Felt::new(3)
            .add(Felt::new(5).mul(x))
            .add(Felt::new(7).mul(x.mul(x)));
        assert_eq!(Felt::poly_eval(&coeffs, x), expected);
    }

    #[test]
    fn byte_encoding_round_trips() {
        for v in [0u64, 1, 42, MODULUS - 1] {
            let f = Felt::new(v);
            assert_eq!(Felt::from_bytes(&f.to_bytes()), f);
        }
        // Values ≥ p are reduced on decode.
        assert_eq!(
            Felt::from_bytes(&u64::MAX.to_be_bytes()),
            Felt::new(u64::MAX)
        );
    }
}
