//! Persistent Montgomery-domain field elements for BN254 (issue #575).
//!
//! [`FrMont`] (scalar field, modulus `r`) and [`FqMont`] (base field, modulus
//! `q`) store a field element `a` as its Montgomery representative
//! `a·R mod N` (with `R = 2²⁵⁶`) in four little-endian 64-bit limbs.
//!
//! Every arithmetic operation (`add`, `sub`, `neg`, `mul`, `square`, `inv`)
//! takes and returns values that stay in Montgomery form, so a chain of `k`
//! multiplications costs `k` Montgomery products instead of the
//! `4k` products + `2k` software divisions of the plain `u256` API. Values are
//! converted to and from canonical big-endian `u256` only at the API boundary
//! via [`FrMont::from_u256`] / [`FrMont::to_u256`].
//!
//! # Invariants
//! The limbs are always fully reduced (`< N`). Constructors either check the
//! input ([`FrMont::from_u256`] returns `None` for non-canonical values) or
//! reduce it ([`FrMont::from_u256_reduced`]).
//!
//! # Constant time
//! `add`, `sub`, `neg`, `mul` and `square` use fixed-iteration limb loops and
//! mask-based selection, never data-dependent branches. `inv` runs a fixed
//! exponentiation by the public exponent `N − 2`; only its "input is zero"
//! check branches. `pow_vartime` branches on the bits of the *exponent* and
//! must not be used with a secret exponent.
//!
//! The module contains no `unsafe` code and never panics.

use ethnum::u256;

/// Four 64-bit limbs, little-endian.
type Limbs = [u64; 4];

#[inline(always)]
const fn u256_to_limbs(x: u256) -> Limbs {
    let (hi, lo) = x.into_words();
    [lo as u64, (lo >> 64) as u64, hi as u64, (hi >> 64) as u64]
}

#[inline(always)]
const fn limbs_to_u256(l: &Limbs) -> u256 {
    let lo = (l[0] as u128) | ((l[1] as u128) << 64);
    let hi = (l[2] as u128) | ((l[3] as u128) << 64);
    u256::from_words(hi, lo)
}

/// `a + b·c + carry`, returning `(low, high)` words. Cannot overflow `u128`.
#[inline(always)]
const fn mac(a: u64, b: u64, c: u64, carry: u64) -> (u64, u64) {
    let t = (a as u128) + (b as u128) * (c as u128) + (carry as u128);
    (t as u64, (t >> 64) as u64)
}

/// `a + b + carry`, returning `(sum, carry)`.
#[inline(always)]
const fn adc(a: u64, b: u64, carry: u64) -> (u64, u64) {
    let t = (a as u128) + (b as u128) + (carry as u128);
    (t as u64, (t >> 64) as u64)
}

/// `a − b − borrow`, returning `(difference, borrow)` with `borrow ∈ {0, 1}`.
#[inline(always)]
const fn sbb(a: u64, b: u64, borrow: u64) -> (u64, u64) {
    let t = (a as u128).wrapping_sub((b as u128) + (borrow as u128));
    (t as u64, ((t >> 64) as u64) & 1)
}

/// Constant-time select: `a` if `mask == u64::MAX`, `b` if `mask == 0`.
#[inline(always)]
const fn select(mask: u64, a: &Limbs, b: &Limbs) -> Limbs {
    [
        (a[0] & mask) | (b[0] & !mask),
        (a[1] & mask) | (b[1] & !mask),
        (a[2] & mask) | (b[2] & !mask),
        (a[3] & mask) | (b[3] & !mask),
    ]
}

/// Returns `x − n` if `hi:x ≥ n`, else `x`, in constant time. `hi` is a fifth
/// (carry) word that is either 0 or 1.
#[inline]
const fn reduce_once(x: &Limbs, hi: u64, n: &Limbs) -> Limbs {
    let (d0, b) = sbb(x[0], n[0], 0);
    let (d1, b) = sbb(x[1], n[1], b);
    let (d2, b) = sbb(x[2], n[2], b);
    let (d3, b) = sbb(x[3], n[3], b);
    let (_, b) = sbb(hi, 0, b);
    // b == 1 → hi:x < n → keep x.
    let keep_x = 0u64.wrapping_sub(b);
    select(keep_x, x, &[d0, d1, d2, d3])
}

/// Constant-time CIOS Montgomery product `a·b·R⁻¹ mod n`.
///
/// Requires `b < n` (and `n < 2²⁵⁵`); `a` may be any 256-bit value. Under
/// those preconditions the pre-reduction result is `< 2n`, so a single
/// masked subtraction yields the canonical value in `[0, n)`.
#[inline]
pub(crate) const fn mont_mul(a: &Limbs, b: &Limbs, n: &Limbs, n0inv: u64) -> Limbs {
    let mut t = [0u64; 4];
    let mut t4 = 0u64;
    let mut i = 0;
    while i < 4 {
        // t += b[i] · a
        let (r0, c) = mac(t[0], a[0], b[i], 0);
        let (r1, c) = mac(t[1], a[1], b[i], c);
        let (r2, c) = mac(t[2], a[2], b[i], c);
        let (r3, c) = mac(t[3], a[3], b[i], c);
        let (r4, t5) = adc(t4, c, 0);

        // m chosen so that the low word of t + m·n is zero; then shift.
        let m = r0.wrapping_mul(n0inv);
        let (_, c) = mac(r0, m, n[0], 0);
        let (s0, c) = mac(r1, m, n[1], c);
        let (s1, c) = mac(r2, m, n[2], c);
        let (s2, c) = mac(r3, m, n[3], c);
        let (s3, c) = adc(r4, c, 0);
        t = [s0, s1, s2, s3];
        t4 = t5 + c;
        i += 1;
    }
    reduce_once(&t, t4, n)
}

/// Constant-time `a + b mod n` for `a, b < n < 2²⁵⁵`.
#[inline]
const fn add_limbs(a: &Limbs, b: &Limbs, n: &Limbs) -> Limbs {
    let (s0, c) = adc(a[0], b[0], 0);
    let (s1, c) = adc(a[1], b[1], c);
    let (s2, c) = adc(a[2], b[2], c);
    let (s3, c) = adc(a[3], b[3], c);
    reduce_once(&[s0, s1, s2, s3], c, n)
}

/// Constant-time `a − b mod n` for `a, b < n`.
#[inline]
const fn sub_limbs(a: &Limbs, b: &Limbs, n: &Limbs) -> Limbs {
    let (d0, br) = sbb(a[0], b[0], 0);
    let (d1, br) = sbb(a[1], b[1], br);
    let (d2, br) = sbb(a[2], b[2], br);
    let (d3, br) = sbb(a[3], b[3], br);
    // On underflow add n back (masked).
    let mask = 0u64.wrapping_sub(br);
    let (e0, c) = adc(d0, n[0] & mask, 0);
    let (e1, c) = adc(d1, n[1] & mask, c);
    let (e2, c) = adc(d2, n[2] & mask, c);
    let (e3, _) = adc(d3, n[3] & mask, c);
    [e0, e1, e2, e3]
}

/// Constant-time `a < n` (canonical check).
#[inline]
fn lt_limbs(a: &Limbs, n: &Limbs) -> bool {
    let (_, b) = sbb(a[0], n[0], 0);
    let (_, b) = sbb(a[1], n[1], b);
    let (_, b) = sbb(a[2], n[2], b);
    let (_, b) = sbb(a[3], n[3], b);
    b == 1
}

#[inline(always)]
fn is_zero_limbs(a: &Limbs) -> bool {
    (a[0] | a[1] | a[2] | a[3]) == 0
}

macro_rules! mont_field {
    (
        $(#[$doc:meta])*
        $name:ident,
        modulus = $n:expr,
        n0inv = $n0inv:expr,
        one = $one:expr,
        r2 = $r2:expr,
        n_minus_2 = $nm2:expr $(,)?
    ) => {
        $(#[$doc])*
        #[repr(transparent)]
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
        pub struct $name([u64; 4]);

        impl $name {
            /// Modulus `N` as little-endian limbs.
            pub const MODULUS_LIMBS: [u64; 4] = $n;
            /// `−N⁻¹ mod 2⁶⁴`.
            const N0INV: u64 = $n0inv;
            /// `N − 2` (the Fermat inversion exponent), little-endian limbs.
            const N_MINUS_2: [u64; 4] = $nm2;

            /// The additive identity (Montgomery form of `0`).
            pub const ZERO: Self = Self([0, 0, 0, 0]);
            /// The multiplicative identity (Montgomery form of `1`, i.e. `R mod N`).
            pub const ONE: Self = Self($one);
            /// `R² mod N` stored raw. Multiplying a canonical value by it with a
            /// Montgomery product moves the value into Montgomery form. As a
            /// field element it represents `R mod N`.
            pub const R2: Self = Self($r2);

            /// Converts a canonical big-endian `u256` into Montgomery form.
            ///
            /// Returns `None` if `x ≥ N` (non-canonical); never panics.
            #[inline]
            pub fn from_u256(x: u256) -> Option<Self> {
                let l = u256_to_limbs(x);
                if lt_limbs(&l, &Self::MODULUS_LIMBS) {
                    Some(Self(mont_mul(&l, &Self::R2.0, &Self::MODULUS_LIMBS, Self::N0INV)))
                } else {
                    None
                }
            }

            /// Converts any `u256` into Montgomery form, reducing it mod `N`
            /// first (usable in `const` context, e.g. for constant tables). This matches the reduction semantics of the legacy
            /// `Bn254` `u256` API, which accepts non-canonical inputs.
            #[inline]
            pub const fn from_u256_reduced(x: u256) -> Self {
                // `mont_mul` accepts any 256-bit left operand as long as the
                // right operand (`R²`) is canonical, so no division is needed.
                Self(mont_mul(&u256_to_limbs(x), &Self::R2.0, &Self::MODULUS_LIMBS, Self::N0INV))
            }

            /// Converts back to the canonical big-endian-compatible `u256` in `[0, N)`.
            #[inline]
            pub fn to_u256(&self) -> u256 {
                limbs_to_u256(&mont_mul(&self.0, &[1, 0, 0, 0], &Self::MODULUS_LIMBS, Self::N0INV))
            }

            /// The raw Montgomery limbs (`a·R mod N`, little-endian).
            #[inline(always)]
            pub const fn to_raw_limbs(&self) -> [u64; 4] {
                self.0
            }

            /// Builds a value from raw Montgomery limbs. Returns `None` if the
            /// limbs are not fully reduced (`≥ N`).
            #[inline]
            pub fn from_raw_limbs(limbs: [u64; 4]) -> Option<Self> {
                if lt_limbs(&limbs, &Self::MODULUS_LIMBS) {
                    Some(Self(limbs))
                } else {
                    None
                }
            }

            /// `self + rhs mod N`.
            #[inline]
            #[allow(clippy::should_implement_trait)]
            pub const fn add(&self, rhs: &Self) -> Self {
                Self(add_limbs(&self.0, &rhs.0, &Self::MODULUS_LIMBS))
            }

            /// `self − rhs mod N`.
            #[inline]
            #[allow(clippy::should_implement_trait)]
            pub const fn sub(&self, rhs: &Self) -> Self {
                Self(sub_limbs(&self.0, &rhs.0, &Self::MODULUS_LIMBS))
            }

            /// `−self mod N`.
            #[inline]
            #[allow(clippy::should_implement_trait)]
            pub const fn neg(&self) -> Self {
                Self(sub_limbs(&[0, 0, 0, 0], &self.0, &Self::MODULUS_LIMBS))
            }

            /// `2·self mod N`.
            #[inline]
            pub const fn double(&self) -> Self {
                self.add(self)
            }

            /// `self · rhs mod N` (one Montgomery product).
            #[inline]
            #[allow(clippy::should_implement_trait)]
            pub const fn mul(&self, rhs: &Self) -> Self {
                Self(mont_mul(&self.0, &rhs.0, &Self::MODULUS_LIMBS, Self::N0INV))
            }

            /// `self² mod N`.
            #[inline]
            pub const fn square(&self) -> Self {
                self.mul(self)
            }

            /// `true` iff the element is zero.
            #[inline(always)]
            pub fn is_zero(&self) -> bool {
                is_zero_limbs(&self.0)
            }

            /// Constant-time select: `a` if `choice != 0`, else `b`.
            #[inline]
            pub fn ct_select(choice: u64, a: &Self, b: &Self) -> Self {
                // Map any non-zero `choice` to an all-ones mask without branching.
                let nz = (choice | choice.wrapping_neg()) >> 63;
                Self(select(0u64.wrapping_sub(nz), &a.0, &b.0))
            }

            /// `self^exp` where `exp` is given as little-endian limbs.
            ///
            /// Branches on the bits of `exp`; use only with a public exponent.
            #[inline]
            fn pow_limbs_vartime(&self, exp: &[u64; 4]) -> Self {
                let mut res = Self::ONE;
                let mut started = false;
                let mut i = 4;
                while i > 0 {
                    i -= 1;
                    let mut j = 64;
                    while j > 0 {
                        j -= 1;
                        if started {
                            res = res.square();
                        }
                        if (exp[i] >> j) & 1 == 1 {
                            res = res.mul(self);
                            started = true;
                        }
                    }
                }
                res
            }

            /// `self^exp`. Branches on the bits of `exp` (variable time in the
            /// exponent only); do not use with a secret exponent.
            #[inline]
            pub fn pow_vartime(&self, exp: u256) -> Self {
                self.pow_limbs_vartime(&u256_to_limbs(exp))
            }

            /// Multiplicative inverse via Fermat's little theorem
            /// (`self^(N−2)`). Returns `None` for zero; never panics.
            #[inline]
            pub fn inv(&self) -> Option<Self> {
                if self.is_zero() {
                    None
                } else {
                    Some(self.pow_limbs_vartime(&Self::N_MINUS_2))
                }
            }
        }

        impl core::ops::Add for $name {
            type Output = Self;
            #[inline]
            fn add(self, rhs: Self) -> Self {
                $name::add(&self, &rhs)
            }
        }

        impl core::ops::Sub for $name {
            type Output = Self;
            #[inline]
            fn sub(self, rhs: Self) -> Self {
                $name::sub(&self, &rhs)
            }
        }

        impl core::ops::Mul for $name {
            type Output = Self;
            #[inline]
            fn mul(self, rhs: Self) -> Self {
                $name::mul(&self, &rhs)
            }
        }

        impl core::ops::Neg for $name {
            type Output = Self;
            #[inline]
            fn neg(self) -> Self {
                $name::neg(&self)
            }
        }
    };
}

mont_field!(
    /// BN254 scalar-field element (`mod r`) held persistently in Montgomery form.
    FrMont,
    modulus = [
        4891460686036598785,
        2896914383306846353,
        13281191951274694749,
        3486998266802970665,
    ],
    n0inv = 0xc2e1f593efffffff,
    one = [
        12436184717236109307,
        3962172157175319849,
        7381016538464732718,
        1011752739694698287,
    ],
    r2 = [
        1997599621687373223,
        6052339484930628067,
        10108755138030829701,
        150537098327114917,
    ],
    n_minus_2 = [
        4891460686036598783,
        2896914383306846353,
        13281191951274694749,
        3486998266802970665,
    ],
);

mont_field!(
    /// BN254 base-field element (`mod q`) held persistently in Montgomery form.
    FqMont,
    modulus = [
        4332616871279656263,
        10917124144477883021,
        13281191951274694749,
        3486998266802970665,
    ],
    n0inv = 0x87d20782e4866389,
    one = [
        15230403791020821917,
        754611498739239741,
        7381016538464732716,
        1011752739694698287,
    ],
    r2 = [
        17522657719365597833,
        13107472804851548667,
        5164255478447964150,
        493319470278259999,
    ],
    n_minus_2 = [
        4332616871279656261,
        10917124144477883021,
        13281191951274694749,
        3486998266802970665,
    ],
);

/// `a·b mod r` for arbitrary (possibly non-canonical) `u256` inputs, using two
/// Montgomery products and no division: `mont(mont(a, R²), b) = a·R·b·R⁻¹`.
#[inline]
pub(crate) fn fr_mul_u256(a: u256, b: u256) -> u256 {
    let n = &FrMont::MODULUS_LIMBS;
    let ar = mont_mul(&u256_to_limbs(a), &FrMont::R2.0, n, FrMont::N0INV);
    limbs_to_u256(&mont_mul(&u256_to_limbs(b), &ar, n, FrMont::N0INV))
}

/// `a·b mod q` for arbitrary (possibly non-canonical) `u256` inputs; see [`fr_mul_u256`].
#[inline]
pub(crate) fn fq_mul_u256(a: u256, b: u256) -> u256 {
    let n = &FqMont::MODULUS_LIMBS;
    let ar = mont_mul(&u256_to_limbs(a), &FqMont::R2.0, n, FqMont::N0INV);
    limbs_to_u256(&mont_mul(&u256_to_limbs(b), &ar, n, FqMont::N0INV))
}

/// Raw Montgomery product with `R²` / `1` for the legacy
/// `Bn254::{to,from}_montgomery{,_fq}` helpers (any `u256` input).
#[inline]
pub(crate) fn fr_to_mont_u256(a: u256) -> u256 {
    limbs_to_u256(&FrMont::from_u256_reduced(a).0)
}
#[inline]
pub(crate) fn fr_from_mont_u256(a: u256) -> u256 {
    limbs_to_u256(&mont_mul(
        &u256_to_limbs(a),
        &[1, 0, 0, 0],
        &FrMont::MODULUS_LIMBS,
        FrMont::N0INV,
    ))
}
#[inline]
pub(crate) fn fq_to_mont_u256(a: u256) -> u256 {
    limbs_to_u256(&FqMont::from_u256_reduced(a).0)
}
#[inline]
pub(crate) fn fq_from_mont_u256(a: u256) -> u256 {
    limbs_to_u256(&mont_mul(
        &u256_to_limbs(a),
        &[1, 0, 0, 0],
        &FqMont::MODULUS_LIMBS,
        FqMont::N0INV,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Bn254;

    fn r() -> u256 {
        Bn254::FR_MODULUS
    }
    fn q() -> u256 {
        Bn254::FQ_MODULUS
    }

    #[test]
    fn constants_are_consistent() {
        assert_eq!(FrMont::ONE.to_u256(), u256::ONE);
        assert_eq!(FqMont::ONE.to_u256(), u256::ONE);
        assert_eq!(FrMont::ZERO.to_u256(), u256::ZERO);
        assert_eq!(limbs_to_u256(&FrMont::MODULUS_LIMBS), r());
        assert_eq!(limbs_to_u256(&FqMont::MODULUS_LIMBS), q());
        assert_eq!(FrMont::from_u256(u256::ONE), Some(FrMont::ONE));
        assert_eq!(FqMont::from_u256(u256::ONE), Some(FqMont::ONE));
        // R2 as a field element is R mod N == to_u256(ONE)·R … i.e. ONE's raw limbs.
        assert_eq!(FrMont::R2.to_u256(), limbs_to_u256(&FrMont::ONE.0));
        assert_eq!(FqMont::R2.to_u256(), limbs_to_u256(&FqMont::ONE.0));
    }

    #[test]
    fn boundaries_round_trip_and_reject_non_canonical() {
        let one = u256::ONE;
        for v in [u256::ZERO, one, r() - one] {
            assert_eq!(FrMont::from_u256(v).map(|x| x.to_u256()), Some(v));
        }
        for v in [u256::ZERO, one, q() - one] {
            assert_eq!(FqMont::from_u256(v).map(|x| x.to_u256()), Some(v));
        }
        assert_eq!(FrMont::from_u256(r()), None);
        assert_eq!(FrMont::from_u256(u256::MAX), None);
        assert_eq!(FqMont::from_u256(q()), None);
        assert_eq!(FqMont::from_u256(u256::MAX), None);
        // r ≤ q − 1, so q − 1 is canonical in Fq but not in Fr.
        assert_eq!(FrMont::from_u256(q() - one), None);
        assert_eq!(FrMont::from_raw_limbs(FrMont::MODULUS_LIMBS), None);
        assert_eq!(FqMont::from_raw_limbs(FqMont::ONE.0), Some(FqMont::ONE));
    }

    #[test]
    fn inverse_of_zero_is_none() {
        assert_eq!(FrMont::ZERO.inv(), None);
        assert_eq!(FqMont::ZERO.inv(), None);
        assert_eq!(FrMont::ONE.inv(), Some(FrMont::ONE));
    }

    #[test]
    fn arithmetic_matches_legacy_u256_api() {
        let one = u256::ONE;
        let vals = [
            u256::ZERO,
            one,
            u256::from(2u8),
            r() - one,
            r() - u256::from(2u8),
            u256::from_words(0x1234_5678_9abc_def0, 0xfedc_ba98_7654_3210),
        ];
        for &a in &vals {
            for &b in &vals {
                let (ma, mb) = (FrMont::from_u256(a).unwrap(), FrMont::from_u256(b).unwrap());
                assert_eq!(ma.mul(&mb).to_u256(), Bn254::mul_mod_legacy(a, b));
                assert_eq!(ma.add(&mb).to_u256(), Bn254::add(a, b));
                assert_eq!(ma.sub(&mb).to_u256(), Bn254::sub(a, b));
            }
            let ma = FrMont::from_u256(a).unwrap();
            assert_eq!(ma.neg().to_u256(), Bn254::sub(u256::ZERO, a));
            assert_eq!(ma.square(), ma.mul(&ma));
            if let Some(inv) = ma.inv() {
                assert_eq!(inv.mul(&ma), FrMont::ONE);
            }
        }
    }

    #[test]
    fn reduced_constructor_accepts_non_canonical() {
        let one = u256::ONE;
        assert_eq!(FrMont::from_u256_reduced(r()), FrMont::ZERO);
        assert_eq!(FrMont::from_u256_reduced(r() + one), FrMont::ONE);
        assert_eq!(
            FrMont::from_u256_reduced(u256::MAX).to_u256(),
            u256::MAX % r()
        );
        assert_eq!(
            FqMont::from_u256_reduced(u256::MAX).to_u256(),
            u256::MAX % q()
        );
    }

    #[test]
    fn ct_select_picks_correct_operand() {
        let a = FrMont::ONE;
        let b = FrMont::ZERO;
        assert_eq!(FrMont::ct_select(1, &a, &b), a);
        assert_eq!(FrMont::ct_select(u64::MAX, &a, &b), a);
        assert_eq!(FrMont::ct_select(0, &a, &b), b);
    }
}
