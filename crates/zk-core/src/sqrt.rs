//! Tonelli-Shanks square root for BN254 Fr and Fq fields.
//!
//! Spec: docs/math/tonelli.md and crates/zk-core/src/BN254_Square_Root_Algorithm.md

use crate::Bn254;
use ethnum::u256;

// ── Fr constants ──────────────────────────────────────────────────────────────

/// S_r = 28 (trailing zeros in r-1)
const FR_S: u32 = 28;

/// Q_r = (r-1) / 2^28  (odd part of r-1)
/// r-1 = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000
/// Q_r = (r-1) >> 28
const FR_Q: u256 = u256::from_words(
    0x0000000030644e72e131a029b85045b6_u128,
    0x8181585d2833e84879b9709143e1f593_u128,
);

// ── Public API ────────────────────────────────────────────────────────────────

/// Compute the square root of `a` in the BN254 scalar field Fr.
///
/// Returns `Some(x)` where `x² ≡ a (mod r)`, or `None` if `a` is not a
/// quadratic residue.
pub fn sqrt_fr(a: u256) -> Option<u256> {
    let zero = u256::from_words(0, 0);
    let one = u256::from_words(0, 1);

    if a == zero {
        return Some(zero);
    }

    // Euler's criterion: a^((r-1)/2) must be 1
    let legendre = Bn254::pow(a, Bn254::LEGENDRE_EXP_FR);
    if legendre != one {
        return None;
    }

    // Tonelli-Shanks
    let mut m = FR_S;
    // c = 5^Q_r mod r  (non-residue power, computed at runtime to avoid
    // large pre-computed constant with potential errors)
    let mut c = Bn254::pow(u256::from_words(0, 5), FR_Q);
    let mut t = Bn254::pow(a, FR_Q);
    // R = a^((Q_r+1)/2) — initial square root candidate
    // Compute as a^((Q_r+1)/2) = a^(Q_r) * a^(1/2) approximation via
    // a^((Q_r+1)/2) directly
    let q_plus1 = FR_Q.wrapping_add(one);
    let r_exp = q_plus1 >> 1;
    let mut r = Bn254::pow(a, r_exp);

    loop {
        if t == zero {
            return Some(zero);
        }
        if t == one {
            return Some(r);
        }

        // Find smallest i > 0 such that t^(2^i) == 1
        let mut i = 1u32;
        let mut tmp = Bn254::mul(t, t);
        while tmp != one {
            tmp = Bn254::mul(tmp, tmp);
            i += 1;
            if i >= m {
                return None; // not a QR (shouldn't happen after Euler check)
            }
        }

        // b = c^(2^(m-i-1))
        let mut b = c;
        for _ in 0..(m - i - 1) {
            b = Bn254::mul(b, b);
        }

        m = i;
        c = Bn254::mul(b, b);
        t = Bn254::mul(t, c);
        r = Bn254::mul(r, b);
    }
}

/// Compute the square root of `a` in the BN254 base field Fq.
///
/// Since `q ≡ 3 (mod 4)`, the formula is `a^((q+1)/4) mod q`.
///
/// Returns `Some(x)` where `x² ≡ a (mod q)`, or `None` if `a` is not a
/// quadratic residue.
pub fn sqrt_fq(a: u256) -> Option<u256> {
    let zero = u256::from_words(0, 0);
    let one = u256::from_words(0, 1);

    if a == zero {
        return Some(zero);
    }

    // Euler's criterion
    let legendre = Bn254::pow_fq(a, Bn254::LEGENDRE_EXP_FQ);
    if legendre != one {
        return None;
    }

    // sqrt = a^((q+1)/4)  since q ≡ 3 (mod 4)
    let exp = (Bn254::FQ_MODULUS.wrapping_add(one)) >> 2;
    Some(Bn254::pow_fq(a, exp))
}

/// Decompress a G1 point from its x-coordinate and sign bit.
///
/// Returns `(x, y)` where `y² = x³ + 3 (mod q)` and `(y & 1) == sign_bit`.
pub fn g1_decompress(x: u256, sign_bit: u8) -> Option<(u256, u256)> {
    let x_sq = Bn254::mul_fq(x, x);
    let x_cb = Bn254::mul_fq(x_sq, x);
    let y_sq = Bn254::add_fq(x_cb, Bn254::G1_B);

    let y = sqrt_fq(y_sq)?;

    // Normalise sign
    let y_final = if (y.as_u128() & 1) as u8 != sign_bit {
        Bn254::sub_fq(Bn254::FQ_MODULUS, y)
    } else {
        y
    };

    Some((x, y_final))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn fq(lo: u128) -> u256 {
        u256::from_words(0, lo)
    }

    #[test]
    fn sqrt_fq_zero() {
        assert_eq!(sqrt_fq(fq(0)), Some(fq(0)));
    }

    #[test]
    fn sqrt_fq_one() {
        let root = sqrt_fq(fq(1)).unwrap();
        assert_eq!(Bn254::mul_fq(root, root), fq(1));
    }

    #[test]
    fn sqrt_fq_four() {
        let root = sqrt_fq(fq(4)).unwrap();
        assert_eq!(Bn254::mul_fq(root, root), fq(4));
    }

    #[test]
    fn sqrt_fq_nine() {
        let root = sqrt_fq(fq(9)).unwrap();
        assert_eq!(Bn254::mul_fq(root, root), fq(9));
    }

    #[test]
    fn sqrt_fq_roundtrip_large() {
        // 25 = 5²
        let root = sqrt_fq(fq(25)).unwrap();
        assert_eq!(Bn254::mul_fq(root, root), fq(25));
    }

    #[test]
    fn sqrt_fr_zero() {
        assert_eq!(sqrt_fr(fq(0)), Some(fq(0)));
    }

    #[test]
    fn sqrt_fr_one() {
        let root = sqrt_fr(fq(1)).unwrap();
        assert_eq!(Bn254::mul(root, root), fq(1));
    }

    #[test]
    fn sqrt_fr_four() {
        let root = sqrt_fr(fq(4)).unwrap();
        assert_eq!(Bn254::mul(root, root), fq(4));
    }

    #[test]
    fn sqrt_fr_nine() {
        let root = sqrt_fr(fq(9)).unwrap();
        assert_eq!(Bn254::mul(root, root), fq(9));
    }

    #[test]
    fn g1_decompress_generator() {
        // BN254 G1 generator: x=1, y=2
        let (x, y) = g1_decompress(fq(1), 0).unwrap();
        assert_eq!(x, fq(1));
        assert_eq!(Bn254::mul_fq(y, y), Bn254::add_fq(fq(1), fq(3))); // y² = x³+3 = 4
    }
}
