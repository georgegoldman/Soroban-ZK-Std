//! Dense polynomial arithmetic over BN254 Fr.
//!
//! Polynomials are stored as coefficient vectors `[a0, a1, ..., an]`
//! representing `a0 + a1·X + ... + an·Xⁿ`.
//!
//! Spec: docs/math/poly_div.md, docs/math/lagrange.md

use crate::{Bn254, ZkError};
use ethnum::u256;

// Maximum degree supported without heap allocation.
// Increase as needed; kept small for WASM stack safety.
pub const MAX_DEGREE: usize = 64;

/// A dense polynomial over Fr stored on the stack.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Poly {
    /// Coefficients in ascending degree order.
    pub coeffs: [u256; MAX_DEGREE],
    /// Number of valid coefficients (degree + 1).
    pub len: usize,
}

impl Poly {
    /// Zero polynomial.
    pub fn zero() -> Self {
        Self {
            coeffs: [u256::from_words(0, 0); MAX_DEGREE],
            len: 1,
        }
    }

    /// Constant polynomial `c`.
    pub fn constant(c: u256) -> Self {
        let mut p = Self::zero();
        p.coeffs[0] = c;
        p
    }

    /// Build from a slice of coefficients (ascending degree).
    pub fn from_slice(coeffs: &[u256]) -> Result<Self, ZkError> {
        if coeffs.is_empty() || coeffs.len() > MAX_DEGREE {
            return Err(ZkError::InvalidInput);
        }
        let mut p = Self::zero();
        p.len = coeffs.len();
        p.coeffs[..coeffs.len()].copy_from_slice(coeffs);
        Ok(p)
    }

    /// Degree of the polynomial (0 for constants, including zero).
    pub fn degree(&self) -> usize {
        self.len.saturating_sub(1)
    }

    /// Evaluate `f(x)` using Horner's method.
    pub fn eval(&self, x: u256) -> u256 {
        if self.len == 0 {
            return u256::from_words(0, 0);
        }
        let mut result = self.coeffs[self.len - 1];
        for i in (0..self.len - 1).rev() {
            result = Bn254::add(Bn254::mul(result, x), self.coeffs[i]);
        }
        result
    }

    /// Add two polynomials.
    pub fn add(&self, rhs: &Self) -> Self {
        let len = self.len.max(rhs.len);
        let mut out = Self::zero();
        out.len = len;
        for i in 0..len {
            let a = if i < self.len { self.coeffs[i] } else { u256::from_words(0, 0) };
            let b = if i < rhs.len { rhs.coeffs[i] } else { u256::from_words(0, 0) };
            out.coeffs[i] = Bn254::add(a, b);
        }
        out
    }

    /// Subtract two polynomials.
    pub fn sub(&self, rhs: &Self) -> Self {
        let len = self.len.max(rhs.len);
        let mut out = Self::zero();
        out.len = len;
        for i in 0..len {
            let a = if i < self.len { self.coeffs[i] } else { u256::from_words(0, 0) };
            let b = if i < rhs.len { rhs.coeffs[i] } else { u256::from_words(0, 0) };
            out.coeffs[i] = Bn254::sub(a, b);
        }
        out
    }

    /// Multiply two polynomials (schoolbook O(n²)).
    pub fn mul(&self, rhs: &Self) -> Result<Self, ZkError> {
        let out_len = self.len + rhs.len - 1;
        if out_len > MAX_DEGREE {
            return Err(ZkError::InvalidInput);
        }
        let mut out = Self::zero();
        out.len = out_len;
        for i in 0..self.len {
            for j in 0..rhs.len {
                let term = Bn254::mul(self.coeffs[i], rhs.coeffs[j]);
                out.coeffs[i + j] = Bn254::add(out.coeffs[i + j], term);
            }
        }
        Ok(out)
    }

    /// Polynomial long division: returns `(quotient, remainder)` such that
    /// `self = quotient * divisor + remainder`.
    pub fn div_rem(&self, divisor: &Self) -> Result<(Self, Self), ZkError> {
        let zero = u256::from_words(0, 0);
        if divisor.len == 0 || divisor.coeffs[divisor.len - 1] == zero {
            return Err(ZkError::InvalidInput);
        }
        if self.len < divisor.len {
            return Ok((Self::zero(), self.clone()));
        }

        let mut remainder = self.clone();
        let mut quotient = Self::zero();
        let q_len = self.len - divisor.len + 1;
        quotient.len = q_len;

        let lead_inv = Bn254::invert(divisor.coeffs[divisor.len - 1]);

        for i in (0..q_len).rev() {
            let coeff = Bn254::mul(remainder.coeffs[i + divisor.len - 1], lead_inv);
            quotient.coeffs[i] = coeff;
            for j in 0..divisor.len {
                let sub = Bn254::mul(coeff, divisor.coeffs[j]);
                remainder.coeffs[i + j] = Bn254::sub(remainder.coeffs[i + j], sub);
            }
        }

        // Trim remainder
        let mut rem_len = divisor.len - 1;
        while rem_len > 1 && remainder.coeffs[rem_len - 1] == zero {
            rem_len -= 1;
        }
        remainder.len = rem_len;

        Ok((quotient, remainder))
    }

    /// Lagrange interpolation from `(x_i, y_i)` point pairs.
    ///
    /// Returns the unique polynomial of degree < n passing through all points.
    pub fn lagrange_interpolate(xs: &[u256], ys: &[u256]) -> Result<Self, ZkError> {
        if xs.len() != ys.len() || xs.is_empty() || xs.len() > MAX_DEGREE {
            return Err(ZkError::InvalidInput);
        }
        let n = xs.len();
        let zero = u256::from_words(0, 0);
        let one = u256::from_words(0, 1);

        let mut result = Self::zero();

        for i in 0..n {
            // Build basis polynomial L_i(X) = Π_{j≠i} (X - x_j) / (x_i - x_j)
            let mut basis = Self::constant(one);
            let mut denom = one;

            for j in 0..n {
                if j == i {
                    continue;
                }
                // Multiply basis by (X - x_j)
                let factor = Self::from_slice(&[Bn254::sub(zero, xs[j]), one])?;
                basis = basis.mul(&factor)?;
                // denom *= (x_i - x_j)
                denom = Bn254::mul(denom, Bn254::sub(xs[i], xs[j]));
            }

            let denom_inv = Bn254::invert(denom);
            let yi_over_denom = Bn254::mul(ys[i], denom_inv);

            // Scale basis by y_i / denom
            let mut scaled = Self::zero();
            scaled.len = basis.len;
            for k in 0..basis.len {
                scaled.coeffs[k] = Bn254::mul(basis.coeffs[k], yi_over_denom);
            }

            result = result.add(&scaled);
        }

        Ok(result)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn fr(v: u128) -> u256 {
        u256::from_words(0, v)
    }

    #[test]
    fn eval_constant() {
        let p = Poly::constant(fr(42));
        assert_eq!(p.eval(fr(0)), fr(42));
        assert_eq!(p.eval(fr(100)), fr(42));
    }

    #[test]
    fn eval_linear() {
        // f(x) = 3 + 2x
        let p = Poly::from_slice(&[fr(3), fr(2)]).unwrap();
        assert_eq!(p.eval(fr(0)), fr(3));
        assert_eq!(p.eval(fr(1)), fr(5));
        assert_eq!(p.eval(fr(5)), fr(13));
    }

    #[test]
    fn add_polynomials() {
        let a = Poly::from_slice(&[fr(1), fr(2)]).unwrap();
        let b = Poly::from_slice(&[fr(3), fr(4)]).unwrap();
        let c = a.add(&b);
        assert_eq!(c.coeffs[0], fr(4));
        assert_eq!(c.coeffs[1], fr(6));
    }

    #[test]
    fn mul_polynomials() {
        // (1 + x)(1 + x) = 1 + 2x + x²
        let a = Poly::from_slice(&[fr(1), fr(1)]).unwrap();
        let b = a.mul(&a).unwrap();
        assert_eq!(b.coeffs[0], fr(1));
        assert_eq!(b.coeffs[1], fr(2));
        assert_eq!(b.coeffs[2], fr(1));
    }

    #[test]
    fn div_rem_exact() {
        // (x² - 1) / (x - 1) = (x + 1) remainder 0
        let dividend = Poly::from_slice(&[
            Bn254::sub(fr(0), fr(1)), // -1
            fr(0),
            fr(1),
        ])
        .unwrap();
        let divisor = Poly::from_slice(&[
            Bn254::sub(fr(0), fr(1)), // -1
            fr(1),
        ])
        .unwrap();
        let (q, r) = dividend.div_rem(&divisor).unwrap();
        assert_eq!(q.eval(fr(0)), fr(1)); // constant term = 1
        assert_eq!(q.eval(fr(1)), fr(2)); // 1 + 1 = 2
        assert_eq!(r.eval(fr(0)), fr(0)); // remainder = 0
    }

    #[test]
    fn lagrange_two_points() {
        // Points (0, 1) and (1, 3) → f(x) = 1 + 2x
        let xs = [fr(0), fr(1)];
        let ys = [fr(1), fr(3)];
        let p = Poly::lagrange_interpolate(&xs, &ys).unwrap();
        assert_eq!(p.eval(fr(0)), fr(1));
        assert_eq!(p.eval(fr(1)), fr(3));
        assert_eq!(p.eval(fr(2)), fr(5));
    }

    #[test]
    fn lagrange_three_points() {
        // Points (0,0), (1,1), (2,4) → f(x) = x²
        let xs = [fr(0), fr(1), fr(2)];
        let ys = [fr(0), fr(1), fr(4)];
        let p = Poly::lagrange_interpolate(&xs, &ys).unwrap();
        assert_eq!(p.eval(fr(0)), fr(0));
        assert_eq!(p.eval(fr(1)), fr(1));
        assert_eq!(p.eval(fr(2)), fr(4));
        assert_eq!(p.eval(fr(3)), fr(9));
    }
}
