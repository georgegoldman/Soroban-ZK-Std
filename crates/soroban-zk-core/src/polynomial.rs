use core::cmp::max;
use core::convert::TryFrom;
use ethnum::u256;

use crate::{Bn254, ZkError};

/// Dense BN254 polynomials with a compile-time cap on coefficient storage.
///
/// `MAX_COEFFS` bounds the canonical coefficient count. The `len` field tracks
/// how many leading coefficients are valid.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DensePolynomial<const MAX_COEFFS: usize> {
    pub coeffs: [u256; MAX_COEFFS],
    pub len: usize,
}

/// Sparse BN254 polynomials with a compile-time cap on term storage.
///
/// `MAX_TERMS` bounds the canonical `(exponent, coefficient)` term count. The
/// `len` field tracks how many leading entries are valid.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SparsePolynomial<const MAX_TERMS: usize> {
    pub terms: [(usize, u256); MAX_TERMS],
    pub len: usize,
}

fn zero() -> u256 {
    u256::from(0u8)
}

fn one() -> u256 {
    u256::from(1u8)
}

fn canonical_len(values: &[u256]) -> usize {
    let mut len = values.len();
    while len > 0 && values[len - 1] == zero() {
        len -= 1;
    }
    len
}

impl<const MAX_COEFFS: usize> DensePolynomial<MAX_COEFFS> {
    pub fn from_coefficients_slice(coeffs: &[u256]) -> Result<Self, ZkError> {
        let len = canonical_len(coeffs);
        if len > MAX_COEFFS {
            return Err(ZkError::InvalidInput);
        }

        let mut out = [zero(); MAX_COEFFS];
        out[..len].copy_from_slice(&coeffs[..len]);

        Ok(Self { coeffs: out, len })
    }

    pub fn zero() -> Self {
        Self {
            coeffs: [zero(); MAX_COEFFS],
            len: 0,
        }
    }

    pub fn one() -> Self {
        if MAX_COEFFS == 0 {
            panic!();
        }

        let mut coeffs = [zero(); MAX_COEFFS];
        coeffs[0] = one();

        Self { coeffs, len: 1 }
    }

    pub fn is_zero(&self) -> bool {
        self.len == 0
    }

    pub fn degree(&self) -> usize {
        if self.is_zero() {
            0
        } else {
            self.len - 1
        }
    }

    pub fn coeffs(&self) -> &[u256] {
        &self.coeffs[..self.len]
    }

    pub fn evaluate(&self, x: u256) -> u256 {
        if self.is_zero() {
            return zero();
        }

        let mut result = zero();
        for coeff in self.coeffs().iter().rev() {
            result = Bn254::mul(result, x);
            result = Bn254::add(result, *coeff);
        }
        result
    }

    pub fn add(&self, other: &Self) -> Self {
        let len = max(self.len, other.len);
        debug_assert!(len <= MAX_COEFFS);

        let mut coeffs = [zero(); MAX_COEFFS];
        for (i, slot) in coeffs.iter_mut().enumerate().take(len) {
            let a = if i < self.len { self.coeffs[i] } else { zero() };
            let b = if i < other.len {
                other.coeffs[i]
            } else {
                zero()
            };
            *slot = Bn254::add(a, b);
        }

        Self {
            coeffs,
            len: canonical_len(&coeffs[..len]),
        }
    }

    pub fn sub(&self, other: &Self) -> Self {
        let len = max(self.len, other.len);
        debug_assert!(len <= MAX_COEFFS);

        let mut coeffs = [zero(); MAX_COEFFS];
        for (i, slot) in coeffs.iter_mut().enumerate().take(len) {
            let a = if i < self.len { self.coeffs[i] } else { zero() };
            let b = if i < other.len {
                other.coeffs[i]
            } else {
                zero()
            };
            *slot = Bn254::sub(a, b);
        }

        Self {
            coeffs,
            len: canonical_len(&coeffs[..len]),
        }
    }

    pub fn try_mul(&self, other: &Self) -> Result<Self, ZkError> {
        if self.is_zero() || other.is_zero() {
            return Ok(Self::zero());
        }

        let len = self.len + other.len - 1;
        if len > MAX_COEFFS {
            return Err(ZkError::InvalidInput);
        }

        let mut coeffs = [zero(); MAX_COEFFS];
        for i in 0..self.len {
            for j in 0..other.len {
                let product = Bn254::mul(self.coeffs[i], other.coeffs[j]);
                coeffs[i + j] = Bn254::add(coeffs[i + j], product);
            }
        }

        Ok(Self { coeffs, len })
    }

    pub fn mul(&self, other: &Self) -> Self {
        match self.try_mul(other) {
            Ok(poly) => poly,
            Err(_) => panic!(),
        }
    }

    pub fn scalar_mul(&self, scalar: u256) -> Self {
        let mut coeffs = [zero(); MAX_COEFFS];
        for (i, slot) in coeffs.iter_mut().enumerate().take(self.len) {
            *slot = Bn254::mul(self.coeffs[i], scalar);
        }

        Self {
            coeffs,
            len: canonical_len(&coeffs[..self.len]),
        }
    }

    /// Computes `(q(X), p(z))` where `p(X) - p(z) = (X - z) * q(X)` using
    /// allocation-free Ruffini synthetic division.
    pub fn ruffini_divide(&self, z: u256) -> Result<(Self, u256), ZkError> {
        let mut q_coeffs = [zero(); MAX_COEFFS];
        let eval = ruffini_quotient_in_place(self.coeffs(), z, &mut q_coeffs)?;
        let q_len = canonical_len(&q_coeffs[..self.len.saturating_sub(1)]);
        Ok((
            Self {
                coeffs: q_coeffs,
                len: q_len,
            },
            eval,
        ))
    }
}

/// Two-adicity of the BN254 scalar field `Fr`: `2^28 | (r - 1)`.
pub const BN254_TWO_ADICITY: u32 = 28;

/// Multiplicative generator `g = 5` of the BN254 scalar field `Fr` (also a
/// standard coset shift for coset NTTs).
pub const BN254_MULTIPLICATIVE_GENERATOR: u256 = u256::from_words(0, 5);

/// Canonical primitive `2^28`-th root of unity in BN254 `Fr`:
/// `5^((r - 1) / 2^28) mod r`.
pub const BN254_TWO_ADIC_ROOT_OF_UNITY: u256 = u256::from_words(
    0x2a3c09f0a58a7e8500e0a7eb8ef62abc_u128,
    0x402d111e41112ed49bd61b6e725b19f0_u128,
);

/// Returns the canonical primitive `n`-th root of unity in BN254 `Fr`.
///
/// Requires `n` to be a power of two with `1 <= n <= 2^28`.
pub fn primitive_root_of_unity(n: usize) -> Result<u256, ZkError> {
    if !n.is_power_of_two() {
        return Err(ZkError::InvalidInput);
    }
    let log_n = n.trailing_zeros();
    if log_n > BN254_TWO_ADICITY {
        return Err(ZkError::InvalidInput);
    }
    if log_n == 0 {
        return Ok(one());
    }

    let mut root = BN254_TWO_ADIC_ROOT_OF_UNITY;
    for _ in 0..(BN254_TWO_ADICITY - log_n) {
        root = Bn254::mul(root, root);
    }
    Ok(root)
}

/// Validates that `omega` is a primitive `n`-th root of unity in BN254 `Fr`:
/// `n` is a power of two (`1 <= n <= 2^28`), `omega < FR_MODULUS`,
/// `omega^n == 1`, and for `n >= 2`, `omega^(n/2) != 1`.
pub fn validate_root_of_unity(omega: u256, n: usize) -> Result<(), ZkError> {
    if !n.is_power_of_two() || n.trailing_zeros() > BN254_TWO_ADICITY {
        return Err(ZkError::InvalidInput);
    }
    if !Bn254::is_valid_scalar(omega) {
        return Err(ZkError::InvalidFieldElement);
    }
    if n == 1 {
        return if omega == one() {
            Ok(())
        } else {
            Err(ZkError::InvalidInput)
        };
    }

    let log_n = n.trailing_zeros();
    let mut half_pow = omega;
    for _ in 0..(log_n - 1) {
        half_pow = Bn254::mul(half_pow, half_pow);
    }
    let full_pow = Bn254::mul(half_pow, half_pow);

    if full_pow == one() && half_pow != one() {
        Ok(())
    } else {
        Err(ZkError::InvalidInput)
    }
}

fn validate_field_slice(values: &[u256]) -> Result<(), ZkError> {
    for &v in values {
        if !Bn254::is_valid_scalar(v) {
            return Err(ZkError::InvalidFieldElement);
        }
    }
    Ok(())
}

/// Performs an in-place bit-reversal permutation on a power-of-two slice.
pub fn bit_reverse_permute(values: &mut [u256]) -> Result<(), ZkError> {
    let n = values.len();
    if !n.is_power_of_two() {
        return Err(ZkError::InvalidInput);
    }
    if n <= 1 {
        return Ok(());
    }

    let log_n = n.trailing_zeros();
    let shift = usize::BITS - log_n;
    for i in 0..n {
        let j = i.reverse_bits() >> shift;
        if i < j {
            values.swap(i, j);
        }
    }
    Ok(())
}

/// Core iterative Radix-2 Cooley-Tukey NTT on a pre-validated power-of-two slice.
fn ntt_core_in_place(values: &mut [u256], omega: u256) -> Result<(), ZkError> {
    let n = values.len();
    if n <= 1 {
        return Ok(());
    }

    bit_reverse_permute(values)?;

    let mut len = 2usize;
    while len <= n {
        let half = len / 2;
        let w_step = Bn254::pow(omega, u256::from((n / len) as u128));
        let mut start = 0usize;
        while start < n {
            let mut w = one();
            for j in 0..half {
                let u = values[start + j];
                let v = Bn254::mul(values[start + j + half], w);
                values[start + j] = Bn254::add(u, v);
                values[start + j + half] = Bn254::sub(u, v);
                w = Bn254::mul(w, w_step);
            }
            start += len;
        }
        len <<= 1;
    }

    Ok(())
}

/// Computes the forward Radix-2 Cooley-Tukey NTT in place over BN254 `Fr`.
///
/// Transforms coefficient vector `(a_0, ..., a_{n-1})` into evaluations
/// `(a(1), a(omega), ..., a(omega^{n-1}))`.
pub fn ntt_in_place(values: &mut [u256], omega: u256) -> Result<(), ZkError> {
    validate_root_of_unity(omega, values.len())?;
    validate_field_slice(values)?;
    ntt_core_in_place(values, omega)
}

/// Computes the inverse Radix-2 Cooley-Tukey NTT in place over BN254 `Fr`.
///
/// Recovers coefficient vector `(a_0, ..., a_{n-1})` from evaluations on
/// `(1, omega, ..., omega^{n-1})`.
pub fn intt_in_place(values: &mut [u256], omega: u256) -> Result<(), ZkError> {
    let n = values.len();
    validate_root_of_unity(omega, n)?;
    validate_field_slice(values)?;
    if n <= 1 {
        return Ok(());
    }

    let omega_inv = Bn254::invert(omega);
    ntt_core_in_place(values, omega_inv)?;

    let n_inv = Bn254::invert(u256::from(n as u128));
    for slot in values.iter_mut() {
        *slot = Bn254::mul(*slot, n_inv);
    }

    Ok(())
}

/// Computes the coset NTT in place over BN254 `Fr`.
///
/// Evaluates `p(coset_shift * omega^j)` for `0 <= j < n` by scaling
/// `values[i] *= coset_shift^i` followed by a standard forward NTT.
pub fn coset_ntt_in_place(
    values: &mut [u256],
    omega: u256,
    coset_shift: u256,
) -> Result<(), ZkError> {
    if !Bn254::is_valid_scalar(coset_shift) {
        return Err(ZkError::InvalidFieldElement);
    }
    if coset_shift == zero() {
        return Err(ZkError::InvalidInput);
    }
    validate_root_of_unity(omega, values.len())?;
    validate_field_slice(values)?;

    let mut shift_pow = one();
    for slot in values.iter_mut() {
        *slot = Bn254::mul(*slot, shift_pow);
        shift_pow = Bn254::mul(shift_pow, coset_shift);
    }

    ntt_core_in_place(values, omega)
}

/// Computes the inverse coset NTT in place over BN254 `Fr`.
///
/// Recovers coefficients from evaluations on the coset
/// `{coset_shift * omega^j : 0 <= j < n}`.
pub fn coset_intt_in_place(
    values: &mut [u256],
    omega: u256,
    coset_shift: u256,
) -> Result<(), ZkError> {
    if !Bn254::is_valid_scalar(coset_shift) {
        return Err(ZkError::InvalidFieldElement);
    }
    if coset_shift == zero() {
        return Err(ZkError::InvalidInput);
    }
    intt_in_place(values, omega)?;

    let shift_inv = Bn254::invert(coset_shift);
    let mut shift_inv_pow = one();
    for slot in values.iter_mut() {
        *slot = Bn254::mul(*slot, shift_inv_pow);
        shift_inv_pow = Bn254::mul(shift_inv_pow, shift_inv);
    }

    Ok(())
}

/// Multiplies two zero-padded power-of-two polynomials in `O(n log n)` time
/// using in-place NTT/INTT with zero heap allocations.
///
/// The product is written into `a`; `b` is overwritten as scratch space.
/// Callers must ensure both slices have the same power-of-two length `n` large
/// enough to hold the product without wrap-around (`n >= deg(a) + deg(b) + 1`).
pub fn poly_mul_ntt_in_place(a: &mut [u256], b: &mut [u256], omega: u256) -> Result<(), ZkError> {
    if a.len() != b.len() {
        return Err(ZkError::InvalidInput);
    }
    validate_root_of_unity(omega, a.len())?;
    validate_field_slice(a)?;
    validate_field_slice(b)?;

    ntt_core_in_place(a, omega)?;
    ntt_core_in_place(b, omega)?;

    for (ai, bi) in a.iter_mut().zip(b.iter()) {
        *ai = Bn254::mul(*ai, *bi);
    }

    intt_in_place(a, omega)
}

/// Computes the quotient `q(X) = (p(X) - p(z)) / (X - z)` via allocation-free
/// Ruffini synthetic division and returns the evaluation `p(z)`.
///
/// Writes the quotient coefficients into `quotient_out` (zero-padding any
/// remaining trailing slots). Requires
/// `quotient_out.len() >= coeffs.len().saturating_sub(1)`.
pub fn ruffini_quotient_in_place(
    coeffs: &[u256],
    z: u256,
    quotient_out: &mut [u256],
) -> Result<u256, ZkError> {
    if !Bn254::is_valid_scalar(z) {
        return Err(ZkError::InvalidFieldElement);
    }
    validate_field_slice(coeffs)?;

    let q_len = coeffs.len().saturating_sub(1);
    if quotient_out.len() < q_len {
        return Err(ZkError::InvalidInput);
    }

    for slot in quotient_out.iter_mut().skip(q_len) {
        *slot = zero();
    }

    if coeffs.is_empty() {
        return Ok(zero());
    }
    if coeffs.len() == 1 {
        return Ok(coeffs[0]);
    }

    let mut acc = coeffs[coeffs.len() - 1];
    quotient_out[q_len - 1] = acc;
    for i in (1..coeffs.len() - 1).rev() {
        acc = Bn254::add(Bn254::mul(acc, z), coeffs[i]);
        quotient_out[i - 1] = acc;
    }

    let eval = Bn254::add(Bn254::mul(acc, z), coeffs[0]);
    Ok(eval)
}

impl<const MAX_TERMS: usize> SparsePolynomial<MAX_TERMS> {
    pub fn from_terms_slice(terms: &[(usize, u256)]) -> Result<Self, ZkError> {
        let mut out = [(0usize, zero()); MAX_TERMS];
        let mut len = 0;

        for &(exp, coeff) in terms {
            if coeff == zero() {
                continue;
            }

            let mut insert_at = 0;
            while insert_at < len && out[insert_at].0 < exp {
                insert_at += 1;
            }

            if insert_at < len && out[insert_at].0 == exp {
                let new_coeff = Bn254::add(out[insert_at].1, coeff);
                if new_coeff == zero() {
                    for i in insert_at..(len - 1) {
                        out[i] = out[i + 1];
                    }
                    len -= 1;
                } else {
                    out[insert_at].1 = new_coeff;
                }
                continue;
            }

            if len == MAX_TERMS {
                return Err(ZkError::InvalidInput);
            }

            for i in (insert_at..len).rev() {
                out[i + 1] = out[i];
            }
            out[insert_at] = (exp, coeff);
            len += 1;
        }

        Ok(Self { terms: out, len })
    }

    pub fn zero() -> Self {
        Self {
            terms: [(0usize, zero()); MAX_TERMS],
            len: 0,
        }
    }

    pub fn is_zero(&self) -> bool {
        self.len == 0
    }

    pub fn degree(&self) -> usize {
        if self.is_zero() {
            0
        } else {
            self.terms[self.len - 1].0
        }
    }

    pub fn terms(&self) -> &[(usize, u256)] {
        &self.terms[..self.len]
    }

    pub fn evaluate(&self, x: u256) -> u256 {
        let mut result = zero();

        for &(exp, coeff) in self.terms() {
            let x_pow = if exp == 0 {
                one()
            } else {
                Bn254::pow(x, u256::from(exp as u128))
            };
            let term = Bn254::mul(coeff, x_pow);
            result = Bn254::add(result, term);
        }

        result
    }
}

impl<const MAX_COEFFS: usize, const MAX_TERMS: usize> TryFrom<&SparsePolynomial<MAX_TERMS>>
    for DensePolynomial<MAX_COEFFS>
{
    type Error = ZkError;

    fn try_from(value: &SparsePolynomial<MAX_TERMS>) -> Result<Self, Self::Error> {
        if value.is_zero() {
            return Ok(Self::zero());
        }

        let degree = value.degree();
        if degree + 1 > MAX_COEFFS {
            return Err(ZkError::InvalidInput);
        }

        let mut coeffs = [zero(); MAX_COEFFS];
        for &(exp, coeff) in value.terms() {
            coeffs[exp] = coeff;
        }

        Ok(Self {
            coeffs,
            len: degree + 1,
        })
    }
}

impl<const MAX_COEFFS: usize, const MAX_TERMS: usize> TryFrom<&DensePolynomial<MAX_COEFFS>>
    for SparsePolynomial<MAX_TERMS>
{
    type Error = ZkError;

    fn try_from(value: &DensePolynomial<MAX_COEFFS>) -> Result<Self, Self::Error> {
        let mut out = [(0usize, zero()); MAX_TERMS];
        let mut len = 0;

        for (exp, coeff) in value.coeffs().iter().copied().enumerate() {
            if coeff == zero() {
                continue;
            }

            if len == MAX_TERMS {
                return Err(ZkError::InvalidInput);
            }

            out[len] = (exp, coeff);
            len += 1;
        }

        Ok(Self { terms: out, len })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type Dense4 = DensePolynomial<4>;
    type Sparse4 = SparsePolynomial<4>;

    #[test]
    fn dense_strips_trailing_zeros_and_respects_bound() {
        let poly = Dense4::from_coefficients_slice(&[one(), zero(), zero()]).unwrap();
        assert_eq!(poly.coeffs(), &[one()]);
        assert_eq!(poly.degree(), 0);
    }

    #[test]
    fn dense_rejects_over_limit_after_canonicalization() {
        let coeffs = [one(), one(), one(), one(), one()];
        assert_eq!(
            Dense4::from_coefficients_slice(&coeffs),
            Err(ZkError::InvalidInput)
        );
    }

    #[test]
    fn sparse_combines_duplicates_and_filters_zeroes() {
        let poly =
            Sparse4::from_terms_slice(&[(0, one()), (2, one()), (2, zero()), (2, one())]).unwrap();

        assert_eq!(poly.terms(), &[(0, one()), (2, Bn254::add(one(), one()))]);
    }

    #[test]
    fn sparse_rejects_over_limit_after_dedup() {
        let terms = [(0, one()), (1, one()), (2, one()), (3, one()), (4, one())];

        assert_eq!(
            Sparse4::from_terms_slice(&terms),
            Err(ZkError::InvalidInput)
        );
    }

    #[test]
    fn dense_and_sparse_conversions_round_trip() {
        let dense = Dense4::from_coefficients_slice(&[one(), zero(), one()]).unwrap();
        let sparse: Sparse4 = Sparse4::try_from(&dense).unwrap();
        let dense_round_trip: Dense4 = Dense4::try_from(&sparse).unwrap();

        assert_eq!(dense_round_trip, dense);
    }

    #[test]
    fn dense_multiplication_enforces_bound() {
        let a = DensePolynomial::<3>::from_coefficients_slice(&[one(), one(), one()]).unwrap();
        let b = DensePolynomial::<3>::from_coefficients_slice(&[one(), one(), one()]).unwrap();

        assert_eq!(a.try_mul(&b), Err(ZkError::InvalidInput));
    }

    #[test]
    fn primitive_root_of_unity_matches_arkworks_and_validates() {
        use ark_bn254::Fr as ArkFr;
        use ark_ff::{BigInteger, FftField, PrimeField};

        let ark_root = ArkFr::TWO_ADIC_ROOT_OF_UNITY;
        let bytes = ark_root.into_bigint().to_bytes_be();
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        let expected_root = u256::from_be_bytes(arr);
        assert_eq!(BN254_TWO_ADIC_ROOT_OF_UNITY, expected_root);

        for k in 0..=10u32 {
            let n = 1usize << k;
            let omega = primitive_root_of_unity(n).unwrap();
            assert_eq!(validate_root_of_unity(omega, n), Ok(()));
        }

        assert_eq!(primitive_root_of_unity(0), Err(ZkError::InvalidInput));
        assert_eq!(primitive_root_of_unity(3), Err(ZkError::InvalidInput));
        assert_eq!(
            validate_root_of_unity(u256::from(2u8), 1),
            Err(ZkError::InvalidInput)
        );
        let omega2 = primitive_root_of_unity(2).unwrap();
        assert_eq!(
            validate_root_of_unity(omega2, 4),
            Err(ZkError::InvalidInput)
        );
        assert_eq!(
            validate_root_of_unity(u256::from(5u8), 4),
            Err(ZkError::InvalidInput)
        );
        assert_eq!(
            validate_root_of_unity(Bn254::FR_MODULUS, 4),
            Err(ZkError::InvalidFieldElement)
        );
    }

    #[test]
    fn bit_reverse_permute_happy_and_negative() {
        let mut v = [
            u256::from(0u8),
            u256::from(1u8),
            u256::from(2u8),
            u256::from(3u8),
            u256::from(4u8),
            u256::from(5u8),
            u256::from(6u8),
            u256::from(7u8),
        ];
        bit_reverse_permute(&mut v).unwrap();
        assert_eq!(
            v,
            [
                u256::from(0u8),
                u256::from(4u8),
                u256::from(2u8),
                u256::from(6u8),
                u256::from(1u8),
                u256::from(5u8),
                u256::from(3u8),
                u256::from(7u8),
            ]
        );
        bit_reverse_permute(&mut v).unwrap();
        for (i, &val) in v.iter().enumerate() {
            assert_eq!(val, u256::from(i as u8));
        }

        let mut empty: [u256; 0] = [];
        assert_eq!(bit_reverse_permute(&mut empty), Err(ZkError::InvalidInput));
        let mut non_pow2 = [one(), one(), one()];
        assert_eq!(
            bit_reverse_permute(&mut non_pow2),
            Err(ZkError::InvalidInput)
        );
    }

    #[test]
    fn ntt_and_intt_round_trip_and_match_horner() {
        let coeffs = [
            u256::from(3u8),
            u256::from(7u8),
            u256::from(11u8),
            u256::from(19u8),
            u256::from(23u8),
            u256::from(29u8),
            u256::from(31u8),
            u256::from(37u8),
        ];
        let poly = DensePolynomial::<8>::from_coefficients_slice(&coeffs).unwrap();
        let omega = primitive_root_of_unity(8).unwrap();

        let mut evals = coeffs;
        ntt_in_place(&mut evals, omega).unwrap();

        let mut w_pow = one();
        for &ev in &evals {
            assert_eq!(ev, poly.evaluate(w_pow));
            w_pow = Bn254::mul(w_pow, omega);
        }

        intt_in_place(&mut evals, omega).unwrap();
        assert_eq!(evals, coeffs);
    }

    #[test]
    fn coset_ntt_and_intt_round_trip_and_match_horner() {
        let coeffs = [
            u256::from(5u8),
            u256::from(2u8),
            u256::from(9u8),
            u256::from(13u8),
        ];
        let poly = DensePolynomial::<4>::from_coefficients_slice(&coeffs).unwrap();
        let omega = primitive_root_of_unity(4).unwrap();
        let shift = BN254_MULTIPLICATIVE_GENERATOR;

        let mut evals = coeffs;
        coset_ntt_in_place(&mut evals, omega, shift).unwrap();

        let mut x = shift;
        for &ev in &evals {
            assert_eq!(ev, poly.evaluate(x));
            x = Bn254::mul(x, omega);
        }

        coset_intt_in_place(&mut evals, omega, shift).unwrap();
        assert_eq!(evals, coeffs);

        assert_eq!(
            coset_ntt_in_place(&mut evals, omega, zero()),
            Err(ZkError::InvalidInput)
        );
        assert_eq!(
            coset_ntt_in_place(&mut evals, omega, Bn254::FR_MODULUS),
            Err(ZkError::InvalidFieldElement)
        );
    }

    #[test]
    fn poly_mul_ntt_matches_schoolbook_and_rejects_invalid() {
        let a_coeffs = [u256::from(1u8), u256::from(2u8), u256::from(3u8), zero()];
        let b_coeffs = [u256::from(4u8), u256::from(5u8), zero(), zero()];
        let omega = primitive_root_of_unity(4).unwrap();

        let a_poly = DensePolynomial::<8>::from_coefficients_slice(&a_coeffs).unwrap();
        let b_poly = DensePolynomial::<8>::from_coefficients_slice(&b_coeffs).unwrap();
        let expected = a_poly.try_mul(&b_poly).unwrap();

        let mut a = a_coeffs;
        let mut b = b_coeffs;
        poly_mul_ntt_in_place(&mut a, &mut b, omega).unwrap();
        assert_eq!(&a[..expected.len], expected.coeffs());

        let mut short = [one(), one()];
        assert_eq!(
            poly_mul_ntt_in_place(&mut a, &mut short, omega),
            Err(ZkError::InvalidInput)
        );
    }

    #[test]
    fn ruffini_division_reconstructs_polynomial() {
        let coeffs = [
            u256::from(5u8),
            u256::from(3u8),
            u256::from(2u8),
            u256::from(7u8),
        ];
        let poly = DensePolynomial::<8>::from_coefficients_slice(&coeffs).unwrap();
        let z = u256::from(11u8);

        let (q, eval) = poly.ruffini_divide(z).unwrap();
        assert_eq!(eval, poly.evaluate(z));

        let neg_z = Bn254::sub(zero(), z);
        let linear = DensePolynomial::<8>::from_coefficients_slice(&[neg_z, one()]).unwrap();
        let rem = DensePolynomial::<8>::from_coefficients_slice(&[eval]).unwrap();
        let reconstructed = linear.try_mul(&q).unwrap().add(&rem);
        assert_eq!(reconstructed, poly);

        let mut too_small = [zero(); 2];
        assert_eq!(
            ruffini_quotient_in_place(&coeffs, z, &mut too_small),
            Err(ZkError::InvalidInput)
        );
        let mut ok_buf = [zero(); 3];
        assert_eq!(
            ruffini_quotient_in_place(&coeffs, Bn254::FR_MODULUS, &mut ok_buf),
            Err(ZkError::InvalidFieldElement)
        );
    }

    mod proptests {
        use super::*;
        use ark_bn254::Fr as ArkFr;
        use ark_ff::{BigInteger, Field, PrimeField};
        use proptest::prelude::*;

        fn u256_to_ark(v: u256) -> ArkFr {
            ArkFr::from_be_bytes_mod_order(&v.to_be_bytes())
        }

        fn ark_to_u256(f: ArkFr) -> u256 {
            let bytes = f.into_bigint().to_bytes_be();
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            u256::from_be_bytes(arr)
        }

        fn arb_fr() -> impl Strategy<Value = u256> {
            (any::<u128>(), any::<u128>()).prop_map(|(hi, lo)| {
                let raw = u256::from_words(hi, lo);
                raw % Bn254::FR_MODULUS
            })
        }

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(32))]

            #[test]
            fn prop_ntt_matches_ark_ff_evaluation_and_inverts(
                coeffs in proptest::collection::vec(arb_fr(), 8..=8),
                shift in arb_fr().prop_filter("non-zero shift", |&s| s != u256::from(0u8)),
            ) {
                let n = 8usize;
                let omega = primitive_root_of_unity(n).unwrap();
                let ark_omega = u256_to_ark(omega);
                let ark_coeffs: [ArkFr; 8] = core::array::from_fn(|i| u256_to_ark(coeffs[i]));

                let mut buf = coeffs.clone();
                ntt_in_place(&mut buf, omega).unwrap();
                for (j, &ev) in buf.iter().enumerate() {
                    let x = ark_omega.pow([j as u64]);
                    let mut expected = ArkFr::from(0u64);
                    for c in ark_coeffs.iter().rev() {
                        expected = expected * x + *c;
                    }
                    prop_assert_eq!(ev, ark_to_u256(expected));
                }

                intt_in_place(&mut buf, omega).unwrap();
                prop_assert_eq!(buf, coeffs.clone());

                let ark_shift = u256_to_ark(shift);
                let mut cbuf = coeffs.clone();
                coset_ntt_in_place(&mut cbuf, omega, shift).unwrap();
                for (j, &ev) in cbuf.iter().enumerate() {
                    let x = ark_shift * ark_omega.pow([j as u64]);
                    let mut expected = ArkFr::from(0u64);
                    for c in ark_coeffs.iter().rev() {
                        expected = expected * x + *c;
                    }
                    prop_assert_eq!(ev, ark_to_u256(expected));
                }

                coset_intt_in_place(&mut cbuf, omega, shift).unwrap();
                prop_assert_eq!(cbuf, coeffs);
            }

            #[test]
            fn prop_poly_mul_ntt_and_ruffini_match_ark_ff(
                a_in in proptest::collection::vec(arb_fr(), 4..=4),
                b_in in proptest::collection::vec(arb_fr(), 4..=4),
                z in arb_fr(),
            ) {
                let n = 8usize;
                let omega = primitive_root_of_unity(n).unwrap();
                let mut a = [zero(); 8];
                let mut b = [zero(); 8];
                a[..4].copy_from_slice(&a_in);
                b[..4].copy_from_slice(&b_in);

                poly_mul_ntt_in_place(&mut a, &mut b, omega).unwrap();

                let mut expected = [ArkFr::from(0u64); 8];
                for i in 0..4 {
                    for j in 0..4 {
                        expected[i + j] += u256_to_ark(a_in[i]) * u256_to_ark(b_in[j]);
                    }
                }
                for i in 0..8 {
                    prop_assert_eq!(a[i], ark_to_u256(expected[i]));
                }

                let mut q = [zero(); 3];
                let eval = ruffini_quotient_in_place(&a_in, z, &mut q).unwrap();
                let ark_z = u256_to_ark(z);
                let mut ark_eval = ArkFr::from(0u64);
                for &c in a_in.iter().rev() {
                    ark_eval = ark_eval * ark_z + u256_to_ark(c);
                }
                prop_assert_eq!(eval, ark_to_u256(ark_eval));

                let mut recon = [ArkFr::from(0u64); 4];
                recon[0] = ark_eval;
                for i in 0..3 {
                    let qi = u256_to_ark(q[i]);
                    recon[i + 1] += qi;
                    recon[i] -= qi * ark_z;
                }
                for i in 0..4 {
                    prop_assert_eq!(ark_to_u256(recon[i]), a_in[i]);
                }
            }
        }
    }
}
