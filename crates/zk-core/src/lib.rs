#![no_std]
use ethnum::u256;

/// Errors returned by zero-knowledge conversion and validation operations.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ZkError {
    /// The supplied value is ≥ the BN254 scalar field modulus and is not a valid field element.
    InvalidFieldElement,
}

/// A BN254 scalar field element guaranteed to be in the range `[0, r)`.
///
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

impl Bn254 {
    pub const BASE_MODULUS: ethnum::u256 = ethnum::u256::from_words(
        0x30644e72e131a029b85045b68181585d_u128, // high 128 bits (first 16 bytes)
        0x97816a916871ca8d3c208c16d87cfd47_u128, // low 128 bits  (last 16 bytes)
    );

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
        let rhs = Self::add(x_cb, u256::from(3u8));

        y_sq == rhs
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
}
