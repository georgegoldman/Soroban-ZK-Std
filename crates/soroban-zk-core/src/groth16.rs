//! Groth16 verifying key (de)serialization for BN254.
//!
//! This module provides the [`Groth16VerifyingKey`] type: a structured
//! representation of the on-chain verifying key used to verify Groth16 proofs.
//! It is deliberately kept **Soroban-free** so that it can be used from pure
//! test harnesses and off-chain tools without pulling in the Stellar SDK.
//!
//! The actual proof-verification step (pairing check) lives in
//! `crates/soroban-zk-std/src/groth16.rs`, which adds the Soroban `Env` and
//! calls the `bn254_multi_pairing_check` host function.
//!
//! ## no_std
//! Uses `alloc::vec::Vec` for the variable-length IC array.  Ensure that the
//! consuming crate has a global allocator (e.g., the Soroban allocator).

extern crate alloc;
use alloc::vec::Vec;

use crate::{Bn254, G1Affine, G2Affine, ZkError};

// ============================================================================
// Groth16 Verifying Key
// ============================================================================

/// A deserialized Groth16 verifying key over BN254.
///
/// ### Wire format
/// The canonical byte encoding expected by [`Groth16VerifyingKey::from_bytes`]
/// is the flat concatenation used by snarkjs / circom exports:
///
/// | Field     | Offset          | Size (bytes) | Description                   |
/// |-----------|-----------------|--------------|-------------------------------|
/// | `alpha_g1`| 0               | 64           | G1 point (x ‖ y, BE 32 B each)|
/// | `beta_g2` | 64              | 128          | G2 point (EIP-197 layout)     |
/// | `gamma_g2`| 192             | 128          | G2 point (EIP-197 layout)     |
/// | `delta_g2`| 320             | 128          | G2 point (EIP-197 layout)     |
/// | `ic_len`  | 448             | 4            | u32 Big-Endian count of IC pts|
/// | `ic`      | 452             | ic_len × 64  | IC G1 points (x ‖ y, BE)      |
///
/// ### Security note
/// [`Groth16VerifyingKey::from_bytes`] performs **point-on-curve** validation
/// for all G1 points and **curve-equation** validation for all G2 points.
/// Subgroup validation for G2 is deferred to the pairing check at the host
/// boundary (see [`Bn254::is_valid_g2_subgroup`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Groth16VerifyingKey {
    pub alpha_g1: G1Affine,
    pub beta_g2: G2Affine,
    pub gamma_g2: G2Affine,
    pub delta_g2: G2Affine,
    /// Input-commitment (IC) points.  `ic[0]` is the constant term;
    /// `ic[1..n]` correspond to the `n` public inputs.
    pub ic: Vec<G1Affine>,
}

impl Groth16VerifyingKey {
    /// Minimum byte length: alpha_g1 (64) + 3 G2 points (384) + ic_len (4).
    const MIN_LEN: usize = 64 + 128 + 128 + 128 + 4;

    // -----------------------------------------------------------------------
    // Deserialisation
    // -----------------------------------------------------------------------

    /// Deserializes a flat byte slice into a [`Groth16VerifyingKey`].
    ///
    /// # Errors
    /// Returns [`ZkError::DeserializationError`] when:
    /// - the slice is shorter than the minimum encoded length,
    /// - the declared `ic_len` does not match the remaining bytes,
    /// - any G1 point fails the BN254 on-curve check, or
    /// - any G2 point fails the curve-equation check.
    ///
    /// Returns [`ZkError::InvalidPoint`] when a G1 point passes the
    /// on-curve check but fails the subgroup check (cofactor = 1 for G1,
    /// so this currently mirrors the on-curve check).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ZkError> {
        if bytes.len() < Self::MIN_LEN {
            return Err(ZkError::DeserializationError);
        }

        let mut offset = 0;

        let alpha_g1 = Self::parse_g1(bytes, &mut offset)?;
        let beta_g2 = Self::parse_g2(bytes, &mut offset)?;
        let gamma_g2 = Self::parse_g2(bytes, &mut offset)?;
        let delta_g2 = Self::parse_g2(bytes, &mut offset)?;

        // Parse IC length (Big-Endian u32).
        let ic_len = u32::from_be_bytes(
            bytes[offset..offset + 4]
                .try_into()
                .map_err(|_| ZkError::DeserializationError)?,
        ) as usize;
        offset += 4;

        // Validate exact total length.
        let expected_total = offset + ic_len * 64;
        if bytes.len() != expected_total {
            return Err(ZkError::DeserializationError);
        }

        let mut ic = Vec::with_capacity(ic_len);
        for _ in 0..ic_len {
            ic.push(Self::parse_g1(bytes, &mut offset)?);
        }

        Ok(Self {
            alpha_g1,
            beta_g2,
            gamma_g2,
            delta_g2,
            ic,
        })
    }

    // -----------------------------------------------------------------------
    // Serialisation
    // -----------------------------------------------------------------------

    /// Serializes the verifying key to a byte vector using the layout
    /// described in [`Groth16VerifyingKey`].
    pub fn to_bytes(&self) -> Vec<u8> {
        let total = 64 + 128 * 3 + 4 + self.ic.len() * 64;
        let mut out = Vec::with_capacity(total);

        out.extend_from_slice(&self.alpha_g1.to_bytes());
        out.extend_from_slice(&self.beta_g2.to_bytes());
        out.extend_from_slice(&self.gamma_g2.to_bytes());
        out.extend_from_slice(&self.delta_g2.to_bytes());
        out.extend_from_slice(&(self.ic.len() as u32).to_be_bytes());
        for p in &self.ic {
            out.extend_from_slice(&p.to_bytes());
        }

        out
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    /// Reads 64 bytes at `*offset` as a G1 affine point and validates it.
    fn parse_g1(buf: &[u8], offset: &mut usize) -> Result<G1Affine, ZkError> {
        let p = G1Affine::from_bytes(&buf[*offset..*offset + 64])?;
        *offset += 64;
        // For BN254 G1, cofactor = 1 → on-curve ⟹ in subgroup.
        if !Bn254::is_valid_g1(p.x, p.y) {
            return Err(ZkError::InvalidPoint);
        }
        Ok(p)
    }

    /// Reads 128 bytes at `*offset` as a G2 affine point and validates it.
    fn parse_g2(buf: &[u8], offset: &mut usize) -> Result<G2Affine, ZkError> {
        let p = G2Affine::from_bytes(&buf[*offset..*offset + 128])?;
        *offset += 128;
        if !Bn254::is_valid_g2_curve(p.x, p.y) {
            return Err(ZkError::InvalidPoint);
        }
        Ok(p)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::g1::G1_GENERATOR;
    use ethnum::u256;

    /// The standard BN254 G2 generator point (EIP-197 / CAP-0074 layout).
    fn g2_generator() -> G2Affine {
        G2Affine {
            x: (
                u256::from_str_radix(
                    "1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed",
                    16,
                )
                .unwrap(),
                u256::from_str_radix(
                    "198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2",
                    16,
                )
                .unwrap(),
            ),
            y: (
                u256::from_str_radix(
                    "12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa",
                    16,
                )
                .unwrap(),
                u256::from_str_radix(
                    "090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b",
                    16,
                )
                .unwrap(),
            ),
        }
    }

    /// Builds a dummy-but-valid verifying key for serialization round-trip tests.
    fn dummy_vk(ic_count: usize) -> Groth16VerifyingKey {
        let g1 = G1_GENERATOR;
        let g2 = g2_generator();
        let ic = alloc::vec![g1; ic_count];
        Groth16VerifyingKey {
            alpha_g1: g1,
            beta_g2: g2,
            gamma_g2: g2,
            delta_g2: g2,
            ic,
        }
    }

    #[test]
    fn roundtrip_single_ic_point() {
        let vk = dummy_vk(1);
        let encoded = vk.to_bytes();
        let decoded = Groth16VerifyingKey::from_bytes(&encoded).expect("round-trip should succeed");
        assert_eq!(vk, decoded);
    }

    #[test]
    fn roundtrip_multiple_ic_points() {
        let vk = dummy_vk(3);
        let encoded = vk.to_bytes();
        let decoded = Groth16VerifyingKey::from_bytes(&encoded).expect("round-trip should succeed");
        assert_eq!(vk, decoded);
    }

    #[test]
    fn roundtrip_zero_ic_points() {
        let vk = dummy_vk(0);
        let encoded = vk.to_bytes();
        let decoded =
            Groth16VerifyingKey::from_bytes(&encoded).expect("zero-IC round-trip should succeed");
        assert_eq!(vk, decoded);
    }

    #[test]
    fn rejects_too_short() {
        let bytes = [0u8; 10];
        let result = Groth16VerifyingKey::from_bytes(&bytes);
        assert!(
            matches!(result, Err(ZkError::DeserializationError)),
            "expected DeserializationError for 10-byte input"
        );
    }

    #[test]
    fn rejects_truncated_ic() {
        // Build a valid VK with 2 IC points but truncate the last G1 point by 1 byte.
        let vk = dummy_vk(2);
        let mut encoded = vk.to_bytes();
        encoded.pop();
        let result = Groth16VerifyingKey::from_bytes(&encoded);
        assert!(
            matches!(result, Err(ZkError::DeserializationError)),
            "expected DeserializationError for truncated IC"
        );
    }

    #[test]
    fn serialised_length_is_correct() {
        let ic_count = 4usize;
        let vk = dummy_vk(ic_count);
        let encoded = vk.to_bytes();
        let expected_len = 64 + 128 * 3 + 4 + ic_count * 64;
        assert_eq!(encoded.len(), expected_len);
    }
}
