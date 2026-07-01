use crate::error::ZkError;
use zk_core::{G1Affine, G2Affine, g1_is_in_subgroup, g2_is_in_subgroup};
use alloc::vec::Vec;

/// Groth16 Verifying Key for BN254.
///
/// This structure holds the points required to verify a Groth16 proof.
/// The byte layout is compatible with standard snarkjs/circom exports.
///
/// ### Byte Layout:
/// | Field    | Offset | Length | Description |
/// |----------|--------|--------|-------------|
/// | alpha_g1 | 0      | 64     | G1 point (x: 32B, y: 32B) |
/// | beta_g2  | 64     | 128    | G2 point (x: 64B, y: 64B) |
/// | gamma_g2 | 192    | 128    | G2 point (x: 64B, y: 64B) |
/// | delta_g2 | 320    | 128    | G2 point (x: 64B, y: 64B) |
/// | ic_len   | 448    | 4      | u32 (Big-Endian) number of IC points |
/// | ic       | 452    | N * 64 | N G1 points (x: 32B, y: 32B) |
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Groth16VerifyingKey {
    pub alpha_g1: G1Affine,
    pub beta_g2: G2Affine,
    pub gamma_g2: G2Affine,
    pub delta_g2: G2Affine,
    pub ic: Vec<G1Affine>,
}

impl Groth16VerifyingKey {
    /// Deserializes a flat byte array into a `Groth16VerifyingKey`.
    /// Performs point-on-curve and subgroup checks for all points.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ZkError> {
        const MIN_LEN: usize = 64 + 128 + 128 + 128 + 4;
        if bytes.len() < MIN_LEN {
            return Err(ZkError::DeserializationError);
        }

        let mut offset = 0;

        // Helper to parse G1
        let mut parse_g1 = |buf: &[u8], off: &mut usize| -> Result<G1Affine, ZkError> {
            let p = G1Affine::from_bytes(&buf[*off..*off + 64])
                .map_err(|_| ZkError::DeserializationError)?;
            *off += 64;
            if !g1_is_in_subgroup(&p) {
                return Err(ZkError::InvalidPoint);
            }
            Ok(p)
        };

        // Helper to parse G2
        let mut parse_g2 = |buf: &[u8], off: &mut usize| -> Result<G2Affine, ZkError> {
            let p = G2Affine::from_bytes(&buf[*off..*off + 128])
                .map_err(|_| ZkError::DeserializationError)?;
            *off += 128;
            if !g2_is_in_subgroup(&p) {
                return Err(ZkError::InvalidPoint);
            }
            Ok(p)
        };

        let alpha_g1 = parse_g1(bytes, &mut offset)?;
        let beta_g2 = parse_g2(bytes, &mut offset)?;
        let gamma_g2 = parse_g2(bytes, &mut offset)?;
        let delta_g2 = parse_g2(bytes, &mut offset)?;

        // Parse IC length (Big Endian)
        let ic_len = u32::from_be_bytes(
            bytes[offset..offset + 4]
                .try_into()
                .map_err(|_| ZkError::DeserializationError)?,
        ) as usize;
        offset += 4;

        // Check total length
        if bytes.len() != offset + (ic_len * 64) {
            return Err(ZkError::DeserializationError);
        }

        let mut ic = Vec::with_capacity(ic_len);
        for _ in 0..ic_len {
            ic.push(parse_g1(bytes, &mut offset)?);
        }

        Ok(Groth16VerifyingKey {
            alpha_g1,
            beta_g2,
            gamma_g2,
            delta_g2,
            ic,
        })
    }

    /// Serializes the Verifying Key to a byte vector.
    /// Note: This requires the `alloc` crate.
    pub fn to_bytes(&self) -> Vec<u8> {
        let total_size = 64 + (128 * 3) + 4 + (self.ic.len() * 64);
        let mut bytes = Vec::with_capacity(total_size);

        bytes.extend_from_slice(&self.alpha_g1.to_bytes());
        bytes.extend_from_slice(&self.beta_g2.to_bytes());
        bytes.extend_from_slice(&self.gamma_g2.to_bytes());
        bytes.extend_from_slice(&self.delta_g2.to_bytes());
        
        bytes.extend_from_slice(&(self.ic.len() as u32).to_be_bytes());
        
        for p in &self.ic {
            bytes.extend_from_slice(&p.to_bytes());
        }

        bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zk_core::{G1_GENERATOR, G2_GENERATOR};

    #[test]
    fn test_vk_roundtrip() {
        // Construct a dummy but valid VK
        // In a real scenario, these would be points from a trusted setup
        let vk = Groth16VerifyingKey {
            alpha_g1: G1_GENERATOR,
            beta_g2: G2_GENERATOR,
            gamma_g2: G2_GENERATOR,
            delta_g2: G2_GENERATOR,
            ic: Vec::from([G1_GENERATOR, G1_GENERATOR]),
        };

        let encoded = vk.to_bytes();
        let decoded = Groth16VerifyingKey::from_bytes(&encoded).expect("Should decode");

        assert_eq!(vk, decoded);
    }

    #[test]
    fn test_invalid_length() {
        let bytes = vec![0u8; 10];
        let result = Groth16VerifyingKey::from_bytes(&bytes);
        assert!(matches!(result, Err(ZkError::DeserializationError)));
    }
}
