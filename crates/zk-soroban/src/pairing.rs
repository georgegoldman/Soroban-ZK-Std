use ethnum::u256;
use soroban_sdk::crypto::bn254::{Bn254G1Affine as SdkG1Affine, Bn254G2Affine as SdkG2Affine};
use soroban_sdk::BytesN;
use soroban_sdk::Env;
use soroban_sdk::Vec;
use zk_core::{G1Affine, ZkError};

/// A BN254 G2 point in affine coordinates (X, Y).
/// Coordinates are elements of the degree-2 extension field Fq²,
/// represented as `a + b*u`, where `0` is the real part and `1` is the imaginary part.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct G2Affine {
    pub x: (u256, u256),
    pub y: (u256, u256),
}

impl G2Affine {
    /// Serializes the G2 point into a 128-byte array according to CAP-0074 §3.2 / EIP-197.
    ///
    /// ## Byte Layout
    /// The 128 bytes are structured as:
    /// - Bytes 0..32:   `x.1` (X imaginary / c1)
    /// - Bytes 32..64:  `x.0` (X real / c0)
    /// - Bytes 64..96:  `y.1` (Y imaginary / c1)
    /// - Bytes 96..128: `y.0` (Y real / c0)
    ///
    /// All 32-byte chunks are encoded in Big-Endian format.
    pub fn to_bytes(&self) -> [u8; 128] {
        let mut bytes = [0u8; 128];
        // EIP-197 / CAP-0074: c1 (imaginary) precedes c0 (real)
        bytes[0..32].copy_from_slice(&self.x.1.to_be_bytes()); // X c1
        bytes[32..64].copy_from_slice(&self.x.0.to_be_bytes()); // X c0
        bytes[64..96].copy_from_slice(&self.y.1.to_be_bytes()); // Y c1
        bytes[96..128].copy_from_slice(&self.y.0.to_be_bytes()); // Y c0
        bytes
    }
}
/// Serializes a G1Affine point into a 64-byte array.
///
/// ## Byte Layout
/// - Bytes 0..32:  `x` (Big-Endian)
/// - Bytes 32..64: `y` (Big-Endian)
fn g1_to_bytes(g1: &G1Affine) -> [u8; 64] {
    let mut bytes = [0u8; 64];
    bytes[0..32].copy_from_slice(&g1.x.to_be_bytes());
    bytes[32..64].copy_from_slice(&g1.y.to_be_bytes());
    bytes
}

/// Evaluates the BN254 pairing check e(A1, B1) * ... * e(An, Bn) == 1.
pub fn pairing_check(env: &Env, pairs: &[(G1Affine, G2Affine)]) -> Result<bool, ZkError> {
    if pairs.is_empty() {
        return Err(ZkError::InvalidInput);
    }

    let mut vp1: Vec<SdkG1Affine> = Vec::new(env);
    let mut vp2: Vec<SdkG2Affine> = Vec::new(env);

    for (g1, g2) in pairs {
        let sdk_g1 = SdkG1Affine::from_bytes(BytesN::from_array(env, &g1_to_bytes(g1)));
        let sdk_g2 = SdkG2Affine::from_bytes(BytesN::from_array(env, &g2.to_bytes()));

        vp1.push_back(sdk_g1);
        vp2.push_back(sdk_g2);
    }

    Ok(env.crypto().bn254().pairing_check(vp1, vp2))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethnum::u256;
    use soroban_sdk::Env;

    // BN254 G1 generator
    fn g1_generator() -> G1Affine {
        G1Affine {
            x: u256::from(1u8),
            y: u256::from(2u8),
        }
    }

    // Negation of the BN254 G1 generator: (x, p - y)
    // p = 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47
    fn g1_generator_neg() -> G1Affine {
        G1Affine {
            x: u256::from(1u8),
            y: u256::from_str_radix(
                "30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd45",
                16,
            )
            .unwrap(),
        }
    }

    // Standard BN254 G2 generator (canonical EIP-197 coordinates)
    fn g2_generator() -> G2Affine {
        G2Affine {
            x: (
                // x_c0 (real)
                u256::from_str_radix(
                    "1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed",
                    16,
                )
                .unwrap(),
                // x_c1 (imaginary)
                u256::from_str_radix(
                    "198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2",
                    16,
                )
                .unwrap(),
            ),
            y: (
                // y_c0 (real)
                u256::from_str_radix(
                    "12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa",
                    16,
                )
                .unwrap(),
                // y_c1 (imaginary)
                u256::from_str_radix(
                    "090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b",
                    16,
                )
                .unwrap(),
            ),
        }
    }

    #[test]
    fn test_pairing_check_rejects_empty_input() {
        let env = Env::default();
        assert_eq!(pairing_check(&env, &[]), Err(ZkError::InvalidInput));
    }

    /// Verifies the bilinearity identity: e(G1, G2) * e(-G1, G2) == 1.
    /// This holds because -G1 = negation over G1, so e(G1, G2) * e(-G1, G2)
    /// = e(G1 - G1, G2) = e(O, G2) = 1.
    #[test]
    fn test_pairing_g1_neg_g1_same_g2_equals_one() {
        let env = Env::default();
        let result = pairing_check(
            &env,
            &[
                (g1_generator(), g2_generator()),
                (g1_generator_neg(), g2_generator()),
            ],
        );
        assert!(result.unwrap(), "e(G1, G2) * e(-G1, G2) should equal 1");
    }

    /// Verifies that a single valid pairing pair e(G1, G2) alone does NOT equal 1
    /// (i.e. the result is non-trivial when the product is not the identity).
    #[test]
    fn test_pairing_single_pair_is_not_one() {
        let env = Env::default();
        let result = pairing_check(&env, &[(g1_generator(), g2_generator())]);
        assert!(!result.unwrap(), "e(G1, G2) alone should not equal 1");
    }
}
