//! Groth16 verifier — Soroban host integration.
//!
//! Implements `zk_core::groth16::PairingCheck` using the CAP-0075
//! `bn254_multi_pairing_check` host function, then exposes a single
//! `verify_groth16` entry-point for use in Soroban contracts.

use ethnum::u256;
use soroban_sdk::crypto::bn254::{Bn254G1Affine as SdkG1, Bn254G2Affine as SdkG2};
use soroban_sdk::{BytesN, Env, Vec};
use zk_core::groth16::{Groth16Proof, PairingCheck, VerifyingKey};
use zk_core::{G1Affine, ZkError};

// ── Host pairing adapter ──────────────────────────────────────────────────────

/// Wraps the Soroban `Env` to implement `PairingCheck` via CAP-0075.
pub struct SorobanPairing<'a> {
    pub env: &'a Env,
}

impl<'a> PairingCheck for SorobanPairing<'a> {
    fn check_4(
        &self,
        a1: G1Affine,
        b1_x: (u256, u256),
        b1_y: (u256, u256),
        a2: G1Affine,
        b2_x: (u256, u256),
        b2_y: (u256, u256),
        a3: G1Affine,
        b3_x: (u256, u256),
        b3_y: (u256, u256),
        a4: G1Affine,
        b4_x: (u256, u256),
        b4_y: (u256, u256),
    ) -> Result<bool, ZkError> {
        let env = self.env;

        let mut vp1: Vec<SdkG1> = Vec::new(env);
        let mut vp2: Vec<SdkG2> = Vec::new(env);

        let pairs: [(G1Affine, (u256, u256), (u256, u256)); 4] = [
            (a1, b1_x, b1_y),
            (a2, b2_x, b2_y),
            (a3, b3_x, b3_y),
            (a4, b4_x, b4_y),
        ];

        for (g1, g2x, g2y) in &pairs {
            vp1.push_back(g1_to_sdk(env, g1));
            vp2.push_back(g2_to_sdk(env, *g2x, *g2y));
        }

        Ok(env.crypto().bn254().pairing_check(vp1, vp2))
    }
}

// ── Public entry-point ────────────────────────────────────────────────────────

/// Verify a Groth16 proof inside a Soroban contract.
///
/// # Arguments
/// * `env`           — Soroban execution environment
/// * `vk`            — Verification key (loaded from contract storage)
/// * `proof`         — The proof to verify
/// * `public_inputs` — Public witness values (must be valid Fr elements)
///
/// # Returns
/// `Ok(true)` if the proof is valid, `Ok(false)` if invalid,
/// `Err(ZkError)` on malformed inputs.
pub fn verify_groth16(
    env: &Env,
    vk: &VerifyingKey,
    proof: &Groth16Proof,
    public_inputs: &[u256],
) -> Result<bool, ZkError> {
    let pairing = SorobanPairing { env };
    zk_core::groth16::verify(&pairing, vk, proof, public_inputs)
}

// ── Serialization helpers ─────────────────────────────────────────────────────

fn g1_to_sdk(env: &Env, p: &G1Affine) -> SdkG1 {
    let mut bytes = [0u8; 64];
    bytes[0..32].copy_from_slice(&p.x.to_be_bytes());
    bytes[32..64].copy_from_slice(&p.y.to_be_bytes());
    SdkG1::from_bytes(BytesN::from_array(env, &bytes))
}

fn g2_to_sdk(env: &Env, x: (u256, u256), y: (u256, u256)) -> SdkG2 {
    let mut bytes = [0u8; 128];
    bytes[0..32].copy_from_slice(&x.0.to_be_bytes());
    bytes[32..64].copy_from_slice(&x.1.to_be_bytes());
    bytes[64..96].copy_from_slice(&y.0.to_be_bytes());
    bytes[96..128].copy_from_slice(&y.1.to_be_bytes());
    SdkG2::from_bytes(BytesN::from_array(env, &bytes))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::Env;
    use zk_core::groth16::MAX_PUBLIC_INPUTS;

    fn fr(v: u128) -> u256 {
        u256::from_words(0, v)
    }

    fn g1(x: u128, y: u128) -> G1Affine {
        G1Affine { x: fr(x), y: fr(y) }
    }

    /// Build a minimal (invalid) VK for structural tests.
    fn dummy_vk() -> VerifyingKey {
        VerifyingKey {
            alpha_g1: g1(1, 2),
            beta_g2_x: (fr(0), fr(0)),
            beta_g2_y: (fr(0), fr(0)),
            gamma_g2_x: (fr(0), fr(0)),
            gamma_g2_y: (fr(0), fr(0)),
            delta_g2_x: (fr(0), fr(0)),
            delta_g2_y: (fr(0), fr(0)),
            ic: [g1(0, 0); MAX_PUBLIC_INPUTS],
            ic_len: 1,
        }
    }

    #[test]
    fn rejects_too_many_public_inputs() {
        let env = Env::default();
        let vk = dummy_vk(); // ic_len = 1, so 0 public inputs allowed
        let proof = Groth16Proof {
            a: g1(1, 2),
            b_x: (fr(0), fr(0)),
            b_y: (fr(0), fr(0)),
            c: g1(1, 2),
        };
        // Providing 1 public input when ic_len=1 means we need ic_len >= 2
        let result = verify_groth16(&env, &vk, &proof, &[fr(1)]);
        assert_eq!(result, Err(ZkError::InvalidInput));
    }

    #[test]
    fn rejects_invalid_scalar_public_input() {
        let env = Env::default();
        let mut vk = dummy_vk();
        vk.ic_len = 2;
        vk.ic[1] = g1(1, 2);

        let proof = Groth16Proof {
            a: g1(1, 2),
            b_x: (fr(0), fr(0)),
            b_y: (fr(0), fr(0)),
            c: g1(1, 2),
        };
        // FR_MODULUS is not a valid scalar
        let result = verify_groth16(&env, &vk, &proof, &[zk_core::Bn254::FR_MODULUS]);
        assert_eq!(result, Err(ZkError::InvalidFieldElement));
    }
}
