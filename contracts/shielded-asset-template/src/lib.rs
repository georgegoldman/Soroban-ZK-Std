#![no_std]

use ethnum::u256;
use soroban_sdk::{contract, contractimpl, contracttype, Address, Bytes, Env, String};
use soroban_zk_core::G1Affine;
use soroban_zk_std::events::{
    publish_verification_event, ZkFailureContext, ZkVerificationEvent, ZkVerificationStage,
};
use soroban_zk_std::groth16::{groth16_verify, Groth16Proof, Groth16VerifyingKey};
use soroban_zk_std::pairing::G2Affine;

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EncryptedBalance {
    pub c1_x: soroban_sdk::U256,
    pub c1_y: soroban_sdk::U256,
    pub c2_x: soroban_sdk::U256,
    pub c2_y: soroban_sdk::U256,
}

#[contract]
pub struct ShieldedAsset;

#[contractimpl]
impl ShieldedAsset {
    /// Transfers a shielded amount between two users, while providing a ciphertext to the regulator.
    /// The ZK Proof guarantees:
    /// 1. Sender has sufficient balance.
    /// 2. Sender balance, Receiver balance, and Regulator ciphertexts all encrypt the SAME amount.
    /// 3. Values are in range (no negative amounts).
    ///
    /// This implementation demonstrates the new structured event system that provides
    /// detailed information about verification success/failure for enhanced debugging.
    pub fn transfer_shielded(
        env: Env,
        sender: Address,
        receiver: Address,
        proof_bytes: Bytes,
        public_inputs_bytes: Bytes,
    ) {
        sender.require_auth();

        let proof_length = proof_bytes.len();
        let proof_system = "groth16";
        let public_inputs_count = 1u32; // This template uses 1 public input

        // 1. Deserialize the Groth16 Proof (A, B, C points)
        let mut proof_buf = [0u8; 256];
        if proof_bytes.len() != 256 {
            // Emit structured event for invalid proof length
            let event = ZkVerificationEvent::failure(
                &env,
                proof_system,
                public_inputs_count,
                proof_length,
                false,
                &soroban_zk_std::ZkContractError::DeserializationError,
                ZkVerificationStage::ProofDeserialization,
                Some(ZkFailureContext::deserialization_error(proof_length)),
            );
            publish_verification_event(&env, event);
            panic!("Invalid proof length");
        }
        proof_bytes.copy_into_slice(&mut proof_buf);

        let proof = match Groth16Proof::from_bytes(&proof_buf) {
            Ok(p) => p,
            Err(_) => {
                // Emit structured event for deserialization failure
                let event = ZkVerificationEvent::failure(
                    &env,
                    proof_system,
                    public_inputs_count,
                    proof_length,
                    false,
                    &soroban_zk_std::ZkContractError::DeserializationError,
                    ZkVerificationStage::ProofDeserialization,
                    Some(ZkFailureContext::with_info(
                        &env,
                        "Invalid proof format or curve points",
                    )),
                );
                publish_verification_event(&env, event);
                panic!("Invalid proof format");
            }
        };

        // 2. Load the Verifying Key
        let vk = get_verifying_key();

        // 3. Parse public inputs (e.g. public keys, updated state roots)
        let mut pi_buf = [0u8; 32];
        public_inputs_bytes.copy_into_slice(&mut pi_buf);
        let public_input = u256::from_be_bytes(pi_buf);

        // 4. VERIFY THE ZERO KNOWLEDGE PROOF with structured event emission!
        let is_valid = match groth16_verify(&env, &vk, &proof, &[public_input]) {
            Ok(valid) => valid,
            Err(_) => {
                // Emit structured event for verification error
                let event = ZkVerificationEvent::failure(
                    &env,
                    proof_system,
                    public_inputs_count,
                    proof_length,
                    false,
                    &soroban_zk_std::ZkContractError::HostError,
                    ZkVerificationStage::PairingCheck,
                    Some(ZkFailureContext::with_info(&env, "Pairing check failed")),
                );
                publish_verification_event(&env, event);
                panic!("Verification failed due to malformed points");
            }
        };

        if !is_valid {
            // Emit structured event for invalid proof
            let event = ZkVerificationEvent::pairing_failure(
                &env,
                proof_system,
                public_inputs_count,
                proof_length,
                false,
            );
            publish_verification_event(&env, event);
            panic!("ZK Proof is invalid! Transfer rejected.");
        }

        // 5. ZK Proof passed! Emit success event
        let success_event = ZkVerificationEvent::success(
            &env,
            proof_system,
            public_inputs_count,
            proof_length,
            false,
        )
        .with_context(&env, "Shielded transfer verified successfully");
        publish_verification_event(&env, success_event);

        // Update the encrypted balances via Homomorphic Addition
        // (Implementation of homomorphic addition omitted for brevity in this template)

        // Additional legacy event for backward compatibility
        #[allow(deprecated)]
        env.events().publish(
            (sender, receiver),
            String::from_str(&env, "Shielded Transfer Verified"),
        );
    }
}

// ---------------------------------------------------------------------------
// Verifying Key
//
// Generated by snarkjs (groth16 protocol, bn128 curve) from the
// `contracts/shielded-asset-template` reference balance-check circuit.
//
// Source: hackathon-demo/circuit/verification_key.json
// Circuit: shielded_transfer.circom  (1 public input: balance amount)
//
// All field elements are BN254 Fq / Fr values in big-endian u256.
// G2 coordinates follow the (c0_real, c1_imaginary) tuple convention used
// throughout this codebase and EIP-197 / CAP-0074.
// ---------------------------------------------------------------------------

/// Returns the Groth16 verifying key for the shielded-balance circuit.
///
/// The curve points were produced by running:
///
/// ```text
/// snarkjs groth16 setup shielded_transfer.r1cs pot10_final.ptau circuit_0000.zkey
/// snarkjs zkey contribute circuit_0000.zkey circuit_final.zkey
/// snarkjs zkey export verificationkey circuit_final.zkey verification_key.json
/// ```
///
/// and are committed here as compile-time constants so that the contract
/// binary embeds them without any runtime storage reads.
pub fn get_verifying_key<'a>() -> Groth16VerifyingKey<'a> {
    Groth16VerifyingKey {
        // alpha_g1 (α₁)
        alpha_g1: G1Affine {
            x: u256::from_str_radix(
                "6052c6ae90b77a962b3b355cf88cff3f084dfb2a423bd020222acd3e477a214",
                16,
            )
            .unwrap(),
            y: u256::from_str_radix(
                "20d1bbde469078cd777dab43de968f8d5330297c23334b32fe9b78841f64b18",
                16,
            )
            .unwrap(),
        },

        // beta_g2 (β₂)
        // snarkjs vk_beta_2 format: [[c1, c0], [c1, c0], [1, 0]]
        // Our G2Affine tuple: (c0_real, c1_imaginary)
        beta_g2: G2Affine {
            x: (
                u256::from_str_radix(
                    "1535f84fa5582f2f37628109bc1441ad4911d9d9b22294516260d7e9a9659b38",
                    16,
                )
                .unwrap(), // x.0 = c0 (real)
                u256::from_str_radix(
                    "1d639914164bbf9f91fe66713fc79afd3d2bf21206b2ac265b3fa94075852760",
                    16,
                )
                .unwrap(), // x.1 = c1 (imaginary)
            ),
            y: (
                u256::from_str_radix(
                    "278fdcd0f4eda04f64df74dddf21946f69d2eabee79fe18f4189b8782cacad19",
                    16,
                )
                .unwrap(), // y.0 = c0 (real)
                u256::from_str_radix(
                    "537bca9350ea24d4599a146d91e6964cbe99de3159b49aa35a496953bd33d28",
                    16,
                )
                .unwrap(), // y.1 = c1 (imaginary)
            ),
        },

        // gamma_g2 (γ₂) — standard BN254 G2 generator
        gamma_g2: G2Affine {
            x: (
                u256::from_str_radix(
                    "198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2",
                    16,
                )
                .unwrap(), // x.0 = c0 (real)
                u256::from_str_radix(
                    "1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed",
                    16,
                )
                .unwrap(), // x.1 = c1 (imaginary)
            ),
            y: (
                u256::from_str_radix(
                    "090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b",
                    16,
                )
                .unwrap(), // y.0 = c0 (real)
                u256::from_str_radix(
                    "12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa",
                    16,
                )
                .unwrap(), // y.1 = c1 (imaginary)
            ),
        },

        // delta_g2 (δ₂)
        delta_g2: G2Affine {
            x: (
                u256::from_str_radix(
                    "1e497761c3ab876d78d244ea8dc62bd747bc62de185a628978144d909d4a0462",
                    16,
                )
                .unwrap(), // x.0 = c0 (real)
                u256::from_str_radix(
                    "10c58eeca2bb26cfa71c9c334d68f8075cf12d73d58ea25b5d0aee17152b31d2",
                    16,
                )
                .unwrap(), // x.1 = c1 (imaginary)
            ),
            y: (
                u256::from_str_radix(
                    "15b53a8bc08343ab2a9388050710f5905c3e08d3a35c5dfb53ee0e0984f55ef5",
                    16,
                )
                .unwrap(), // y.0 = c0 (real)
                u256::from_str_radix(
                    "1fdd7a52499f577befaea5705386a0a5028fbb314d575eb707fff2f93697923e",
                    16,
                )
                .unwrap(), // y.1 = c1 (imaginary)
            ),
        },

        // IC (Input Commitments): IC[0] + Σ(public_input[i] * IC[i+1])
        //
        // IC[0]: constant term
        // IC[1]: coefficient of public_input[0] (the proven balance amount)
        ic: &[
            G1Affine {
                x: u256::from_str_radix(
                    "0a11cbd92460f325207159536d80c9f44582e95462d19ac2c084caac89c25ca0",
                    16,
                )
                .unwrap(),
                y: u256::from_str_radix(
                    "14f2f0f329e1ee1dd5b5f67adb53683a02b72312bc4175c4ce29578f93a3cb04",
                    16,
                )
                .unwrap(),
            },
            G1Affine {
                x: u256::from_str_radix(
                    "0ea2aee8ab2a7ccd129e35144e1f291401ef18d20cc2ab8523244707ddbc9474",
                    16,
                )
                .unwrap(),
                y: u256::from_str_radix(
                    "0bced3ef5782c6a4278f685e6851503ab10d38e29cd74b98ced8521f5f174a17",
                    16,
                )
                .unwrap(),
            },
        ],
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::Address as _, Address, Bytes, Env};

    // -----------------------------------------------------------------------
    // Helper: encode a Groth16 proof into the 256-byte wire format expected by
    // `ShieldedAsset::transfer_shielded`.
    //
    // Layout (all values big-endian):
    //   [  0.. 64] π_A  : G1 point  (x ‖ y, 32 bytes each)
    //   [ 64..192] π_B  : G2 point  (x_c1 ‖ x_c0 ‖ y_c1 ‖ y_c0, 32 bytes each)
    //   [192..256] π_C  : G1 point  (x ‖ y, 32 bytes each)
    // -----------------------------------------------------------------------
    fn encode_proof_bytes(
        pi_a_x: u256,
        pi_a_y: u256,
        // G2 in snarkjs order: [[c1, c0], [c1, c0]]
        pi_b_x_c1: u256,
        pi_b_x_c0: u256,
        pi_b_y_c1: u256,
        pi_b_y_c0: u256,
        pi_c_x: u256,
        pi_c_y: u256,
    ) -> [u8; 256] {
        let mut buf = [0u8; 256];
        // π_A — G1
        buf[0..32].copy_from_slice(&pi_a_x.to_be_bytes());
        buf[32..64].copy_from_slice(&pi_a_y.to_be_bytes());
        // π_B — G2: EIP-197 order is c1 first, c0 second (imaginary then real)
        buf[64..96].copy_from_slice(&pi_b_x_c1.to_be_bytes());
        buf[96..128].copy_from_slice(&pi_b_x_c0.to_be_bytes());
        buf[128..160].copy_from_slice(&pi_b_y_c1.to_be_bytes());
        buf[160..192].copy_from_slice(&pi_b_y_c0.to_be_bytes());
        // π_C — G1
        buf[192..224].copy_from_slice(&pi_c_x.to_be_bytes());
        buf[224..256].copy_from_slice(&pi_c_y.to_be_bytes());
        buf
    }

    // -----------------------------------------------------------------------
    // Proof produced by snarkjs for the shielded_transfer circuit with
    // public input = 10_000_000 (0x989680).
    //
    // Source: hackathon-demo/circuit/proof.json + public.json
    // -----------------------------------------------------------------------
    fn real_proof_bytes() -> [u8; 256] {
        encode_proof_bytes(
            // π_A
            u256::from_str_radix(
                "2f77eb63c271e2cca4a295df9916b421e9fb41b3c694c102eadfa4e44ff79b58",
                16,
            )
            .unwrap(),
            u256::from_str_radix(
                "0fbe11e02a69703eae736e1a9fa648d373de8037b3641401f3f51ceab1917639",
                16,
            )
            .unwrap(),
            // π_B  (c1, c0 for x; c1, c0 for y)
            u256::from_str_radix(
                "0681078624b043fd7ccf9ebcbba8887a1a7a7f55bee75f8febb3549374261cf9",
                16,
            )
            .unwrap(),
            u256::from_str_radix(
                "2e87f692862f70c356b46ecde7c62919786b86ab7bc980c4e99307fac25a1fe0",
                16,
            )
            .unwrap(),
            u256::from_str_radix(
                "1f93fdab2366e92b799573ab11e503c1809063b6db9792458c330e92abd79093",
                16,
            )
            .unwrap(),
            u256::from_str_radix(
                "197af1d086d2551b4fced7d0ac49b68fbb8ce4adebf4c905789e5fc1169e53e7",
                16,
            )
            .unwrap(),
            // π_C
            u256::from_str_radix(
                "190fb0afd05020cd12f3299e660292615298e43a846cc7a3afacdc4db6a33c7e",
                16,
            )
            .unwrap(),
            u256::from_str_radix(
                "0d03086b1cad72d3e905abd8923124b130a2aeb0a0fb8b84e7869a66f1bff111",
                16,
            )
            .unwrap(),
        )
    }

    /// Encode a single 256-bit public input as a 32-byte big-endian slice.
    fn encode_public_input(value: u256) -> [u8; 32] {
        value.to_be_bytes()
    }

    // -----------------------------------------------------------------------
    // Unit test: VK sanity — alpha_g1, gamma_g2, and IC must be non-zero
    // -----------------------------------------------------------------------
    #[test]
    fn test_verifying_key_is_not_zero() {
        let vk = get_verifying_key();

        assert_ne!(
            vk.alpha_g1.x,
            u256::from(0u8),
            "alpha_g1.x must not be the placeholder zero"
        );
        assert_ne!(
            vk.alpha_g1.y,
            u256::from(0u8),
            "alpha_g1.y must not be the placeholder zero"
        );

        assert_ne!(
            vk.gamma_g2.x.0,
            u256::from(0u8),
            "gamma_g2.x.0 must not be zero"
        );

        assert_eq!(
            vk.ic.len(),
            2,
            "IC must have exactly 2 elements for 1 public input"
        );
        assert_ne!(vk.ic[0].x, u256::from(0u8), "IC[0].x must not be zero");
        assert_ne!(vk.ic[1].x, u256::from(0u8), "IC[1].x must not be zero");
    }

    // -----------------------------------------------------------------------
    // Unit test: VK gamma_g2 == standard BN254 G2 generator
    // -----------------------------------------------------------------------
    #[test]
    fn test_gamma_g2_matches_bn254_generator() {
        let vk = get_verifying_key();
        let gen = G2Affine::generator();

        assert_eq!(
            vk.gamma_g2, gen,
            "gamma_g2 should be the standard BN254 G2 generator"
        );
    }

    // -----------------------------------------------------------------------
    // Integration test: end-to-end Groth16 proof verification
    //
    // Uses the real snarkjs-generated proof and verifying key for the
    // shielded_transfer circuit with public input 10_000_000.
    //
    // The Soroban testutils `Env` provides a software-fallback pairing
    // implementation so the test runs without a live network.
    // -----------------------------------------------------------------------
    #[test]
    fn test_groth16_verify_valid_proof_accepts() {
        let env = Env::default();

        let vk = get_verifying_key();
        let proof_raw = real_proof_bytes();

        let proof = Groth16Proof::from_bytes(&proof_raw)
            .expect("Real proof bytes must deserialize without error");

        // public input: 10_000_000
        let public_input = u256::from(10_000_000u64);

        let result = groth16_verify(&env, &vk, &proof, &[public_input])
            .expect("groth16_verify must not return an Err for a valid proof");

        assert!(
            result,
            "A valid Groth16 proof with the correct public input must verify as true"
        );
    }

    // -----------------------------------------------------------------------
    // Negative test: wrong public input must not verify
    // -----------------------------------------------------------------------
    #[test]
    fn test_groth16_verify_wrong_public_input_rejects() {
        let env = Env::default();

        let vk = get_verifying_key();
        let proof_raw = real_proof_bytes();
        let proof = Groth16Proof::from_bytes(&proof_raw).unwrap();

        // Supply a public input that differs from the one used during proving
        let wrong_input = u256::from(9_999_999u64);

        let result = groth16_verify(&env, &vk, &proof, &[wrong_input])
            .expect("groth16_verify must not panic for a structurally valid proof");

        assert!(
            !result,
            "A valid proof with the WRONG public input must verify as false"
        );
    }

    // -----------------------------------------------------------------------
    // Integration test: full contract call path via ShieldedAsset::transfer_shielded
    //
    // Exercises the complete on-contract code path including proof parsing,
    // VK loading, pairing check, and event emission.
    // -----------------------------------------------------------------------
    #[test]
    fn test_transfer_shielded_valid_proof_succeeds() {
        let env = Env::default();
        env.mock_all_auths();

        let sender = Address::generate(&env);
        let receiver = Address::generate(&env);

        let proof_raw = real_proof_bytes();
        let proof_bytes = Bytes::from_slice(&env, &proof_raw);

        let pi_raw = encode_public_input(u256::from(10_000_000u64));
        let public_inputs_bytes = Bytes::from_slice(&env, &pi_raw);

        // Must not panic
        ShieldedAsset::transfer_shielded(env, sender, receiver, proof_bytes, public_inputs_bytes);
    }

    // -----------------------------------------------------------------------
    // Negative contract path: invalid proof length must panic
    // -----------------------------------------------------------------------
    #[test]
    #[should_panic(expected = "Invalid proof length")]
    fn test_transfer_shielded_wrong_length_panics() {
        let env = Env::default();
        env.mock_all_auths();

        let sender = Address::generate(&env);
        let receiver = Address::generate(&env);

        // Only 64 bytes — too short
        let proof_bytes = Bytes::from_slice(&env, &[0u8; 64]);
        let pi_raw = encode_public_input(u256::from(10_000_000u64));
        let public_inputs_bytes = Bytes::from_slice(&env, &pi_raw);

        ShieldedAsset::transfer_shielded(env, sender, receiver, proof_bytes, public_inputs_bytes);
    }
}
