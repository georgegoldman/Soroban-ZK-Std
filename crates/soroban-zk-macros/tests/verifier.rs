//! Compile-pass + end-to-end tests for `include_snarkjs_vk!` and
//! `#[zk_verifier]` (Issue #567).
//!
//! The fixture `tests/fixtures/verification_key.json` is the SnarkJS
//! verifying key of the `contracts/shielded-asset-template` reference circuit
//! (one public input), and `PROOF_HEX` is a real proof for public input
//! `10_000_000` produced by the same circuit.

use ethnum::u256;
use soroban_sdk::testutils::Events as _;
use soroban_sdk::{contract, vec, BytesN, Env, U256};
use soroban_zk_std::{include_snarkjs_vk, zk_verifier, Groth16VerifyingKey, ZkContractError};

/// Compile-pass: the macro is usable in a `const` item (zero heap, no storage).
const VK: Groth16VerifyingKey<'static> =
    include_snarkjs_vk!("tests/fixtures/verification_key.json");

/// A real 256-byte proof `A || B || C` (G2 in EIP-197 `c1 || c0` wire order).
const PROOF_HEX: &str = "2f77eb63c271e2cca4a295df9916b421e9fb41b3c694c102eadfa4e44ff79b580fbe11e02a69703eae736e1a9fa648d373de8037b3641401f3f51ceab19176392e87f692862f70c356b46ecde7c62919786b86ab7bc980c4e99307fac25a1fe00681078624b043fd7ccf9ebcbba8887a1a7a7f55bee75f8febb3549374261cf9197af1d086d2551b4fced7d0ac49b68fbb8ce4adebf4c905789e5fc1169e53e71f93fdab2366e92b799573ab11e503c1809063b6db9792458c330e92abd79093190fb0afd05020cd12f3299e660292615298e43a846cc7a3afacdc4db6a33c7e0d03086b1cad72d3e905abd8923124b130a2aeb0a0fb8b84e7869a66f1bff111";
const PUBLIC_INPUT: u128 = 10_000_000;

fn proof_bytes(env: &Env) -> BytesN<256> {
    let mut out = [0u8; 256];
    for (i, byte) in out.iter_mut().enumerate() {
        let hex = &PROOF_HEX[2 * i..2 * i + 2];
        *byte = u8::from_str_radix(hex, 16).unwrap();
    }
    BytesN::from_array(env, &out)
}

fn hex_u256(s: &str) -> u256 {
    u256::from_str_radix(s, 16).unwrap()
}

#[contract]
pub struct ReplayProtectedVerifier;

#[zk_verifier(protocol = "groth16", vk = VK, anti_replay = true)]
impl ReplayProtectedVerifier {
    /// User-written methods in the block are kept alongside the generated ones.
    pub fn public_input_count() -> u32 {
        (VK.ic.len() - 1) as u32
    }
}

#[contract]
pub struct PlainVerifier;

#[zk_verifier(protocol = "groth16", vk = VK, method = "check")]
impl PlainVerifier {}

#[test]
fn snarkjs_vk_matches_reference_constants() {
    // alpha / IC are copied verbatim; G2 keeps SnarkJS [c0, c1] as (c0, c1).
    assert_eq!(
        VK.alpha_g1.x,
        hex_u256("06052c6ae90b77a962b3b355cf88cff3f084dfb2a423bd020222acd3e477a214")
    );
    assert_eq!(VK.gamma_g2, soroban_zk_std::G2Affine::generator());
    assert_eq!(
        VK.beta_g2.x,
        (
            hex_u256("1d639914164bbf9f91fe66713fc79afd3d2bf21206b2ac265b3fa94075852760"),
            hex_u256("1535f84fa5582f2f37628109bc1441ad4911d9d9b22294516260d7e9a9659b38"),
        )
    );
    assert_eq!(VK.ic.len(), 2);
    assert_eq!(
        VK.ic[1].x,
        hex_u256("0ea2aee8ab2a7ccd129e35144e1f291401ef18d20cc2ab8523244707ddbc9474")
    );
}

#[test]
fn snarkjs_vk_round_trips_through_vk_bytes() {
    // The embedded key must survive the crate's own validating codec.
    let env = Env::default();
    let bytes = soroban_zk_std::vk_to_bytes(&env, &VK);
    let owned = soroban_zk_std::vk_from_bytes(&env, &bytes).unwrap();
    assert_eq!(owned.as_vk().ic, VK.ic);
}

#[test]
fn valid_proof_verifies_end_to_end_and_emits_event() {
    let env = Env::default();
    let id = env.register(ReplayProtectedVerifier, ());
    let client = ReplayProtectedVerifierClient::new(&env, &id);
    let proof = proof_bytes(&env);
    let inputs = vec![&env, U256::from_u128(&env, PUBLIC_INPUT)];

    assert_eq!(client.public_input_count(), 1);
    assert!(!client.is_proof_spent(&proof, &inputs));
    assert!(client.verify_proof(&proof, &inputs));
    assert!(!env.events().all().events().is_empty());
    assert!(client.is_proof_spent(&proof, &inputs));
}

#[test]
fn replayed_proof_is_rejected() {
    let env = Env::default();
    let id = env.register(ReplayProtectedVerifier, ());
    let client = ReplayProtectedVerifierClient::new(&env, &id);
    let proof = proof_bytes(&env);
    let inputs = vec![&env, U256::from_u128(&env, PUBLIC_INPUT)];

    assert!(client.verify_proof(&proof, &inputs));
    assert_eq!(
        client.try_verify_proof(&proof, &inputs),
        Err(Ok(ZkContractError::ReplayDetected))
    );
}

#[test]
fn wrong_public_input_fails_pairing() {
    let env = Env::default();
    let id = env.register(PlainVerifier, ());
    let client = PlainVerifierClient::new(&env, &id);
    let proof = proof_bytes(&env);

    let wrong = vec![&env, U256::from_u128(&env, PUBLIC_INPUT + 1)];
    assert!(!client.check(&proof, &wrong));
    // Without anti-replay the same valid proof may be checked repeatedly.
    let right = vec![&env, U256::from_u128(&env, PUBLIC_INPUT)];
    assert!(client.check(&proof, &right));
    assert!(client.check(&proof, &right));
}

#[test]
fn malformed_calls_return_typed_errors() {
    let env = Env::default();
    let id = env.register(PlainVerifier, ());
    let client = PlainVerifierClient::new(&env, &id);
    let proof = proof_bytes(&env);

    // Wrong number of public inputs.
    assert_eq!(
        client.try_check(&proof, &vec![&env]),
        Err(Ok(ZkContractError::InvalidInput))
    );

    // Public input >= the BN254 scalar modulus r.
    let r = U256::from_parts(
        &env,
        0x30644e72e131a029,
        0xb85045b68181585d,
        0x2833e84879b97091,
        0x43e1f593f0000001,
    );
    assert_eq!(
        client.try_check(&proof, &vec![&env, r]),
        Err(Ok(ZkContractError::InvalidFieldElement))
    );

    // Proof whose A point is off-curve.
    let mut raw = proof.to_array();
    raw[63] ^= 1;
    assert_eq!(
        client.try_check(
            &BytesN::from_array(&env, &raw),
            &vec![&env, U256::from_u128(&env, 1)]
        ),
        Err(Ok(ZkContractError::DeserializationError))
    );
}
