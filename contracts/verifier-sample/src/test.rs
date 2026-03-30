#![cfg(test)]

use super::*;
use soroban_sdk::{Bytes, Env, U256};

#[test]
fn test_valid_scalar_below_modulus() {
    let env = Env::default();
    let contract_id = env.register(Verifier, ());
    let client = VerifierClient::new(&env, &contract_id);

    let val = U256::from_u128(&env, 42);
    assert!(client.check(&val));
}

#[test]
fn test_invalid_scalar_above_modulus() {
    let env = Env::default();
    let contract_id = env.register(Verifier, ());
    let client = VerifierClient::new(&env, &contract_id);

    // U256::MAX is way above BN254 modulus — must be rejected
    let bytes = Bytes::from_array(&env, &[0xff_u8; 32]);
    let val = U256::from_be_bytes(&env, &bytes);
    assert!(!client.check(&val));
}

#[test]
fn test_zero_is_valid_scalar() {
    let env = Env::default();
    let contract_id = env.register(Verifier, ());
    let client = VerifierClient::new(&env, &contract_id);

    let val = U256::from_u128(&env, 0);
    assert!(client.check(&val));
}

#[test]
fn test_modulus_itself_is_invalid() {
    let env = Env::default();
    let contract_id = env.register(Verifier, ());
    let client = VerifierClient::new(&env, &contract_id);

    // BN254 modulus exactly — must fail (valid range is 0..modulus-1)
    let modulus_bytes: [u8; 32] = [
        0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58,
        0x5d, 0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91, 0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00,
        0x00, 0x01,
    ];
    let bytes = Bytes::from_array(&env, &modulus_bytes);
    let val = U256::from_be_bytes(&env, &bytes);
    assert!(!client.check(&val));
}
