//! Phase 4 — Fuzzing the SHA-256 parsing boundaries.
//!
//! The SHA-256 gadget accepts byte slices and field-element arrays as input.
//! This suite bombards those entry points with randomised, malformed, and
//! out-of-bounds inputs to guarantee they *never panic* and that invalid
//! inputs are always rejected via `Result` types rather than crashing the VM.

use proptest::prelude::*;
use sha2::{Digest, Sha256};
use soroban_sdk::{Env, U256};
use soroban_zk_std::gadgets::hash::sha256::{
    assert_sha256_fields, sha256, sha256_field, sha256_fields, MAX_MSG_BYTES,
};

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// The core `sha256` function must never panic on any byte input length
    /// up to the supported maximum (and slightly beyond to test boundary).
    #[test]
    fn fuzz_sha256_core_no_panic(bytes in prop::collection::vec(any::<u8>(), 0..8192)) {
        let _ = sha256(&bytes);
        prop_assert!(true); // If we reach here, no panic occurred
    }

    /// `sha256` must match the reference `sha2` crate on arbitrary input.
    #[test]
    fn fuzz_sha256_matches_reference(bytes in prop::collection::vec(any::<u8>(), 0..4096)) {
        let expected = Sha256::digest(&bytes);
        let got = sha256(&bytes);
        prop_assert_eq!(&got[..], &expected[..]);
    }

    /// Single-field-element hashing must never panic on any U256 value.
    #[test]
    fn fuzz_sha256_field_no_panic(x_bytes in any::<[u8; 32]>()) {
        let env = Env::default();
        env.cost_estimate().budget().reset_unlimited();
        let x = U256::from_be_bytes(&env, &soroban_sdk::Bytes::from_array(&env, &x_bytes));
        let _ = sha256_field(&env, x);
        prop_assert!(true);
    }

    /// Single-field-element hashing must match the reference implementation.
    #[test]
    fn fuzz_sha256_field_matches_reference(x_bytes in any::<[u8; 32]>()) {
        let env = Env::default();
        env.cost_estimate().budget().reset_unlimited();
        let x = U256::from_be_bytes(&env, &soroban_sdk::Bytes::from_array(&env, &x_bytes));
        let mut b = [0u8; 32];
        x.to_be_bytes().copy_into_slice(&mut b);
        let expected = Sha256::digest(b);
        let got = sha256_field(&env, x);
        let mut got_bytes = [0u8; 32];
        got.to_be_bytes().copy_into_slice(&mut got_bytes);
        prop_assert_eq!(&got_bytes[..], &expected[..]);
    }

    /// Multi-field hashing must never panic on any array of U256 values
    /// (including empty array, single element, and many elements).
    #[test]
    fn fuzz_sha256_fields_no_panic(
        fields_bytes in prop::collection::vec(any::<[u8; 32]>(), 0..128)
    ) {
        let env = Env::default();
        env.cost_estimate().budget().reset_unlimited();
        let fields: Vec<U256> = fields_bytes.iter().map(|b| {
            U256::from_be_bytes(&env, &soroban_sdk::Bytes::from_array(&env, b))
        }).collect();
        let _ = sha256_fields(&env, &fields);
        prop_assert!(true);
    }

    /// Multi-field hashing must return Err for inputs exceeding MAX_MSG_BYTES.
    #[test]
    fn fuzz_sha256_fields_rejects_oversized(
        fields_bytes in prop::collection::vec(any::<[u8; 32]>(), 65..128)
    ) {
        let env = Env::default();
        env.cost_estimate().budget().reset_unlimited();
        let fields: Vec<U256> = fields_bytes.iter().map(|b| {
            U256::from_be_bytes(&env, &soroban_sdk::Bytes::from_array(&env, b))
        }).collect();
        let result = sha256_fields(&env, &fields);
        // 65 * 32 = 2080 > 2048 = MAX_MSG_BYTES
        prop_assert!(result.is_err());
    }

    /// Multi-field hashing must match the reference when within bounds.
    #[test]
    fn fuzz_sha256_fields_matches_reference(
        fields_bytes in prop::collection::vec(any::<[u8; 32]>(), 0..64)
    ) {
        let env = Env::default();
        env.cost_estimate().budget().reset_unlimited();
        let fields: Vec<U256> = fields_bytes.iter().map(|b| {
            U256::from_be_bytes(&env, &soroban_sdk::Bytes::from_array(&env, b))
        }).collect();

        // Build reference bytes
        let mut ref_bytes = Vec::new();
        for b in &fields_bytes {
            ref_bytes.extend_from_slice(b);
        }
        let expected = Sha256::digest(&ref_bytes);

        let got = sha256_fields(&env, &fields);
        prop_assert!(got.is_ok());
        let mut got_bytes = [0u8; 32];
        got.unwrap().to_be_bytes().copy_into_slice(&mut got_bytes);
        prop_assert_eq!(&got_bytes[..], &expected[..]);
    }

    /// Assert function must never panic and correctly validates digests.
    #[test]
    fn fuzz_assert_sha256_fields_no_panic(
        fields_bytes in prop::collection::vec(any::<[u8; 32]>(), 0..64),
        claimed_bytes in any::<[u8; 32]>()
    ) {
        let env = Env::default();
        env.cost_estimate().budget().reset_unlimited();
        let fields: Vec<U256> = fields_bytes.iter().map(|b| {
            U256::from_be_bytes(&env, &soroban_sdk::Bytes::from_array(&env, b))
        }).collect();
        let claimed = U256::from_be_bytes(&env, &soroban_sdk::Bytes::from_array(&env, &claimed_bytes));
        let _ = assert_sha256_fields(&env, &fields, &claimed);
        prop_assert!(true);
    }

    /// Assert function correctly accepts valid digests and rejects invalid ones.
    #[test]
    fn fuzz_assert_sha256_fields_correctness(
        fields_bytes in prop::collection::vec(any::<[u8; 32]>(), 0..64)
    ) {
        let env = Env::default();
        env.cost_estimate().budget().reset_unlimited();
        let fields: Vec<U256> = fields_bytes.iter().map(|b| {
            U256::from_be_bytes(&env, &soroban_sdk::Bytes::from_array(&env, b))
        }).collect();

        // Build reference bytes
        let mut ref_bytes = Vec::new();
        for b in &fields_bytes {
            ref_bytes.extend_from_slice(b);
        }
        let expected: [u8; 32] = Sha256::digest(&ref_bytes).into();
        let correct_digest = U256::from_be_bytes(&env, &soroban_sdk::Bytes::from_array(&env, &expected));

        // Correct digest should be accepted
        let result_ok = assert_sha256_fields(&env, &fields, &correct_digest);
        prop_assert!(result_ok.is_ok());

        // Incorrect digest should be rejected
        let wrong_bytes: [u8; 32] = [0xFF; 32];
        let wrong_digest = U256::from_be_bytes(&env, &soroban_sdk::Bytes::from_array(&env, &wrong_bytes));
        let result_err = assert_sha256_fields(&env, &fields, &wrong_digest);
        prop_assert_eq!(result_err, Err(soroban_zk_core::ZkError::ConstraintUnsatisfied));
    }

    /// Field-to-bytes conversion must never panic on any U256
    #[test]
    fn fuzz_field_to_bytes_no_panic(x_bytes in any::<[u8; 32]>()) {
        let env = Env::default();
        let x = U256::from_be_bytes(&env, &soroban_sdk::Bytes::from_array(&env, &x_bytes));
        let bytes = soroban_zk_std::gadgets::hash::sha256::field_to_bytes(&env, &x);
        prop_assert_eq!(bytes.len(), 32);
    }
}

/// Empty input edge case
#[test]
fn fuzz_sha256_empty_input() {
    let result = sha256(&[]);
    let expected = Sha256::digest([]);
    assert_eq!(&result[..], &expected[..]);
}

/// Input exactly at MAX_MSG_BYTES boundary
#[test]
fn fuzz_sha256_max_msg_bytes_boundary() {
    let data = vec![0xAAu8; MAX_MSG_BYTES];
    let _ = sha256(&data);
}

/// Input one byte over MAX_MSG_BYTES (should still not panic, just process)
#[test]
fn fuzz_sha256_over_max_msg_bytes() {
    let data = vec![0xAAu8; MAX_MSG_BYTES + 1];
    let _ = sha256(&data);
}
