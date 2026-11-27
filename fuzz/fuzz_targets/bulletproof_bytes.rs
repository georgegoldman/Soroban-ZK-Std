// SPDX-License-Identifier: Apache-2.0
#![no_main]

use libfuzzer_sys::fuzz_target;
use soroban_zk_core::ZkError;
use soroban_zk_fuzz::{decode_bulletproof, BULLETPROOF_LEN};

// Fuzz the fixed 64-bit Bulletproof wire format (17 G1 points + 5 Fr scalars).
//
// The target asserts the parser never panics and that malformed lengths or
// out-of-field/off-curve records are rejected with `Err`.
fuzz_target!(|data: &[u8]| {
    match decode_bulletproof(data) {
        Ok(_) => assert_eq!(data.len(), BULLETPROOF_LEN),
        Err(error) => assert_eq!(error, ZkError::DeserializationError),
    }
});
