// SPDX-License-Identifier: Apache-2.0
#![no_main]

use libfuzzer_sys::fuzz_target;
use soroban_zk_core::ZkError;
use soroban_zk_fuzz::{decode_plonk_proof, PLONK_PROOF_LEN};

// Fuzz the fixed PLONK proof wire format (9 G1 commitments + 8 Fr scalars).
//
// The target asserts the parser never panics and that malformed lengths or
// out-of-field/off-curve records are rejected with `Err`.
fuzz_target!(|data: &[u8]| {
    match decode_plonk_proof(data) {
        Ok(_) => assert_eq!(data.len(), PLONK_PROOF_LEN),
        Err(error) => assert_eq!(error, ZkError::DeserializationError),
    }
});
