// SPDX-License-Identifier: Apache-2.0
#![no_main]

use libfuzzer_sys::fuzz_target;
use soroban_zk_std::groth16::Groth16Proof;

// Fuzz the 256-byte Groth16 proof decoder (`A || B || C`).
//
// The decoder must never panic. Any input whose length is not exactly 256
// bytes must be rejected with a clean `Err`.
fuzz_target!(|data: &[u8]| {
    let result = Groth16Proof::from_bytes(data);
    if data.len() != 256 {
        assert!(result.is_err(), "non-256-byte proof must be rejected");
    }
});
