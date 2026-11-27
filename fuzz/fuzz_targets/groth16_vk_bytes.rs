// SPDX-License-Identifier: Apache-2.0
#![no_main]

use libfuzzer_sys::fuzz_target;
use soroban_sdk::{Bytes, Env};
use soroban_zk_std::vk::vk_from_bytes;

// Fuzz the serialized Groth16 verifying-key decoder.
//
// Layout: `alpha_g1 (64) || beta_g2 (128) || gamma_g2 (128) || delta_g2 (128)
// || ic_len (4) || ic[0..] (64 each)`. Every point is re-validated, so a
// truncated or corrupted key must fail closed with a clean `Err` and never
// trigger a host trap.
fuzz_target!(|data: &[u8]| {
    let env = Env::default();
    let bytes = Bytes::from_slice(&env, data);
    let result = vk_from_bytes(&env, &bytes);
    if data.len() < 452 {
        assert!(result.is_err(), "short verifying key must be rejected");
    }
});
