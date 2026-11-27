// SPDX-License-Identifier: Apache-2.0
#![no_main]

use libfuzzer_sys::fuzz_target;
use soroban_zk_core::ZkError;
use soroban_zk_fuzz::decode_xdr;

// Fuzz XDR-style decoding of fixed-width field/point records.
//
// The walker accepts concatenated G1 (64-byte), G2 (128-byte) and Fr
// (32-byte) records. It must never panic: a partial record or a word that is
// not a valid field element returns a clean `Err`.
fuzz_target!(|data: &[u8]| {
    match decode_xdr(data) {
        Ok(decoded) => assert!(decoded > 0),
        Err(error) => assert_eq!(error, ZkError::DeserializationError),
    }
});
