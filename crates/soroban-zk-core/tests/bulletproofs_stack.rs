//! Issue #541 — Stack frame audit and 64 KB stack-limit verification for
//! Bulletproofs 64-bit range-proof verification (`msm_bucket`, `ipa_fold`,
//! `verify`).
//!
//! Soroban's WASM runtime enforces a strict 64 KB (65,536-byte) call stack
//! limit. This test verifies:
//! 1. The stack-allocated bucket array `[G1Projective; 16]` in `msm_bucket`
//!    and the folding arrays in `ipa_fold` match their audited byte sizes.
//! 2. Running `bulletproofs::verify` on a full 64-bit range proof (including
//!    `v = u64::MAX`) completes cleanly inside a 64 KB stack without overflow.

use core::mem::size_of;
use ethnum::u256;
use soroban_zk_core::bulletproofs::{self, Generators, RangeProof};
use soroban_zk_core::{G1Affine, G1Projective};

/// Soroban WASM runtime maximum call stack size (64 KB).
const SOROBAN_WASM_STACK_LIMIT_BYTES: usize = 64 * 1024;

/// Number of buckets in `msm_bucket` (`1 << MSM_WINDOW` where `MSM_WINDOW = 4`).
const MSM_BUCKETS: usize = 16;

/// Bit-length of a full 64-bit range proof.
const N: usize = 64;

#[test]
fn bulletproofs_type_stack_sizes_within_budget() {
    assert_eq!(size_of::<u256>(), 32);
    assert_eq!(size_of::<G1Affine>(), 64);
    assert_eq!(size_of::<G1Projective>(), 96);

    // `msm_bucket` stack allocation: `let mut buckets = [G1Projective::identity(); MSM_BUCKETS];`
    let buckets_bytes = size_of::<[G1Projective; MSM_BUCKETS]>();
    assert_eq!(buckets_bytes, 1536);
    assert!(buckets_bytes < SOROBAN_WASM_STACK_LIMIT_BYTES);

    // `ipa_fold` by-value generator arrays (`g0`, `h0`) + `(g_scalars, h_scalars)`
    let gen_array_bytes = size_of::<[G1Affine; N]>();
    let scalar_array_bytes = size_of::<[u256; N]>();
    assert_eq!(gen_array_bytes, 4096);
    assert_eq!(scalar_array_bytes, 2048);

    // Combined dominant allocations across `compute_residual` -> `ipa_fold` -> `msm_bucket`:
    //   compute_residual: h_tilde (4096 B)
    //   ipa_fold:         g0 (4096 B) + h0 (4096 B) + g_scalars (2048 B) + h_scalars (2048 B)
    //   msm_bucket:       buckets (1536 B)
    let dominant_bytes = gen_array_bytes * 3 + scalar_array_bytes * 2 + buckets_bytes;
    assert_eq!(dominant_bytes, 17_920);
    assert!(dominant_bytes < SOROBAN_WASM_STACK_LIMIT_BYTES);
}

#[test]
fn verify_full_64bit_range_proof_within_64kb_stack() {
    let gens = Generators::new();
    let v = u256::from(u64::MAX);
    let gamma = u256::from(42u8);
    let randomness = [7u8; 64];

    let proof: RangeProof = bulletproofs::prove(&gens, v, gamma, &randomness)
        .expect("prove must succeed for full 64-bit value u64::MAX");

    // Execute verification on a thread capped at Soroban's 64 KB stack limit.
    let ok = std::thread::scope(|s| {
        let handle = std::thread::Builder::new()
            .name("soroban-64kb-stack-verify".into())
            .stack_size(SOROBAN_WASM_STACK_LIMIT_BYTES)
            .spawn_scoped(s, || bulletproofs::verify(&gens, &proof))
            .expect("failed to spawn 64 KB stack thread");
        handle
            .join()
            .expect("verify_proof panicked or overflowed 64 KB stack")
    });

    assert!(ok, "full 64-bit range proof must verify");
}
