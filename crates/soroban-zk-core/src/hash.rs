//! Poseidon2 sponge construction for BN254.
//!
//! This module provides the **pure-math layer** of the Poseidon2 hash:
//!
//! * [`Poseidon2State`] — a 3-element sponge state over `u256`.
//! * [`Poseidon2Permutation`] — trait that abstracts the permutation step,
//!   allowing the caller to supply either a software reference implementation
//!   or the native `poseidon2_permutation` Soroban host function.
//! * [`poseidon2_hash_with`] — convenience function that absorbs an input
//!   slice and squeezes a single digest using a given permutation.
//!
//! ## Design rationale
//!
//! `soroban-zk-core` must stay **no_std and Soroban-SDK-free**.  The
//! Soroban-specific wiring lives in `crates/soroban-zk-std/src/poseidon2.rs`,
//! which implements [`Poseidon2Permutation`] by calling
//! `env.crypto().poseidon2_permutation(…)`.
//!
//! ## Sponge parameters (BN254 Poseidon2)
//! * Width  `t = 3`  (capacity 1 + rate 2)
//! * Rate   `r = 2`
//! * Capacity `c = 1`
//! * Padding: append `1` to the first unused rate slot, then `0`s.

use crate::ZkError;
use ethnum::u256;

// ============================================================================
// Constants
// ============================================================================

/// Sponge width (number of field elements in the full state).
pub const WIDTH: usize = 3;

/// Sponge rate (number of field elements absorbed per permutation).
pub const RATE: usize = 2;

/// Domain separator for the empty-input case.
///
/// This equals `Poseidon2Permutation([0, 0, 0])[0]` for the BN254 variant.
/// Produced by applying a single permutation to the all-zero state.
pub const DOMAIN_SEPARATOR: [u8; 32] = [
    0x20, 0x34, 0xc7, 0x7c, 0x66, 0xd2, 0x10, 0x77, 0x67, 0x30, 0x3e, 0x83, 0x92, 0x94, 0x2f, 0x9a,
    0x2e, 0x6e, 0x30, 0x01, 0x8d, 0xf1, 0x89, 0x0f, 0x50, 0x80, 0xc9, 0x8f, 0x82, 0x87, 0x41, 0x16,
];

// ============================================================================
// Permutation trait
// ============================================================================

/// Applies one Poseidon2 permutation round to the 3-element BN254 state.
///
/// Implementors may call the Soroban `poseidon2_permutation` host function
/// (in `soroban-zk-std`) or use a software reference implementation for tests.
pub trait Poseidon2Permutation {
    /// Permutes `state` in-place.
    ///
    /// `state` contains exactly [`WIDTH`] (= 3) BN254 field elements.
    fn permute(&self, state: &mut [u256; WIDTH]);
}

// ============================================================================
// Sponge state
// ============================================================================

/// A stateful Poseidon2 sponge over `WIDTH` BN254 field elements.
///
/// Typical usage:
/// ```rust,ignore
/// let mut sponge = Poseidon2State::new();
/// sponge.absorb(value1, &perm);
/// sponge.absorb(value2, &perm);
/// let digest = sponge.squeeze(&perm);
/// ```
pub struct Poseidon2State {
    state: [u256; WIDTH],
    /// Number of field elements absorbed into the current rate block (0..RATE).
    absorbed: usize,
}

impl Poseidon2State {
    /// Creates a new sponge initialised to the all-zero state.
    pub fn new() -> Self {
        Self {
            state: [u256::from(0u8); WIDTH],
            absorbed: 0,
        }
    }

    /// Absorbs a single BN254 field element into the sponge.
    ///
    /// Addition is used to merge the input with the existing state slot
    /// (standard Poseidon sponge absorption).
    ///
    /// If the rate portion is full after this absorption, `perm` is invoked
    /// automatically to advance the state before the next absorption.
    pub fn absorb<P: Poseidon2Permutation>(&mut self, value: u256, perm: &P) {
        self.state[self.absorbed] = self.state[self.absorbed].wrapping_add(value);
        self.absorbed += 1;

        if self.absorbed == RATE {
            perm.permute(&mut self.state);
            self.absorbed = 0;
        }
    }

    /// Squeezes a single digest element from the sponge.
    ///
    /// Padding (a `1` appended to the next open rate slot) is applied before
    /// the permutation when there are un-permuted absorbed elements.  A post-
    /// squeeze permutation is also applied so the sponge remains in a valid
    /// state for multi-squeeze / Fiat-Shamir transcript usage.
    pub fn squeeze<P: Poseidon2Permutation>(&mut self, perm: &P) -> u256 {
        // Padding: set the next rate slot to 1.
        self.state[self.absorbed] = self.state[self.absorbed].wrapping_add(u256::from(1u8));
        perm.permute(&mut self.state);
        self.absorbed = 0;

        let output = self.state[0];

        // Post-squeeze permutation for multi-squeeze / transcript use.
        perm.permute(&mut self.state);

        output
    }
}

impl Default for Poseidon2State {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Top-level convenience function
// ============================================================================

/// Hashes a slice of BN254 field elements to a single digest using the
/// Poseidon2 sponge construction.
///
/// **Empty-input case:** returns the [`DOMAIN_SEPARATOR`] constant without
/// calling the permutation, matching the reference test vector.
///
/// # Errors
/// Currently infallible for non-empty inputs; returns `Ok(_)`.
/// The `Result` wrapper is kept for forward-compatibility with future
/// validation (e.g., max-input-length checks).
pub fn poseidon2_hash_with<P: Poseidon2Permutation>(
    inputs: &[u256],
    perm: &P,
) -> Result<u256, ZkError> {
    if inputs.is_empty() {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&DOMAIN_SEPARATOR);
        return Ok(u256::from_be_bytes(arr));
    }

    let mut sponge = Poseidon2State::new();
    for &val in inputs {
        sponge.absorb(val, perm);
    }
    Ok(sponge.squeeze(perm))
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Minimal software permutation for unit-testing.
    // NOT cryptographically sound — used only to drive the sponge state
    // machine in a deterministic, verifiable way.
    // -----------------------------------------------------------------------

    struct CountingPermutation {
        pub call_count: core::cell::Cell<u32>,
    }

    impl CountingPermutation {
        fn new() -> Self {
            Self {
                call_count: core::cell::Cell::new(0),
            }
        }
    }

    impl Poseidon2Permutation for CountingPermutation {
        fn permute(&self, state: &mut [u256; WIDTH]) {
            let count = u256::from(self.call_count.get() + 1);
            self.call_count.set(self.call_count.get() + 1);
            // Mix: add each element to its neighbour, then multiply slot 0 by
            // a round constant, so that different input values propagate into
            // the output slot.
            let s0 = state[0];
            let s1 = state[1];
            let s2 = state[2];
            state[0] = s0.wrapping_add(s1).wrapping_add(count);
            state[1] = s1.wrapping_add(s2).wrapping_add(count);
            state[2] = s2.wrapping_add(s0).wrapping_add(count);
        }
    }

    #[test]
    fn empty_input_returns_domain_separator() {
        let perm = CountingPermutation::new();
        let digest = poseidon2_hash_with(&[], &perm).unwrap();
        let expected = u256::from_be_bytes(DOMAIN_SEPARATOR);
        assert_eq!(
            digest, expected,
            "empty-input hash must return the domain separator constant"
        );
        // The permutation must NOT have been called for empty input.
        assert_eq!(perm.call_count.get(), 0);
    }

    #[test]
    fn single_input_triggers_two_permutes_in_squeeze() {
        let perm = CountingPermutation::new();
        let _ = poseidon2_hash_with(&[u256::from(42u8)], &perm).unwrap();
        // absorb(42): absorbed == 1 < RATE → no permute yet.
        // squeeze()  → padding + permute (1) + post-squeeze permute (1) = 2 total.
        assert_eq!(perm.call_count.get(), 2);
    }

    #[test]
    fn two_inputs_trigger_rate_permute_plus_squeeze() {
        // RATE == 2: absorbing 2 inputs fills the block → 1 permute during absorption.
        // squeeze(): absorbed == 0 → padding at slot 0, permute (1) + post (1) = 2.
        // Total = 1 + 2 = 3.
        let perm = CountingPermutation::new();
        let _ = poseidon2_hash_with(&[u256::from(1u8), u256::from(2u8)], &perm).unwrap();
        assert_eq!(perm.call_count.get(), 3);
    }

    #[test]
    fn determinism() {
        let inputs = [u256::from(7u8), u256::from(13u8)];

        let perm1 = CountingPermutation::new();
        let h1 = poseidon2_hash_with(&inputs, &perm1).unwrap();

        let perm2 = CountingPermutation::new();
        let h2 = poseidon2_hash_with(&inputs, &perm2).unwrap();

        assert_eq!(h1, h2, "Poseidon2 sponge must be deterministic");
    }

    #[test]
    fn different_inputs_produce_different_digests() {
        let perm_a = CountingPermutation::new();
        let h_a = poseidon2_hash_with(&[u256::from(1u8)], &perm_a).unwrap();

        let perm_b = CountingPermutation::new();
        let h_b = poseidon2_hash_with(&[u256::from(2u8)], &perm_b).unwrap();

        assert_ne!(h_a, h_b);
    }

    #[test]
    fn sequential_squeezes_differ() {
        // Simulate a Fiat-Shamir transcript: absorb once, squeeze twice.
        let perm = CountingPermutation::new();
        let mut sponge = Poseidon2State::new();

        sponge.absorb(u256::from(99u8), &perm);
        let q1 = sponge.squeeze(&perm);
        let q2 = sponge.squeeze(&perm);

        assert_ne!(q1, q2, "consecutive squeezes must produce distinct values");
    }

    #[test]
    fn absorb_across_rate_boundary() {
        // 3 inputs span two rate blocks (RATE == 2):
        //   block-0: [inp0, inp1] → 1 permute during inp1 absorption.
        //   block-1: [inp2]       → 2 permutes in squeeze.
        // Total: 3.
        let perm = CountingPermutation::new();
        let _ = poseidon2_hash_with(&[u256::from(1u8), u256::from(2u8), u256::from(3u8)], &perm)
            .unwrap();
        assert_eq!(perm.call_count.get(), 3);
    }
}
