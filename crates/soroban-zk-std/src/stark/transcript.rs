//! Fiat-Shamir transcript over the native SHA-256 host binding (Issue #366).
//!
//! The transcript is the only source of "randomness" in a STARK verifier: every
//! FRI folding challenge and query is squeezed from a running SHA-256 state that
//! has absorbed all public data and commitments. Keeping the state as a plain
//! `[u8; 32]` means squeezing/absorption is allocation-free.

use soroban_sdk::{Bytes, BytesN, Env};

use crate::stark::field::Felt;

/// A SHA-256-running Fiat-Shamir transcript.
pub struct Transcript {
    state: [u8; 32],
}

impl Transcript {
    /// A fresh, zero-initialized transcript.
    pub fn new() -> Self {
        Transcript { state: [0u8; 32] }
    }

    /// Absorb raw bytes with explicit length-prefix framing: first absorbs
    /// `(data.len() as u64).to_be_bytes()` into the running state, then
    /// absorbs `state = SHA256(state ‖ chunk)` over 32-byte chunks.
    ///
    /// Prefixing the exact byte length guarantees that distinct byte slices
    /// (such as `[1]` vs `[1, 0]` or empty vs non-empty) never collide under
    /// fixed-width block absorption.
    /// Out-of-range reads cannot occur: the loop is bounded by `data.len()`.
    pub fn absorb(&mut self, env: &Env, data: &Bytes) {
        let mut running = self.state;
        let n = data.len();

        let mut len_buf = [0u8; 40];
        len_buf[..32].copy_from_slice(&running);
        len_buf[32..40].copy_from_slice(&(u64::from(n)).to_be_bytes());
        running = env
            .crypto()
            .sha256(&Bytes::from_array(env, &len_buf))
            .to_array();

        let mut off = 0u32;
        while off < n {
            let mut buf = [0u8; 64];
            buf[..32].copy_from_slice(&running);
            let mut k = 0usize;
            while k < 32 && off < n {
                // `off < n == data.len()`, so this never fails; `unwrap_or`
                // keeps the function panic-free regardless.
                buf[32 + k] = data.get(off).unwrap_or(0);
                k += 1;
                off += 1;
            }
            running = env
                .crypto()
                .sha256(&Bytes::from_array(env, &buf))
                .to_array();
        }
        self.state = running;
    }

    /// Absorb a single field element (its 8-byte encoding).
    pub fn absorb_felt(&mut self, env: &Env, f: Felt) {
        let b = f.to_bytes();
        self.absorb(env, &Bytes::from_array(env, &b));
    }

    /// Absorb a 32-byte digest (e.g. a Merkle root or commitment).
    pub fn absorb_digest(&mut self, env: &Env, d: &BytesN<32>) {
        self.absorb(env, &Bytes::from_array(env, &d.to_array()));
    }

    /// Squeeze a 32-byte digest and advance the transcript state.
    pub fn squeeze(&mut self, env: &Env) -> BytesN<32> {
        let out = env.crypto().sha256(&Bytes::from_array(env, &self.state));
        self.state = out.to_array();
        BytesN::from_array(env, &out.to_array())
    }

    /// Squeeze a field element challenge by reducing the first 8 bytes of the
    /// squeezed digest modulo the Goldilocks prime.
    pub fn squeeze_felt(&mut self, env: &Env) -> Felt {
        let h = self.squeeze(env).to_array();
        let mut b = [0u8; 8];
        b.copy_from_slice(&h[..8]);
        Felt::new(u64::from_be_bytes(b))
    }
}

impl Default for Transcript {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use soroban_sdk::Env;

    fn env() -> Env {
        let e = Env::default();
        e.cost_estimate().budget().reset_unlimited();
        e
    }

    #[test]
    fn squeeze_is_deterministic_and_input_sensitive() {
        let env = env();
        let mut t1 = Transcript::new();
        t1.absorb_felt(&env, Felt::new(7));
        let c1 = t1.squeeze_felt(&env);

        let mut t2 = Transcript::new();
        t2.absorb_felt(&env, Felt::new(7));
        let c2 = t2.squeeze_felt(&env);
        assert_eq!(c1, c2, "same input -> same challenge");

        let mut t3 = Transcript::new();
        t3.absorb_felt(&env, Felt::new(8)); // different
        let c3 = t3.squeeze_felt(&env);
        assert_ne!(c1, c3, "different input -> different challenge");
    }

    #[test]
    fn squeeze_advances_state() {
        let env = env();
        let mut t = Transcript::new();
        let a = t.squeeze(&env);
        let b = t.squeeze(&env);
        assert_ne!(a, b, "two squeezes must differ (state advances)");
    }

    #[test]
    fn absorb_handles_empty_and_long_inputs() {
        let env = env();
        let mut t = Transcript::new();
        let before = t.squeeze(&env);

        let mut t2 = Transcript::new();
        t2.absorb(&env, &Bytes::new(&env));
        assert_ne!(
            before,
            t2.squeeze(&env),
            "empty absorb is length-framed and advances state"
        );

        // Longer than one 32-byte chunk, and not a multiple of it.
        let mut long = [0u8; 77];
        for (i, b) in long.iter_mut().enumerate() {
            *b = i as u8;
        }
        let mut t3 = Transcript::new();
        t3.absorb(&env, &Bytes::from_slice(&env, &long));
        let mut t4 = Transcript::new();
        t4.absorb(&env, &Bytes::from_slice(&env, &long));
        assert_eq!(t3.squeeze_felt(&env), t4.squeeze_felt(&env));
    }

    #[test]
    fn absorb_distinct_lengths_do_not_collide() {
        let env = env();

        let mut t1 = Transcript::new();
        t1.absorb(&env, &Bytes::from_slice(&env, &[1u8]));

        let mut t2 = Transcript::new();
        t2.absorb(&env, &Bytes::from_slice(&env, &[1u8, 0u8]));

        assert_ne!(
            t1.squeeze(&env),
            t2.squeeze(&env),
            "[1u8] must not collide with [1u8, 0u8]"
        );

        let mut t3 = Transcript::new();
        t3.absorb(&env, &Bytes::from_slice(&env, &[]));

        let mut t4 = Transcript::new();
        t4.absorb(&env, &Bytes::from_slice(&env, &[0u8]));

        assert_ne!(
            t3.squeeze(&env),
            t4.squeeze(&env),
            "[] must not collide with [0u8]"
        );
    }
}
