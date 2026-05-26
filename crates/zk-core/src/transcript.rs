//! Fiat-Shamir transcript for non-interactive ZK proofs.
//!
//! Derives verifier challenges deterministically from a running hash of
//! all prover messages. Uses a simple sponge-compatible state based on
//! sequential field-element absorption.
//!
//! In the Soroban environment the actual permutation is delegated to the
//! CAP-0075 host call via `zk-soroban::poseidon2`. This crate-level
//! transcript provides the *no_std* state machine and byte-to-field
//! conversion helpers that work without the Soroban SDK.
//!
//! Spec: docs/math/fiat_shamir.md

use crate::{Bn254, ZkError, G1Affine};
use ethnum::u256;

/// Maximum number of absorbed field elements before the transcript must be
/// squeezed. Kept small to avoid stack pressure in WASM.
const MAX_PENDING: usize = 32;

/// A Fiat-Shamir transcript state machine.
///
/// Absorbs commitments (G1 points, field elements, byte labels) and
/// produces pseudorandom challenges in Fr.
///
/// The internal state is a running hash accumulated via a simple
/// Merkle-Damgård-style compression using BN254 field arithmetic.
/// For production use, replace `compress` with the Poseidon2 host call.
#[derive(Debug, Clone)]
pub struct Transcript {
    /// Running state (single Fr element).
    state: u256,
    /// Pending elements waiting to be compressed.
    pending: [u256; MAX_PENDING],
    pending_len: usize,
}

impl Transcript {
    /// Create a new transcript with a domain separator.
    ///
    /// The domain separator is hashed into the initial state to prevent
    /// cross-protocol attacks.
    pub fn new(domain: &[u8]) -> Self {
        let mut t = Self {
            state: u256::from_words(0, 0),
            pending: [u256::from_words(0, 0); MAX_PENDING],
            pending_len: 0,
        };
        // Absorb domain separator bytes as a field element
        let dom_fe = bytes_to_field(domain);
        t.absorb_scalar(dom_fe);
        t
    }

    /// Absorb a G1 affine point into the transcript.
    pub fn absorb_point(&mut self, label: &[u8], point: &G1Affine) {
        let label_fe = bytes_to_field(label);
        self.absorb_scalar(label_fe);
        self.absorb_scalar(point.x);
        self.absorb_scalar(point.y);
    }

    /// Absorb a scalar field element into the transcript.
    pub fn absorb_scalar(&mut self, val: u256) {
        if self.pending_len == MAX_PENDING {
            self.compress();
        }
        self.pending[self.pending_len] = val;
        self.pending_len += 1;
    }

    /// Absorb raw bytes (e.g. a label or serialized value).
    pub fn absorb_bytes(&mut self, label: &[u8], data: &[u8]) {
        self.absorb_scalar(bytes_to_field(label));
        // Process data in 31-byte chunks to stay within Fr
        let mut i = 0;
        while i < data.len() {
            let end = (i + 31).min(data.len());
            let fe = bytes_to_field(&data[i..end]);
            self.absorb_scalar(fe);
            i += 31;
        }
    }

    /// Squeeze a challenge scalar in Fr.
    pub fn challenge(&mut self, label: &[u8]) -> u256 {
        self.absorb_scalar(bytes_to_field(label));
        self.compress();
        // Reduce state into Fr
        let r = Bn254::FR_MODULUS;
        if self.state >= r {
            self.state.wrapping_sub(r)
        } else {
            self.state
        }
    }

    /// Squeeze multiple challenges at once.
    pub fn challenges(&mut self, label: &[u8], n: usize) -> Result<[u256; 6], ZkError> {
        if n > 6 {
            return Err(ZkError::InvalidInput);
        }
        let mut out = [u256::from_words(0, 0); 6];
        for i in 0..n {
            // Each challenge gets a unique counter mixed in
            self.absorb_scalar(u256::from_words(0, i as u128));
            out[i] = self.challenge(label);
        }
        Ok(out)
    }

    // ── Internal ──────────────────────────────────────────────────────────

    /// Compress pending elements into the running state.
    ///
    /// Uses a simple sequential Poseidon-like compression:
    /// `state = Σ pending[i] * (i+1)  +  state * (pending_len+1)  mod r`
    ///
    /// In production this should be replaced with the Poseidon2 host call.
    fn compress(&mut self) {
        let mut acc = Bn254::mul(self.state, u256::from_words(0, (self.pending_len + 1) as u128));
        for (i, &fe) in self.pending[..self.pending_len].iter().enumerate() {
            let weight = u256::from_words(0, (i + 1) as u128);
            acc = Bn254::add(acc, Bn254::mul(fe, weight));
        }
        self.state = acc;
        self.pending_len = 0;
    }
}

/// Convert up to 31 bytes into a BN254 Fr element (big-endian, zero-padded).
///
/// Truncates to 31 bytes to guarantee the result is < r.
fn bytes_to_field(bytes: &[u8]) -> u256 {
    let mut buf = [0u8; 32];
    let src = if bytes.len() > 31 { &bytes[..31] } else { bytes };
    // Place bytes in the low end (big-endian)
    let offset = 32 - src.len();
    buf[offset..].copy_from_slice(src);
    let val = u256::from_be_bytes(buf);
    // Reduce mod r just in case
    if val >= Bn254::FR_MODULUS {
        val.wrapping_sub(Bn254::FR_MODULUS)
    } else {
        val
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn challenge_is_deterministic() {
        let mut t1 = Transcript::new(b"test-protocol");
        let mut t2 = Transcript::new(b"test-protocol");

        let c1 = t1.challenge(b"alpha");
        let c2 = t2.challenge(b"alpha");
        assert_eq!(c1, c2);
    }

    #[test]
    fn different_domains_give_different_challenges() {
        let mut t1 = Transcript::new(b"protocol-a");
        let mut t2 = Transcript::new(b"protocol-b");

        let c1 = t1.challenge(b"alpha");
        let c2 = t2.challenge(b"alpha");
        assert_ne!(c1, c2);
    }

    #[test]
    fn absorbing_different_points_gives_different_challenges() {
        let p1 = G1Affine {
            x: u256::from_words(0, 1),
            y: u256::from_words(0, 2),
        };
        let p2 = G1Affine {
            x: u256::from_words(0, 3),
            y: u256::from_words(0, 4),
        };

        let mut t1 = Transcript::new(b"proto");
        t1.absorb_point(b"A", &p1);
        let c1 = t1.challenge(b"beta");

        let mut t2 = Transcript::new(b"proto");
        t2.absorb_point(b"A", &p2);
        let c2 = t2.challenge(b"beta");

        assert_ne!(c1, c2);
    }

    #[test]
    fn challenge_is_in_field() {
        let mut t = Transcript::new(b"range-check");
        for _ in 0..10 {
            let c = t.challenge(b"x");
            assert!(c < Bn254::FR_MODULUS);
        }
    }

    #[test]
    fn sequential_challenges_differ() {
        let mut t = Transcript::new(b"plonk");
        let beta = t.challenge(b"beta");
        let gamma = t.challenge(b"gamma");
        let alpha = t.challenge(b"alpha");
        assert_ne!(beta, gamma);
        assert_ne!(gamma, alpha);
        assert_ne!(beta, alpha);
    }

    #[test]
    fn absorb_bytes_affects_challenge() {
        let mut t1 = Transcript::new(b"proto");
        t1.absorb_bytes(b"data", b"hello");
        let c1 = t1.challenge(b"x");

        let mut t2 = Transcript::new(b"proto");
        t2.absorb_bytes(b"data", b"world");
        let c2 = t2.challenge(b"x");

        assert_ne!(c1, c2);
    }
}
