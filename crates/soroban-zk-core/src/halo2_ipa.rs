
//! Halo2-IPA recursive step tracking structs.
//!
//! The Inner Product Argument (IPA) used by Halo2 reduces a commitment
//! `P = <a, G> + <b, H>` over vectors of length `n` down to a single scalar
//! check in `log2(n)` rounds. Each round produces two cross-commitment points
//! `L_i` and `R_i`, derives a Fiat-Shamir challenge `u_i`, and folds both the
//! vector halves and generator halves by that challenge.
//!
//! This module provides the fixed-size, stack-only data structures that a
//! verifier needs to carry state across those rounds:
//!
//! * [`IpaRoundCommitments`] — the `(L, R)` pair emitted by the prover in one round.
//! * [`IpaRoundChallenge`] — the verifier's Fiat-Shamir scalar and its inverse.
//! * [`IpaRoundState`] — the complete folded state after one round (folded
//!   commitment, active vector length, and challenge history).
//! * [`IpaProof`] — the full prover transcript: all `(L_i, R_i)` pairs plus the
//!   final scalar pair `(a, b)`.
//! * [`IpaVerifierState`] — the mutable verifier accumulator walked across all
//!   `log2(n)` rounds, terminated by `finish`.
//! * [`IpaBatchVerifier`] — a batch verifier that folds multiple IPA proofs
//!   into a single randomized linear combination, reducing the number of
//!   elliptic-curve scalar multiplications required for verification.
//! * [`IpaBatchEntry`] — one proof's inputs to a batched verification.
//!
//! ## Const-generic layout
//!
//! Every structure is parameterised by `ROUNDS = log2(n)` so the compiler
//! can size all arrays at compile time. There are **zero heap allocations** and
//! no `Clone`/`Copy` bounds on anything beyond `u256` and `G1Affine`, keeping
//! WASM binary size minimal.
//!
//! ## Relationship to `bulletproofs`
//!
//! The `crate::bulletproofs` module implements a standalone Bulletproofs IPA
//! hardcoded to `n = 64`. This module is the *generic, reusable* IPA layer for
//! Halo2-style recursive verifiers where `n` (and therefore `ROUNDS`) varies.

use ethnum::u256;

use crate::{Bn254, G1Affine, ZkError};

// ---------------------------------------------------------------------------
// Per-round commitment pair
// ---------------------------------------------------------------------------

/// The two cross-commitment points the prover emits in a single IPA folding round.
///
/// In round `i` the prover computes:
/// ```text
/// L_i = <a_lo, G_hi> + <b_hi, H_lo> + c_L · U
/// R_i = <a_hi, G_lo> + <b_lo, H_hi> + c_R · U
/// ```
/// where `a_lo`/`a_hi` are the low/high halves of the current `a` vector, and
/// `U` is the inner-product base point derived from the verifier challenge `z`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpaRoundCommitments {
    /// Left cross-commitment `L_i`.
    pub l: G1Affine,
    /// Right cross-commitment `R_i`.
    pub r: G1Affine,
}

impl IpaRoundCommitments {
    /// Construct a commitment pair from the prover's `L` and `R` output.
    pub fn new(l: G1Affine, r: G1Affine) -> Self {
        Self { l, r }
    }
}

// ---------------------------------------------------------------------------
// Per-round Fiat-Shamir challenge
// ---------------------------------------------------------------------------

/// The Fiat-Shamir scalar derived from absorbing `(L_i, R_i)` into the
/// transcript, together with its precomputed inverse and square/inverse-square.
///
/// Caching `u_inv`, `u_sq`, and `u_sq_inv` avoids repeated field inversions on
/// the hot verification path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpaRoundChallenge {
    /// The challenge scalar `u_i ∈ Fr`.
    pub u: u256,
    /// `u_i^{-1} mod r`.
    pub u_inv: u256,
    /// `u_i^2 mod r` (used in the commitment folding equation).
    pub u_sq: u256,
    /// `u_i^{-2} mod r`.
    pub u_sq_inv: u256,
}

impl IpaRoundChallenge {
    /// Derive the full challenge struct from a raw scalar `u`.
    ///
    /// Returns `Err(ZkError::InvalidFieldElement)` if `u` is zero (non-invertible).
    pub fn from_scalar(u: u256) -> Result<Self, ZkError> {
        if u == u256::from(0u8) {
            return Err(ZkError::InvalidFieldElement);
        }
        let u_inv = Bn254::invert(u);
        let u_sq = Bn254::mul(u, u);
        let u_sq_inv = Bn254::mul(u_inv, u_inv);
        Ok(Self {
            u,
            u_inv,
            u_sq,
            u_sq_inv,
        })
    }
}

// ---------------------------------------------------------------------------
// Per-round verifier state
// ---------------------------------------------------------------------------

/// The verifier's running state *after* processing round `i`.
///
/// `ROUNDS` is the total number of folding rounds (`= log2(n)`). Only the
/// first `round_index` entries of `challenges` are populated; the rest are
/// zero-initialised and must not be read.
///
/// ### Folded commitment invariant
///
/// At the start of round 0, `folded_commitment` equals the original proof
/// commitment `P`. After round `i` it satisfies:
///
/// ```text
/// P' = u_i^2 · L_i  +  P  +  u_i^{-2} · R_i
/// ```
///
/// (additive form; all arithmetic is over the BN254 G1 group).
///
/// ### Active length
///
/// `active_len` tracks the current vector length, halved each round. It must
/// be a power of two and `> 0` for the state to be valid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpaRoundState<const ROUNDS: usize> {
    /// The running folded commitment `P'` after this round.
    pub folded_commitment: G1Affine,
    /// The number of remaining active elements (halved each round).
    pub active_len: usize,
    /// The current round index `i` (0-based). Equals the number of completed
    /// rounds; incremented by `IpaVerifierState::apply_round`.
    pub round_index: usize,
    /// The challenge history: `challenges[i]` was used in round `i`.
    /// Entries at index `>= round_index` are uninitialised / zero.
    pub challenges: [IpaRoundChallenge; ROUNDS],
}

impl<const ROUNDS: usize> IpaRoundState<ROUNDS> {
    /// Construct the *initial* round state before any folding has occurred.
    ///
    /// * `commitment` — the proof commitment `P` (e.g. the polynomial
    ///   commitment adjusted by the inner-product challenge).
    /// * `n` — the initial vector length; must be `1 << ROUNDS`.
    ///
    /// Returns `Err(ZkError::InvalidInput)` if `n != 1 << ROUNDS` or `ROUNDS == 0`.
    pub fn initial(commitment: G1Affine, n: usize) -> Result<Self, ZkError> {
        if ROUNDS == 0 || n != (1usize << ROUNDS) {
            return Err(ZkError::InvalidInput);
        }
        // Zero-initialise the challenge array using a known-safe sentinel.
        // We use `u256::from(1u8)` (the multiplicative identity) so that
        // un-applied rounds have trivially valid (but unused) challenges.
        let sentinel = IpaRoundChallenge {
            u: u256::from(1u8),
            u_inv: u256::from(1u8),
            u_sq: u256::from(1u8),
            u_sq_inv: u256::from(1u8),
        };
        Ok(Self {
            folded_commitment: commitment,
            active_len: n,
            round_index: 0,
            challenges: [sentinel; ROUNDS],
        })
    }

    /// Returns `true` if all `ROUNDS` folding steps have been applied.
    #[inline(always)]
    pub fn is_complete(&self) -> bool {
        self.round_index == ROUNDS
    }

    /// Returns `true` if `active_len` is a power of two, which is the
    /// invariant that must hold throughout the IPA reduction.
    #[inline(always)]
    pub fn active_len_is_valid(&self) -> bool {
        self.active_len > 0 && self.active_len.is_power_of_two()
    }
}

// ---------------------------------------------------------------------------
// Full IPA proof (prover transcript)
// ---------------------------------------------------------------------------

/// The complete Halo2-IPA prover transcript for a single polynomial commitment.
///
/// A proof for a vector of length `n = 1 << ROUNDS` consists of:
/// * `ROUNDS` pairs `(L_i, R_i)` of cross-commitments.
/// * A final scalar pair `(a, b)` such that the verifier can check
///   `a · b == inner_product` and `a · G' + b · H' == P_final`.
///
/// `ROUNDS` must equal `log2(n)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpaProof<const ROUNDS: usize> {
    /// The `(L_i, R_i)` pairs for rounds `0..ROUNDS`.
    pub round_commitments: [IpaRoundCommitments; ROUNDS],
    /// The prover's final scalar `a` (residual `a[0]` after all folds).
    pub a_final: u256,
    /// The prover's final scalar `b` (residual `b[0]` after all folds).
    pub b_final: u256,
}

impl<const ROUNDS: usize> IpaProof<ROUNDS> {
    /// Construct a proof from the prover's outputs. No field-range validation
    /// is performed here; call `validate` for pre-verification checking.
    pub fn new(
        round_commitments: [IpaRoundCommitments; ROUNDS],
        a_final: u256,
        b_final: u256,
    ) -> Self {
        Self {
            round_commitments,
            a_final,
            b_final,
        }
    }

    /// Light structural validation: check that `a_final` and `b_final` are
    /// valid BN254 scalar field elements (`< r`).
    ///
    /// Point coordinates in `round_commitments` are validated implicitly by
    /// the curve-point checks in the verifier loop.
    pub fn validate(&self) -> Result<(), ZkError> {
        if self.a_final >= Bn254::FR_MODULUS || self.b_final >= Bn254::FR_MODULUS {
            return Err(ZkError::InvalidFieldElement);
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// IPA verifier state machine
// ---------------------------------------------------------------------------

/// A stateful verifier accumulator that processes one IPA folding round at a
/// time, tracking the full challenge history for later multi-scalar checks.
///
/// ### Usage pattern
///
/// ```rust,ignore
/// // Initialise from the proof commitment and total vector length.
/// let mut vs = IpaVerifierState::<6>::new(commitment, 64)?;
///
/// // Apply each round (challenges come from your Fiat-Shamir transcript).
/// for i in 0..6 {
///     vs.apply_round(proof.round_commitments[i], challenge_i)?;
/// }
///
/// // Retrieve the final folded state for the scalar check.
/// let final_state = vs.finish()?;
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpaVerifierState<const ROUNDS: usize> {
    state: IpaRoundState<ROUNDS>,
}

impl<const ROUNDS: usize> IpaVerifierState<ROUNDS> {
    /// Initialise the verifier state from the initial proof commitment `P`
    /// and the vector length `n = 1 << ROUNDS`.
    ///
    /// Returns `Err(ZkError::InvalidInput)` if the dimensions are inconsistent.
    pub fn new(commitment: G1Affine, n: usize) -> Result<Self, ZkError> {
        Ok(Self {
            state: IpaRoundState::initial(commitment, n)?,
        })
    }

    /// Apply one folding round.
    ///
    /// The caller supplies:
    /// * `round_comms` — the prover's `(L_i, R_i)` for this round.
    /// * `challenge`   — the derived `IpaRoundChallenge` for this round (the
    ///   caller drives the Fiat-Shamir transcript and passes the result here).
    ///
    /// The commitment is updated as:
    /// ```text
    /// P' = u^2 · L  +  P  +  u^{-2} · R
    /// ```
    ///
    /// # Errors
    ///
    /// * `ZkError::InvalidInput` if all rounds have already been applied.
    pub fn apply_round(
        &mut self,
        round_comms: IpaRoundCommitments,
        challenge: IpaRoundChallenge,
    ) -> Result<(), ZkError> {
        if self.state.is_complete() {
            return Err(ZkError::InvalidInput);
        }

        // P' = u^2 · L + P + u^{-2} · R
        let scaled_l = round_comms.l.scalar_mul(challenge.u_sq);
        let scaled_r = round_comms.r.scalar_mul(challenge.u_sq_inv);
        let p_prime = self
            .state
            .folded_commitment
            .add(&scaled_l)
            .add(&scaled_r);

        // Record the challenge in the history before mutating `round_index`.
        let idx = self.state.round_index;
        self.state.challenges[idx] = challenge;

        // Update state for next round.
        self.state.folded_commitment = p_prime;
        self.state.active_len >>= 1;
        self.state.round_index += 1;

        Ok(())
    }

    /// Finalise the verifier state once all `ROUNDS` rounds have been applied.
    ///
    /// Returns the final [`IpaRoundState`] for the caller to run the terminal
    /// scalar check against the proof's `(a_final, b_final)` scalars:
    ///
    /// ```text
    /// assert  P_final == a_final · G' + b_final · H' + (a_final · b_final) · U
    /// ```
    ///
    /// # Errors
    ///
    /// * `ZkError::InvalidInput` if not all `ROUNDS` rounds have been applied yet.
    pub fn finish(self) -> Result<IpaRoundState<ROUNDS>, ZkError> {
        if !self.state.is_complete() {
            return Err(ZkError::InvalidInput);
        }
        Ok(self.state)
    }

    /// Read-only access to the current state without consuming the verifier.
    pub fn state(&self) -> &IpaRoundState<ROUNDS> {
        &self.state
    }
}

// ---------------------------------------------------------------------------
// Batched IPA verification
// ---------------------------------------------------------------------------

/// One proof's inputs to a batched IPA verification.
///
/// Each entry carries the initial commitment `P`, the prover transcript
/// `proof`, and the per-round Fiat-Shamir challenges derived by the caller
/// from the transcript. The challenges are supplied externally so the batch
/// verifier stays agnostic to the transcript hash function.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpaBatchEntry<const ROUNDS: usize> {
    /// The initial proof commitment `P` for this entry.
    pub commitment: G1Affine,
    /// The prover transcript for this entry.
    pub proof: IpaProof<ROUNDS>,
    /// The per-round Fiat-Shamir challenges for this entry, in round order.
    pub challenges: [IpaRoundChallenge; ROUNDS],
}

impl<const ROUNDS: usize> IpaBatchEntry<ROUNDS> {
    /// Construct a batch entry from its commitment, proof, and challenges.
    pub fn new(
        commitment: G1Affine,
        proof: IpaProof<ROUNDS>,
        challenges: [IpaRoundChallenge; ROUNDS],
    ) -> Self {
        Self {
            commitment,
            proof,
            challenges,
        }
    }
}

/// A batched IPA verifier that folds `N` independent IPA proofs into a single
/// randomized linear combination.
///
/// ### Batching strategy
///
/// Given `N` proofs, the verifier samples `N` random scalars `ρ_0..ρ_{N-1}`
/// (supplied by the caller, e.g. from a Fiat-Shamir transcript over all
/// commitments). It then forms the combined commitment
///
/// 
// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::G1Affine;
    use ethnum::u256;

    /// A trivially valid G1 point used as a stand-in in structural tests.
    /// (This is the BN254 generator G1 = (1, 2).)
    fn g1_gen() -> G1Affine {
        G1Affine {
            x: u256::from(1u8),
            y: u256::from(2u8),
        }
    }

    fn identity() -> G1Affine {
        G1Affine {
            x: u256::from(0u8),
            y: u256::from(0u8),
        }
    }

    // -----------------------------------------------------------------------
    // IpaRoundChallenge
    // -----------------------------------------------------------------------

    #[test]
    fn round_challenge_zero_is_rejected() {
        assert_eq!(
            IpaRoundChallenge::from_scalar(u256::from(0u8)),
            Err(ZkError::InvalidFieldElement)
        );
    }

    #[test]
    fn round_challenge_one_is_self_inverse() {
        let c = IpaRoundChallenge::from_scalar(u256::from(1u8)).unwrap();
        assert_eq!(c.u, u256::from(1u8));
        assert_eq!(c.u_inv, u256::from(1u8));
        assert_eq!(c.u_sq, u256::from(1u8));
        assert_eq!(c.u_sq_inv, u256::from(1u8));
    }

    #[test]
    fn round_challenge_inverse_product_is_one() {
        // u * u_inv == 1 (mod r)
        let u_raw = u256::from(7u8);
        let c = IpaRoundChallenge::from_scalar(u_raw).unwrap();
        assert_eq!(Bn254::mul(c.u, c.u_inv), u256::from(1u8));
        assert_eq!(Bn254::mul(c.u_sq, c.u_sq_inv), u256::from(1u8));
    }

    // -----------------------------------------------------------------------
    // IpaRoundState
    // -----------------------------------------------------------------------

    #[test]
    fn initial_state_dimensions_validated() {
        // n must equal 1 << ROUNDS
        assert!(IpaRoundState::<3>::initial(identity(), 8).is_ok());
        assert_eq!(
            IpaRoundState::<3>::initial(identity(), 7),
            Err(ZkError::InvalidInput)
        );
        assert_eq!(
            IpaRoundState::<3>::initial(identity(), 9),
            Err(ZkError::InvalidInput)
        );
    }

    #[test]
    fn initial_state_rounds_zero_is_invalid() {
        // ROUNDS == 0 is meaningless (n would have to be 1).
        assert_eq!(
            IpaRoundState::<0>::initial(identity(), 1),
            Err(ZkError::InvalidInput)
        );
    }

    #[test]
    fn initial_state_is_not_complete() {
        let s = IpaRoundState::<4>::initial(identity(), 16).unwrap();
        assert!(!s.is_complete());
        assert!(s.active_len_is_valid());
        assert_eq!(s.round_index, 0);
        assert_eq!(s.active_len, 16);
    }

    // -----------------------------------------------------------------------
    // IpaProof
    // -----------------------------------------------------------------------

    #[test]
    fn proof_validate_rejects_out_of_range_scalars() {
        let comms = [IpaRoundCommitments::new(identity(), identity()); 3];
        let bad_scalar = Bn254::FR_MODULUS; // exactly the modulus, not a valid field element

        let proof_bad_a = IpaProof::<3>::new(comms, bad_scalar, u256::from(1u8));
        assert_eq!(proof_bad_a.validate(), Err(ZkError::InvalidFieldElement));

        let proof_bad_b = IpaProof::<3>::new(comms, u256::from(1u8), bad_scalar);
        assert_eq!(proof_bad_b.validate(), Err(ZkError::InvalidFieldElement));

        let proof_ok = IpaProof::<3>::new(comms, u256::from(1u8), u256::from(2u8));
        assert!(proof_ok.validate().is_ok());
    }

    // -----------------------------------------------------------------------
    // IpaVerifierState
    // -----------------------------------------------------------------------

    #[test]
    fn verifier_state_dimension_mismatch_is_rejected() {
        // 3 rounds requires n == 8
        assert!(IpaVerifierState::<3>::new(identity(), 8).is_ok());
        assert_eq!(
            IpaVerifierState::<3>::new(identity(), 4),
            Err(ZkError::InvalidInput)
        );
    }

    #[test]
    fn finish_before_all_rounds_is_rejected() {
        let vs = IpaVerifierState::<2>::new(identity(), 4).unwrap();
        // No rounds applied yet → finish must fail.
        assert_eq!(vs.finish(), Err(ZkError::InvalidInput));
    }

    #[test]
    fn apply_round_beyond_limit_is_rejected() {
        let mut vs = IpaVerifierState::<1>::new(identity(), 2).unwrap();
        let c = IpaRoundChallenge::from_scalar(u256::from(3u8)).unwrap();
        let rc = IpaRoundCommitments::new(identity(), identity());

        // First round: OK.
        assert!(vs.apply_round(rc, c).is_ok());
        // Second round on a 1-round verifier: must fail.
        assert_eq!(vs.apply_round(rc, c), Err(ZkError::InvalidInput));
    }

    #[test]
    fn full_round_cycle_updates_state_correctly() {
        // 2-round IPA (n=4). We don't verify correctness of the curve math here—
        // that is exercised by the integration tests. We verify the *state
        // machine* behaviour: round_index increments, active_len halves, and
        // challenges are recorded.
        let p0 = g1_gen();
        let mut vs = IpaVerifierState::<2>::new(p0, 4).unwrap();

        let c1 = IpaRoundChallenge::from_scalar(u256::from(2u8)).unwrap();
        let c2 = IpaRoundChallenge::from_scalar(u256::from(5u8)).unwrap();
        let l1 = IpaRoundCommitments::new(g1_gen(), g1_gen());
        let l2 = IpaRoundCommitments::new(g1_gen(), g1_gen());

        vs.apply_round(l1, c1).unwrap();
        assert_eq!(vs.state().round_index, 1);
        assert_eq!(vs.state().active_len, 2);
        assert!(!vs.state().is_complete());

        vs.apply_round(l2, c2).unwrap();
        assert_eq!(vs.state().round_index, 2);
        assert_eq!(vs.state().active_len, 1);
        assert!(vs.state().is_complete());

        // Challenges stored in order.
        let final_state = vs.finish().unwrap();
        assert_eq!(final_state.challenges[0].u, u256::from(2u8));
        assert_eq!(final_state.challenges[1].u, u256::from(5u8));
    }

    #[test]
    fn commitment_fold_formula_matches_manual_computation() {
        // Manually compute P' = u^2·L + P + u^{-2}·R for a single round and
        // compare against IpaVerifierState output.
        let p = g1_gen(); // commitment
        let l = g1_gen();
        let r = g1_gen();

        let u_raw = u256::from(3u8);
        let c = IpaRoundChallenge::from_scalar(u_raw).unwrap();

        // Manual: P' = u^2·L + P + u^{-2}·R
        let expected = l
            .scalar_mul(c.u_sq)
            .add(&p)
            .add(&r.scalar_mul(c.u_sq_inv));

        let mut vs = IpaVerifierState::<1>::new(p, 2).unwrap();
        vs.apply_round(IpaRoundCommitments::new(l, r), c).unwrap();
        let final_state = vs.finish().unwrap();

        assert_eq!(final_state.folded_commitment, expected);
    }
}
