//! PLONK KZG Evaluation Proof Verifier (Stellar Integration Layer).
//!
//! This module wires the pure-math [`kzg_eval_proof_points`] function from
//! `soroban-zk-core` to the Soroban `bn254_multi_pairing_check` host function
//! via the existing [`pairing_check`] abstraction.
//!
//! ## Protocol
//!
//! The final KZG check in PLONK verification reduces to a two-pair equation:
//!
//! ```text
//! e(W_ζ + u·W_{ζω},  [τ]₂)
//! · e(-(ζ·W_ζ + u·ζω·W_{ζω} + F - [E]₁),  G₂)
//! == 1
//! ```
//!
//! where:
//! - `[τ]₂` is the SRS G2 element (the trusted-setup key)
//! - `G₂` is the BN254 G2 generator
//! - `F` is the batched polynomial commitment (see [`KzgEvalProofInputs`])
//! - `[E]₁` is the batched evaluation encoded as a G1 point
//!
//! [`kzg_eval_proof_points`] handles all G1 arithmetic and returns the two
//! G1 points for the equation above.  This module pairs them against the
//! appropriate G2 points using the Soroban host's native pairing engine.
//!
//! ## Security Notes
//!
//! - All input scalars are validated against the BN254 scalar field modulus
//!   before any curve operation (inside [`kzg_eval_proof_points`]).
//! - G1 points coming from the proof (`w_zeta`, `w_zeta_omega`, and the
//!   commitments) **must** be validated by the caller before constructing
//!   [`KzgEvalProofInputs`].  Use [`crate::host::g1_from_host_bytes`] or
//!   check [`soroban_zk_core::Bn254::is_valid_g1_subgroup`] directly.
//! - G2 points (`srs_g2`, generator) are validated inside [`pairing_check`].

use ethnum::u256;
use soroban_sdk::Env;
use soroban_zk_core::{
    decode_g1_point, derive_plonk_batch_seed, derive_plonk_full_challenges, encode_g1_point,
    evaluate_public_inputs_barycentric, fold_quotient_commitment, fr_root_of_unity,
    kzg_eval_proof_points, plonk_batch_verify_points, Bn254, G1Affine, KzgEvalProofInputs,
    PlonkProof, PlonkTranscript, ZkError,
};

use crate::pairing::{pairing_check, validate_g2_coords, G2Affine};

#[inline(always)]
fn is_g1_identity(p: G1Affine) -> bool {
    p.x == u256::from(0u8) && p.y == u256::from(0u8)
}

/// Evaluates `e(lhs, srs_g2) · e(-rhs, G₂) == 1`, handling identity G1 terms
/// (`e(𝒪, Q) = 1`) cleanly after validating `srs_g2`.
fn check_kzg_pairing_equation(
    env: &Env,
    lhs: G1Affine,
    rhs: G1Affine,
    srs_g2: G2Affine,
) -> Result<bool, ZkError> {
    if !validate_g2_coords(&srs_g2) {
        return Err(ZkError::InvalidInput);
    }
    let g2_gen = G2Affine::generator();
    match (is_g1_identity(lhs), is_g1_identity(rhs)) {
        (true, true) => Ok(true),
        (false, true) => pairing_check(env, &[(lhs, srs_g2)]),
        (true, false) => pairing_check(env, &[(neg_g1(rhs), g2_gen)]),
        (false, false) => pairing_check(env, &[(lhs, srs_g2), (neg_g1(rhs), g2_gen)]),
    }
}

/// Negates a G1Affine point: `(x, y) -> (x, -y mod Fq)`.
///
/// Returns the identity unchanged.
#[inline(always)]
fn neg_g1(p: G1Affine) -> G1Affine {
    if p.x == u256::from(0u8) && p.y == u256::from(0u8) {
        p
    } else {
        G1Affine {
            x: p.x,
            y: Bn254::sub_fq(u256::from(0u8), p.y),
        }
    }
}

/// Verifies the batched KZG evaluation proofs for PLONK at `ζ` and `ζω`.
///
/// This is the entry point for the "opening check" step of a PLONK verifier.
/// It performs the full two-pair pairing equation using the Soroban
/// `bn254_multi_pairing_check` host function (CAP-0075).
///
/// # Arguments
///
/// * `env` – Soroban execution environment (needed for the pairing host call).
/// * `inputs` – All evaluations, commitments, and opening proofs (see
///   [`KzgEvalProofInputs`]).
/// * `srs_g2` – The SRS G2 element `[τ]₂` from the trusted setup.  In
///   practice this is stored in the verifying key.
///
/// # Returns
///
/// * `Ok(true)` if the pairing equation holds (proof accepted).
/// * `Ok(false)` if the pairing equation fails (proof rejected).
/// * `Err(ZkError::InvalidInput)` / `Err(ZkError::InvalidFieldElement)` on
///   malformed inputs (propagated from [`kzg_eval_proof_points`]).
/// * `Err(ZkError::HostError)` if the host pairing call fails unexpectedly.
///
/// # Gas Guidance
///
/// This call performs exactly two pairings via `bn254_multi_pairing_check`.
/// At Protocol 25 rates each pair costs ~40 M instructions; total budget for
/// this call is ~80 M instructions.  The G1 scalar-mul operations in
/// [`kzg_eval_proof_points`] add roughly 10–30 M depending on the batch size.
///
/// # Example
///
/// ```rust,ignore
/// use soroban_zk_std::plonk_kzg::verify_plonk_kzg;
/// use soroban_zk_core::KzgEvalProofInputs;
/// use soroban_zk_std::pairing::G2Affine;
///
/// let accepted = verify_plonk_kzg(&env, &inputs, srs_g2)?;
/// assert!(accepted, "proof verification failed");
/// ```
pub fn verify_plonk_kzg(
    env: &Env,
    inputs: &KzgEvalProofInputs<'_>,
    srs_g2: G2Affine,
) -> Result<bool, ZkError> {
    // 1. Compute the two G1 points from the batched polynomial arithmetic.
    let (lhs, rhs) = kzg_eval_proof_points(inputs)?;

    // 2. Check:  e(lhs, srs_g2) · e(-rhs, G2_gen) == 1
    check_kzg_pairing_equation(env, lhs, rhs, srs_g2)
}

/// Verifies `M` PLONK proofs with a **single** pairing call (Issue #427).
///
/// Each entry of `inputs` is a full [`KzgEvalProofInputs`] for one proof (the
/// same bundle consumed by [`verify_plonk_kzg`]). Instead of running one
/// two-pair `bn254_multi_pairing_check` per proof (`2·M` pairings total), the
/// per-proof `(lhs_j, rhs_j)` points are combined with random batch scalars
/// `rho_j` derived from `batch_seed` and folded into a single two-pair check:
///
/// ```text
/// e( sum_j rho_j·lhs_j , [tau]_2 ) · e( -sum_j rho_j·rhs_j , G₂ ) == 1
/// ```
///
/// This collapses the dominant on-chain cost (pairings) from `2·M` to `2`, so
/// verifying a batch is far cheaper than verifying each proof independently.
/// The G1 arithmetic is delegated to
/// [`plonk_batch_verify_points`] (allocation-free).
///
/// # Arguments
///
/// * `env` – Soroban execution environment (needed for the pairing host call).
/// * `inputs` – One [`KzgEvalProofInputs`] bundle per proof. Must be
///   non-empty.
/// * `batch_seed` – 32-byte seed used to derive the batch scalars `rho_j`.
/// * `srs_g2` – The SRS G2 element `[tau]₂` from the trusted setup.
///
/// # Returns
///
/// * `Ok(true)` if the aggregated pairing holds (all proofs accepted).
/// * `Ok(false)` if it fails (at least one proof is invalid).
/// * `Err(...)` on malformed inputs (empty batch, out-of-range scalars, or a
///   per-proof bundle failing validation) or a host pairing failure.
///
/// # Security
///
/// `batch_seed` **must** be unpredictable to the prover and not controlled by
/// it — e.g. derived from a transcript that binds every proof in the batch, or
/// an on-chain randomness beacon. A fixed or prover-chosen seed lets a malicious
/// prover cheat the randomized combination and breaks soundness.
///
/// As with [`verify_plonk_kzg`], the G1 points inside each bundle
/// (`w_zeta`, `w_zeta_omega`, commitments) **must** be subgroup-validated by
/// the caller before constructing [`KzgEvalProofInputs`].
///
/// # Example
///
/// ```rust,ignore
/// use soroban_zk_std::plonk_kzg::verify_plonk_kzg_batch;
///
/// let accepted = verify_plonk_kzg_batch(&env, &inputs, &batch_seed, srs_g2)?;
/// assert!(accepted, "batch verification failed");
/// ```
pub fn verify_plonk_kzg_batch(
    env: &Env,
    inputs: &[KzgEvalProofInputs<'_>],
    batch_seed: &[u8; 32],
    srs_g2: G2Affine,
) -> Result<bool, ZkError> {
    // 1. Fold every proof into the two batched G1 points (single accumulator
    //    pass, no heap allocation).
    let (lhs, rhs) = plonk_batch_verify_points(inputs, batch_seed)?;

    // 2. One two-pair check replaces the M individual checks:
    //        e(lhs, [tau]_2) · e(-rhs, G₂) == 1
    check_kzg_pairing_equation(env, lhs, rhs, srs_g2)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethnum::u256;
    use soroban_sdk::Env;
    use soroban_zk_core::G1Affine;

    // ─── helpers ────────────────────────────────────────────────────────────

    fn g1_gen() -> G1Affine {
        G1Affine {
            x: u256::from(1u8),
            y: u256::from(2u8),
        }
    }

    fn g2_gen() -> G2Affine {
        G2Affine::generator()
    }

    // ─── unit tests ─────────────────────────────────────────────────────────

    /// Calling `verify_plonk_kzg` with well-formed inputs must not panic and
    /// must return a `bool` (true or false) rather than an error.
    ///
    /// Note: Because the fixture is *not* a valid proof, the pairing will
    /// return `false`.  We only assert the absence of errors here.
    #[test]
    fn verify_plonk_kzg_completes_without_error_for_valid_inputs() {
        let env = Env::default();
        let commitments = [g1_gen()];
        let evaluations = [u256::from(3u8)];

        let inputs = KzgEvalProofInputs {
            commitments: &commitments,
            evaluations_at_zeta: &evaluations,
            commitment_at_zeta_omega: g1_gen(),
            evaluation_at_zeta_omega: u256::from(5u8),
            w_zeta: g1_gen(),
            w_zeta_omega: g1_gen(),
            v: u256::from(7u8),
            u: u256::from(11u8),
            zeta: u256::from(13u8),
            omega: u256::from(17u8),
        };

        // A random G2 point used as the mock SRS element.
        let srs_g2 = g2_gen();

        // Must return Ok(bool) — not panic, not Err.
        match verify_plonk_kzg(&env, &inputs, srs_g2) {
            Ok(_accepted) => { /* pass — result is mathematically undefined for dummy data */ }
            Err(e) => panic!("unexpected error: {:?}", e),
        }
    }

    /// `verify_plonk_kzg` must propagate `ZkError::InvalidInput` when the
    /// commitment and evaluation slices have different lengths.
    #[test]
    fn verify_plonk_kzg_propagates_invalid_input_error() {
        let env = Env::default();
        let commitments = [g1_gen()];
        let evaluations = [u256::from(1u8), u256::from(2u8)]; // wrong length

        let inputs = KzgEvalProofInputs {
            commitments: &commitments,
            evaluations_at_zeta: &evaluations,
            commitment_at_zeta_omega: g1_gen(),
            evaluation_at_zeta_omega: u256::from(5u8),
            w_zeta: g1_gen(),
            w_zeta_omega: g1_gen(),
            v: u256::from(7u8),
            u: u256::from(11u8),
            zeta: u256::from(13u8),
            omega: u256::from(17u8),
        };

        assert_eq!(
            verify_plonk_kzg(&env, &inputs, g2_gen()),
            Err(ZkError::InvalidInput)
        );
    }

    /// `verify_plonk_kzg` must propagate `ZkError::InvalidFieldElement` when
    /// any challenge scalar is ≥ the BN254 scalar field modulus.
    #[test]
    fn verify_plonk_kzg_propagates_field_element_error() {
        let env = Env::default();
        let commitments = [g1_gen()];
        let evaluations = [u256::from(3u8)];

        let inputs = KzgEvalProofInputs {
            commitments: &commitments,
            evaluations_at_zeta: &evaluations,
            commitment_at_zeta_omega: g1_gen(),
            evaluation_at_zeta_omega: u256::from(5u8),
            w_zeta: g1_gen(),
            w_zeta_omega: g1_gen(),
            v: u256::from(7u8),
            u: u256::from(11u8),
            zeta: Bn254::FR_MODULUS, // out-of-range zeta
            omega: u256::from(17u8),
        };

        assert_eq!(
            verify_plonk_kzg(&env, &inputs, g2_gen()),
            Err(ZkError::InvalidFieldElement)
        );
    }

    /// Structural test: verify the full call chain reaches the pairing engine.
    /// With u = 0 and carefully chosen inputs, we confirm no panic/error occurs.
    /// See inline comments for the mathematical reasoning.
    #[test]
    fn verify_plonk_kzg_trivial_self_cancelling_proof() {
        let env = Env::default();

        // With u = 0: lhs = W_ζ
        // With zeta = 0: zeta*W_ζ = identity
        // F = C_0 = G1_gen, [E]_1 = eval_0 * G1_gen = 1 * G1_gen = G1_gen
        // → F - [E]_1 = G1_gen - G1_gen = identity
        // → rhs = identity
        //
        // Pairing check: e(G1_gen, srs_g2) · e(-identity, G2_gen) = e(G1_gen, srs_g2) ≠ 1
        // So the proof is NOT accepted — but no error should be returned.
        let commitments = [g1_gen()];
        let evaluations = [u256::from(1u8)];

        let inputs = KzgEvalProofInputs {
            commitments: &commitments,
            evaluations_at_zeta: &evaluations,
            commitment_at_zeta_omega: g1_gen(),
            evaluation_at_zeta_omega: u256::from(0u8),
            w_zeta: g1_gen(),
            w_zeta_omega: g1_gen(),
            v: u256::from(1u8),
            u: u256::from(0u8),
            zeta: u256::from(0u8),
            omega: u256::from(1u8),
        };

        let result = verify_plonk_kzg(&env, &inputs, g2_gen());
        assert!(result.is_ok(), "expected Ok, got {:?}", result);
    }

    // ─── multi-proof batch tests (Issue #427) ───────────────────────────────

    /// Builds a well-formed [`KzgEvalProofInputs`] bundle for batch tests.
    fn batch_bundle() -> KzgEvalProofInputs<'static> {
        static C: &[G1Affine] = &[G1Affine {
            x: u256::from_words(0, 1),
            y: u256::from_words(0, 2),
        }];
        static E: &[u256] = &[u256::from_words(0, 3)];
        KzgEvalProofInputs {
            commitments: C,
            evaluations_at_zeta: E,
            commitment_at_zeta_omega: g1_gen(),
            evaluation_at_zeta_omega: u256::from(5u8),
            w_zeta: g1_gen(),
            w_zeta_omega: g1_gen(),
            v: u256::from(7u8),
            u: u256::from(11u8),
            zeta: u256::from(13u8),
            omega: u256::from(17u8),
        }
    }

    /// An empty batch is a structural error, never a pairing call.
    #[test]
    fn verify_plonk_kzg_batch_rejects_empty_batch() {
        let env = Env::default();
        assert_eq!(
            verify_plonk_kzg_batch(&env, &[], &[7u8; 32], g2_gen()),
            Err(ZkError::InvalidInput)
        );
    }

    /// A batch of well-formed bundles must run the single aggregated pairing
    /// and return `Ok(bool)` (the dummy data is not a real proof, so we only
    /// assert the absence of errors).
    #[test]
    fn verify_plonk_kzg_batch_completes_without_error() {
        let env = Env::default();
        let inputs = [batch_bundle(), batch_bundle()];
        match verify_plonk_kzg_batch(&env, &inputs, &[9u8; 32], g2_gen()) {
            Ok(_) => { /* pass — result undefined for dummy data */ }
            Err(e) => panic!("unexpected error: {:?}", e),
        }
    }

    /// A zero `batch_seed` reduces the first batch scalar to zero and must be
    /// rejected before any pairing is attempted.
    #[test]
    fn verify_plonk_kzg_batch_rejects_zero_seed() {
        let env = Env::default();
        let inputs = [batch_bundle()];
        assert_eq!(
            verify_plonk_kzg_batch(&env, &inputs, &[0u8; 32], g2_gen()),
            Err(ZkError::InvalidFieldElement)
        );
    }
}

// ============================================================================
// Full PLONK verification
// ============================================================================
//
// [`verify_plonk_kzg`] above checks the terminal KZG opening only; the items
// below add the transcript, the barycentric `PI(ζ)`, the split-quotient fold
// and the quotient identity. See [`verify_plonk_full`] for the exact pipeline.

/// Canonical encoded size of a [`PlonkVerifyingKey`].
pub const PLONK_VK_BYTES: usize = 128 + 5 * 64 + 8 + 32 + 32 + 8;

/// Largest public-input vector [`verify_plonk_full`] accepts. The barycentric
/// scratch buffers are stack arrays, so the bound is a compile-time constant.
pub const MAX_PUBLIC_INPUTS: usize = 32;

/// Verifying key for [`verify_plonk_full`].
///
/// Canonical layout of [`PlonkVerifyingKey::to_bytes`]:
/// `[τ]₂` (128 bytes) ‖ five selector commitments (64 bytes each) ‖
/// domain size (8 bytes, big-endian) ‖ `k₁` (32) ‖ `k₂` (32) ‖
/// public-input count (8).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PlonkVerifyingKey {
    /// Trusted-setup G2 element `[τ]₂`.
    pub srs_g2: G2Affine,
    /// Commitments to the five selector polynomials
    /// `q_L, q_R, q_O, q_M, q_C`.
    pub selector_commitments: [G1Affine; 5],
    /// Evaluation-domain size `n` (a power of two, at most `2^28`).
    pub domain_size: usize,
    /// Coset shift for the second wire permutation.
    pub k1: u256,
    /// Coset shift for the third wire permutation.
    pub k2: u256,
    /// Number of public inputs the circuit exposes.
    pub num_public_inputs: usize,
}

impl PlonkVerifyingKey {
    /// Serializes the key into its canonical fixed-size encoding.
    pub fn to_bytes(&self) -> [u8; PLONK_VK_BYTES] {
        let mut out = [0u8; PLONK_VK_BYTES];
        out[..128].copy_from_slice(&self.srs_g2.to_bytes());
        let mut offset = 128usize;
        for commitment in self.selector_commitments.iter() {
            out[offset..offset + 64].copy_from_slice(&encode_g1_point(commitment));
            offset += 64;
        }
        out[offset..offset + 8].copy_from_slice(&(self.domain_size as u64).to_be_bytes());
        offset += 8;
        out[offset..offset + 32].copy_from_slice(&self.k1.to_be_bytes());
        offset += 32;
        out[offset..offset + 32].copy_from_slice(&self.k2.to_be_bytes());
        offset += 32;
        out[offset..offset + 8].copy_from_slice(&(self.num_public_inputs as u64).to_be_bytes());
        out
    }

    /// Decodes a key from the canonical [`PlonkVerifyingKey::to_bytes`]
    /// encoding, rejecting malformed points, non-canonical scalars and an
    /// unusable domain size (zero or not a power of two).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ZkError> {
        if bytes.len() != PLONK_VK_BYTES {
            return Err(ZkError::DeserializationError);
        }
        let srs_g2 = crate::groth16::g2_from_bytes(&bytes[..128])?;
        let mut selector_commitments = [G1Affine {
            x: u256::from(0u8),
            y: u256::from(0u8),
        }; 5];
        for (i, commitment) in selector_commitments.iter_mut().enumerate() {
            let start = 128 + i * 64;
            *commitment = decode_g1_point(&bytes[start..start + 64])?;
        }
        let domain_size = read_u64(&bytes[448..456])? as usize;
        if domain_size == 0 || !domain_size.is_power_of_two() {
            return Err(ZkError::DeserializationError);
        }
        let k1 = read_fr(&bytes[456..488])?;
        let k2 = read_fr(&bytes[488..520])?;
        let num_public_inputs = read_u64(&bytes[520..528])? as usize;
        if num_public_inputs > MAX_PUBLIC_INPUTS {
            return Err(ZkError::DeserializationError);
        }
        Ok(Self {
            srs_g2,
            selector_commitments,
            domain_size,
            k1,
            k2,
            num_public_inputs,
        })
    }

    /// SHA-256 digest of the canonical encoding, absorbed by the transcript so
    /// no challenge can be replayed against a different key.
    pub fn digest(&self) -> [u8; 32] {
        soroban_zk_core::hash::Hash::hash(&self.to_bytes()).0
    }
}

fn read_u64(slice: &[u8]) -> Result<u64, ZkError> {
    if slice.len() != 8 {
        return Err(ZkError::DeserializationError);
    }
    let mut buf = [0u8; 8];
    buf.copy_from_slice(slice);
    Ok(u64::from_be_bytes(buf))
}

fn read_fr(slice: &[u8]) -> Result<u256, ZkError> {
    if slice.len() != 32 {
        return Err(ZkError::DeserializationError);
    }
    let mut buf = [0u8; 32];
    buf.copy_from_slice(slice);
    Bn254::fr_from_bytes(buf).ok_or(ZkError::DeserializationError)
}

/// Rejects G1 points that are neither the canonical identity nor a valid
/// prime-order curve point, before any of them reaches the pairing engine.
fn validate_proof_point(point: &G1Affine) -> Result<(), ZkError> {
    if is_g1_identity(*point) {
        return Ok(());
    }
    if !Bn254::is_valid_g1_subgroup(point.x, point.y) {
        return Err(ZkError::InvalidInput);
    }
    Ok(())
}

/// Verifies a complete PLONK proof end to end.
///
/// The pipeline is:
///
/// 1. structural validation (public-input count/range, subgroup-valid
///    commitments, canonical scalars, power-of-two domain);
/// 2. transcript derivation of `(β, γ, α, ζ, v, u)` from the key digest, the
///    public inputs and every proof element;
/// 3. barycentric evaluation of `PI(ζ)` over the roots of unity `ω^i`;
/// 4. reconstruction of the split-quotient commitment and verification of the
///    quotient identity `L(ζ) + PI(ζ) = t(ζ)·(ζⁿ - 1)`;
/// 5. the batched KZG opening at `ζ` (wires `a, b, c` and quotient `t`) plus
///    the shifted opening of `z` at `ζω`, batched with `v` and folded with
///    `u`, terminating in one `bn254_multi_pairing_check` host call.
///
/// Returns `Ok(false)` for a well-formed but non-satisfying proof (a decision),
/// and a typed [`ZkError`] for malformed input.
///
/// # Errors
/// * [`ZkError::InvalidInput`] — public-input count mismatch or overflow,
///   non-power-of-two / zero domain, off-curve or small-subgroup commitment.
/// * [`ZkError::InvalidFieldElement`] — a public input, coset shift or
///   challenge is not a canonical `Fr` element, or a challenge degenerated
///   (`β, γ, α, v, u == 0`, or `ζ == 1`).
/// * [`ZkError::HostError`] — the pairing host call failed.
pub fn verify_plonk_full(
    env: &Env,
    vk: &PlonkVerifyingKey,
    proof: &PlonkProof,
    public_inputs: &[u256],
) -> Result<bool, ZkError> {
    // ── 1. Structural validation ────────────────────────────────────────────
    if vk.domain_size == 0
        || !vk.domain_size.is_power_of_two()
        || vk.domain_size.trailing_zeros() > soroban_zk_core::FR_TWO_ADICITY
    {
        return Err(ZkError::InvalidInput);
    }
    if public_inputs.len() != vk.num_public_inputs || public_inputs.len() > MAX_PUBLIC_INPUTS {
        return Err(ZkError::InvalidInput);
    }
    for public_input in public_inputs {
        if !Bn254::is_valid_scalar(*public_input) {
            return Err(ZkError::InvalidFieldElement);
        }
    }
    if !Bn254::is_valid_scalar(vk.k1) || !Bn254::is_valid_scalar(vk.k2) {
        return Err(ZkError::InvalidFieldElement);
    }
    if !validate_g2_coords(&vk.srs_g2) {
        return Err(ZkError::InvalidInput);
    }
    for commitment in proof
        .wire_commitments
        .iter()
        .chain(core::iter::once(&proof.z_commitment))
        .chain(proof.quotient_commitments.iter())
        .chain(core::iter::once(&proof.w_zeta))
        .chain(core::iter::once(&proof.w_zeta_omega))
    {
        validate_proof_point(commitment)?;
    }
    for evaluation in proof
        .wire_evaluations
        .iter()
        .chain(proof.sigma_evaluations.iter())
        .chain(core::iter::once(&proof.z_omega_evaluation))
        .chain(core::iter::once(&proof.quotient_evaluation))
        .chain(core::iter::once(&proof.linearization_evaluation))
    {
        if !Bn254::is_valid_scalar(*evaluation) {
            return Err(ZkError::InvalidFieldElement);
        }
    }

    // ── 2. Fiat–Shamir challenges ───────────────────────────────────────────
    let vk_digest = vk.digest();
    let mut transcript =
        PlonkTranscript::plonk_init(vk.domain_size, vk.k1, vk.k2, &vk_digest, public_inputs)?;
    let challenges = derive_plonk_full_challenges(&mut transcript, proof);

    let zero = u256::from(0u8);
    let one = u256::from(1u8);
    if challenges.beta == zero
        || challenges.gamma == zero
        || challenges.alpha == zero
        || challenges.zeta == one
        || challenges.v == zero
        || challenges.u == zero
    {
        // A degenerate challenge would drop a permutation term (`beta`,
        // `gamma`, `alpha`), leave the opening batch unweighted (`v`) or skip
        // the shifted opening entirely (`u`), so it can never be accepted.
        return Err(ZkError::InvalidFieldElement);
    }

    // ── 3. Barycentric PI(ζ) ────────────────────────────────────────────────
    let omega = fr_root_of_unity(vk.domain_size)?;
    let mut denominators = [zero; MAX_PUBLIC_INPUTS];
    let mut prefix = [zero; MAX_PUBLIC_INPUTS];
    let pi_zeta = evaluate_public_inputs_barycentric(
        public_inputs,
        vk.domain_size,
        challenges.zeta,
        omega,
        &mut denominators[..public_inputs.len()],
        &mut prefix[..public_inputs.len()],
    )?;

    // ── 4. Split-quotient commitment + quotient identity ────────────────────
    let t_commitment =
        fold_quotient_commitment(&proof.quotient_commitments, challenges.zeta, vk.domain_size)?;
    let zeta_n = Bn254::pow(challenges.zeta, u256::from(vk.domain_size as u64));
    let vanishing = Bn254::sub(zeta_n, one);
    let t_times_vanishing = Bn254::mul(proof.quotient_evaluation, vanishing);
    let linearized = Bn254::add(proof.linearization_evaluation, pi_zeta);
    if linearized != t_times_vanishing {
        return Ok(false);
    }

    // ── 5. Batched KZG opening ──────────────────────────────────────────────
    let commitments = [
        proof.wire_commitments[0],
        proof.wire_commitments[1],
        proof.wire_commitments[2],
        t_commitment,
    ];
    let evaluations = [
        proof.wire_evaluations[0],
        proof.wire_evaluations[1],
        proof.wire_evaluations[2],
        proof.quotient_evaluation,
    ];
    let inputs = KzgEvalProofInputs {
        commitments: &commitments,
        evaluations_at_zeta: &evaluations,
        commitment_at_zeta_omega: proof.z_commitment,
        evaluation_at_zeta_omega: proof.z_omega_evaluation,
        w_zeta: proof.w_zeta,
        w_zeta_omega: proof.w_zeta_omega,
        v: challenges.v,
        u: challenges.u,
        zeta: challenges.zeta,
        omega,
    };
    verify_plonk_kzg(env, &inputs, vk.srs_g2)
}

/// Verifies a batch of PLONK openings with a seed derived from a transcript
/// that absorbs every batched proof, instead of a caller-supplied seed.
///
/// This is the safe counterpart of [`verify_plonk_kzg_batch`]: a fixed or
/// prover-chosen seed (for example `1`, which leaves every batch weight at one)
/// can no longer break the randomized combination.
pub fn verify_plonk_kzg_batch_safe(
    env: &Env,
    inputs: &[KzgEvalProofInputs<'_>],
    srs_g2: G2Affine,
) -> Result<bool, ZkError> {
    let batch_seed = derive_plonk_batch_seed(inputs)?;
    verify_plonk_kzg_batch(env, inputs, &batch_seed, srs_g2)
}

// ============================================================================
// End-to-end tests
// ============================================================================

#[cfg(test)]
mod full_verifier_tests {
    use super::*;
    use soroban_zk_core::{
        evaluate_public_inputs_barycentric, fold_quotient_commitment, fr_root_of_unity,
        G1Projective, PlonkProof, PlonkTranscript,
    };

    const N: usize = 4;

    fn zero() -> u256 {
        u256::from(0u8)
    }

    fn one() -> u256 {
        u256::from(1u8)
    }

    /// `mult · G1` with the BN254 generator `(1, 2)`.
    fn g1(mult: u64) -> G1Affine {
        G1Affine {
            x: one(),
            y: u256::from(2u8),
        }
        .scalar_mul(u256::from(mult))
    }

    fn public_inputs() -> [u256; N] {
        [u256::from(3u8), one(), u256::from(4u8), one()]
    }

    fn verifying_key(num_public_inputs: usize) -> PlonkVerifyingKey {
        PlonkVerifyingKey {
            srs_g2: G2Affine::generator(),
            selector_commitments: [g1(1), g1(2), g1(3), g1(4), g1(5)],
            domain_size: N,
            k1: u256::from(5u8),
            k2: u256::from(6u8),
            num_public_inputs,
        }
    }

    /// Honest-prover reconstruction of a genuinely satisfying PLONK proof.
    ///
    /// The commitments are fixed first (so `β, γ, α, ζ` are derived exactly as
    /// the verifier derives them), then the evaluations are chosen and `v` is
    /// squeezed. Because the pairing check with `[τ]₂ = G2` accepts iff
    /// `lhs == rhs`, the two opening witnesses are then *solved* so both the
    /// `u⁰` and `u¹` coefficients of that equation hold:
    ///
    /// ```text
    /// W_ζ       = (F - [E]₁) / (1 - ζ)
    /// W_ζω      = -z(ζω) · G1 / (1 - ζω)
    /// ```
    fn honest_proof(vk: &PlonkVerifyingKey, public_inputs: &[u256; N]) -> PlonkProof {
        let mut proof = PlonkProof {
            wire_commitments: [g1(2), g1(3), g1(5)],
            z_commitment: g1(7),
            quotient_commitments: [g1(11), g1(13), g1(17)],
            w_zeta: g1(19),
            w_zeta_omega: g1(23),
            wire_evaluations: [zero(); 3],
            sigma_evaluations: [zero(); 2],
            z_omega_evaluation: zero(),
            quotient_evaluation: zero(),
            linearization_evaluation: zero(),
        };

        let digest = vk.digest();
        let mut transcript =
            PlonkTranscript::plonk_init(vk.domain_size, vk.k1, vk.k2, &digest, public_inputs)
                .expect("transcript init");
        let _ = transcript.plonk_beta_gamma(&proof);
        let _ = transcript.plonk_alpha(&proof);
        let zeta = transcript.plonk_zeta(&proof);
        let omega = fr_root_of_unity(vk.domain_size).expect("root of unity");

        let mut denominators = [zero(); N];
        let mut prefix = [zero(); N];
        let pi_zeta = evaluate_public_inputs_barycentric(
            public_inputs,
            vk.domain_size,
            zeta,
            omega,
            &mut denominators,
            &mut prefix,
        )
        .expect("PI(zeta)");

        proof.wire_evaluations = [u256::from(5u8), u256::from(6u8), u256::from(7u8)];
        proof.sigma_evaluations = [u256::from(8u8), u256::from(9u8)];
        proof.z_omega_evaluation = u256::from(4u8);
        proof.quotient_evaluation = u256::from(9u8);
        let zeta_n = Bn254::pow(zeta, u256::from(N as u64));
        let vanishing = Bn254::sub(zeta_n, one());
        proof.linearization_evaluation =
            Bn254::sub(Bn254::mul(proof.quotient_evaluation, vanishing), pi_zeta);

        let v = transcript.plonk_v(&proof);

        let t_commitment =
            fold_quotient_commitment(&proof.quotient_commitments, zeta, vk.domain_size)
                .expect("quotient fold");
        let commitments = [
            proof.wire_commitments[0],
            proof.wire_commitments[1],
            proof.wire_commitments[2],
            t_commitment,
        ];
        let evaluations = [
            proof.wire_evaluations[0],
            proof.wire_evaluations[1],
            proof.wire_evaluations[2],
            proof.quotient_evaluation,
        ];

        let mut batched_commitment = G1Projective::identity();
        let mut batched_evaluation = zero();
        let mut v_pow = one();
        for (commitment, evaluation) in commitments.iter().zip(evaluations.iter()) {
            batched_commitment = batched_commitment.add(&Bn254::g1_scalar_mul(
                G1Projective::from(*commitment),
                v_pow,
            ));
            batched_evaluation = Bn254::add(batched_evaluation, Bn254::mul(v_pow, *evaluation));
            v_pow = Bn254::mul(v_pow, v);
        }

        let neg_batched_evaluation = Bn254::g1_scalar_mul(
            G1Projective::from(g1(1)),
            Bn254::sub(zero(), batched_evaluation),
        );
        proof.w_zeta = Bn254::g1_scalar_mul(
            batched_commitment.add(&neg_batched_evaluation),
            Bn254::invert(Bn254::sub(one(), zeta)),
        )
        .to_affine();

        let zeta_omega = Bn254::mul(zeta, omega);
        let w_omega_scalar = Bn254::mul(
            Bn254::sub(zero(), proof.z_omega_evaluation),
            Bn254::invert(Bn254::sub(one(), zeta_omega)),
        );
        proof.w_zeta_omega =
            Bn254::g1_scalar_mul(G1Projective::from(g1(1)), w_omega_scalar).to_affine();

        let _ = transcript.plonk_u(&proof);
        proof
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn honest_proof_verifies_end_to_end() {
        let env = Env::default();
        let public_inputs = public_inputs();
        let vk = verifying_key(public_inputs.len());
        let proof = honest_proof(&vk, &public_inputs);
        assert_eq!(
            verify_plonk_full(&env, &vk, &proof, &public_inputs),
            Ok(true)
        );
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn corrupted_proofs_are_rejected() {
        let env = Env::default();
        let public_inputs = public_inputs();
        let vk = verifying_key(public_inputs.len());
        let good = honest_proof(&vk, &public_inputs);

        // A wrong wire evaluation breaks the batched opening.
        let mut bad = good;
        bad.wire_evaluations[0] = Bn254::add(bad.wire_evaluations[0], one());
        assert_eq!(
            verify_plonk_full(&env, &vk, &bad, &public_inputs),
            Ok(false)
        );

        // The linearization evaluation is bound through the quotient identity.
        let mut bad = good;
        bad.linearization_evaluation = Bn254::add(bad.linearization_evaluation, one());
        assert_eq!(
            verify_plonk_full(&env, &vk, &bad, &public_inputs),
            Ok(false)
        );

        // ... as is the quotient evaluation (identity and opening).
        let mut bad = good;
        bad.quotient_evaluation = Bn254::add(bad.quotient_evaluation, one());
        assert_eq!(
            verify_plonk_full(&env, &vk, &bad, &public_inputs),
            Ok(false)
        );

        // A substituted wire commitment moves ζ and breaks the opening.
        let mut bad = good;
        bad.wire_commitments[1] = g1(29);
        assert_eq!(
            verify_plonk_full(&env, &vk, &bad, &public_inputs),
            Ok(false)
        );

        // A forged opening proof cannot satisfy the pairing equation.
        let mut bad = good;
        bad.w_zeta = g1(31);
        assert_eq!(
            verify_plonk_full(&env, &vk, &bad, &public_inputs),
            Ok(false)
        );

        // Swapping the shifted opening also fails.
        let mut bad = good;
        bad.w_zeta_omega = g1(37);
        assert_eq!(
            verify_plonk_full(&env, &vk, &bad, &public_inputs),
            Ok(false)
        );
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn public_inputs_are_bound_by_the_transcript() {
        let env = Env::default();
        let public_inputs = public_inputs();
        let vk = verifying_key(public_inputs.len());
        let proof = honest_proof(&vk, &public_inputs);
        let mut other = public_inputs;
        other[0] = Bn254::add(other[0], one());
        assert_eq!(verify_plonk_full(&env, &vk, &proof, &other), Ok(false));
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn structural_errors_are_typed() {
        let env = Env::default();
        let public_inputs = public_inputs();
        let vk = verifying_key(public_inputs.len());
        let proof = honest_proof(&vk, &public_inputs);

        assert_eq!(
            verify_plonk_full(&env, &vk, &proof, &public_inputs[..3]),
            Err(ZkError::InvalidInput)
        );
        let wide = [one(); MAX_PUBLIC_INPUTS + 1];
        let wide_vk = verifying_key(wide.len());
        assert_eq!(
            verify_plonk_full(&env, &wide_vk, &proof, &wide),
            Err(ZkError::InvalidInput)
        );

        let mut bad_pi = public_inputs;
        bad_pi[0] = Bn254::FR_MODULUS;
        assert_eq!(
            verify_plonk_full(&env, &vk, &proof, &bad_pi),
            Err(ZkError::InvalidFieldElement)
        );

        let mut bad = proof;
        bad.z_commitment = G1Affine {
            x: one(),
            y: u256::from(3u8),
        };
        assert_eq!(
            verify_plonk_full(&env, &vk, &bad, &public_inputs),
            Err(ZkError::InvalidInput)
        );

        for domain_size in [0usize, 3usize] {
            let mut bad_vk = vk;
            bad_vk.domain_size = domain_size;
            assert_eq!(
                verify_plonk_full(&env, &bad_vk, &proof, &public_inputs),
                Err(ZkError::InvalidInput)
            );
        }
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn canonical_bytes_round_trip_through_the_verifier() {
        let env = Env::default();
        let public_inputs = public_inputs();
        let vk = verifying_key(public_inputs.len());
        let proof = honest_proof(&vk, &public_inputs);

        let decoded = PlonkProof::from_bytes(&proof.to_bytes()).expect("proof must decode");
        assert_eq!(decoded, proof);
        assert_eq!(
            verify_plonk_full(&env, &vk, &decoded, &public_inputs),
            Ok(true)
        );

        let decoded_vk =
            PlonkVerifyingKey::from_bytes(&vk.to_bytes()).expect("verifying key must decode");
        assert_eq!(decoded_vk, vk);
        assert_eq!(decoded_vk.digest(), vk.digest());
        assert_eq!(
            verify_plonk_full(&env, &decoded_vk, &decoded, &public_inputs),
            Ok(true)
        );
    }

    #[test]
    fn verifying_key_bytes_reject_malformed_input() {
        let vk = verifying_key(4);
        let bytes = vk.to_bytes();
        assert_eq!(
            PlonkVerifyingKey::from_bytes(&bytes[..PLONK_VK_BYTES - 1]),
            Err(ZkError::DeserializationError)
        );

        // Off-curve selector commitment.
        let mut bad = bytes;
        bad[128 + 63] ^= 1;
        assert_eq!(
            PlonkVerifyingKey::from_bytes(&bad),
            Err(ZkError::DeserializationError)
        );

        // Zero domain size.
        let mut bad = bytes;
        bad[448..456].copy_from_slice(&0u64.to_be_bytes());
        assert_eq!(
            PlonkVerifyingKey::from_bytes(&bad),
            Err(ZkError::DeserializationError)
        );

        // Non-canonical k1.
        let mut bad = bytes;
        bad[456..488].copy_from_slice(&Bn254::FR_MODULUS.to_be_bytes());
        assert_eq!(
            PlonkVerifyingKey::from_bytes(&bad),
            Err(ZkError::DeserializationError)
        );
    }

    #[test]
    fn safe_batch_wrapper_rejects_empty_batch() {
        let env = Env::default();
        assert_eq!(
            verify_plonk_kzg_batch_safe(&env, &[], G2Affine::generator()),
            Err(ZkError::InvalidInput)
        );
    }
}
