use alloc::vec::Vec as AllocVec;
use ethnum::u256;
use soroban_sdk::crypto::bn254::{Bn254Fr as SdkFr, Bn254G1Affine as SdkG1Affine};
use soroban_sdk::{Bytes, BytesN, Env, Vec, U256};
use soroban_zk_core::{Bn254, G1Affine, ZkError};

use crate::events::ZkFailureContext;
use crate::pairing::{g1_to_bytes, pairing_check, validate_g2_coords, G2Affine};

/// A Groth16 proof over BN254.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct Groth16Proof {
    pub a: G1Affine,
    pub b: G2Affine,
    pub c: G1Affine,
}

/// A Groth16 verifying key over BN254.
#[derive(Debug, Copy, Clone)]
pub struct Groth16VerifyingKey<'a> {
    pub alpha_g1: G1Affine,
    pub beta_g2: G2Affine,
    pub gamma_g2: G2Affine,
    pub delta_g2: G2Affine,
    pub ic: &'a [G1Affine],
}

impl Groth16Proof {
    /// Decodes a Groth16 proof from `A || B || C`, where A and C are G1 points
    /// and B is a G2 point.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ZkError> {
        Self::from_bytes_detailed(bytes).0
    }

    /// Enhanced proof deserialization that also reports *why* a rejection
    /// happened.
    ///
    /// Returns `(result, context)`. On success `context` is `None`; on failure
    /// it carries the byte offset of the malformed component so callers can
    /// attach it to a structured verification event. Building the context here
    /// needs no `Env` (the failure is described by an offset, not a string), so
    /// this compiles on `wasm32v1-none` and never uses `Env::default()`.
    pub fn from_bytes_detailed(
        bytes: &[u8],
    ) -> (Result<Self, ZkError>, Option<ZkFailureContext>) {
        if bytes.len() != 256 {
            return (
                Err(ZkError::DeserializationError),
                Some(ZkFailureContext::deserialization_error(bytes.len() as u32)),
            );
        }

        let a = match g1_from_bytes_detailed(&bytes[..64], 0).0 {
            Ok(point) => point,
            Err(e) => {
                return (
                    Err(e),
                    Some(ZkFailureContext::deserialization_error(0)),
                )
            }
        };
        let b = match g2_from_bytes_detailed(&bytes[64..192]).0 {
            Ok(point) => point,
            Err(e) => {
                return (
                    Err(e),
                    Some(ZkFailureContext::deserialization_error(64)),
                )
            }
        };
        let c = match g1_from_bytes_detailed(&bytes[192..], 192).0 {
            Ok(point) => point,
            Err(e) => {
                return (
                    Err(e),
                    Some(ZkFailureContext::deserialization_error(192)),
                )
            }
        };

        (Ok(Self { a, b, c }), None)
    }

    /// Encodes the proof as `A || B || C` (256 bytes), the exact inverse of
    /// [`Self::from_bytes`]: A and C are 64-byte big-endian G1 points and B is a
    /// 128-byte G2 point in the EIP-197 / CAP-0074 layout (`c1` before `c0`).
    pub fn to_bytes(&self) -> [u8; 256] {
        let mut bytes = [0u8; 256];
        bytes[..64].copy_from_slice(&g1_to_bytes(&self.a));
        bytes[64..192].copy_from_slice(&self.b.to_bytes());
        bytes[192..].copy_from_slice(&g1_to_bytes(&self.c));
        bytes
    }
}

/// Verifies a Groth16 proof using the rearranged multi-pairing equation:
///
/// `e(A, B) == e(alpha, beta) * e(acc, gamma) * e(C, delta)`
///
/// where `acc = IC_0 + s_1 * IC_1 + ... + s_n * IC_n`.
///
/// This is checked as a single 4-pair product:
///
/// `e(A, B) * e(-alpha, beta) * e(-acc, gamma) * e(-C, delta) == 1`
pub fn groth16_verify(
    env: &Env,
    vk: &Groth16VerifyingKey<'_>,
    proof: &Groth16Proof,
    public_inputs: &[u256],
) -> Result<bool, ZkError> {
    groth16_verify_detailed(env, vk, proof, public_inputs).0
}

/// Enhanced Groth16 verification that also reports *why* a rejection happened.
///
/// Returns `(result, context)`. On success `context` is `None`; on failure it
/// describes the failing stage — the invalid public-input index, a malformed
/// verifying key, or a pairing failure — so `ZkContract::verify_proof` can
/// publish it with the structured verification event. Context construction uses
/// the caller's `Env`; no `Env::default()` is ever created here.
pub fn groth16_verify_detailed(
    env: &Env,
    vk: &Groth16VerifyingKey<'_>,
    proof: &Groth16Proof,
    public_inputs: &[u256],
) -> (Result<bool, ZkError>, Option<ZkFailureContext>) {
    if vk.ic.is_empty() || public_inputs.len() != vk.ic.len() - 1 {
        return (
            Err(ZkError::InvalidInput),
            Some(ZkFailureContext::with_info(
                env,
                "public input count does not match the verifying key",
            )),
        );
    }

    // Validate each public input and track which one fails.
    for (index, input) in public_inputs.iter().enumerate() {
        if !Bn254::is_valid_scalar(*input) {
            return (
                Err(ZkError::InvalidFieldElement),
                Some(ZkFailureContext::invalid_input(index as u32)),
            );
        }
    }

    let acc = if public_inputs.is_empty() {
        vk.ic[0]
    } else {
        let msm = match g1_msm(env, &vk.ic[1..], public_inputs) {
            Ok(msm) => msm,
            Err(e) => {
                return (
                    Err(e),
                    Some(ZkFailureContext::with_info(
                        env,
                        "public input commitment could not be computed",
                    )),
                )
            }
        };
        vk.ic[0].add(&msm)
    };

    let pairs = [
        (proof.a, proof.b),
        (neg_g1(vk.alpha_g1), vk.beta_g2),
        (neg_g1(proof.c), vk.delta_g2),
        (neg_g1(acc), vk.gamma_g2),
    ];

    // `acc` is the point at infinity when `IC_0 + MSM` cancels out. Then
    // `e(-acc, gamma) == 1`, so the factor is dropped instead of handing the
    // non-affine (0, 0) encoding to the pairing check (which rejects it).
    let pairs: &[(G1Affine, G2Affine)] = if is_g1_identity(&acc) {
        &pairs[..3]
    } else {
        &pairs
    };

    match pairing_check(env, pairs) {
        Ok(result) => (Ok(result), None),
        Err(e) => (
            Err(e),
            Some(ZkFailureContext::with_info(env, "pairing check failed")),
        ),
    }
}

/// Domain separator for the batch-verification Fiat-Shamir transcript.
const BATCH_TRANSCRIPT_DOMAIN: &[u8] = b"soroban-zk-std/groth16-batch/v1";

/// Batch-verifies `M` Groth16 proofs against one verifying key with a single
/// multi-pairing check of `M + 3` pairs (instead of `4M` pairings).
///
/// For unpredictable non-zero scalars `r_j` it checks
///
/// `Π_j e(r_j·A_j, B_j) == e(Σ r_j·alpha, beta) · e(Σ r_j·acc_j, gamma) · e(Σ r_j·C_j, delta)`
///
/// as `Π_j e(r_j·A_j, B_j) · e(-(Σ r_j)·alpha, beta) · e(-Σ r_j·acc_j, gamma) · e(-Σ r_j·C_j, delta) == 1`,
/// where `acc_j = IC_0 + Σ_i s_{j,i}·IC_i`. The aggregated `Σ r_j·acc_j` is
/// computed as one MSM over `IC` with scalars `(Σ_j r_j, Σ_j r_j·s_{j,1}, …)`.
///
/// The `r_j` are derived Fiat-Shamir style from a SHA-256 transcript (host
/// `sha256`) absorbing the verifying key and every `(proof_j, inputs_j)`, so a
/// prover cannot choose proofs whose errors cancel across the batch. Each
/// `r_j = H(seed || j) mod r`, mapped to `1` in the negligible case it is zero.
///
/// Returns `Ok(true)` only if every proof in the batch is valid; `Ok(false)` if
/// at least one is invalid (the batch does not identify which one).
///
/// # Errors
/// - [`ZkError::InvalidInput`]: empty batch, `proofs.len() != public_inputs_batch.len()`,
///   an input vector whose length is not `vk.ic.len() - 1`, an empty `vk.ic`,
///   an identity `alpha`, or an `A`/`C` point that is not a valid G1 point.
/// - [`ZkError::InvalidFieldElement`]: a public input `>= r`.
pub fn groth16_verify_batch(
    env: &Env,
    vk: &Groth16VerifyingKey<'_>,
    proofs: &[Groth16Proof],
    public_inputs_batch: &[&[u256]],
) -> Result<bool, ZkError> {
    if proofs.is_empty() || proofs.len() != public_inputs_batch.len() {
        return Err(ZkError::InvalidInput);
    }
    if proofs.len() > u32::MAX as usize {
        return Err(ZkError::InvalidInput);
    }
    if vk.ic.is_empty() || is_g1_identity(&vk.alpha_g1) {
        return Err(ZkError::InvalidInput);
    }

    let n_inputs = vk.ic.len() - 1;
    for inputs in public_inputs_batch {
        if inputs.len() != n_inputs {
            return Err(ZkError::InvalidInput);
        }
        for (index, input) in inputs.iter().enumerate() {
            if !Bn254::is_valid_scalar(*input) {
                let _context = ZkFailureContext::invalid_input(index as u32);
                return Err(ZkError::InvalidFieldElement);
            }
        }
    }

    // A and C are fed to host MSM / scalar-mul calls, which trap on malformed
    // points, so reject them gracefully first. BN254 G1 has cofactor 1, so the
    // on-curve check is also the subgroup check. B is validated by the pairing
    // check below.
    for proof in proofs {
        if !Bn254::is_valid_g1(proof.a.x, proof.a.y) || !Bn254::is_valid_g1(proof.c.x, proof.c.y) {
            return Err(ZkError::InvalidInput);
        }
    }

    // A batch of one gains nothing from randomisation.
    if proofs.len() == 1 {
        return groth16_verify(env, vk, &proofs[0], public_inputs_batch[0]);
    }

    let seed = batch_transcript_seed(env, vk, proofs, public_inputs_batch);

    let mut pairs: AllocVec<(G1Affine, G2Affine)> = AllocVec::with_capacity(proofs.len() + 3);
    let mut r_values: AllocVec<u256> = AllocVec::with_capacity(proofs.len());
    let mut c_points: AllocVec<G1Affine> = AllocVec::with_capacity(proofs.len());
    let mut ic_scalars: AllocVec<u256> = AllocVec::with_capacity(vk.ic.len());
    ic_scalars.resize(vk.ic.len(), u256::from(0u8));

    for (j, (proof, inputs)) in proofs.iter().zip(public_inputs_batch.iter()).enumerate() {
        let r_j = batch_challenge(env, &seed, j as u32);
        r_values.push(r_j);
        c_points.push(proof.c);

        // Σ_j r_j for IC_0, Σ_j r_j·s_{j,i} for IC_i.
        ic_scalars[0] = Bn254::add(ic_scalars[0], r_j);
        for (slot, input) in ic_scalars[1..].iter_mut().zip(inputs.iter()) {
            *slot = Bn254::add(*slot, Bn254::mul(r_j, *input));
        }

        let r_a = g1_msm(env, &[proof.a], &[r_j])?;
        pairs.push((r_a, proof.b));
    }

    let alpha_sum = g1_msm(env, &[vk.alpha_g1], &[ic_scalars[0]])?;
    let acc_sum = g1_msm(env, vk.ic, &ic_scalars)?;
    let c_sum = g1_msm(env, &c_points, &r_values)?;

    // Identity terms contribute a factor of 1 and are omitted.
    for (point, g2) in [
        (alpha_sum, vk.beta_g2),
        (acc_sum, vk.gamma_g2),
        (c_sum, vk.delta_g2),
    ] {
        if !is_g1_identity(&point) {
            pairs.push((neg_g1(point), g2));
        }
    }

    pairing_check(env, &pairs)
}

/// Hashes the verifying key and every `(proof_j, inputs_j)` into a 32-byte seed.
fn batch_transcript_seed(
    env: &Env,
    vk: &Groth16VerifyingKey<'_>,
    proofs: &[Groth16Proof],
    public_inputs_batch: &[&[u256]],
) -> [u8; 32] {
    let mut transcript = Bytes::new(env);
    transcript.extend_from_slice(BATCH_TRANSCRIPT_DOMAIN);
    transcript.extend_from_array(&g1_to_bytes(&vk.alpha_g1));
    transcript.extend_from_array(&vk.beta_g2.to_bytes());
    transcript.extend_from_array(&vk.gamma_g2.to_bytes());
    transcript.extend_from_array(&vk.delta_g2.to_bytes());
    transcript.extend_from_array(&(vk.ic.len() as u32).to_be_bytes());
    for point in vk.ic {
        transcript.extend_from_array(&g1_to_bytes(point));
    }
    transcript.extend_from_array(&(proofs.len() as u32).to_be_bytes());
    for (proof, inputs) in proofs.iter().zip(public_inputs_batch.iter()) {
        transcript.extend_from_array(&proof.to_bytes());
        for input in inputs.iter() {
            transcript.extend_from_array(&input.to_be_bytes());
        }
    }
    env.crypto().sha256(&transcript).to_array()
}

/// Derives the non-zero batch scalar `r_j = H(seed || j) mod r`.
fn batch_challenge(env: &Env, seed: &[u8; 32], index: u32) -> u256 {
    let mut buf = [0u8; 36];
    buf[..32].copy_from_slice(seed);
    buf[32..].copy_from_slice(&index.to_be_bytes());
    let digest = env
        .crypto()
        .sha256(&Bytes::from_array(env, &buf))
        .to_array();
    let r = u256::from_be_bytes(digest) % Bn254::FR_MODULUS;
    if r == u256::from(0u8) {
        u256::from(1u8)
    } else {
        r
    }
}

/// The affine point at infinity is encoded as `(0, 0)` throughout this crate
/// and by the CAP-0075 host functions.
fn is_g1_identity(point: &G1Affine) -> bool {
    point.x == u256::from(0u8) && point.y == u256::from(0u8)
}

/// Decodes a G1 point returned by a host function, accepting the all-zero
/// point-at-infinity encoding (e.g. an MSM whose scalars are all zero) that
/// [`g1_from_bytes`] rejects for untrusted input.
fn g1_from_host_result(bytes: &[u8; 64]) -> Result<G1Affine, ZkError> {
    if bytes.iter().all(|b| *b == 0) {
        return Ok(G1Affine {
            x: u256::from(0u8),
            y: u256::from(0u8),
        });
    }
    g1_from_bytes(bytes)
}

pub(crate) fn g1_from_bytes(bytes: &[u8]) -> Result<G1Affine, ZkError> {
    g1_from_bytes_detailed(bytes, 0).0
}

/// G1 decoder that also reports the byte offset of the malformed component.
///
/// `offset` is where this point starts inside the full proof encoding (0 for A,
/// 192 for C), so callers can surface a precise `deserialization_error`.
pub(crate) fn g1_from_bytes_detailed(
    bytes: &[u8],
    offset: u32,
) -> (Result<G1Affine, ZkError>, Option<ZkFailureContext>) {
    if bytes.len() != 64 {
        return (
            Err(ZkError::DeserializationError),
            Some(ZkFailureContext::deserialization_error(offset)),
        );
    }

    let mut x_bytes = [0u8; 32];
    let mut y_bytes = [0u8; 32];
    x_bytes.copy_from_slice(&bytes[..32]);
    y_bytes.copy_from_slice(&bytes[32..64]);

    let x = match Bn254::fq_from_bytes(x_bytes) {
        Some(x) => x,
        None => {
            return (
                Err(ZkError::DeserializationError),
                Some(ZkFailureContext::deserialization_error(offset)),
            )
        }
    };
    let y = match Bn254::fq_from_bytes(y_bytes) {
        Some(y) => y,
        None => {
            return (
                Err(ZkError::DeserializationError),
                Some(ZkFailureContext::deserialization_error(offset)),
            )
        }
    };

    if !Bn254::is_valid_g1_subgroup(x, y) {
        return (
            Err(ZkError::DeserializationError),
            Some(ZkFailureContext::deserialization_error(offset)),
        );
    }

    (Ok(G1Affine { x, y }), None)
}

pub(crate) fn g2_from_bytes(bytes: &[u8]) -> Result<G2Affine, ZkError> {
    g2_from_bytes_detailed(bytes).0
}

/// G2 decoder that also reports the byte offset of the malformed component.
pub(crate) fn g2_from_bytes_detailed(
    bytes: &[u8],
) -> (Result<G2Affine, ZkError>, Option<ZkFailureContext>) {
    if bytes.len() != 128 {
        return (
            Err(ZkError::DeserializationError),
            Some(ZkFailureContext::deserialization_error(64)),
        );
    }

    let x1 = match read_fq(&bytes[0..32]) {
        Ok(value) => value,
        Err(e) => return (Err(e), Some(ZkFailureContext::deserialization_error(64))),
    };
    let x0 = match read_fq(&bytes[32..64]) {
        Ok(value) => value,
        Err(e) => return (Err(e), Some(ZkFailureContext::deserialization_error(96))),
    };
    let y1 = match read_fq(&bytes[64..96]) {
        Ok(value) => value,
        Err(e) => return (Err(e), Some(ZkFailureContext::deserialization_error(128))),
    };
    let y0 = match read_fq(&bytes[96..128]) {
        Ok(value) => value,
        Err(e) => return (Err(e), Some(ZkFailureContext::deserialization_error(160))),
    };

    let g2 = G2Affine {
        x: (x0, x1),
        y: (y0, y1),
    };

    // Validate that the deserialized G2 point is on the curve AND in the prime-order
    // subgroup. This ensures that untrusted proof data cannot contain invalid-curve
    // or small-subgroup G2 elements that would otherwise break proof soundness.
    if !validate_g2_coords(&g2) {
        return (
            Err(ZkError::DeserializationError),
            Some(ZkFailureContext::deserialization_error(64)),
        );
    }

    (Ok(g2), None)
}

fn read_fq(bytes: &[u8]) -> Result<u256, ZkError> {
    if bytes.len() != 32 {
        return Err(ZkError::DeserializationError);
    }

    let mut field_bytes = [0u8; 32];
    field_bytes.copy_from_slice(bytes);
    Bn254::fq_from_bytes(field_bytes).ok_or(ZkError::DeserializationError)
}

fn g1_msm(env: &Env, points: &[G1Affine], scalars: &[u256]) -> Result<G1Affine, ZkError> {
    if points.is_empty() || points.len() != scalars.len() {
        return Err(ZkError::InvalidInput);
    }

    let mut sdk_points: Vec<SdkG1Affine> = Vec::new(env);
    let mut sdk_scalars: Vec<SdkFr> = Vec::new(env);

    for point in points {
        sdk_points.push_back(SdkG1Affine::from_bytes(BytesN::from_array(
            env,
            &g1_to_bytes(point),
        )));
    }

    for scalar in scalars {
        let scalar_u256 = U256::from_be_bytes(env, &Bytes::from_array(env, &scalar.to_be_bytes()));
        sdk_scalars.push_back(SdkFr::from_u256(scalar_u256));
    }

    let result = env.crypto().bn254().g1_msm(sdk_points, sdk_scalars);
    g1_from_host_result(&result.to_array())
}

fn neg_g1(point: G1Affine) -> G1Affine {
    if is_g1_identity(&point) {
        point
    } else {
        G1Affine {
            x: point.x,
            y: Bn254::sub_fq(u256::from(0u8), point.y),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::{Bn254 as ArkBn254, Fr as ArkFr};
    use ark_ff::{BigInteger, PrimeField};
    use ark_groth16::{prepare_verifying_key, Groth16};
    use ark_relations::gr1cs::{
        ConstraintSynthesizer, ConstraintSystemRef, LinearCombination, SynthesisError,
    };
    use ark_snark::SNARK;
    use ark_std::rand::{rngs::StdRng, SeedableRng};
    use soroban_sdk::Env;

    // ── Detailed-context coverage (Issue #596) ───────────────────────────────

    /// A canonical generator encoding for G1 (x = 1, y = 2), used to make the
    /// later components of a proof the only invalid part.
    fn g1_generator_bytes() -> [u8; 64] {
        let mut out = [0u8; 64];
        out[31] = 1;
        out[63] = 2;
        out
    }

    #[test]
    fn detailed_deserialization_reports_byte_length_for_wrong_size() {
        let (result, context) = Groth16Proof::from_bytes_detailed(&[0u8; 10]);
        assert_eq!(result, Err(ZkError::DeserializationError));
        let context = context.expect("wrong-length proofs must carry context");
        assert_eq!(context.byte_offset, Some(10));
        assert!(context.invalid_point.is_none());
    }

    #[test]
    fn detailed_deserialization_reports_offset_of_first_invalid_g1() {
        // A = (0, 0) is not a valid untrusted G1 encoding, so the failure is at
        // the start of the proof.
        let (result, context) = Groth16Proof::from_bytes_detailed(&[0u8; 256]);
        assert_eq!(result, Err(ZkError::DeserializationError));
        assert_eq!(context.expect("context").byte_offset, Some(0));
    }

    #[test]
    fn detailed_deserialization_reports_offset_of_invalid_g2() {
        let mut bytes = [0u8; 256];
        bytes[..64].copy_from_slice(&g1_generator_bytes());
        // B stays all-zero, which is not a valid G2 point (it starts at 64).
        let (result, context) = Groth16Proof::from_bytes_detailed(&bytes);
        assert_eq!(result, Err(ZkError::DeserializationError));
        assert_eq!(context.expect("context").byte_offset, Some(64));
    }

    #[test]
    fn detailed_verification_reports_invalid_public_input_index() {
        let env = Env::default();
        let point = G1Affine {
            x: u256::from(1u8),
            y: u256::from(2u8),
        };
        let g2 = G2Affine {
            x: (u256::from(1u8), u256::from(2u8)),
            y: (u256::from(1u8), u256::from(2u8)),
        };
        let ic = [point, point];
        let vk = Groth16VerifyingKey {
            alpha_g1: point,
            beta_g2: g2,
            gamma_g2: g2,
            delta_g2: g2,
            ic: &ic,
        };
        let proof = Groth16Proof {
            a: point,
            b: g2,
            c: point,
        };

        // `u256::MAX` is above the BN254 scalar modulus; the check runs before
        // any MSM or pairing work.
        let (result, context) =
            groth16_verify_detailed(&env, &vk, &proof, &[u256::MAX]);
        assert_eq!(result, Err(ZkError::InvalidFieldElement));
        let context = context.expect("invalid inputs must carry context");
        assert_eq!(context.invalid_input_index, Some(0));
    }

    #[test]
    fn detailed_verification_reports_ic_length_mismatch() {
        let env = Env::default();
        let point = G1Affine {
            x: u256::from(1u8),
            y: u256::from(2u8),
        };
        let g2 = G2Affine {
            x: (u256::from(1u8), u256::from(2u8)),
            y: (u256::from(1u8), u256::from(2u8)),
        };
        let ic = [point];
        let vk = Groth16VerifyingKey {
            alpha_g1: point,
            beta_g2: g2,
            gamma_g2: g2,
            delta_g2: g2,
            ic: &ic,
        };
        let proof = Groth16Proof {
            a: point,
            b: g2,
            c: point,
        };

        // One public input is supplied but the VK commits to zero.
        let (result, context) = groth16_verify_detailed(&env, &vk, &proof, &[u256::from(1u8)]);
        assert_eq!(result, Err(ZkError::InvalidInput));
        let context = context.expect("mismatched input counts must carry context");
        assert!(context.context_info.is_some());
    }

    #[derive(Clone)]
    struct SquareCircuit {
        x: Option<ArkFr>,
        public_square: Option<ArkFr>,
    }

    impl ConstraintSynthesizer<ArkFr> for SquareCircuit {
        fn generate_constraints(
            self,
            cs: ConstraintSystemRef<ArkFr>,
        ) -> Result<(), SynthesisError> {
            let x = cs.new_witness_variable(|| self.x.ok_or(SynthesisError::AssignmentMissing))?;
            let square = cs.new_input_variable(|| {
                self.public_square.ok_or(SynthesisError::AssignmentMissing)
            })?;

            cs.enforce_r1cs_constraint(
                || LinearCombination::from(x),
                || LinearCombination::from(x),
                || LinearCombination::from(square),
            )
        }
    }

    #[test]
    fn proof_from_bytes_round_trips_layout() {
        let proof = Groth16Proof {
            a: g1_generator(),
            b: g2_generator(),
            c: g1_generator(),
        };

        let mut bytes = [0u8; 256];
        bytes[..64].copy_from_slice(&g1_to_bytes(&proof.a));
        bytes[64..192].copy_from_slice(&proof.b.to_bytes());
        bytes[192..].copy_from_slice(&g1_to_bytes(&proof.c));

        assert_eq!(Groth16Proof::from_bytes(&bytes), Ok(proof));
    }

    #[test]
    fn proof_from_bytes_rejects_wrong_length() {
        assert_eq!(
            Groth16Proof::from_bytes(&[0u8; 255]),
            Err(ZkError::DeserializationError)
        );
    }

    #[test]
    fn proof_from_bytes_rejects_invalid_g2_not_on_curve() {
        // Create a valid proof layout but with a G2 point perturbed to be off-curve
        let valid_proof = Groth16Proof {
            a: g1_generator(),
            b: g2_generator(),
            c: g1_generator(),
        };

        let mut bytes = [0u8; 256];
        bytes[..64].copy_from_slice(&g1_to_bytes(&valid_proof.a));
        bytes[64..192].copy_from_slice(&valid_proof.b.to_bytes());
        bytes[192..].copy_from_slice(&g1_to_bytes(&valid_proof.c));

        // Perturb the G2 y-coordinate (byte 64+32+32 = 128, real part)
        // This changes y0 to be slightly different
        bytes[128] = bytes[128].wrapping_add(1);

        // The deserialized proof should reject this invalid G2 point
        assert_eq!(
            Groth16Proof::from_bytes(&bytes),
            Err(ZkError::DeserializationError),
            "Proof with off-curve G2 point should be rejected at deserialization"
        );
    }

    #[test]
    fn proof_from_bytes_rejects_g2_at_zero() {
        let mut bytes = [0u8; 256];
        // Set all G2 coordinates to zero (byte 64-192)
        // bytes 64-192 are already zero from initialization

        bytes[..64].copy_from_slice(&g1_to_bytes(&g1_generator()));
        // bytes[64..192] remain 0 (invalid G2 point at zero)
        bytes[192..].copy_from_slice(&g1_to_bytes(&g1_generator()));

        assert_eq!(
            Groth16Proof::from_bytes(&bytes),
            Err(ZkError::DeserializationError),
            "Proof with G2 point at (0, 0) should be rejected"
        );
    }

    #[test]
    fn groth16_verify_rejects_wrong_public_input_len() {
        let env = Env::default();
        let proof = Groth16Proof {
            a: g1_generator(),
            b: g2_generator(),
            c: g1_generator(),
        };
        let vk = Groth16VerifyingKey {
            alpha_g1: g1_generator(),
            beta_g2: g2_generator(),
            gamma_g2: g2_generator(),
            delta_g2: g2_generator(),
            ic: &[g1_generator()],
        };

        assert_eq!(
            groth16_verify(&env, &vk, &proof, &[u256::from(1u8)]),
            Err(ZkError::InvalidInput)
        );
    }

    #[test]
    fn groth16_verify_rejects_out_of_range_public_input() {
        let env = Env::default();
        let proof = Groth16Proof {
            a: g1_generator(),
            b: g2_generator(),
            c: g1_generator(),
        };
        let ic = [g1_generator(), g1_generator()];
        let vk = Groth16VerifyingKey {
            alpha_g1: g1_generator(),
            beta_g2: g2_generator(),
            gamma_g2: g2_generator(),
            delta_g2: g2_generator(),
            ic: &ic,
        };

        assert_eq!(
            groth16_verify(&env, &vk, &proof, &[Bn254::FR_MODULUS]),
            Err(ZkError::InvalidFieldElement)
        );
    }

    #[test]
    fn groth16_verify_accepts_valid_proof_and_rejects_wrong_input() {
        let env = Env::default();
        let mut rng = StdRng::seed_from_u64(7);
        let setup_circuit = SquareCircuit {
            x: None,
            public_square: None,
        };

        let (pk, vk) = Groth16::<ArkBn254>::circuit_specific_setup(setup_circuit, &mut rng)
            .expect("setup should succeed");

        let public_square = ArkFr::from(9u64);
        let proof = Groth16::<ArkBn254>::prove(
            &pk,
            SquareCircuit {
                x: Some(ArkFr::from(3u64)),
                public_square: Some(public_square),
            },
            &mut rng,
        )
        .expect("proof generation should succeed");

        let pvk = prepare_verifying_key(&vk);
        assert!(
            Groth16::<ArkBn254>::verify_with_processed_vk(&pvk, &[public_square], &proof)
                .expect("arkworks verification should succeed")
        );

        let ic = [
            ark_g1_to_local(vk.gamma_abc_g1[0]),
            ark_g1_to_local(vk.gamma_abc_g1[1]),
        ];
        let local_vk = Groth16VerifyingKey {
            alpha_g1: ark_g1_to_local(vk.alpha_g1),
            beta_g2: ark_g2_to_local(vk.beta_g2),
            gamma_g2: ark_g2_to_local(vk.gamma_g2),
            delta_g2: ark_g2_to_local(vk.delta_g2),
            ic: &ic,
        };
        let local_proof = Groth16Proof {
            a: ark_g1_to_local(proof.a),
            b: ark_g2_to_local(proof.b),
            c: ark_g1_to_local(proof.c),
        };
        let correct_input = [ark_fr_to_u256(public_square)];
        let wrong_input = [u256::from(8u8)];

        assert_eq!(
            groth16_verify(&env, &local_vk, &local_proof, &correct_input),
            Ok(true)
        );
        assert_eq!(
            groth16_verify(&env, &local_vk, &local_proof, &wrong_input),
            Ok(false)
        );
    }

    /// Arkworks-generated `x² = square` circuit fixture (one public input).
    struct SquareFixture {
        pk: ark_groth16::ProvingKey<ArkBn254>,
        pvk: ark_groth16::PreparedVerifyingKey<ArkBn254>,
        alpha_g1: G1Affine,
        beta_g2: G2Affine,
        gamma_g2: G2Affine,
        delta_g2: G2Affine,
        ic: [G1Affine; 2],
        rng: StdRng,
    }

    impl SquareFixture {
        fn new(seed: u64) -> Self {
            let mut rng = StdRng::seed_from_u64(seed);
            let (pk, vk) = Groth16::<ArkBn254>::circuit_specific_setup(
                SquareCircuit {
                    x: None,
                    public_square: None,
                },
                &mut rng,
            )
            .expect("setup should succeed");
            Self {
                pvk: prepare_verifying_key(&vk),
                alpha_g1: ark_g1_to_local(vk.alpha_g1),
                beta_g2: ark_g2_to_local(vk.beta_g2),
                gamma_g2: ark_g2_to_local(vk.gamma_g2),
                delta_g2: ark_g2_to_local(vk.delta_g2),
                ic: [
                    ark_g1_to_local(vk.gamma_abc_g1[0]),
                    ark_g1_to_local(vk.gamma_abc_g1[1]),
                ],
                pk,
                rng,
            }
        }

        fn vk(&self) -> Groth16VerifyingKey<'_> {
            Groth16VerifyingKey {
                alpha_g1: self.alpha_g1,
                beta_g2: self.beta_g2,
                gamma_g2: self.gamma_g2,
                delta_g2: self.delta_g2,
                ic: &self.ic,
            }
        }

        /// Proves knowledge of `x` with public input `x²`, cross-checked by arkworks.
        fn prove(&mut self, x: u64) -> (Groth16Proof, [u256; 1]) {
            let square = ArkFr::from(x) * ArkFr::from(x);
            let proof = Groth16::<ArkBn254>::prove(
                &self.pk,
                SquareCircuit {
                    x: Some(ArkFr::from(x)),
                    public_square: Some(square),
                },
                &mut self.rng,
            )
            .expect("proof generation should succeed");
            assert!(
                Groth16::<ArkBn254>::verify_with_processed_vk(&self.pvk, &[square], &proof)
                    .expect("arkworks verification should succeed")
            );
            (
                Groth16Proof {
                    a: ark_g1_to_local(proof.a),
                    b: ark_g2_to_local(proof.b),
                    c: ark_g1_to_local(proof.c),
                },
                [ark_fr_to_u256(square)],
            )
        }
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn proof_to_bytes_round_trips_with_from_bytes() {
        let generator_proof = Groth16Proof {
            a: g1_generator(),
            b: g2_generator(),
            c: g1_generator(),
        };
        assert_eq!(
            Groth16Proof::from_bytes(&generator_proof.to_bytes()),
            Ok(generator_proof)
        );

        let mut fixture = SquareFixture::new(11);
        let (proof, _) = fixture.prove(3);
        let bytes = proof.to_bytes();
        assert_eq!(Groth16Proof::from_bytes(&bytes), Ok(proof));
        assert_eq!(
            Groth16Proof::from_bytes(&bytes).map(|p| p.to_bytes()),
            Ok(bytes)
        );
    }

    #[test]
    fn g1_from_host_result_maps_zero_bytes_to_identity() {
        let identity = g1_from_host_result(&[0u8; 64]).expect("identity must decode");
        assert!(is_g1_identity(&identity));
        assert_eq!(
            g1_from_host_result(&g1_to_bytes(&g1_generator())),
            Ok(g1_generator())
        );
        // Untrusted proof bytes still reject the (0, 0) encoding.
        assert_eq!(
            g1_from_bytes(&[0u8; 64]),
            Err(ZkError::DeserializationError)
        );
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn groth16_verify_accepts_zero_public_input() {
        // x = 0 gives public input 0, so the host MSM returns the point at
        // infinity (previously rejected with DeserializationError).
        let env = Env::default();
        let mut fixture = SquareFixture::new(21);
        let (proof, inputs) = fixture.prove(0);
        assert_eq!(inputs, [u256::from(0u8)]);

        let vk = fixture.vk();
        assert_eq!(groth16_verify(&env, &vk, &proof, &inputs), Ok(true));
        assert_eq!(
            groth16_verify(&env, &vk, &proof, &[u256::from(1u8)]),
            Ok(false)
        );
    }

    #[test]
    fn g1_msm_with_all_zero_scalars_is_identity() {
        let env = Env::default();
        let result = g1_msm(
            &env,
            &[g1_generator(), g1_generator()],
            &[u256::from(0u8), u256::from(0u8)],
        );
        assert!(matches!(result, Ok(p) if is_g1_identity(&p)));
    }

    /// Several full verifications in one test exceed the default per-`Env`
    /// budget, so batch tests lift the limit.
    fn unlimited_env() -> Env {
        let env = Env::default();
        env.cost_estimate().budget().reset_unlimited();
        env
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn groth16_verify_batch_is_cheaper_than_individual_verification() {
        let mut fixture = SquareFixture::new(61);
        let (p0, i0) = fixture.prove(0);
        let (p1, i1) = fixture.prove(2);
        let (p2, i2) = fixture.prove(3);
        let (p3, i3) = fixture.prove(5);
        let proofs = [p0, p1, p2, p3];
        let inputs: [&[u256]; 4] = [&i0, &i1, &i2, &i3];
        let vk = fixture.vk();

        let single_env = unlimited_env();
        for (proof, input) in proofs.iter().zip(inputs.iter()) {
            assert_eq!(groth16_verify(&single_env, &vk, proof, input), Ok(true));
        }
        let single_cost = single_env.cost_estimate().budget().cpu_instruction_cost();

        let batch_env = unlimited_env();
        assert_eq!(
            groth16_verify_batch(&batch_env, &vk, &proofs, &inputs),
            Ok(true)
        );
        let batch_cost = batch_env.cost_estimate().budget().cpu_instruction_cost();

        assert!(
            batch_cost < single_cost,
            "batch ({batch_cost}) should cost less host CPU than 4 single verifies ({single_cost})"
        );
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn groth16_verify_batch_accepts_four_valid_proofs() {
        let env = unlimited_env();
        let mut fixture = SquareFixture::new(31);
        // Includes x = 0 (public input 0) to cover the identity MSM path.
        let (p0, i0) = fixture.prove(0);
        let (p1, i1) = fixture.prove(2);
        let (p2, i2) = fixture.prove(3);
        let (p3, i3) = fixture.prove(5);
        let proofs = [p0, p1, p2, p3];
        let inputs: [&[u256]; 4] = [&i0, &i1, &i2, &i3];

        let vk = fixture.vk();
        for (proof, input) in proofs.iter().zip(inputs.iter()) {
            assert_eq!(groth16_verify(&env, &vk, proof, input), Ok(true));
        }
        assert_eq!(groth16_verify_batch(&env, &vk, &proofs, &inputs), Ok(true));
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn groth16_verify_batch_rejects_single_corrupted_proof() {
        let env = unlimited_env();
        let mut fixture = SquareFixture::new(41);
        let (p0, i0) = fixture.prove(1);
        let (p1, i1) = fixture.prove(4);
        let (p2, i2) = fixture.prove(6);
        let (p3, i3) = fixture.prove(7);
        let vk = fixture.vk();

        // Corrupt one proof: swap in another proof's (valid, on-curve) A point.
        let mut corrupted = p2;
        corrupted.a = p1.a;
        let proofs = [p0, p1, corrupted, p3];
        let inputs: [&[u256]; 4] = [&i0, &i1, &i2, &i3];
        assert_eq!(groth16_verify(&env, &vk, &corrupted, &i2), Ok(false));
        assert_eq!(groth16_verify_batch(&env, &vk, &proofs, &inputs), Ok(false));

        // Valid proofs with one wrong public input are rejected too.
        let wrong = [u256::from(8u8)];
        let inputs: [&[u256]; 4] = [&i0, &i1, &wrong, &i3];
        assert_eq!(
            groth16_verify_batch(&env, &vk, &[p0, p1, p2, p3], &inputs),
            Ok(false)
        );

        // Swapping two proofs' inputs must not verify either.
        let inputs: [&[u256]; 4] = [&i1, &i0, &i2, &i3];
        assert_eq!(
            groth16_verify_batch(&env, &vk, &[p0, p1, p2, p3], &inputs),
            Ok(false)
        );
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn groth16_verify_batch_of_one_matches_single_verify() {
        let env = Env::default();
        let mut fixture = SquareFixture::new(51);
        let (proof, inputs) = fixture.prove(3);
        let vk = fixture.vk();
        assert_eq!(
            groth16_verify_batch(&env, &vk, &[proof], &[&inputs]),
            Ok(true)
        );
        assert_eq!(
            groth16_verify_batch(&env, &vk, &[proof], &[&[u256::from(8u8)]]),
            Ok(false)
        );
    }

    #[test]
    fn groth16_verify_batch_rejects_malformed_batches() {
        let env = Env::default();
        let proof = Groth16Proof {
            a: g1_generator(),
            b: g2_generator(),
            c: g1_generator(),
        };
        let ic = [g1_generator(), g1_generator()];
        let vk = Groth16VerifyingKey {
            alpha_g1: g1_generator(),
            beta_g2: g2_generator(),
            gamma_g2: g2_generator(),
            delta_g2: g2_generator(),
            ic: &ic,
        };
        let one = [u256::from(1u8)];

        // Empty batch.
        assert_eq!(
            groth16_verify_batch(&env, &vk, &[], &[]),
            Err(ZkError::InvalidInput)
        );
        // proofs / inputs length mismatch.
        assert_eq!(
            groth16_verify_batch(&env, &vk, &[proof, proof], &[&one]),
            Err(ZkError::InvalidInput)
        );
        // Per-proof public input count does not match vk.ic.
        assert_eq!(
            groth16_verify_batch(
                &env,
                &vk,
                &[proof, proof],
                &[&one, &[u256::from(1u8), u256::from(2u8)]]
            ),
            Err(ZkError::InvalidInput)
        );
        assert_eq!(
            groth16_verify_batch(&env, &vk, &[proof, proof], &[&one, &[]]),
            Err(ZkError::InvalidInput)
        );
        // Public input outside the scalar field.
        assert_eq!(
            groth16_verify_batch(&env, &vk, &[proof, proof], &[&one, &[Bn254::FR_MODULUS]]),
            Err(ZkError::InvalidFieldElement)
        );
        // Off-curve A point is rejected before any host call.
        let mut bad = proof;
        bad.a.y = Bn254::add_fq(bad.a.y, u256::from(1u8));
        assert_eq!(
            groth16_verify_batch(&env, &vk, &[proof, bad], &[&one, &one]),
            Err(ZkError::InvalidInput)
        );
        // Empty IC in the verifying key.
        let empty_vk = Groth16VerifyingKey { ic: &[], ..vk };
        assert_eq!(
            groth16_verify_batch(&env, &empty_vk, &[proof], &[&[]]),
            Err(ZkError::InvalidInput)
        );
    }

    fn ark_fr_to_u256(value: ArkFr) -> u256 {
        let bytes = value.into_bigint().to_bytes_be();
        let mut out = [0u8; 32];
        out[32 - bytes.len()..].copy_from_slice(&bytes);
        u256::from_be_bytes(out)
    }

    fn ark_g1_to_local(point: ark_bn254::G1Affine) -> G1Affine {
        G1Affine {
            x: fq_to_u256(point.x),
            y: fq_to_u256(point.y),
        }
    }

    fn ark_g2_to_local(point: ark_bn254::G2Affine) -> G2Affine {
        G2Affine {
            x: (fq_to_u256(point.x.c0), fq_to_u256(point.x.c1)),
            y: (fq_to_u256(point.y.c0), fq_to_u256(point.y.c1)),
        }
    }

    fn fq_to_u256(value: ark_bn254::Fq) -> u256 {
        let bytes = value.into_bigint().to_bytes_be();
        let mut out = [0u8; 32];
        out[32 - bytes.len()..].copy_from_slice(&bytes);
        u256::from_be_bytes(out)
    }

    fn g1_generator() -> G1Affine {
        G1Affine {
            x: u256::from(1u8),
            y: u256::from(2u8),
        }
    }

    fn g2_generator() -> G2Affine {
        G2Affine {
            x: (
                u256::from_str_radix(
                    "1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed",
                    16,
                )
                .unwrap(),
                u256::from_str_radix(
                    "198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2",
                    16,
                )
                .unwrap(),
            ),
            y: (
                u256::from_str_radix(
                    "12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa",
                    16,
                )
                .unwrap(),
                u256::from_str_radix(
                    "090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b",
                    16,
                )
                .unwrap(),
            ),
        }
    }

    /// Computes a square root of an Fq² element `(a0, a1)` using the identity
    /// `(x + y·u)² = (x² - y², 2xy)`. Returns `None` if `a` is not a quadratic
    /// residue in Fq².
    fn fq2_sqrt(a: (u256, u256)) -> Option<(u256, u256)> {
        let norm = Bn254::add_fq(Bn254::mul_fq(a.0, a.0), Bn254::mul_fq(a.1, a.1));
        let alpha = Bn254::sqrt_fq(norm);
        if Bn254::mul_fq(alpha, alpha) != norm {
            return None;
        }
        let inv2 = Bn254::invert_fq(u256::from(2u8));
        let x2 = Bn254::mul_fq(Bn254::add_fq(alpha, a.0), inv2);
        let y2 = Bn254::mul_fq(Bn254::sub_fq(alpha, a.0), inv2);
        let x = Bn254::sqrt_fq(x2);
        if Bn254::mul_fq(x, x) != x2 {
            return None;
        }
        let mut y = Bn254::sqrt_fq(y2);
        if Bn254::mul_fq(y, y) != y2 {
            return None;
        }
        // Fix the sign of y so that 2xy == a.1 (the imaginary part constraint).
        if Bn254::mul_fq(Bn254::add_fq(x, x), y) != a.1 {
            y = Bn254::sub_fq(u256::from(0u8), y);
        }
        if Bn254::fq2_sq((x, y)) != a {
            return None;
        }
        Some((x, y))
    }

    /// Finds a G2 point that is on the curve `y² = x³ + β` but is NOT in the
    /// prime-order subgroup (i.e. `[r]·Q ≠ ∞`). With overwhelming probability a
    /// random on-curve point has full group order `r·h₂`, so the first on-curve
    /// point we find is off-subgroup.
    fn g2_off_subgroup_point() -> G2Affine {
        let beta = (Bn254::G2_B_REAL, Bn254::G2_B_IMAG);
        let mut x_re = u256::from(1u8);
        loop {
            let x = (x_re, u256::from(0u8));
            let x2 = Bn254::fq2_sq(x);
            let x3 = Bn254::fq2_mul(x2, x);
            let rhs = Bn254::fq2_add(x3, beta);
            if let Some(y) = fq2_sqrt(rhs) {
                if !Bn254::is_in_correct_subgroup(x, y) {
                    return G2Affine { x, y };
                }
            }
            x_re = Bn254::add_fq(x_re, u256::from(1u8));
        }
    }

    #[test]
    fn test_g2_from_bytes_accepts_valid_generator() {
        let g2 = g2_generator();
        let bytes = g2.to_bytes();
        assert_eq!(
            g2_from_bytes(&bytes),
            Ok(g2),
            "valid G2 generator should parse"
        );
    }

    #[test]
    fn test_g2_from_bytes_rejects_off_curve_point() {
        // Take a valid on-curve point and perturb its y-coordinate so it no longer
        // satisfies y² = x³ + β.
        let mut bad = g2_generator();
        bad.y.0 = Bn254::add_fq(bad.y.0, u256::from(1u8));

        let bytes = bad.to_bytes();
        assert_eq!(
            g2_from_bytes(&bytes),
            Err(ZkError::DeserializationError),
            "g2_from_bytes must reject an off-curve G2 point"
        );
    }

    #[test]
    fn test_g2_from_bytes_rejects_invalid_subgroup_point() {
        // Feed a point that is on the curve but NOT in the prime-order subgroup.
        let off_subgroup = g2_off_subgroup_point();
        // Sanity: it really is on the curve but not in the subgroup.
        assert!(Bn254::is_on_curve(off_subgroup.x, off_subgroup.y));
        assert!(!Bn254::is_in_correct_subgroup(
            off_subgroup.x,
            off_subgroup.y
        ));

        let bytes = off_subgroup.to_bytes();
        assert_eq!(
            g2_from_bytes(&bytes),
            Err(ZkError::DeserializationError),
            "g2_from_bytes must reject a G2 point outside the prime-order subgroup"
        );
    }
}
