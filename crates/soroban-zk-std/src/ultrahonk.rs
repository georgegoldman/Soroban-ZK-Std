//! Noir / Barretenberg UltraHonk verification core on Soroban.
//!
//! UltraHonk is the proof system emitted by `bb` for Noir circuits. Its verifier
//! is a pipeline of four stages, and this module implements every stage that is
//! independent of the circuit's relation:
//!
//! 1. **Byte parsing** — [`HonkVerifyingKey::from_bytes`] and
//!    [`HonkProof::from_bytes`] decode the flat Barretenberg encoding with
//!    strict length, field-range and subgroup validation.
//! 2. **Fiat–Shamir** — [`derive_honk_challenges`] absorbs the verifying key,
//!    public inputs, commitments and Sumcheck univariates into a
//!    [`HonkTranscript`] and derives the relation/Sumcheck challenges. Both
//!    Keccak-256 (the `bb` "Keccak" transcript) and Poseidon2 (the
//!    `bb` "Poseidon2" transcript) are supported.
//! 3. **Multilinear Sumcheck** — the rounds are verified with
//!    [`soroban_zk_core::sumcheck`], the allocation-free verifier in the core
//!    crate.
//! 4. **Zeromorph/Shplonk opening reduction** — every univariate opening claim
//!    produced by the Zeromorph reduction is batched with a random linear
//!    combination into a single `pairing_check`, so the whole opening stage
//!    costs two pairings regardless of how many polynomials were opened.
//!
//! # Scope
//!
//! The *relation* (the circuit's constraint system) is deliberately not baked
//! into this module: [`verify_ultrahonk`] takes the two relation-side values a
//! relation evaluator must produce, namely the initial Sumcheck claim and the
//! expected final evaluation. Everything else — parsing, transcript,
//! round-chain verification and the pairing reduction — is checked here. This
//! keeps the on-chain code independent of the circuit while still refusing any
//! proof whose Sumcheck chain or opening equations do not hold.
#![allow(clippy::too_many_arguments)]

use alloc::vec::Vec;

use ethnum::u256;
use soroban_sdk::{Bytes, Env};
use soroban_zk_core::hash::Hash;
use soroban_zk_core::sumcheck::{verify_sumcheck, RoundPolynomial, SumcheckReduction};
use soroban_zk_core::{poseidon2, Bn254, G1Affine, G1Projective, ZkError};

use crate::pairing::{pairing_check, validate_g2_coords, G2Affine};
use crate::vk::G1_GENERATOR;

// ── Encoding constants ──────────────────────────────────────────────────────

/// Version tag of the flat encoding decoded by this module.
///
/// Bump this whenever the field order of the Barretenberg encoding changes so a
/// stale proof is rejected as [`ZkError::DeserializationError`] instead of being
/// mis-parsed.
pub const HONK_FORMAT_VERSION: u32 = 1;

/// Size of a serialized BN254 Fr element.
pub const FR_BYTES: usize = 32;
/// Size of a serialized BN254 G1 point (`x || y`, big-endian).
pub const G1_BYTES: usize = 64;
/// Size of a serialized BN254 G2 point (EIP-197 layout).
pub const G2_BYTES: usize = 128;

/// Wire-polynomial commitments `w_l, w_r, w_o, w_4`.
pub const NUM_WIRE_COMMITMENTS: usize = 4;
/// Lookup commitments (`lookup_inverses`, `lookup_read_counts`, `lookup_read_tags`).
pub const NUM_LOOKUP_COMMITMENTS: usize = 3;
/// Libra (range-constraint) commitments.
pub const NUM_LIBRA_COMMITMENTS: usize = 3;
/// Preprocessed selector commitments in a verifying key.
pub const NUM_SELECTOR_COMMITMENTS: usize = 8;
/// Copy-permutation (sigma) commitments in a verifying key.
pub const NUM_SIGMA_COMMITMENTS: usize = 4;
/// Polynomial-identity commitments in a verifying key.
pub const NUM_ID_COMMITMENTS: usize = 4;
/// Lookup-table commitments in a verifying key.
pub const NUM_TABLE_COMMITMENTS: usize = 4;
/// Total G1 commitments in a verifying key.
pub const NUM_PREPROCESSED_COMMITMENTS: usize = NUM_SELECTOR_COMMITMENTS
    + NUM_SIGMA_COMMITMENTS
    + NUM_ID_COMMITMENTS
    + NUM_TABLE_COMMITMENTS
    + 2;

/// Evaluation claims at the Sumcheck point `ζ`.
pub const NUM_UNSHIFTED_EVALUATIONS: usize = 11;
/// Evaluation claims at the shifted point `ζ⁻¹` (Gemini).
pub const NUM_SHIFTED_EVALUATIONS: usize = NUM_WIRE_COMMITMENTS;
/// Total evaluation claims carried by a proof.
pub const NUM_SUMCHECK_EVALUATIONS: usize = NUM_UNSHIFTED_EVALUATIONS + NUM_SHIFTED_EVALUATIONS;

/// Maximum supported `log₂(circuit size)`; also the Sumcheck round bound.
pub const MAX_LOG_N: u32 = 24;
/// Coefficients per Sumcheck round polynomial (UltraHonk relations are degree 2).
pub const SUMCHECK_TERMS: usize = 3;

/// Identity G1 point encoding, accepted for commitments/opening proofs that are
/// legitimately zero.
pub const G1_IDENTITY: G1Affine = G1Affine {
    x: u256::from_words(0, 0),
    y: u256::from_words(0, 0),
};

// ── Byte parsing ────────────────────────────────────────────────────────────

fn take<'a>(bytes: &'a [u8], cursor: &mut usize, len: usize) -> Result<&'a [u8], ZkError> {
    let end = cursor
        .checked_add(len)
        .ok_or(ZkError::DeserializationError)?;
    let chunk = bytes
        .get(*cursor..end)
        .ok_or(ZkError::DeserializationError)?;
    *cursor = end;
    Ok(chunk)
}

fn read_u32(bytes: &[u8], cursor: &mut usize) -> Result<u32, ZkError> {
    let chunk = take(bytes, cursor, 4)?;
    let mut buf = [0u8; 4];
    buf.copy_from_slice(chunk);
    Ok(u32::from_be_bytes(buf))
}

fn read_fr(bytes: &[u8], cursor: &mut usize) -> Result<u256, ZkError> {
    let chunk = take(bytes, cursor, FR_BYTES)?;
    let mut buf = [0u8; FR_BYTES];
    buf.copy_from_slice(chunk);
    let value = u256::from_be_bytes(buf);
    if !Bn254::is_valid_scalar(value) {
        return Err(ZkError::InvalidFieldElement);
    }
    Ok(value)
}

fn read_g1(bytes: &[u8], cursor: &mut usize) -> Result<G1Affine, ZkError> {
    let chunk = take(bytes, cursor, G1_BYTES)?;
    let mut xb = [0u8; 32];
    let mut yb = [0u8; 32];
    xb.copy_from_slice(&chunk[..32]);
    yb.copy_from_slice(&chunk[32..]);
    let x = Bn254::fq_from_bytes(xb).ok_or(ZkError::DeserializationError)?;
    let y = Bn254::fq_from_bytes(yb).ok_or(ZkError::DeserializationError)?;
    // Barretenberg serializes the point at infinity as all-zero coordinates.
    if x == u256::from(0u8) && y == u256::from(0u8) {
        return Ok(G1_IDENTITY);
    }
    if !Bn254::is_valid_g1_subgroup(x, y) {
        return Err(ZkError::DeserializationError);
    }
    Ok(G1Affine { x, y })
}

fn read_g2(bytes: &[u8], cursor: &mut usize) -> Result<G2Affine, ZkError> {
    let chunk = take(bytes, cursor, G2_BYTES)?;
    let mut x1b = [0u8; 32];
    let mut x0b = [0u8; 32];
    let mut y1b = [0u8; 32];
    let mut y0b = [0u8; 32];
    x1b.copy_from_slice(&chunk[..32]);
    x0b.copy_from_slice(&chunk[32..64]);
    y1b.copy_from_slice(&chunk[64..96]);
    y0b.copy_from_slice(&chunk[96..]);
    let x = (
        Bn254::fq_from_bytes(x0b).ok_or(ZkError::DeserializationError)?,
        Bn254::fq_from_bytes(x1b).ok_or(ZkError::DeserializationError)?,
    );
    let y = (
        Bn254::fq_from_bytes(y0b).ok_or(ZkError::DeserializationError)?,
        Bn254::fq_from_bytes(y1b).ok_or(ZkError::DeserializationError)?,
    );
    let point = G2Affine { x, y };
    if !validate_g2_coords(&point) {
        return Err(ZkError::DeserializationError);
    }
    Ok(point)
}

fn read_g1_array<const N: usize>(
    bytes: &[u8],
    cursor: &mut usize,
) -> Result<[G1Affine; N], ZkError> {
    let mut out = [G1_IDENTITY; N];
    for slot in out.iter_mut() {
        *slot = read_g1(bytes, cursor)?;
    }
    Ok(out)
}

fn write_g1(out: &mut Vec<u8>, point: &G1Affine) {
    out.extend_from_slice(&point.x.to_be_bytes());
    out.extend_from_slice(&point.y.to_be_bytes());
}

// ── Verifying key ───────────────────────────────────────────────────────────

/// A parsed UltraHonk verifying key.
///
/// Flat encoding (all integers big-endian):
///
/// ```text
/// offset  size  field
/// 0       4     format version
/// 4       4     log2(circuit size) n
/// 8       4     number of public inputs
/// 12      512   selector commitments q_c, q_l, q_r, q_o, q_4, q_m, q_lookup, q_arith
/// 524     256   sigma_1 .. sigma_4
/// 780     256   id_1 .. id_4
/// 1036    256   table_1 .. table_4
/// 1292    64    lagrange_first
/// 1356    64    lagrange_last
/// 1420    128   SRS element [τ]₂
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HonkVerifyingKey {
    /// Encoding version tag.
    pub version: u32,
    /// `log₂` of the circuit size.
    pub log_n: u32,
    /// Number of public inputs the circuit commits to.
    pub num_public_inputs: u32,
    /// Preprocessed selector commitments.
    pub selectors: [G1Affine; NUM_SELECTOR_COMMITMENTS],
    /// Copy-permutation commitments.
    pub sigmas: [G1Affine; NUM_SIGMA_COMMITMENTS],
    /// Polynomial-identity commitments.
    pub ids: [G1Affine; NUM_ID_COMMITMENTS],
    /// Lookup-table commitments.
    pub tables: [G1Affine; NUM_TABLE_COMMITMENTS],
    /// Lagrange basis commitment for the first row.
    pub lagrange_first: G1Affine,
    /// Lagrange basis commitment for the last row.
    pub lagrange_last: G1Affine,
    /// KZG SRS element `[τ]₂`.
    pub srs_g2: G2Affine,
}

impl HonkVerifyingKey {
    /// Total byte length of the flat encoding.
    pub const BYTE_LEN: usize = 12 + NUM_PREPROCESSED_COMMITMENTS * G1_BYTES + G2_BYTES;

    /// Decodes and validates a verifying key.
    ///
    /// # Errors
    ///
    /// - [`ZkError::DeserializationError`] for a wrong version tag, a truncated
    ///   or over-long buffer, a G1 point outside the prime-order subgroup, or an
    ///   invalid SRS G2 point.
    /// - [`ZkError::InvalidInput`] if `log_n` is outside `1..=MAX_LOG_N` or the
    ///   circuit has no public inputs entry (0 is allowed).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ZkError> {
        if bytes.len() != Self::BYTE_LEN {
            return Err(ZkError::DeserializationError);
        }
        let mut cursor = 0usize;
        let version = read_u32(bytes, &mut cursor)?;
        if version != HONK_FORMAT_VERSION {
            return Err(ZkError::DeserializationError);
        }
        let log_n = read_u32(bytes, &mut cursor)?;
        if log_n == 0 || log_n > MAX_LOG_N {
            return Err(ZkError::InvalidInput);
        }
        let num_public_inputs = read_u32(bytes, &mut cursor)?;

        let selectors = read_g1_array::<NUM_SELECTOR_COMMITMENTS>(bytes, &mut cursor)?;
        let sigmas = read_g1_array::<NUM_SIGMA_COMMITMENTS>(bytes, &mut cursor)?;
        let ids = read_g1_array::<NUM_ID_COMMITMENTS>(bytes, &mut cursor)?;
        let tables = read_g1_array::<NUM_TABLE_COMMITMENTS>(bytes, &mut cursor)?;
        let lagrange_first = read_g1(bytes, &mut cursor)?;
        let lagrange_last = read_g1(bytes, &mut cursor)?;
        let srs_g2 = read_g2(bytes, &mut cursor)?;

        if cursor != bytes.len() {
            return Err(ZkError::DeserializationError);
        }

        Ok(Self {
            version,
            log_n,
            num_public_inputs,
            selectors,
            sigmas,
            ids,
            tables,
            lagrange_first,
            lagrange_last,
            srs_g2,
        })
    }

    /// Re-encodes the key in the flat layout decoded by [`Self::from_bytes`].
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::BYTE_LEN);
        out.extend_from_slice(&self.version.to_be_bytes());
        out.extend_from_slice(&self.log_n.to_be_bytes());
        out.extend_from_slice(&self.num_public_inputs.to_be_bytes());
        for point in &self.selectors {
            write_g1(&mut out, point);
        }
        for point in &self.sigmas {
            write_g1(&mut out, point);
        }
        for point in &self.ids {
            write_g1(&mut out, point);
        }
        for point in &self.tables {
            write_g1(&mut out, point);
        }
        write_g1(&mut out, &self.lagrange_first);
        write_g1(&mut out, &self.lagrange_last);
        out.extend_from_slice(&self.srs_g2.x.1.to_be_bytes());
        out.extend_from_slice(&self.srs_g2.x.0.to_be_bytes());
        out.extend_from_slice(&self.srs_g2.y.1.to_be_bytes());
        out.extend_from_slice(&self.srs_g2.y.0.to_be_bytes());
        out
    }
}

// ── Proof ───────────────────────────────────────────────────────────────────

/// A parsed UltraHonk proof.
///
/// Flat encoding (all integers big-endian, `n = log_n`):
///
/// ```text
/// offset            size        field
/// 0                 4           format version
/// 4                 256         wire commitments w_l, w_r, w_o, w_4
/// 260               64          grand product commitment z_perm
/// 324               192         lookup commitments
/// 516               192         libra commitments
/// 708               96·n        Sumcheck univariates (3 coefficients each)
/// 708 + 96·n        480         evaluation claims (15 × 32)
/// 1188 + 96·n       64          Shplonk Q
/// 1252 + 96·n       64          KZG quotient
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HonkProof {
    /// Encoding version tag.
    pub version: u32,
    /// Wire-polynomial commitments.
    pub wire_commitments: [G1Affine; NUM_WIRE_COMMITMENTS],
    /// Grand-product (permutation) commitment.
    pub grand_product_commitment: G1Affine,
    /// Lookup commitments.
    pub lookup_commitments: [G1Affine; NUM_LOOKUP_COMMITMENTS],
    /// Libra commitments.
    pub libra_commitments: [G1Affine; NUM_LIBRA_COMMITMENTS],
    /// Sumcheck round polynomials; only the first `num_rounds` are meaningful.
    pub sumcheck_univariates: [RoundPolynomial<SUMCHECK_TERMS>; MAX_LOG_N as usize],
    /// Number of Sumcheck rounds (`log_n`).
    pub num_rounds: usize,
    /// Evaluation claims at `ζ` (first 11) and `ζ⁻¹` (last 4).
    pub sumcheck_evaluations: [u256; NUM_SUMCHECK_EVALUATIONS],
    /// Batched Shplonk opening proof.
    pub shplonk_q: G1Affine,
    /// Final KZG quotient opening proof.
    pub kzg_quotient: G1Affine,
}

impl HonkProof {
    /// Total byte length for a proof with `log_n` Sumcheck rounds.
    pub fn byte_len(log_n: u32) -> usize {
        4 + 11 * G1_BYTES
            + (log_n as usize) * SUMCHECK_TERMS * FR_BYTES
            + NUM_SUMCHECK_EVALUATIONS * FR_BYTES
            + 2 * G1_BYTES
    }

    /// Decodes and validates a proof for a circuit of size `2^log_n`.
    ///
    /// # Errors
    ///
    /// - [`ZkError::InvalidInput`] if `log_n` is outside `1..=MAX_LOG_N`.
    /// - [`ZkError::DeserializationError`] for a wrong version tag, truncated or
    ///   over-long buffers, off-curve or non-subgroup G1 points, or a
    ///   non-canonical Sumcheck round polynomial.
    /// - [`ZkError::InvalidFieldElement`] for an evaluation ≥ the Fr modulus.
    pub fn from_bytes(bytes: &[u8], log_n: u32) -> Result<Self, ZkError> {
        if log_n == 0 || log_n > MAX_LOG_N {
            return Err(ZkError::InvalidInput);
        }
        if bytes.len() != Self::byte_len(log_n) {
            return Err(ZkError::DeserializationError);
        }

        let mut cursor = 0usize;
        let version = read_u32(bytes, &mut cursor)?;
        if version != HONK_FORMAT_VERSION {
            return Err(ZkError::DeserializationError);
        }

        let wire_commitments = read_g1_array::<NUM_WIRE_COMMITMENTS>(bytes, &mut cursor)?;
        let grand_product_commitment = read_g1(bytes, &mut cursor)?;
        let lookup_commitments = read_g1_array::<NUM_LOOKUP_COMMITMENTS>(bytes, &mut cursor)?;
        let libra_commitments = read_g1_array::<NUM_LIBRA_COMMITMENTS>(bytes, &mut cursor)?;

        let mut sumcheck_univariates =
            [RoundPolynomial::<SUMCHECK_TERMS>::zero(); MAX_LOG_N as usize];
        for slot in sumcheck_univariates.iter_mut().take(log_n as usize) {
            let mut coefficients = [u256::from(0u8); SUMCHECK_TERMS];
            for coefficient in coefficients.iter_mut() {
                *coefficient = read_fr(bytes, &mut cursor)?;
            }
            *slot = RoundPolynomial::<SUMCHECK_TERMS>::from_coefficients(&coefficients)?;
        }

        let mut sumcheck_evaluations = [u256::from(0u8); NUM_SUMCHECK_EVALUATIONS];
        for evaluation in sumcheck_evaluations.iter_mut() {
            *evaluation = read_fr(bytes, &mut cursor)?;
        }

        let shplonk_q = read_g1(bytes, &mut cursor)?;
        let kzg_quotient = read_g1(bytes, &mut cursor)?;

        if cursor != bytes.len() {
            return Err(ZkError::DeserializationError);
        }

        Ok(Self {
            version,
            wire_commitments,
            grand_product_commitment,
            lookup_commitments,
            libra_commitments,
            sumcheck_univariates,
            num_rounds: log_n as usize,
            sumcheck_evaluations,
            shplonk_q,
            kzg_quotient,
        })
    }

    /// Re-encodes the proof in the flat layout decoded by [`Self::from_bytes`].
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::byte_len(self.num_rounds as u32));
        out.extend_from_slice(&self.version.to_be_bytes());
        for point in &self.wire_commitments {
            write_g1(&mut out, point);
        }
        write_g1(&mut out, &self.grand_product_commitment);
        for point in &self.lookup_commitments {
            write_g1(&mut out, point);
        }
        for point in &self.libra_commitments {
            write_g1(&mut out, point);
        }
        for round in self.sumcheck_univariates.iter().take(self.num_rounds) {
            let coefficients = round.coefficients();
            for index in 0..SUMCHECK_TERMS {
                let coefficient = coefficients.get(index).copied().unwrap_or(u256::from(0u8));
                out.extend_from_slice(&coefficient.to_be_bytes());
            }
        }
        for evaluation in &self.sumcheck_evaluations {
            out.extend_from_slice(&evaluation.to_be_bytes());
        }
        write_g1(&mut out, &self.shplonk_q);
        write_g1(&mut out, &self.kzg_quotient);
        out
    }
}

// ── Fiat–Shamir transcript ──────────────────────────────────────────────────

/// Hash function backing the UltraHonk Fiat–Shamir transcript.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChallengeHash {
    /// Keccak-256, hosted by the Soroban `crypto().keccak256` host function.
    Keccak256,
    /// Poseidon2 over BN254 Fr (`bb`'s Poseidon2 transcript).
    Poseidon2,
}

enum TranscriptState {
    Keccak([u8; 32]),
    Poseidon(poseidon2::Transcript),
}

/// Domain separator for the UltraHonk transcript.
pub const HONK_DOMAIN: &[u8] = b"soroban-zk-std/ultrahonk/v1";

/// A Fiat–Shamir transcript over either Keccak-256 or Poseidon2.
///
/// Both instantiations are digest-chained: every absorb folds the previous
/// 32-byte digest with the new data, so challenges depend on the entire
/// transcript prefix and never on a fixed or guessed value.
pub struct HonkTranscript {
    state: TranscriptState,
}

fn keccak256(env: &Env, bytes: &[u8]) -> [u8; 32] {
    env.crypto()
        .keccak256(&Bytes::from_slice(env, bytes))
        .to_array()
}

impl HonkTranscript {
    /// Starts a transcript bound to a verifying key and public inputs.
    pub fn new(
        env: &Env,
        hasher: ChallengeHash,
        vk_digest: &[u8; 32],
        public_inputs_digest: &[u8; 32],
    ) -> Self {
        match hasher {
            ChallengeHash::Keccak256 => {
                let domain = keccak256(env, HONK_DOMAIN);
                let mut buffer = [0u8; 96];
                buffer[..32].copy_from_slice(&domain);
                buffer[32..64].copy_from_slice(vk_digest);
                buffer[64..].copy_from_slice(public_inputs_digest);
                Self {
                    state: TranscriptState::Keccak(keccak256(env, &buffer)),
                }
            }
            ChallengeHash::Poseidon2 => {
                let mut sponge = poseidon2::Transcript::new();
                sponge.absorb_scalar(poseidon2::hash_to_fr(HONK_DOMAIN));
                sponge.absorb_scalar(u256::from_be_bytes(*vk_digest) % Bn254::FR_MODULUS);
                sponge
                    .absorb_scalar(u256::from_be_bytes(*public_inputs_digest) % Bn254::FR_MODULUS);
                Self {
                    state: TranscriptState::Poseidon(sponge),
                }
            }
        }
    }

    /// Absorbs one Fr scalar.
    pub fn absorb_scalar(&mut self, env: &Env, value: u256) {
        match &mut self.state {
            TranscriptState::Keccak(digest) => {
                let mut buffer = [0u8; 64];
                buffer[..32].copy_from_slice(digest);
                buffer[32..].copy_from_slice(&value.to_be_bytes());
                let next = keccak256(env, &buffer);
                *digest = next;
            }
            TranscriptState::Poseidon(sponge) => sponge.absorb_scalar(value),
        }
    }

    /// Absorbs a G1 point as its two coordinates.
    pub fn absorb_point(&mut self, env: &Env, point: &G1Affine) {
        self.absorb_scalar(env, point.x);
        self.absorb_scalar(env, point.y);
    }

    /// Derives the next challenge, reduced into `[0, r)` and never zero.
    ///
    /// A zero challenge is mapped to one so an unlucky digest can never zero
    /// out a linear combination (which would silently drop batched claims).
    pub fn challenge(&mut self, env: &Env) -> u256 {
        let value = match &mut self.state {
            TranscriptState::Keccak(digest) => {
                let next = keccak256(env, digest);
                *digest = next;
                u256::from_be_bytes(next) % Bn254::FR_MODULUS
            }
            TranscriptState::Poseidon(sponge) => sponge.challenge() % Bn254::FR_MODULUS,
        };
        if value == u256::from(0u8) {
            u256::from(1u8)
        } else {
            value
        }
    }
}

/// SHA-256 digest of the verifying key bytes, bound into every transcript.
pub fn honk_vk_digest(vk_bytes: &[u8]) -> [u8; 32] {
    Hash::hash(vk_bytes).0
}

/// SHA-256 chain over the public inputs, bound into every transcript.
pub fn honk_public_inputs_digest(public_inputs: &[u256]) -> [u8; 32] {
    let mut digest = Hash::hash(b"soroban-zk-std/ultrahonk/public-inputs/v1").0;
    for &input in public_inputs {
        let mut buffer = [0u8; 64];
        buffer[..32].copy_from_slice(&digest);
        buffer[32..].copy_from_slice(&input.to_be_bytes());
        digest = Hash::hash(&buffer).0;
    }
    digest
}

/// All challenges an UltraHonk verifier derives from a proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HonkChallenges {
    /// Wire-compression challenge `η`.
    pub eta: u256,
    /// Permutation challenge `β`.
    pub beta: u256,
    /// Permutation challenge `γ`.
    pub gamma: u256,
    /// Relation-batching challenge `α`.
    pub alpha: u256,
    /// Sumcheck challenges `r_0 … r_{n-1}` (zero-padded).
    pub sumcheck: [u256; MAX_LOG_N as usize],
    /// Number of meaningful Sumcheck challenges.
    pub num_rounds: usize,
    /// Shplonk/Gemini batching challenge `ν`.
    pub nu: u256,
}

impl HonkChallenges {
    /// `r_0 … r_{n-1}`.
    pub fn sumcheck_slice(&self) -> &[u256] {
        &self.sumcheck[..self.num_rounds]
    }

    /// The Sumcheck evaluation point `ζ = r_{n-1}` (zero for an empty chain).
    pub fn zeta(&self) -> u256 {
        if self.num_rounds == 0 {
            u256::from(0u8)
        } else {
            self.sumcheck[self.num_rounds - 1]
        }
    }
}

/// Derives the relation and Sumcheck challenges from a parsed proof.
///
/// Absorb order: wire commitments → `η`, grand product → `β`, `γ`, lookup and
/// libra commitments → `α`, then each Sumcheck univariate → `r_i`, then the
/// evaluation claims and opening proofs → `ν`. Public inputs and the verifying
/// key enter through the transcript seed, so a challenge can never be replayed
/// against a different circuit or input set.
///
/// # Errors
///
/// Propagates parsing-side validation and [`ZkError::InvalidInput`] if the proof
/// was parsed for a different circuit size than the key declares.
pub fn derive_honk_challenges(
    env: &Env,
    vk: &HonkVerifyingKey,
    proof: &HonkProof,
    public_inputs: &[u256],
    hasher: ChallengeHash,
) -> Result<HonkChallenges, ZkError> {
    if proof.num_rounds != vk.log_n as usize {
        return Err(ZkError::InvalidInput);
    }

    let (vk_digest, pi_digest) = transcript_seeds(vk, public_inputs);
    let mut transcript = HonkTranscript::new(env, hasher, &vk_digest, &pi_digest);

    for commitment in &proof.wire_commitments {
        transcript.absorb_point(env, commitment);
    }
    let eta = transcript.challenge(env);

    transcript.absorb_point(env, &proof.grand_product_commitment);
    let beta = transcript.challenge(env);
    let gamma = transcript.challenge(env);

    for commitment in &proof.lookup_commitments {
        transcript.absorb_point(env, commitment);
    }
    for commitment in &proof.libra_commitments {
        transcript.absorb_point(env, commitment);
    }
    let alpha = transcript.challenge(env);

    let mut sumcheck = [u256::from(0u8); MAX_LOG_N as usize];
    for (slot, round) in sumcheck
        .iter_mut()
        .zip(proof.sumcheck_univariates.iter())
        .take(proof.num_rounds)
    {
        for &coefficient in round.coefficients() {
            transcript.absorb_scalar(env, coefficient);
        }
        *slot = transcript.challenge(env);
    }

    for &evaluation in &proof.sumcheck_evaluations {
        transcript.absorb_scalar(env, evaluation);
    }
    transcript.absorb_point(env, &proof.shplonk_q);
    transcript.absorb_point(env, &proof.kzg_quotient);
    let nu = transcript.challenge(env);

    Ok(HonkChallenges {
        eta,
        beta,
        gamma,
        alpha,
        sumcheck,
        num_rounds: proof.num_rounds,
        nu,
    })
}

fn transcript_seeds(vk: &HonkVerifyingKey, public_inputs: &[u256]) -> ([u8; 32], [u8; 32]) {
    let vk_bytes = vk.to_bytes();
    (
        honk_vk_digest(&vk_bytes),
        honk_public_inputs_digest(public_inputs),
    )
}

// ── Zeromorph / Shplonk opening reduction ───────────────────────────────────

/// One univariate KZG opening claim.
///
/// Zeromorph emits claims of this shape after folding a multilinear opening into
/// univariate openings; Shplonk then batches any mix of evaluation points into a
/// single pairing check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpeningClaim {
    /// Commitment `[f]₁`.
    pub commitment: G1Affine,
    /// Evaluation point `z`.
    pub point: u256,
    /// Claimed evaluation `f(z)`.
    pub evaluation: u256,
    /// Opening proof `[(f(X) - f(z)) / (X - z)]₁`.
    pub proof: G1Affine,
}

#[inline(always)]
fn is_identity(point: &G1Affine) -> bool {
    point.x == u256::from(0u8) && point.y == u256::from(0u8)
}

fn negate_g1(point: G1Affine) -> G1Affine {
    if is_identity(&point) {
        point
    } else {
        G1Affine {
            x: point.x,
            y: Bn254::sub_fq(u256::from(0u8), point.y),
        }
    }
}

/// Reduces `k` opening claims to the two G1 points of a single pairing check.
///
/// With independent claim `i` satisfying `e(W_i, [τ - z_i]₂) = e(C_i - [v_i]₁, G₂)`,
/// a random linear combination with `ν`-powers gives
///
/// ```text
/// Q = Σ νⁱ·W_i
/// R = Σ νⁱ·(C_i - [v_i]₁ + z_i·W_i)
/// e(Q, [τ]₂) · e(-R, G₂) == 1
/// ```
///
/// so `k` openings collapse into two pairings. A cheating prover passes with
/// probability at most `k / |Fr|` by Schwartz–Zippel over `ν`, which the
/// Fiat–Shamir transcript fixes after the commitments are bound.
///
/// # Errors
///
/// - [`ZkError::InvalidInput`] for an empty claim list.
/// - [`ZkError::InvalidFieldElement`] if `nu` is zero/out of range or any claim
///   point or evaluation is out of range.
pub fn reduce_opening_claims(
    claims: &[OpeningClaim],
    nu: u256,
) -> Result<(G1Affine, G1Affine), ZkError> {
    if claims.is_empty() {
        return Err(ZkError::InvalidInput);
    }
    if nu == u256::from(0u8) || !Bn254::is_valid_scalar(nu) {
        return Err(ZkError::InvalidFieldElement);
    }

    let mut q = G1Projective::identity();
    let mut r = G1Projective::identity();
    let mut nu_power = u256::from(1u8);

    for claim in claims {
        if !Bn254::is_valid_scalar(claim.point) || !Bn254::is_valid_scalar(claim.evaluation) {
            return Err(ZkError::InvalidFieldElement);
        }

        let weighted_proof = Bn254::g1_scalar_mul(G1Projective::from(claim.proof), nu_power);
        q = q.add(&weighted_proof);

        let commitment = G1Projective::from(claim.commitment);
        let evaluation_point =
            Bn254::g1_scalar_mul(G1Projective::from(G1_GENERATOR), claim.evaluation);
        let scaled_proof = Bn254::g1_scalar_mul(G1Projective::from(claim.proof), claim.point);
        let combined = commitment
            .add(&evaluation_point_negated(evaluation_point))
            .add(&scaled_proof);

        r = r.add(&Bn254::g1_scalar_mul(combined, nu_power));
        nu_power = Bn254::mul(nu_power, nu);
    }

    Ok((q.to_affine(), r.to_affine()))
}

fn evaluation_point_negated(point: G1Projective) -> G1Projective {
    let affine = point.to_affine();
    G1Projective::from(negate_g1(affine))
}

/// Verifies a batch of KZG opening claims with exactly one `pairing_check`.
///
/// # Errors
///
/// Propagates the validation errors of [`reduce_opening_claims`], plus
/// [`ZkError::InvalidInput`] if the SRS G2 element is not a valid subgroup
/// point, and [`ZkError::HostError`] if the host pairing call fails.
pub fn verify_kzg_openings(
    env: &Env,
    claims: &[OpeningClaim],
    nu: u256,
    srs_g2: G2Affine,
) -> Result<bool, ZkError> {
    if !validate_g2_coords(&srs_g2) {
        return Err(ZkError::InvalidInput);
    }
    let (q, r) = reduce_opening_claims(claims, nu)?;
    let g2_generator = G2Affine::generator();

    match (is_identity(&q), is_identity(&r)) {
        (true, true) => Ok(true),
        (false, true) => pairing_check(env, &[(q, srs_g2)]),
        (true, false) => pairing_check(env, &[(negate_g1(r), g2_generator)]),
        (false, false) => pairing_check(env, &[(q, srs_g2), (negate_g1(r), g2_generator)]),
    }
}

// ── Full verification pipeline ──────────────────────────────────────────────

/// Builds the OpeningClaims implied by a proof's evaluation claims.
fn build_opening_claims(
    proof: &HonkProof,
    challenges: &HonkChallenges,
) -> Result<[OpeningClaim; NUM_SUMCHECK_EVALUATIONS], ZkError> {
    let zeta = challenges.zeta();
    if zeta == u256::from(0u8) {
        // A zero evaluation point has no distinct shifted point.
        return Err(ZkError::InvalidFieldElement);
    }
    let zeta_inverse = Bn254::invert(zeta);

    let mut commitments = [G1_IDENTITY; NUM_UNSHIFTED_EVALUATIONS];
    commitments[..NUM_WIRE_COMMITMENTS].copy_from_slice(&proof.wire_commitments);
    commitments[NUM_WIRE_COMMITMENTS] = proof.grand_product_commitment;
    let lookup_start = NUM_WIRE_COMMITMENTS + 1;
    commitments[lookup_start..lookup_start + NUM_LOOKUP_COMMITMENTS]
        .copy_from_slice(&proof.lookup_commitments);
    let libra_start = lookup_start + NUM_LOOKUP_COMMITMENTS;
    commitments[libra_start..libra_start + NUM_LIBRA_COMMITMENTS]
        .copy_from_slice(&proof.libra_commitments);

    let mut claims = [OpeningClaim {
        commitment: G1_IDENTITY,
        point: u256::from(0u8),
        evaluation: u256::from(0u8),
        proof: G1_IDENTITY,
    }; NUM_SUMCHECK_EVALUATIONS];

    for (index, claim) in claims.iter_mut().enumerate() {
        if index < NUM_UNSHIFTED_EVALUATIONS {
            *claim = OpeningClaim {
                commitment: commitments[index],
                point: zeta,
                evaluation: proof.sumcheck_evaluations[index],
                proof: proof.shplonk_q,
            };
        } else {
            let wire = index - NUM_UNSHIFTED_EVALUATIONS;
            *claim = OpeningClaim {
                commitment: proof.wire_commitments[wire],
                point: zeta_inverse,
                evaluation: proof.sumcheck_evaluations[index],
                proof: proof.kzg_quotient,
            };
        }
    }

    Ok(claims)
}

/// Verifies the Sumcheck and opening stages of an UltraHonk proof.
///
/// `claimed_sum` is the relation's initial Sumcheck claim (the sum of the
/// relation polynomial over the hypercube, as computed by the relation
/// evaluator) and `relation_evaluation` is that evaluator's final oracle value
/// at the Sumcheck point. Everything else is derived from the proof itself.
///
/// Returns `Ok(true)` only when the round chain, the final oracle evaluation and
/// the batched KZG opening equation all hold.
///
/// # Errors
///
/// - [`ZkError::DeserializationError`] / [`ZkError::InvalidFieldElement`] for a
///   malformed key or proof.
/// - [`ZkError::InvalidInput`] if the proof was parsed for a different circuit
///   size than the key, or the public-input count is wrong.
/// - [`ZkError::ConstraintUnsatisfied`] if the Sumcheck chain or final oracle
///   evaluation does not match.
/// - [`ZkError::HostError`] if the host pairing call fails.
pub fn verify_ultrahonk(
    env: &Env,
    vk_bytes: &[u8],
    proof_bytes: &[u8],
    public_inputs: &[u256],
    claimed_sum: u256,
    relation_evaluation: u256,
    hasher: ChallengeHash,
) -> Result<bool, ZkError> {
    let vk = HonkVerifyingKey::from_bytes(vk_bytes)?;
    let proof = HonkProof::from_bytes(proof_bytes, vk.log_n)?;

    if public_inputs.len() != vk.num_public_inputs as usize {
        return Err(ZkError::InvalidInput);
    }
    for &input in public_inputs {
        if !Bn254::is_valid_scalar(input) {
            return Err(ZkError::InvalidFieldElement);
        }
    }

    let challenges = derive_honk_challenges(env, &vk, &proof, public_inputs, hasher)?;

    let reduction: SumcheckReduction<{ MAX_LOG_N as usize }> =
        verify_sumcheck::<{ MAX_LOG_N as usize }, SUMCHECK_TERMS>(
            claimed_sum,
            &proof.sumcheck_univariates[..proof.num_rounds],
            challenges.sumcheck_slice(),
        )?;
    if reduction.final_evaluation != relation_evaluation {
        return Err(ZkError::ConstraintUnsatisfied);
    }

    let claims = build_opening_claims(&proof, &challenges)?;
    verify_kzg_openings(env, &claims, challenges.nu, vk.srs_g2)
}
