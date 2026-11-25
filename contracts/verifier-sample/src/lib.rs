#![no_std]

extern crate alloc;

use alloc::vec::Vec as AllocVec;
use ethnum::u256;
use soroban_sdk::{contract, contracterror, contractimpl, Bytes, Env, Vec, U256};
use soroban_zk_core::{Bn254, G1Affine, KzgEvalProofInputs, ZkError};
use soroban_zk_std::groth16::{groth16_verify, Groth16Proof};
use soroban_zk_std::pairing::G2Affine;
use soroban_zk_std::plonk_kzg::verify_plonk_kzg;
use soroban_zk_std::poseidon2::hash_to_field;
use soroban_zk_std::vk::vk_from_bytes;

/// Harness-local error type.
///
/// `soroban-zk-std` is depended on with `default-features = false` (see
/// `Cargo.toml`), so its `contract` feature — and with it
/// `soroban_zk_std::ZkContractError` — is deliberately unavailable here:
/// enabling it would link the whole proof-system contract stack, including
/// its exported entry points, into the 64 KB WASM this harness exists to
/// measure. This enum mirrors the `ZkError` variants the entrypoints can
/// surface, so callers get the same failure taxonomy without that cost.
/// `ZkError::ReplayDetected` is intentionally not mirrored: no entrypoint
/// here does nullifier or replay work.
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum VerifierError {
    /// A supplied value was >= the BN254 scalar field modulus.
    InvalidFieldElement = 1,
    /// Mismatched input lengths or empty slices.
    InvalidInput = 2,
    /// Serialized bytes could not be decoded.
    DeserializationError = 3,
    /// A raw host call trapped or was unavailable.
    HostError = 4,
    /// A storage read/write/remove failed or required data was missing.
    StorageError = 5,
    /// A ZK constraint or gadget invariant was violated.
    ConstraintUnsatisfied = 6,
}

impl From<ZkError> for VerifierError {
    fn from(err: ZkError) -> Self {
        match err {
            ZkError::InvalidFieldElement => VerifierError::InvalidFieldElement,
            ZkError::InvalidInput => VerifierError::InvalidInput,
            ZkError::DeserializationError => VerifierError::DeserializationError,
            ZkError::HostError => VerifierError::HostError,
            ZkError::StorageError => VerifierError::StorageError,
            ZkError::ConstraintUnsatisfied => VerifierError::ConstraintUnsatisfied,
        }
    }
}

#[contract]
pub struct Verifier;

#[contractimpl]
impl Verifier {
    /// Thin harness entrypoint for the BN254 scalar check (unchanged).
    pub fn check(env: Env, input: U256) -> bool {
        env.is_bn254_scalar(input)
    }

    /// Verify a Groth16 proof against a verifying key, delegating to the
    /// production `groth16_verify` implementation.
    ///
    /// `proof` is the 256-byte wire format `A (64) || B (128) || C (64)`;
    /// `vk` is a verifying key serialized with `vk_to_bytes`. Returns
    /// `Ok(true)` only when the pairing equation holds for the supplied
    /// public inputs; `Ok(false)` when the proof is well-formed but does
    /// not verify; `Err` when any input is malformed or out of range.
    pub fn verify_groth16(
        env: Env,
        proof: Bytes,
        vk: Bytes,
        public_inputs: Vec<U256>,
    ) -> Result<bool, VerifierError> {
        let proof_bytes = bytes_to_array::<256>(&proof)?;
        let proof = Groth16Proof::from_bytes(&proof_bytes)?;
        let owned_vk = vk_from_bytes(&env, &vk)?;
        let inputs = u256_vec(&public_inputs);
        Ok(groth16_verify(&env, &owned_vk.as_vk(), &proof, &inputs)?)
    }

    /// Verify a PLONK-KZG batched evaluation proof, delegating to the
    /// production `verify_plonk_kzg` implementation.
    ///
    /// Points are supplied as big-endian bytes: G1 points as `x || y`
    /// (64 bytes), G2 points in EIP-197 wire order
    /// `x_c1 || x_c0 || y_c1 || y_c0` (128 bytes). Every point is
    /// re-validated for curve and prime-order subgroup membership before
    /// verification, mirroring what the library's own decoders do.
    /// Returns `Ok(true)` only when the batched pairing equation holds.
    #[allow(clippy::too_many_arguments)]
    pub fn verify_plonk_kzg(
        env: Env,
        commitments: Vec<Bytes>,
        evaluations_at_zeta: Vec<U256>,
        commitment_at_zeta_omega: Bytes,
        evaluation_at_zeta_omega: U256,
        w_zeta: Bytes,
        w_zeta_omega: Bytes,
        v: U256,
        u: U256,
        zeta: U256,
        omega: U256,
        srs_g2: Bytes,
    ) -> Result<bool, VerifierError> {
        let commitments = g1_vec(&commitments)?;
        let evaluations_at_zeta = u256_vec(&evaluations_at_zeta);
        let commitment_at_zeta_omega = bytes_to_g1(&commitment_at_zeta_omega)?;
        let w_zeta = bytes_to_g1(&w_zeta)?;
        let w_zeta_omega = bytes_to_g1(&w_zeta_omega)?;
        let srs_g2 = bytes_to_g2(&srs_g2)?;
        let inputs = KzgEvalProofInputs {
            commitments: &commitments,
            evaluations_at_zeta: &evaluations_at_zeta,
            commitment_at_zeta_omega,
            evaluation_at_zeta_omega: u256_from_sdk(&evaluation_at_zeta_omega),
            w_zeta,
            w_zeta_omega,
            v: u256_from_sdk(&v),
            u: u256_from_sdk(&u),
            zeta: u256_from_sdk(&zeta),
            omega: u256_from_sdk(&omega),
        };
        Ok(verify_plonk_kzg(&env, &inputs, srs_g2)?)
    }

    /// Poseidon2 hash of a list of BN254 field elements (t=3, d=5, rate=2),
    /// delegating to the production `hash_to_field` implementation.
    ///
    /// Uses the uncached sponge on purpose: the entrypoint is a pure
    /// computation with no instance-storage interaction, so its gas profile
    /// measures hashing alone. Inputs are reduced mod r on absorb, so an
    /// out-of-range value hashes as its canonical representative rather
    /// than being rejected.
    pub fn poseidon2_hash(env: Env, inputs: Vec<U256>) -> U256 {
        let values: AllocVec<U256> = inputs.iter().collect();
        hash_to_field(&env, &values)
    }
}

/// Copy a `Bytes` value into a fixed-size array, rejecting wrong lengths
/// as a deserialization error instead of panicking.
fn bytes_to_array<const N: usize>(bytes: &Bytes) -> Result<[u8; N], VerifierError> {
    if bytes.len() != N as u32 {
        return Err(VerifierError::DeserializationError);
    }
    let mut buf = [0u8; N];
    bytes.copy_into_slice(&mut buf);
    Ok(buf)
}

/// Convert a Soroban `U256` to an `ethnum::u256` (both big-endian 32-byte).
fn u256_from_sdk(value: &U256) -> u256 {
    let mut buf = [0u8; 32];
    value.to_be_bytes().copy_into_slice(&mut buf);
    u256::from_be_bytes(buf)
}

/// Convert a Soroban `Vec<U256>` to an owned `alloc::vec::Vec<u256>`.
fn u256_vec(values: &Vec<U256>) -> AllocVec<u256> {
    values.iter().map(|v| u256_from_sdk(&v)).collect()
}

/// Decode one 64-byte G1 point (`x || y`, big-endian), validating curve
/// and prime-order subgroup membership — the same checks `groth16_verify`
/// applies to proof points internally.
fn bytes_to_g1(bytes: &Bytes) -> Result<G1Affine, VerifierError> {
    let raw = bytes_to_array::<64>(bytes)?;
    let x = Bn254::fq_from_bytes(raw[0..32].try_into().unwrap())
        .ok_or(VerifierError::DeserializationError)?;
    let y = Bn254::fq_from_bytes(raw[32..64].try_into().unwrap())
        .ok_or(VerifierError::DeserializationError)?;
    if !Bn254::is_valid_g1_subgroup(x, y) {
        return Err(VerifierError::DeserializationError);
    }
    Ok(G1Affine { x, y })
}

/// Decode one 128-byte G2 point in EIP-197 wire order
/// (`x_c1 || x_c0 || y_c1 || y_c0`), validating curve and prime-order
/// subgroup membership — the same checks the library's `g2_from_bytes`
/// applies internally.
fn bytes_to_g2(bytes: &Bytes) -> Result<G2Affine, VerifierError> {
    let raw = bytes_to_array::<128>(bytes)?;
    let x = (
        Bn254::fq_from_bytes(raw[32..64].try_into().unwrap())
            .ok_or(VerifierError::DeserializationError)?,
        Bn254::fq_from_bytes(raw[0..32].try_into().unwrap())
            .ok_or(VerifierError::DeserializationError)?,
    );
    let y = (
        Bn254::fq_from_bytes(raw[96..128].try_into().unwrap())
            .ok_or(VerifierError::DeserializationError)?,
        Bn254::fq_from_bytes(raw[64..96].try_into().unwrap())
            .ok_or(VerifierError::DeserializationError)?,
    );
    if !Bn254::is_valid_g2_subgroup(x, y) {
        return Err(VerifierError::DeserializationError);
    }
    Ok(G2Affine { x, y })
}

/// Decode a `Vec<Bytes>` of 64-byte G1 points.
fn g1_vec(values: &Vec<Bytes>) -> Result<AllocVec<G1Affine>, VerifierError> {
    let mut out = AllocVec::with_capacity(values.len() as usize);
    for bytes in values.iter() {
        out.push(bytes_to_g1(&bytes)?);
    }
    Ok(out)
}

mod test;
