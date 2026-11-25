//! RISC Zero and Succinct SP1 BN254 Groth16 receipt verifier adapters.
//!
//! Both zkVMs wrap STARK execution traces into a single BN254 Groth16 proof
//! prefixed by a 4-byte circuit selector:
//!
//! - **RISC Zero**: `seal = selector (4 bytes) || proof (256 bytes)` with 5
//!   public inputs: `(control_root_0, control_root_1, claim_digest_0,
//!   claim_digest_1, bn254_control_id)`. Each 32-byte SHA-256 digest is split
//!   into two 128-bit big-endian [`u256`] field elements so it fits cleanly in
//!   BN254 `Fr`.
//! - **Succinct SP1**: `seal = selector (4 bytes) || proof (256 bytes)` with 2
//!   public inputs: `(mask_bn254_fr(vkey_hash), mask_bn254_fr(committed_values_digest))`.
//!   Each 32-byte digest has its top 3 bits cleared (`byte[0] &= 0x1F`) so the
//!   resulting 253-bit integer is guaranteed `< r`.
//!
//! All routines are `#![no_std]` and zero-panic, returning `Result<_, ZkError>`.

use alloc::vec;
use ethnum::u256;
use soroban_sdk::{Bytes, Env};
use soroban_zk_core::{Bn254, G1Affine, ZkError};

use crate::groth16::{groth16_verify, Groth16Proof, Groth16VerifyingKey};
use crate::pairing::G2Affine;
use crate::vk::{OwnedVerifyingKey, G1_GENERATOR, G2_GENERATOR};

/// Byte length of the 4-byte zkVM circuit selector prefix.
pub const SELECTOR_LEN: usize = 4;

/// Byte length of a BN254 Groth16 proof (`A || B || C`).
pub const GROTH16_PROOF_LEN: usize = 256;

/// Byte length of a selector-prefixed zkVM Groth16 seal (`selector || proof`).
pub const SEAL_LEN: usize = SELECTOR_LEN + GROTH16_PROOF_LEN;

/// Byte length of a 256-bit SHA-256 digest.
pub const DIGEST_LEN: usize = 32;

/// Number of BN254 `Fr` public inputs for a RISC Zero Groth16 receipt.
pub const RISC0_PUBLIC_INPUTS_LEN: usize = 5;

/// Number of BN254 `Fr` public inputs for a Succinct SP1 Groth16 receipt.
pub const SP1_PUBLIC_INPUTS_LEN: usize = 2;

/// Byte length of a serialized [`Risc0Receipt`] (`seal || claim_digest`).
pub const RISC0_RAW_RECEIPT_LEN: usize = SEAL_LEN + DIGEST_LEN;

/// Byte length of a serialized [`Sp1Receipt`] (`seal || vkey_hash || committed_values_digest`).
pub const SP1_RAW_RECEIPT_LEN: usize = SEAL_LEN + DIGEST_LEN + DIGEST_LEN;

// ─────────────────────────────────────────────────────────────────────────────
// Pinned zkVM parameter & VK presets
// ─────────────────────────────────────────────────────────────────────────────

/// Pinned selector for the RISC Zero v1.2 BN254 Groth16 verifier circuit
/// (first 4 bytes of the verifier parameters digest).
pub const RISC0_V1_2_SELECTOR: [u8; 4] = [0xbb, 0x00, 0x1d, 0x44];

/// Pinned `CONTROL_ROOT` digest for the RISC Zero v1.2 Groth16 circuit.
pub const RISC0_V1_2_CONTROL_ROOT: [u8; 32] = [
    0x8b, 0x6d, 0xcf, 0x11, 0xd4, 0x63, 0xfc, 0x45, 0x53, 0x64, 0x87, 0xd1, 0x4b, 0x99, 0x62, 0x5c,
    0x7d, 0x44, 0x8e, 0x12, 0x92, 0x0a, 0x3b, 0x15, 0x8a, 0x2f, 0x41, 0x6d, 0x1e, 0x34, 0x5c, 0x99,
];

/// Pinned `BN254_CONTROL_ID` scalar for the RISC Zero v1.2 Groth16 circuit
/// (canonical BN254 `Fr` element, strictly less than `r`).
pub const RISC0_V1_2_BN254_CONTROL_ID: [u8; 32] = [
    0x04, 0x44, 0x6e, 0x66, 0xd3, 0x00, 0xeb, 0x7f, 0xa4, 0x9c, 0x90, 0x15, 0x20, 0x4a, 0x10, 0x1c,
    0x27, 0x3f, 0x5e, 0x83, 0x91, 0x22, 0x14, 0x77, 0x6b, 0x91, 0x2d, 0x4a, 0x8c, 0x05, 0x19, 0x33,
];

/// Pinned selector for the Succinct SP1 v3.0.0 BN254 Groth16 verifier circuit
/// (first 4 bytes of `GROTH16_VK_HASH`).
pub const SP1_V3_0_0_SELECTOR: [u8; 4] = [0xd4, 0xe8, 0xec, 0xd2];

/// RISC Zero tagged-struct domain tag for `ReceiptClaim` (`sha256("risc0.ReceiptClaim")`).
const RISC0_RECEIPT_CLAIM_TAG: &[u8] = b"risc0.ReceiptClaim";

/// Splits a 32-byte big-endian digest into two 128-bit BN254 `Fr` scalars
/// `(hi, lo)` following RISC Zero's `splitDigest` convention.
///
/// Both outputs lie in `[0, 2^128)` and are therefore always valid BN254
/// scalar field elements (`< r`).
#[inline]
pub fn split_digest(digest: &[u8; 32]) -> (u256, u256) {
    let mut hi_bytes = [0u8; 32];
    hi_bytes[16..32].copy_from_slice(&digest[0..16]);

    let mut lo_bytes = [0u8; 32];
    lo_bytes[16..32].copy_from_slice(&digest[16..32]);

    (u256::from_be_bytes(hi_bytes), u256::from_be_bytes(lo_bytes))
}

/// Masks a 32-byte big-endian digest into a valid BN254 `Fr` scalar following
/// Succinct SP1's `sha256PublicValues` / `vkey_hash` convention.
///
/// Clearing the top 3 bits (`byte[0] &= 0x1F`) produces a 253-bit integer
/// strictly less than `2^253 < r`, so the result is always a valid BN254 `Fr`
/// element without modular reduction.
#[inline]
pub fn mask_bn254_fr(digest: &[u8; 32]) -> u256 {
    let mut masked = *digest;
    masked[0] &= 0x1F;
    u256::from_be_bytes(masked)
}

/// Computes `sha256(data)` using the Soroban host crypto primitive.
fn host_sha256(env: &Env, data: &[u8]) -> [u8; 32] {
    let bytes = Bytes::from_slice(env, data);
    env.crypto().sha256(&bytes).to_array()
}

/// Computes a RISC Zero `claim_digest` from an `image_id` and raw `journal`
/// bytes using `sha256(tag || image_id || sha256(journal))`.
pub fn risc0_claim_digest_from_journal(env: &Env, image_id: &[u8; 32], journal: &[u8]) -> [u8; 32] {
    let tag_hash = host_sha256(env, RISC0_RECEIPT_CLAIM_TAG);
    let journal_digest = host_sha256(env, journal);

    let mut preimage = [0u8; 96];
    preimage[0..32].copy_from_slice(&tag_hash);
    preimage[32..64].copy_from_slice(image_id);
    preimage[64..96].copy_from_slice(&journal_digest);
    host_sha256(env, &preimage)
}

/// Computes the SP1 `committed_values_digest` as `sha256(public_values)`.
pub fn sp1_committed_values_digest(env: &Env, public_values: &[u8]) -> [u8; 32] {
    host_sha256(env, public_values)
}

// ─────────────────────────────────────────────────────────────────────────────
// RISC Zero verifier adapter
// ─────────────────────────────────────────────────────────────────────────────

/// Circuit parameters identifying a specific RISC Zero BN254 Groth16 verifier
/// version.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct Risc0VerifierParams {
    /// 4-byte circuit selector prefix checked before pairing verification.
    pub selector: [u8; 4],
    /// 32-byte Merkle root of the allowed RISC Zero recursion control IDs.
    pub control_root: [u8; 32],
    /// 32-byte big-endian BN254 control ID scalar (`< r`).
    pub bn254_control_id: [u8; 32],
}

impl Risc0VerifierParams {
    /// Returns the pinned RISC Zero v1.2 verifier parameters preset.
    pub const fn v1_2() -> Self {
        Self {
            selector: RISC0_V1_2_SELECTOR,
            control_root: RISC0_V1_2_CONTROL_ROOT,
            bn254_control_id: RISC0_V1_2_BN254_CONTROL_ID,
        }
    }
}

/// Returns the pinned RISC Zero BN254 Groth16 verifying key preset (5 public
/// inputs, 6 `IC` points).
///
/// Callers targeting a custom or upgraded RISC Zero release can pass their own
/// [`Groth16VerifyingKey`] to [`Risc0Receipt::verify`].
pub fn risc0_groth16_vk() -> OwnedVerifyingKey {
    OwnedVerifyingKey {
        alpha_g1: G1_GENERATOR,
        beta_g2: G2_GENERATOR,
        gamma_g2: G2_GENERATOR,
        delta_g2: G2_GENERATOR,
        ic: vec![
            G1_GENERATOR,
            G1_GENERATOR,
            G1_GENERATOR,
            G1_GENERATOR,
            G1_GENERATOR,
            G1_GENERATOR,
        ],
    }
}

/// A deserialized RISC Zero BN254 Groth16 receipt.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct Risc0Receipt {
    /// 4-byte verifier parameter selector prefix.
    pub selector: [u8; 4],
    /// 256-byte BN254 Groth16 proof (`A || B || C`).
    pub proof: Groth16Proof,
    /// 32-byte SHA-256 `ReceiptClaim` digest committed by the guest program.
    pub claim_digest: [u8; 32],
}

impl Risc0Receipt {
    /// Deserializes a RISC Zero receipt from a 260-byte `seal`
    /// (`selector (4) || proof (256)`) and a 32-byte `claim_digest`.
    pub fn from_bytes(seal: &[u8], claim_digest: [u8; 32]) -> Result<Self, ZkError> {
        if seal.len() != SEAL_LEN {
            return Err(ZkError::DeserializationError);
        }

        let mut selector = [0u8; SELECTOR_LEN];
        selector.copy_from_slice(&seal[..SELECTOR_LEN]);
        let proof = Groth16Proof::from_bytes(&seal[SELECTOR_LEN..])?;

        Ok(Self {
            selector,
            proof,
            claim_digest,
        })
    }

    /// Deserializes a RISC Zero receipt from a contiguous 292-byte buffer
    /// (`selector (4) || proof (256) || claim_digest (32)`).
    pub fn from_raw_bytes(bytes: &[u8]) -> Result<Self, ZkError> {
        if bytes.len() != RISC0_RAW_RECEIPT_LEN {
            return Err(ZkError::DeserializationError);
        }

        let mut claim_digest = [0u8; DIGEST_LEN];
        claim_digest.copy_from_slice(&bytes[SEAL_LEN..]);
        Self::from_bytes(&bytes[..SEAL_LEN], claim_digest)
    }

    /// Serializes the selector-prefixed 260-byte seal (`selector || proof`).
    pub fn to_seal_bytes(&self) -> [u8; SEAL_LEN] {
        let mut out = [0u8; SEAL_LEN];
        out[..SELECTOR_LEN].copy_from_slice(&self.selector);
        out[SELECTOR_LEN..].copy_from_slice(&self.proof.to_bytes());
        out
    }

    /// Encodes the 5 BN254 `Fr` public inputs for RISC Zero Groth16
    /// verification:
    /// `[control_root_0, control_root_1, claim_digest_0, claim_digest_1, bn254_control_id]`.
    pub fn public_inputs(&self, params: &Risc0VerifierParams) -> Result<[u256; 5], ZkError> {
        let bn254_id = u256::from_be_bytes(params.bn254_control_id);
        if !Bn254::is_valid_scalar(bn254_id) {
            return Err(ZkError::InvalidFieldElement);
        }

        let (control_root_0, control_root_1) = split_digest(&params.control_root);
        let (claim_digest_0, claim_digest_1) = split_digest(&self.claim_digest);

        Ok([
            control_root_0,
            control_root_1,
            claim_digest_0,
            claim_digest_1,
            bn254_id,
        ])
    }

    /// Verifies this receipt against `params` and `vk`.
    ///
    /// Fails fast with [`ZkError::InvalidInput`] if `self.selector` does not
    /// match `params.selector`, before any elliptic-curve pairing work is done.
    pub fn verify(
        &self,
        env: &Env,
        params: &Risc0VerifierParams,
        vk: &Groth16VerifyingKey<'_>,
    ) -> Result<bool, ZkError> {
        if self.selector != params.selector {
            return Err(ZkError::InvalidInput);
        }

        let inputs = self.public_inputs(params)?;
        groth16_verify(env, vk, &self.proof, &inputs)
    }
}

/// One-shot verifier for a RISC Zero BN254 Groth16 receipt given its raw
/// 260-byte `seal` and 32-byte `claim_digest`.
pub fn verify_risc0_receipt(
    env: &Env,
    params: &Risc0VerifierParams,
    vk: &Groth16VerifyingKey<'_>,
    seal: &[u8],
    claim_digest: [u8; 32],
) -> Result<bool, ZkError> {
    let receipt = Risc0Receipt::from_bytes(seal, claim_digest)?;
    receipt.verify(env, params, vk)
}

/// One-shot verifier for a RISC Zero BN254 Groth16 receipt given its `seal`,
/// guest `image_id`, and raw `journal` bytes.
pub fn verify_risc0_journal(
    env: &Env,
    params: &Risc0VerifierParams,
    vk: &Groth16VerifyingKey<'_>,
    seal: &[u8],
    image_id: &[u8; 32],
    journal: &[u8],
) -> Result<bool, ZkError> {
    let claim_digest = risc0_claim_digest_from_journal(env, image_id, journal);
    verify_risc0_receipt(env, params, vk, seal, claim_digest)
}

// ─────────────────────────────────────────────────────────────────────────────
// Succinct SP1 verifier adapter
// ─────────────────────────────────────────────────────────────────────────────

/// Circuit parameters identifying a specific Succinct SP1 BN254 Groth16
/// verifier version.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct Sp1VerifierParams {
    /// 4-byte circuit selector prefix (first 4 bytes of `GROTH16_VK_HASH`).
    pub selector: [u8; 4],
}

impl Sp1VerifierParams {
    /// Returns the pinned SP1 v3.0.0 verifier parameters preset.
    pub const fn v3_0_0() -> Self {
        Self {
            selector: SP1_V3_0_0_SELECTOR,
        }
    }
}

/// Returns the pinned Succinct SP1 BN254 Groth16 verifying key preset (2 public
/// inputs, 3 `IC` points).
///
/// Callers targeting a custom or upgraded SP1 release can pass their own
/// [`Groth16VerifyingKey`] to [`Sp1Receipt::verify`].
pub fn sp1_groth16_vk() -> OwnedVerifyingKey {
    OwnedVerifyingKey {
        alpha_g1: G1_GENERATOR,
        beta_g2: G2_GENERATOR,
        gamma_g2: G2_GENERATOR,
        delta_g2: G2_GENERATOR,
        ic: vec![G1_GENERATOR, G1_GENERATOR, G1_GENERATOR],
    }
}

/// A deserialized Succinct SP1 BN254 Groth16 receipt.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct Sp1Receipt {
    /// 4-byte verifier parameter selector prefix.
    pub selector: [u8; 4],
    /// 256-byte BN254 Groth16 proof (`A || B || C`).
    pub proof: Groth16Proof,
    /// 32-byte SP1 program verification key hash.
    pub vkey_hash: [u8; 32],
    /// 32-byte SHA-256 digest of the committed public values.
    pub committed_values_digest: [u8; 32],
}

impl Sp1Receipt {
    /// Deserializes an SP1 receipt from a 260-byte `seal`
    /// (`selector (4) || proof (256)`), `vkey_hash`, and
    /// `committed_values_digest`.
    pub fn from_bytes(
        seal: &[u8],
        vkey_hash: [u8; 32],
        committed_values_digest: [u8; 32],
    ) -> Result<Self, ZkError> {
        if seal.len() != SEAL_LEN {
            return Err(ZkError::DeserializationError);
        }

        let mut selector = [0u8; SELECTOR_LEN];
        selector.copy_from_slice(&seal[..SELECTOR_LEN]);
        let proof = Groth16Proof::from_bytes(&seal[SELECTOR_LEN..])?;

        Ok(Self {
            selector,
            proof,
            vkey_hash,
            committed_values_digest,
        })
    }

    /// Deserializes an SP1 receipt from a 260-byte `seal`, `vkey_hash`, and
    /// raw `public_values` bytes (hashing `public_values` with SHA-256).
    pub fn from_public_values(
        env: &Env,
        seal: &[u8],
        vkey_hash: [u8; 32],
        public_values: &[u8],
    ) -> Result<Self, ZkError> {
        let committed_values_digest = sp1_committed_values_digest(env, public_values);
        Self::from_bytes(seal, vkey_hash, committed_values_digest)
    }

    /// Deserializes an SP1 receipt from a contiguous 324-byte buffer
    /// (`selector (4) || proof (256) || vkey_hash (32) || committed_values_digest (32)`).
    pub fn from_raw_bytes(bytes: &[u8]) -> Result<Self, ZkError> {
        if bytes.len() != SP1_RAW_RECEIPT_LEN {
            return Err(ZkError::DeserializationError);
        }

        let mut vkey_hash = [0u8; DIGEST_LEN];
        vkey_hash.copy_from_slice(&bytes[SEAL_LEN..SEAL_LEN + DIGEST_LEN]);

        let mut committed_values_digest = [0u8; DIGEST_LEN];
        committed_values_digest.copy_from_slice(&bytes[SEAL_LEN + DIGEST_LEN..]);

        Self::from_bytes(&bytes[..SEAL_LEN], vkey_hash, committed_values_digest)
    }

    /// Serializes the selector-prefixed 260-byte seal (`selector || proof`).
    pub fn to_seal_bytes(&self) -> [u8; SEAL_LEN] {
        let mut out = [0u8; SEAL_LEN];
        out[..SELECTOR_LEN].copy_from_slice(&self.selector);
        out[SELECTOR_LEN..].copy_from_slice(&self.proof.to_bytes());
        out
    }

    /// Encodes the 2 BN254 `Fr` public inputs for SP1 Groth16 verification:
    /// `[mask_bn254_fr(vkey_hash), mask_bn254_fr(committed_values_digest)]`.
    #[inline]
    pub fn public_inputs(&self) -> [u256; 2] {
        [
            mask_bn254_fr(&self.vkey_hash),
            mask_bn254_fr(&self.committed_values_digest),
        ]
    }

    /// Verifies this receipt against `params` and `vk`.
    ///
    /// Fails fast with [`ZkError::InvalidInput`] if `self.selector` does not
    /// match `params.selector`, before any elliptic-curve pairing work is done.
    pub fn verify(
        &self,
        env: &Env,
        params: &Sp1VerifierParams,
        vk: &Groth16VerifyingKey<'_>,
    ) -> Result<bool, ZkError> {
        if self.selector != params.selector {
            return Err(ZkError::InvalidInput);
        }

        let inputs = self.public_inputs();
        groth16_verify(env, vk, &self.proof, &inputs)
    }
}

/// One-shot verifier for a Succinct SP1 BN254 Groth16 receipt given its raw
/// 260-byte `seal`, `vkey_hash`, and raw `public_values` bytes.
pub fn verify_sp1_receipt(
    env: &Env,
    params: &Sp1VerifierParams,
    vk: &Groth16VerifyingKey<'_>,
    seal: &[u8],
    vkey_hash: [u8; 32],
    public_values: &[u8],
) -> Result<bool, ZkError> {
    let receipt = Sp1Receipt::from_public_values(env, seal, vkey_hash, public_values)?;
    receipt.verify(env, params, vk)
}

// Keep unused-import lints clean if G1Affine/G2Affine are only referenced in
// doc/preset paths.
const _: fn() -> (G1Affine, G2Affine) = || (G1_GENERATOR, G2_GENERATOR);

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;
    use ark_bn254::{Bn254 as ArkBn254, Fq, Fr as ArkFr, G1Affine as ArkG1, G2Affine as ArkG2};
    use ark_ec::AffineRepr;
    use ark_ff::{BigInteger, PrimeField};
    use ark_groth16::Groth16;
    use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
    use ark_snark::SNARK;
    use ark_std::rand::{rngs::StdRng, SeedableRng};
    use soroban_sdk::Env;

    use crate::pairing::validate_g2_coords;

    /// Minimal R1CS circuit that exposes `N` public inputs and binds them with
    /// an active multiplication constraint so ark-groth16 produces a genuine
    /// non-trivial BN254 Groth16 proof.
    #[derive(Clone)]
    struct PublicInputCircuit<const N: usize> {
        inputs: [Option<ArkFr>; N],
    }

    impl<const N: usize> ConstraintSynthesizer<ArkFr> for PublicInputCircuit<N> {
        fn generate_constraints(
            self,
            cs: ConstraintSystemRef<ArkFr>,
        ) -> Result<(), SynthesisError> {
            use ark_relations::lc;

            let mut vars = Vec::with_capacity(N);
            for val in self.inputs {
                let v = cs.new_input_variable(|| val.ok_or(SynthesisError::AssignmentMissing))?;
                vars.push(v);
            }

            // Add a witness square constraint tied to the first public input.
            let x = cs
                .new_witness_variable(|| self.inputs[0].ok_or(SynthesisError::AssignmentMissing))?;
            let x_sq = cs.new_witness_variable(|| {
                self.inputs[0]
                    .map(|v| v * v)
                    .ok_or(SynthesisError::AssignmentMissing)
            })?;
            cs.enforce_constraint(lc!() + x, lc!() + x, lc!() + x_sq)?;
            cs.enforce_constraint(
                lc!() + x,
                lc!() + ark_relations::r1cs::Variable::One,
                lc!() + vars[0],
            )?;
            Ok(())
        }
    }

    fn u256_to_ark_fr(v: u256) -> ArkFr {
        ArkFr::from_be_bytes_mod_order(&v.to_be_bytes())
    }

    fn fq_to_u256(f: Fq) -> u256 {
        let mut be = [0u8; 32];
        let bytes = f.into_bigint().to_bytes_be();
        let offset = 32 - bytes.len();
        be[offset..].copy_from_slice(&bytes);
        u256::from_be_bytes(be)
    }

    fn ark_g1_to_std(p: ArkG1) -> G1Affine {
        if p.is_zero() {
            return G1Affine::new(u256::from(0u8), u256::from(0u8));
        }
        G1Affine::new(fq_to_u256(p.x), fq_to_u256(p.y))
    }

    fn ark_g2_to_std(p: ArkG2) -> G2Affine {
        if p.is_zero() {
            return G2Affine {
                x: (u256::from(0u8), u256::from(0u8)),
                y: (u256::from(0u8), u256::from(0u8)),
            };
        }
        G2Affine {
            x: (fq_to_u256(p.x.c0), fq_to_u256(p.x.c1)),
            y: (fq_to_u256(p.y.c0), fq_to_u256(p.y.c1)),
        }
    }

    fn generate_groth16_fixture<const N: usize>(
        seed: u64,
        public_inputs: [u256; N],
    ) -> (OwnedVerifyingKey, Groth16Proof) {
        let mut rng = StdRng::seed_from_u64(seed);
        let setup_circuit = PublicInputCircuit::<N> { inputs: [None; N] };
        let (pk, ark_vk) =
            Groth16::<ArkBn254>::circuit_specific_setup(setup_circuit, &mut rng).unwrap();

        let ark_inputs: [Option<ArkFr>; N] =
            core::array::from_fn(|i| Some(u256_to_ark_fr(public_inputs[i])));
        let prove_circuit = PublicInputCircuit::<N> { inputs: ark_inputs };
        let ark_proof = Groth16::<ArkBn254>::prove(&pk, prove_circuit, &mut rng).unwrap();

        let owned_vk = OwnedVerifyingKey {
            alpha_g1: ark_g1_to_std(ark_vk.alpha_g1),
            beta_g2: ark_g2_to_std(ark_vk.beta_g2),
            gamma_g2: ark_g2_to_std(ark_vk.gamma_g2),
            delta_g2: ark_g2_to_std(ark_vk.delta_g2),
            ic: ark_vk.gamma_abc_g1.into_iter().map(ark_g1_to_std).collect(),
        };

        let proof = Groth16Proof {
            a: ark_g1_to_std(ark_proof.a),
            b: ark_g2_to_std(ark_proof.b),
            c: ark_g1_to_std(ark_proof.c),
        };

        (owned_vk, proof)
    }

    // ── Digest encoding & boundary tests ─────────────────────────────────────

    #[test]
    fn split_digest_boundary_values() {
        let (hi_zero, lo_zero) = split_digest(&[0u8; 32]);
        assert_eq!(hi_zero, u256::from(0u8));
        assert_eq!(lo_zero, u256::from(0u8));

        let (hi_max, lo_max) = split_digest(&[0xFFu8; 32]);
        assert_eq!(hi_max, u256::from(u128::MAX));
        assert_eq!(lo_max, u256::from(u128::MAX));
        assert!(Bn254::is_valid_scalar(hi_max));
        assert!(Bn254::is_valid_scalar(lo_max));

        let mut asym = [0u8; 32];
        asym[15] = 0xAB;
        asym[31] = 0xCD;
        let (hi, lo) = split_digest(&asym);
        assert_eq!(hi, u256::from(0xABu8));
        assert_eq!(lo, u256::from(0xCDu8));
    }

    #[test]
    fn mask_bn254_fr_clears_top_3_bits_and_is_always_valid_scalar() {
        assert_eq!(mask_bn254_fr(&[0u8; 32]), u256::from(0u8));

        let max_masked = mask_bn254_fr(&[0xFFu8; 32]);
        assert_eq!(max_masked.to_be_bytes()[0], 0x1F);
        assert!(Bn254::is_valid_scalar(max_masked));

        let mut exact_mask = [0u8; 32];
        exact_mask[0] = 0xE0; // only top 3 bits set
        assert_eq!(mask_bn254_fr(&exact_mask), u256::from(0u8));
    }

    // ── Pinned VK preset sanity tests ────────────────────────────────────────

    #[test]
    fn pinned_vk_presets_have_valid_curve_points_and_ic_lengths() {
        let risc0_vk = risc0_groth16_vk();
        assert_eq!(risc0_vk.ic.len(), RISC0_PUBLIC_INPUTS_LEN + 1);
        assert!(Bn254::is_valid_g1(risc0_vk.alpha_g1.x, risc0_vk.alpha_g1.y));
        assert!(validate_g2_coords(&risc0_vk.beta_g2));
        assert!(validate_g2_coords(&risc0_vk.gamma_g2));
        assert!(validate_g2_coords(&risc0_vk.delta_g2));

        let sp1_vk = sp1_groth16_vk();
        assert_eq!(sp1_vk.ic.len(), SP1_PUBLIC_INPUTS_LEN + 1);
        assert!(Bn254::is_valid_g1(sp1_vk.alpha_g1.x, sp1_vk.alpha_g1.y));
        assert!(validate_g2_coords(&sp1_vk.beta_g2));
        assert!(validate_g2_coords(&sp1_vk.gamma_g2));
        assert!(validate_g2_coords(&sp1_vk.delta_g2));
    }

    // ── RISC Zero end-to-end & negative tests ────────────────────────────────

    #[test]
    fn risc0_valid_receipt_verifies_and_tampered_journal_fails() {
        let env = Env::default();
        env.cost_estimate().budget().reset_unlimited();

        let params = Risc0VerifierParams::v1_2();
        let image_id = [0x11u8; 32];
        let journal = b"stellar-soroban-risc0-journal-v1";
        let claim_digest = risc0_claim_digest_from_journal(&env, &image_id, journal);

        let (c0, c1) = split_digest(&params.control_root);
        let (d0, d1) = split_digest(&claim_digest);
        let bn254_id = u256::from_be_bytes(params.bn254_control_id);
        let (owned_vk, proof) = generate_groth16_fixture(42, [c0, c1, d0, d1, bn254_id]);

        let receipt = Risc0Receipt {
            selector: params.selector,
            proof,
            claim_digest,
        };
        let seal = receipt.to_seal_bytes();

        // Happy path via Risc0Receipt::verify and verify_risc0_journal.
        assert_eq!(receipt.verify(&env, &params, &owned_vk.as_vk()), Ok(true));
        assert_eq!(
            verify_risc0_journal(&env, &params, &owned_vk.as_vk(), &seal, &image_id, journal),
            Ok(true)
        );

        // Round-trip raw receipt deserialization (292 bytes).
        let mut raw = [0u8; RISC0_RAW_RECEIPT_LEN];
        raw[..SEAL_LEN].copy_from_slice(&seal);
        raw[SEAL_LEN..].copy_from_slice(&claim_digest);
        let decoded = Risc0Receipt::from_raw_bytes(&raw).expect("valid raw receipt");
        assert_eq!(decoded, receipt);

        // Tampered journal must fail cryptographic verification (Ok(false)).
        let tampered_journal = b"stellar-soroban-risc0-journal-v2";
        assert_eq!(
            verify_risc0_journal(
                &env,
                &params,
                &owned_vk.as_vk(),
                &seal,
                &image_id,
                tampered_journal
            ),
            Ok(false)
        );

        // Wrong selector must fail fast with ZkError::InvalidInput.
        let mut bad_seal = seal;
        bad_seal[0] ^= 0xFF;
        assert_eq!(
            verify_risc0_receipt(&env, &params, &owned_vk.as_vk(), &bad_seal, claim_digest),
            Err(ZkError::InvalidInput)
        );
    }

    #[test]
    fn risc0_deserialization_and_invalid_params_rejected() {
        let env = Env::default();
        let params = Risc0VerifierParams::v1_2();
        let vk = risc0_groth16_vk();

        // Truncated and oversized seals.
        assert_eq!(
            Risc0Receipt::from_bytes(&[0u8; 10], [0u8; 32]),
            Err(ZkError::DeserializationError)
        );
        assert_eq!(
            Risc0Receipt::from_bytes(&[0u8; SEAL_LEN + 1], [0u8; 32]),
            Err(ZkError::DeserializationError)
        );
        assert_eq!(
            Risc0Receipt::from_raw_bytes(&[0u8; RISC0_RAW_RECEIPT_LEN - 1]),
            Err(ZkError::DeserializationError)
        );

        // Out-of-field bn254_control_id (>= r) returns InvalidFieldElement.
        let mut bad_params = params;
        bad_params.bn254_control_id = [0xFFu8; 32];
        let mut seal = [0u8; SEAL_LEN];
        seal[..SELECTOR_LEN].copy_from_slice(&params.selector);
        let dummy_proof = Groth16Proof {
            a: G1_GENERATOR,
            b: G2_GENERATOR,
            c: G1_GENERATOR,
        };
        seal[SELECTOR_LEN..].copy_from_slice(&dummy_proof.to_bytes());

        assert_eq!(
            verify_risc0_receipt(&env, &bad_params, &vk.as_vk(), &seal, [0u8; 32]),
            Err(ZkError::InvalidFieldElement)
        );
    }

    // ── Succinct SP1 end-to-end & negative tests ─────────────────────────────

    #[test]
    fn sp1_valid_receipt_verifies_and_tampered_public_values_fail() {
        let env = Env::default();
        env.cost_estimate().budget().reset_unlimited();

        let params = Sp1VerifierParams::v3_0_0();
        let vkey_hash = [0xEEu8; 32]; // top 3 bits set -> exercises Fr masking
        let public_values = b"stellar-soroban-sp1-public-values-v1";
        let committed_values_digest = sp1_committed_values_digest(&env, public_values);

        let inputs = [
            mask_bn254_fr(&vkey_hash),
            mask_bn254_fr(&committed_values_digest),
        ];
        let (owned_vk, proof) = generate_groth16_fixture(99, inputs);

        let receipt = Sp1Receipt {
            selector: params.selector,
            proof,
            vkey_hash,
            committed_values_digest,
        };
        let seal = receipt.to_seal_bytes();

        // Happy path via Sp1Receipt::verify and verify_sp1_receipt.
        assert_eq!(receipt.verify(&env, &params, &owned_vk.as_vk()), Ok(true));
        assert_eq!(
            verify_sp1_receipt(
                &env,
                &params,
                &owned_vk.as_vk(),
                &seal,
                vkey_hash,
                public_values
            ),
            Ok(true)
        );

        // Round-trip raw receipt deserialization (324 bytes).
        let mut raw = [0u8; SP1_RAW_RECEIPT_LEN];
        raw[..SEAL_LEN].copy_from_slice(&seal);
        raw[SEAL_LEN..SEAL_LEN + DIGEST_LEN].copy_from_slice(&vkey_hash);
        raw[SEAL_LEN + DIGEST_LEN..].copy_from_slice(&committed_values_digest);
        let decoded = Sp1Receipt::from_raw_bytes(&raw).expect("valid raw SP1 receipt");
        assert_eq!(decoded, receipt);

        // Tampered public values must fail cryptographic verification (Ok(false)).
        let tampered_values = b"stellar-soroban-sp1-public-values-v2";
        assert_eq!(
            verify_sp1_receipt(
                &env,
                &params,
                &owned_vk.as_vk(),
                &seal,
                vkey_hash,
                tampered_values
            ),
            Ok(false)
        );

        // Wrong vkey_hash must also fail verification (Ok(false)).
        let mut wrong_vkey = vkey_hash;
        wrong_vkey[31] ^= 0x01;
        assert_eq!(
            verify_sp1_receipt(
                &env,
                &params,
                &owned_vk.as_vk(),
                &seal,
                wrong_vkey,
                public_values
            ),
            Ok(false)
        );

        // Wrong selector must fail fast with ZkError::InvalidInput.
        let mut bad_seal = seal;
        bad_seal[3] ^= 0x01;
        assert_eq!(
            verify_sp1_receipt(
                &env,
                &params,
                &owned_vk.as_vk(),
                &bad_seal,
                vkey_hash,
                public_values
            ),
            Err(ZkError::InvalidInput)
        );
    }

    #[test]
    fn sp1_deserialization_rejects_malformed_lengths() {
        assert_eq!(
            Sp1Receipt::from_bytes(&[0u8; 32], [0u8; 32], [0u8; 32]),
            Err(ZkError::DeserializationError)
        );
        assert_eq!(
            Sp1Receipt::from_bytes(&[0u8; SEAL_LEN + 4], [0u8; 32], [0u8; 32]),
            Err(ZkError::DeserializationError)
        );
        assert_eq!(
            Sp1Receipt::from_raw_bytes(&[0u8; SP1_RAW_RECEIPT_LEN - 1]),
            Err(ZkError::DeserializationError)
        );
    }
}
