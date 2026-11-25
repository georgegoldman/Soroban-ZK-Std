//! BLS12-381 KZG Polynomial Commitment & EIP-4844 Point-Evaluation Verifier.
//!
//! This module implements native BLS12-381 KZG single and batched opening proof
//! verification as well as EIP-4844 blob point-evaluation verification using
//! Soroban CAP-0059 host functions (`env.crypto().bls12_381()`).
//!
//! ## Verification Equations
//!
//! ### Single KZG Opening Proof
//! Given commitment `C ∈ G₁`, evaluation point `z ∈ Fr`, claimed value `y ∈ Fr`,
//! opening proof `π ∈ G₁`, and trusted-setup element `[τ]₂ ∈ G₂`:
//!
//! ```text
//! e(C - [y]G₁, G₂) · e(-π, [τ - z]G₂) == 1
//! ```
//!
//! ### Batched KZG Opening Proofs
//! For `n` proofs `(Cᵢ, zᵢ, yᵢ, πᵢ)` with Fiat-Shamir challenge `r`:
//!
//! ```text
//! e(Σ rⁱ(Cᵢ - [yᵢ]G₁ + zᵢ·πᵢ), G₂) · e(-Σ rⁱ·πᵢ, [τ]₂) == 1
//! ```
//!
//! ### EIP-4844 Point Evaluation
//! 1. Verifies `versioned_hash == 0x01 || sha256(compress(C))[1..]`.
//! 2. Verifies the KZG opening proof `e(C - [y]G₁, G₂) · e(-π, [τ - z]G₂) == 1`.
//!
//! ## Security
//!
//! All untrusted inputs undergo strict canonical validation before any host
//! curve call:
//! - Scalars must be strictly less than the BLS12-381 scalar modulus `r`.
//! - G1/G2 points must use canonical uncompressed encoding (`compression_flag == 0`,
//!   `sort_flag == 0`, canonical infinity or coordinates `< p`), lie on the curve,
//!   and belong to the prime-order subgroup.

extern crate alloc;

use soroban_sdk::{
    crypto::bls12_381::{Bls12381Fr, Bls12381G1Affine, Bls12381G2Affine},
    Bytes, BytesN, Env, Vec, U256,
};
use soroban_zk_core::ZkError;

/// Size in bytes of a serialized BLS12-381 scalar field element (`Fr`).
pub const FR_SIZE: usize = 32;
/// Size in bytes of a compressed BLS12-381 G1 point (EIP-4844 commitment/proof format).
pub const G1_COMPRESSED_SIZE: usize = 48;
/// Size in bytes of an uncompressed BLS12-381 G1 point (Soroban CAP-0059 format).
pub const G1_UNCOMPRESSED_SIZE: usize = 96;
/// Size in bytes of an uncompressed BLS12-381 G2 point (Soroban CAP-0059 format).
pub const G2_UNCOMPRESSED_SIZE: usize = 192;

/// EIP-4844 version byte for KZG versioned hashes (`VERSIONED_HASH_VERSION_KZG`).
pub const EIP4844_VERSIONED_HASH_VERSION_KZG: u8 = 0x01;
/// Number of field elements per EIP-4844 blob (`FIELD_ELEMENTS_PER_BLOB`).
pub const EIP4844_FIELD_ELEMENTS_PER_BLOB: usize = 4096;

/// BLS12-381 base field modulus `p` (big-endian, 48 bytes).
pub const BLS12_381_FP_MODULUS_BE: [u8; 48] = [
    0x1a, 0x01, 0x11, 0xea, 0x39, 0x7f, 0xe6, 0x9a, 0x4b, 0x1b, 0xa7, 0xb6, 0x43, 0x4b, 0xac, 0xd7,
    0x64, 0x77, 0x4b, 0x84, 0xf3, 0x85, 0x12, 0xbf, 0x67, 0x30, 0xd2, 0xa0, 0xf6, 0xb0, 0xf6, 0x24,
    0x1e, 0xab, 0xff, 0xfe, 0xb1, 0x53, 0xff, 0xff, 0xb9, 0xfe, 0xff, 0xff, 0xff, 0xff, 0xaa, 0xab,
];

/// `(p - 1) / 2` in big-endian (used to determine the lexicographically larger `y` for G1 compression).
const BLS12_381_FP_HALF_MODULUS_BE: [u8; 48] = [
    0x0d, 0x00, 0x88, 0xf5, 0x1c, 0xbf, 0xf3, 0x4d, 0x25, 0x8d, 0xd3, 0xdb, 0x21, 0xa5, 0xd6, 0x6b,
    0xb2, 0x3b, 0xa5, 0xc2, 0x79, 0xc2, 0x89, 0x5f, 0xb3, 0x98, 0x69, 0x50, 0x7b, 0x58, 0x7b, 0x12,
    0x0f, 0x55, 0xff, 0xff, 0x58, 0xa9, 0xff, 0xff, 0xdc, 0xff, 0x7f, 0xff, 0xff, 0xff, 0xd5, 0x55,
];

/// BLS12-381 scalar field modulus `r` (big-endian, 32 bytes).
pub const BLS12_381_FR_MODULUS_BE: [u8; 32] = [
    0x73, 0xed, 0xa7, 0x53, 0x29, 0x9d, 0x7d, 0x48, 0x33, 0x39, 0xd8, 0x08, 0x09, 0xa1, 0xd8, 0x05,
    0x53, 0xbd, 0xa4, 0x02, 0xff, 0xfe, 0x5b, 0xfe, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01,
];

/// Canonical uncompressed BLS12-381 G1 generator (`be(X) || be(Y)`).
pub const G1_GENERATOR_BYTES: [u8; G1_UNCOMPRESSED_SIZE] = [
    0x17, 0xf1, 0xd3, 0xa7, 0x31, 0x97, 0xd7, 0x94, 0x26, 0x95, 0x63, 0x8c, 0x4f, 0xa9, 0xac, 0x0f,
    0xc3, 0x68, 0x8c, 0x4f, 0x97, 0x74, 0xb9, 0x05, 0xa1, 0x4e, 0x3a, 0x3f, 0x17, 0x1b, 0xac, 0x58,
    0x6c, 0x55, 0xe8, 0x3f, 0xf9, 0x7a, 0x1a, 0xef, 0xfb, 0x3a, 0xf0, 0x0a, 0xdb, 0x22, 0xc6, 0xbb,
    0x08, 0xb3, 0xf4, 0x81, 0xe3, 0xaa, 0xa0, 0xf1, 0xa0, 0x9e, 0x30, 0xed, 0x74, 0x1d, 0x8a, 0xe4,
    0xfc, 0xf5, 0xe0, 0x95, 0xd5, 0xd0, 0x0a, 0xf6, 0x00, 0xdb, 0x18, 0xcb, 0x2c, 0x04, 0xb3, 0xed,
    0xd0, 0x3c, 0xc7, 0x44, 0xa2, 0x88, 0x8a, 0xe4, 0x0c, 0xaa, 0x23, 0x29, 0x46, 0xc5, 0xe7, 0xe1,
];

/// Canonical uncompressed BLS12-381 G2 generator (`be(X_c1) || be(X_c0) || be(Y_c1) || be(Y_c0)`).
pub const G2_GENERATOR_BYTES: [u8; G2_UNCOMPRESSED_SIZE] = [
    0x13, 0xe0, 0x2b, 0x60, 0x52, 0x71, 0x9f, 0x60, 0x7d, 0xac, 0xd3, 0xa0, 0x88, 0x27, 0x4f, 0x65,
    0x59, 0x6b, 0xd0, 0xd0, 0x99, 0x20, 0xb6, 0x1a, 0xb5, 0xda, 0x61, 0xbb, 0xdc, 0x7f, 0x50, 0x49,
    0x33, 0x4c, 0xf1, 0x12, 0x13, 0x94, 0x5d, 0x57, 0xe5, 0xac, 0x7d, 0x05, 0x5d, 0x04, 0x2b, 0x7e,
    0x02, 0x4a, 0xa2, 0xb2, 0xf0, 0x8f, 0x0a, 0x91, 0x26, 0x08, 0x05, 0x27, 0x2d, 0xc5, 0x10, 0x51,
    0xc6, 0xe4, 0x7a, 0xd4, 0xfa, 0x40, 0x3b, 0x02, 0xb4, 0x51, 0x0b, 0x64, 0x7a, 0xe3, 0xd1, 0x77,
    0x0b, 0xac, 0x03, 0x26, 0xa8, 0x05, 0xbb, 0xef, 0xd4, 0x80, 0x56, 0xc8, 0xc1, 0x21, 0xbd, 0xb8,
    0x06, 0x06, 0xc4, 0xa0, 0x2e, 0xa7, 0x34, 0xcc, 0x32, 0xac, 0xd2, 0xb0, 0x2b, 0xc2, 0x8b, 0x99,
    0xcb, 0x3e, 0x28, 0x7e, 0x85, 0xa7, 0x63, 0xaf, 0x26, 0x74, 0x92, 0xab, 0x57, 0x2e, 0x99, 0xab,
    0x3f, 0x37, 0x0d, 0x27, 0x5c, 0xec, 0x1d, 0xa1, 0xaa, 0xa9, 0x07, 0x5f, 0xf0, 0x5f, 0x79, 0xbe,
    0x0c, 0xe5, 0xd5, 0x27, 0x72, 0x7d, 0x6e, 0x11, 0x8c, 0xc9, 0xcd, 0xc6, 0xda, 0x2e, 0x35, 0x1a,
    0xad, 0xfd, 0x9b, 0xaa, 0x8c, 0xbd, 0xd3, 0xa7, 0x6d, 0x42, 0x9a, 0x69, 0x51, 0x60, 0xd1, 0x2c,
    0x92, 0x3a, 0xc9, 0xcc, 0x3b, 0xac, 0xa2, 0x89, 0xe1, 0x93, 0x54, 0x86, 0x08, 0xb8, 0x28, 0x01,
];

/// Canonical uncompressed BLS12-381 G1 point at infinity (`0x40 || 0x00*95`).
pub const G1_IDENTITY_BYTES: [u8; G1_UNCOMPRESSED_SIZE] = {
    let mut b = [0u8; G1_UNCOMPRESSED_SIZE];
    b[0] = 0x40;
    b
};

/// Canonical uncompressed BLS12-381 G2 point at infinity (`0x40 || 0x00*191`).
pub const G2_IDENTITY_BYTES: [u8; G2_UNCOMPRESSED_SIZE] = {
    let mut b = [0u8; G2_UNCOMPRESSED_SIZE];
    b[0] = 0x40;
    b
};

/// A single BLS12-381 KZG polynomial opening proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KzgOpeningProof {
    /// Polynomial commitment `C ∈ G₁` (96-byte uncompressed).
    pub commitment: [u8; G1_UNCOMPRESSED_SIZE],
    /// Evaluation point `z ∈ Fr` (32-byte big-endian canonical scalar).
    pub z: [u8; FR_SIZE],
    /// Claimed evaluation `y = p(z) ∈ Fr` (32-byte big-endian canonical scalar).
    pub y: [u8; FR_SIZE],
    /// Opening proof `π ∈ G₁` (96-byte uncompressed).
    pub proof: [u8; G1_UNCOMPRESSED_SIZE],
}

/// Returns the canonical BLS12-381 G1 generator.
#[inline]
pub fn g1_generator(env: &Env) -> Bls12381G1Affine {
    Bls12381G1Affine::from_bytes(BytesN::from_array(env, &G1_GENERATOR_BYTES))
}

/// Returns the canonical BLS12-381 G2 generator.
#[inline]
pub fn g2_generator(env: &Env) -> Bls12381G2Affine {
    Bls12381G2Affine::from_bytes(BytesN::from_array(env, &G2_GENERATOR_BYTES))
}

/// Returns the canonical BLS12-381 G1 point at infinity.
#[inline]
pub fn g1_identity(env: &Env) -> Bls12381G1Affine {
    Bls12381G1Affine::from_bytes(BytesN::from_array(env, &G1_IDENTITY_BYTES))
}

/// Returns the canonical BLS12-381 G2 point at infinity.
#[inline]
pub fn g2_identity(env: &Env) -> Bls12381G2Affine {
    Bls12381G2Affine::from_bytes(BytesN::from_array(env, &G2_IDENTITY_BYTES))
}

/// Validates that `bytes` represents a canonical BLS12-381 scalar (`< r`).
#[inline]
pub fn validate_fr_bytes(bytes: &[u8; FR_SIZE]) -> Result<(), ZkError> {
    if bytes >= &BLS12_381_FR_MODULUS_BE {
        return Err(ZkError::InvalidFieldElement);
    }
    Ok(())
}

/// Parses and validates a canonical 32-byte big-endian BLS12-381 scalar into [`Bls12381Fr`].
#[inline]
pub fn parse_fr(env: &Env, bytes: &[u8; FR_SIZE]) -> Result<Bls12381Fr, ZkError> {
    validate_fr_bytes(bytes)?;
    Ok(Bls12381Fr::from_bytes(BytesN::from_array(env, bytes)))
}

#[inline]
fn is_canonical_fp(slice: &[u8]) -> bool {
    slice.len() == 48 && slice < &BLS12_381_FP_MODULUS_BE[..]
}

#[inline]
fn is_canonical_infinity(bytes: &[u8]) -> bool {
    if bytes.is_empty() || bytes[0] != 0x40 {
        return false;
    }
    bytes[1..].iter().all(|&b| b == 0)
}

/// Validates an untrusted 96-byte uncompressed BLS12-381 G1 point:
/// 1. Checks canonical encoding flags (no compression flag, no sort flag).
/// 2. If infinity flag is set, ensures all remaining bytes are zero.
/// 3. Otherwise checks `X < p` and `Y < p`, on-curve membership, and prime-order subgroup membership.
pub fn validate_g1_bytes(
    env: &Env,
    bytes: &[u8; G1_UNCOMPRESSED_SIZE],
) -> Result<Bls12381G1Affine, ZkError> {
    let flags = bytes[0] & 0xe0;
    if (flags & 0x80) != 0 || (flags & 0x20) != 0 {
        return Err(ZkError::DeserializationError);
    }
    if (flags & 0x40) != 0 {
        if !is_canonical_infinity(bytes) {
            return Err(ZkError::DeserializationError);
        }
        return Ok(Bls12381G1Affine::from_bytes(BytesN::from_array(env, bytes)));
    }

    if !is_canonical_fp(&bytes[0..48]) || !is_canonical_fp(&bytes[48..96]) {
        return Err(ZkError::InvalidFieldElement);
    }

    let pt = Bls12381G1Affine::from_bytes(BytesN::from_array(env, bytes));
    let bls = env.crypto().bls12_381();
    if !bls.g1_is_on_curve(&pt) || !bls.g1_is_in_subgroup(&pt) {
        return Err(ZkError::InvalidInput);
    }
    Ok(pt)
}

/// Validates an untrusted 192-byte uncompressed BLS12-381 G2 point:
/// 1. Checks canonical encoding flags (no compression flag, no sort flag).
/// 2. If infinity flag is set, ensures all remaining bytes are zero.
/// 3. Otherwise checks all four `Fp` coordinates `< p`, on-curve membership, and prime-order subgroup membership.
pub fn validate_g2_bytes(
    env: &Env,
    bytes: &[u8; G2_UNCOMPRESSED_SIZE],
) -> Result<Bls12381G2Affine, ZkError> {
    let flags = bytes[0] & 0xe0;
    if (flags & 0x80) != 0 || (flags & 0x20) != 0 {
        return Err(ZkError::DeserializationError);
    }
    if (flags & 0x40) != 0 {
        if !is_canonical_infinity(bytes) {
            return Err(ZkError::DeserializationError);
        }
        return Ok(Bls12381G2Affine::from_bytes(BytesN::from_array(env, bytes)));
    }

    if !is_canonical_fp(&bytes[0..48])
        || !is_canonical_fp(&bytes[48..96])
        || !is_canonical_fp(&bytes[96..144])
        || !is_canonical_fp(&bytes[144..192])
    {
        return Err(ZkError::InvalidFieldElement);
    }

    let pt = Bls12381G2Affine::from_bytes(BytesN::from_array(env, bytes));
    let bls = env.crypto().bls12_381();
    if !bls.g2_is_on_curve(&pt) || !bls.g2_is_in_subgroup(&pt) {
        return Err(ZkError::InvalidInput);
    }
    Ok(pt)
}

/// Compresses a canonical 96-byte uncompressed BLS12-381 G1 point into the 48-byte
/// Zcash / EIP-4844 compressed format.
pub fn compress_g1(
    uncompressed: &[u8; G1_UNCOMPRESSED_SIZE],
) -> Result<[u8; G1_COMPRESSED_SIZE], ZkError> {
    let flags = uncompressed[0] & 0xe0;
    if (flags & 0x80) != 0 || (flags & 0x20) != 0 {
        return Err(ZkError::DeserializationError);
    }
    if (flags & 0x40) != 0 {
        if !is_canonical_infinity(uncompressed) {
            return Err(ZkError::DeserializationError);
        }
        let mut out = [0u8; G1_COMPRESSED_SIZE];
        out[0] = 0xc0; // compression | infinity
        return Ok(out);
    }
    if !is_canonical_fp(&uncompressed[0..48]) || !is_canonical_fp(&uncompressed[48..96]) {
        return Err(ZkError::InvalidFieldElement);
    }

    let mut out = [0u8; G1_COMPRESSED_SIZE];
    out.copy_from_slice(&uncompressed[0..48]);
    out[0] |= 0x80; // compression flag
    if &uncompressed[48..96] > &BLS12_381_FP_HALF_MODULUS_BE[..] {
        out[0] |= 0x20; // sort flag: y is lexicographically largest
    }
    Ok(out)
}

/// Computes the EIP-4844 KZG versioned hash: `0x01 || sha256(compressed_commitment)[1..]`.
pub fn kzg_commitment_to_versioned_hash(
    env: &Env,
    compressed_commitment: &[u8; G1_COMPRESSED_SIZE],
) -> [u8; 32] {
    let input = Bytes::from_array(env, compressed_commitment);
    let mut hash = env.crypto().sha256(&input).to_array();
    hash[0] = EIP4844_VERSIONED_HASH_VERSION_KZG;
    hash
}

/// Verifies a single BLS12-381 KZG polynomial opening proof:
///
/// ```text
/// e(C - [y]G₁, G₂) · e(-π, [τ - z]G₂) == 1
/// ```
///
/// All untrusted inputs (`commitment`, `z`, `y`, `proof`, `srs_g2`) are validated
/// for canonical field bounds and G1/G2 subgroup membership before calling host
/// pairing operations.
pub fn verify_kzg_proof(
    env: &Env,
    commitment: &[u8; G1_UNCOMPRESSED_SIZE],
    z: &[u8; FR_SIZE],
    y: &[u8; FR_SIZE],
    proof: &[u8; G1_UNCOMPRESSED_SIZE],
    srs_g2: &[u8; G2_UNCOMPRESSED_SIZE],
) -> Result<bool, ZkError> {
    let c_pt = validate_g1_bytes(env, commitment)?;
    let pi_pt = validate_g1_bytes(env, proof)?;
    let tau_g2 = validate_g2_bytes(env, srs_g2)?;
    let z_fr = parse_fr(env, z)?;
    let y_fr = parse_fr(env, y)?;

    let bls = env.crypto().bls12_381();
    let g1_gen = g1_generator(env);
    let g2_gen = g2_generator(env);

    // C - [y]G1
    let y_g1 = bls.g1_mul(&g1_gen, &y_fr);
    let c_minus_y = bls.g1_add(&c_pt, &-y_g1);

    // [tau]G2 - [z]G2
    let z_g2 = bls.g2_mul(&g2_gen, &z_fr);
    let tau_minus_z = bls.g2_add(&tau_g2, &-z_g2);

    let mut vp1 = Vec::new(env);
    vp1.push_back(c_minus_y);
    vp1.push_back(-pi_pt);

    let mut vp2 = Vec::new(env);
    vp2.push_back(g2_gen);
    vp2.push_back(tau_minus_z);

    Ok(bls.pairing_check(vp1, vp2))
}

/// Verifies a batch of BLS12-381 KZG polynomial opening proofs using a single
/// two-pairing check via deterministic Fiat-Shamir random linear combination.
///
/// Returns `Err(ZkError::InvalidInput)` if `proofs` is empty.
pub fn verify_kzg_proof_batch(
    env: &Env,
    proofs: &[KzgOpeningProof],
    srs_g2: &[u8; G2_UNCOMPRESSED_SIZE],
) -> Result<bool, ZkError> {
    if proofs.is_empty() {
        return Err(ZkError::InvalidInput);
    }
    if proofs.len() == 1 {
        let p = &proofs[0];
        return verify_kzg_proof(env, &p.commitment, &p.z, &p.y, &p.proof, srs_g2);
    }

    let tau_g2 = validate_g2_bytes(env, srs_g2)?;
    let bls = env.crypto().bls12_381();
    let g1_gen = g1_generator(env);
    let g2_gen = g2_generator(env);

    // Validate all inputs and build Fiat-Shamir transcript.
    let mut transcript = Bytes::from_slice(env, b"SOROBAN_ZK_BLS12_381_KZG_BATCH_V1");
    let mut c_pts = Vec::new(env);
    let mut pi_pts = Vec::new(env);
    let mut z_frs = Vec::new(env);
    let mut y_frs = Vec::new(env);

    for p in proofs {
        let c_pt = validate_g1_bytes(env, &p.commitment)?;
        let pi_pt = validate_g1_bytes(env, &p.proof)?;
        let z_fr = parse_fr(env, &p.z)?;
        let y_fr = parse_fr(env, &p.y)?;

        transcript.extend_from_array(&p.commitment);
        transcript.extend_from_array(&p.z);
        transcript.extend_from_array(&p.y);
        transcript.extend_from_array(&p.proof);

        c_pts.push_back(c_pt);
        pi_pts.push_back(pi_pt);
        z_frs.push_back(z_fr);
        y_frs.push_back(y_fr);
    }

    // Derive random challenge r = sha256(transcript) mod Fr.
    let hash = env.crypto().sha256(&transcript);
    let r = Bls12381Fr::from_u256(U256::from_be_bytes(env, &hash.into()));

    let mut r_pow = Bls12381Fr::from_u256(U256::from_u32(env, 1));
    let mut g1_points = Vec::new(env);
    let mut g1_scalars = Vec::new(env);
    let mut neg_pi_scalars = Vec::new(env);
    let mut y_acc = Bls12381Fr::from_u256(U256::from_u32(env, 0));

    for i in 0..proofs.len() as u32 {
        let c_i = c_pts.get(i).ok_or(ZkError::InvalidInput)?;
        let pi_i = pi_pts.get(i).ok_or(ZkError::InvalidInput)?;
        let z_i = z_frs.get(i).ok_or(ZkError::InvalidInput)?;
        let y_i = y_frs.get(i).ok_or(ZkError::InvalidInput)?;

        // Accumulate r^i * C_i + (r^i * z_i) * pi_i
        g1_points.push_back(c_i);
        g1_scalars.push_back(r_pow.clone());

        let r_z = bls.fr_mul(&r_pow, &z_i);
        g1_points.push_back(pi_i);
        g1_scalars.push_back(r_z);

        // Accumulate sum r^i * y_i
        let r_y = bls.fr_mul(&r_pow, &y_i);
        y_acc = bls.fr_add(&y_acc, &r_y);

        // Scalar for -sum(r^i * pi_i)
        neg_pi_scalars.push_back(r_pow.clone());

        r_pow = bls.fr_mul(&r_pow, &r);
    }

    // LHS_1 = sum(r^i * C_i + r^i * z_i * pi_i) - [sum(r^i * y_i)]G1
    let msm_lhs = bls.g1_msm(g1_points, g1_scalars);
    let y_g1 = bls.g1_mul(&g1_gen, &y_acc);
    let lhs_g1 = bls.g1_add(&msm_lhs, &-y_g1);

    // LHS_2 = -sum(r^i * pi_i)
    let sum_pi = bls.g1_msm(pi_pts, neg_pi_scalars);
    let neg_sum_pi = -sum_pi;

    let mut vp1 = Vec::new(env);
    vp1.push_back(lhs_g1);
    vp1.push_back(neg_sum_pi);

    let mut vp2 = Vec::new(env);
    vp2.push_back(g2_gen);
    vp2.push_back(tau_g2);

    Ok(bls.pairing_check(vp1, vp2))
}

/// EIP-4844 point-evaluation verifier (`verify_kzg_blob_proof`).
///
/// 1. Validates the commitment and verifies `versioned_hash == 0x01 || sha256(compress(commitment))[1..]`.
/// 2. Verifies the KZG opening proof `e(C - [y]G₁, G₂) · e(-π, [τ - z]G₂) == 1`.
pub fn verify_kzg_blob_proof(
    env: &Env,
    versioned_hash: &[u8; 32],
    z: &[u8; FR_SIZE],
    y: &[u8; FR_SIZE],
    commitment: &[u8; G1_UNCOMPRESSED_SIZE],
    proof: &[u8; G1_UNCOMPRESSED_SIZE],
    srs_g2: &[u8; G2_UNCOMPRESSED_SIZE],
) -> Result<bool, ZkError> {
    // Validate commitment encoding before computing versioned hash.
    let compressed = compress_g1(commitment)?;
    if versioned_hash[0] != EIP4844_VERSIONED_HASH_VERSION_KZG {
        return Ok(false);
    }
    let expected_hash = kzg_commitment_to_versioned_hash(env, &compressed);
    if &expected_hash != versioned_hash {
        return Ok(false);
    }

    verify_kzg_proof(env, commitment, z, y, proof, srs_g2)
}

/// Evaluates a polynomial in evaluation form over a multiplicative roots-of-unity
/// domain `{ω⁰, ω¹, ..., ωⁿ⁻¹}` at point `z` using the barycentric formula:
///
/// ```text
/// p(z) = ((zⁿ - 1) / n) · Σᵢ₌₀ⁿ⁻¹ (evals[i] · ωⁱ) / (z - ωⁱ)
/// ```
///
/// If `z == ωⁱ` for some `i`, returns `evals[i]` directly without dividing by zero.
///
/// Returns `Err(ZkError::InvalidInput)` if `evals` is empty or its length is not a
/// power of two, and `Err(ZkError::InvalidFieldElement)` if any scalar is `>= r`.
pub fn barycentric_evaluate(
    env: &Env,
    evals: &[[u8; FR_SIZE]],
    z: &[u8; FR_SIZE],
    root_of_unity: &[u8; FR_SIZE],
) -> Result<[u8; FR_SIZE], ZkError> {
    let n = evals.len();
    if n == 0 || !n.is_power_of_two() {
        return Err(ZkError::InvalidInput);
    }

    let z_fr = parse_fr(env, z)?;
    let omega = parse_fr(env, root_of_unity)?;
    let bls = env.crypto().bls12_381();

    let one = Bls12381Fr::from_u256(U256::from_u32(env, 1));
    let mut sum = Bls12381Fr::from_u256(U256::from_u32(env, 0));
    let mut omega_i = one.clone();

    for eval_bytes in evals {
        let y_i = parse_fr(env, eval_bytes)?;
        if z_fr == omega_i {
            return Ok(*eval_bytes);
        }
        let denom = bls.fr_sub(&z_fr, &omega_i);
        let denom_inv = bls.fr_inv(&denom);
        let term = bls.fr_mul(&bls.fr_mul(&y_i, &omega_i), &denom_inv);
        sum = bls.fr_add(&sum, &term);
        omega_i = bls.fr_mul(&omega_i, &omega);
    }

    let z_pow_n = bls.fr_pow(&z_fr, n as u64);
    let factor = bls.fr_sub(&z_pow_n, &one);
    let n_fr = Bls12381Fr::from_u256(U256::from_u32(env, n as u32));
    let n_inv = bls.fr_inv(&n_fr);

    let res = bls.fr_mul(&bls.fr_mul(&factor, &n_inv), &sum);
    Ok(res.to_bytes().to_array())
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::Env;

    fn fr_from_u64(env: &Env, v: u64) -> [u8; 32] {
        Bls12381Fr::from_u256(U256::from_u128(env, v as u128))
            .to_bytes()
            .to_array()
    }

    /// Helper: builds a synthetic KZG trusted setup with secret `tau` and generates
    /// a valid opening proof for polynomial `p(X) = c0 + c1*X + c2*X^2` at `z`.
    fn make_poly_opening(
        env: &Env,
        tau: u64,
        coeffs: &[u64],
        z_val: u64,
    ) -> (KzgOpeningProof, [u8; G2_UNCOMPRESSED_SIZE]) {
        let bls = env.crypto().bls12_381();
        let g1 = g1_generator(env);
        let g2 = g2_generator(env);

        let tau_fr = Bls12381Fr::from_u256(U256::from_u128(env, tau as u128));
        let z_fr = Bls12381Fr::from_u256(U256::from_u128(env, z_val as u128));
        let srs_g2 = bls.g2_mul(&g2, &tau_fr).to_bytes().to_array();

        // Evaluate p(tau) and p(z) via Horner's method.
        let mut p_tau = Bls12381Fr::from_u256(U256::from_u32(env, 0));
        let mut p_z = Bls12381Fr::from_u256(U256::from_u32(env, 0));
        for &c in coeffs.iter().rev() {
            let c_fr = Bls12381Fr::from_u256(U256::from_u128(env, c as u128));
            p_tau = bls.fr_add(&bls.fr_mul(&p_tau, &tau_fr), &c_fr);
            p_z = bls.fr_add(&bls.fr_mul(&p_z, &z_fr), &c_fr);
        }

        // C = [p(tau)]G1
        let commitment = bls.g1_mul(&g1, &p_tau).to_bytes().to_array();

        // q(tau) = (p(tau) - p(z)) / (tau - z)
        let num = bls.fr_sub(&p_tau, &p_z);
        let den = bls.fr_sub(&tau_fr, &z_fr);
        let q_tau = bls.fr_mul(&num, &bls.fr_inv(&den));
        let proof = bls.g1_mul(&g1, &q_tau).to_bytes().to_array();

        (
            KzgOpeningProof {
                commitment,
                z: z_fr.to_bytes().to_array(),
                y: p_z.to_bytes().to_array(),
                proof,
            },
            srs_g2,
        )
    }

    #[test]
    fn single_kzg_proof_verifies_valid_and_rejects_tampered() {
        let env = Env::default();
        env.cost_estimate().budget().reset_unlimited();

        // p(X) = 5 + 3X + 7X^2 evaluated at z = 11, secret tau = 42
        let (opening, srs_g2) = make_poly_opening(&env, 42, &[5, 3, 7], 11);

        assert_eq!(
            verify_kzg_proof(
                &env,
                &opening.commitment,
                &opening.z,
                &opening.y,
                &opening.proof,
                &srs_g2,
            ),
            Ok(true)
        );

        // Wrong evaluation y must be rejected.
        let bad_y = fr_from_u64(&env, 999);
        assert_eq!(
            verify_kzg_proof(
                &env,
                &opening.commitment,
                &opening.z,
                &bad_y,
                &opening.proof,
                &srs_g2,
            ),
            Ok(false)
        );

        // Wrong evaluation point z must be rejected.
        let bad_z = fr_from_u64(&env, 12);
        assert_eq!(
            verify_kzg_proof(
                &env,
                &opening.commitment,
                &bad_z,
                &opening.y,
                &opening.proof,
                &srs_g2,
            ),
            Ok(false)
        );
    }

    #[test]
    fn single_kzg_proof_handles_zero_polynomial_identity_points() {
        let env = Env::default();
        env.cost_estimate().budget().reset_unlimited();

        // Zero polynomial: C = O, y = 0, pi = O for any z.
        let bls = env.crypto().bls12_381();
        let tau_fr = Bls12381Fr::from_u256(U256::from_u32(&env, 19));
        let srs_g2 = bls
            .g2_mul(&g2_generator(&env), &tau_fr)
            .to_bytes()
            .to_array();
        let z = fr_from_u64(&env, 7);
        let y = fr_from_u64(&env, 0);

        assert_eq!(
            verify_kzg_proof(
                &env,
                &G1_IDENTITY_BYTES,
                &z,
                &y,
                &G1_IDENTITY_BYTES,
                &srs_g2,
            ),
            Ok(true)
        );
    }

    #[test]
    fn batched_kzg_proof_verifies_multiple_and_rejects_one_bad() {
        let env = Env::default();
        env.cost_estimate().budget().reset_unlimited();

        let (p1, srs_g2) = make_poly_opening(&env, 123, &[1, 2, 3], 5);
        let (p2, _) = make_poly_opening(&env, 123, &[9, 4, 2, 1], 17);
        let (p3, _) = make_poly_opening(&env, 123, &[42], 99);

        assert_eq!(
            verify_kzg_proof_batch(&env, &[p1, p2, p3], &srs_g2),
            Ok(true)
        );

        // Tamper with one proof in the batch -> must reject.
        let mut bad_p2 = p2;
        bad_p2.y = fr_from_u64(&env, 0);
        assert_eq!(
            verify_kzg_proof_batch(&env, &[p1, bad_p2, p3], &srs_g2),
            Ok(false)
        );

        // Empty batch -> InvalidInput.
        assert_eq!(
            verify_kzg_proof_batch(&env, &[], &srs_g2),
            Err(ZkError::InvalidInput)
        );
    }

    #[test]
    fn eip4844_blob_proof_and_versioned_hash_verification() {
        let env = Env::default();
        env.cost_estimate().budget().reset_unlimited();

        let (opening, srs_g2) = make_poly_opening(&env, 777, &[10, 20, 30, 40], 13);
        let compressed = compress_g1(&opening.commitment).expect("compress_g1");
        let versioned_hash = kzg_commitment_to_versioned_hash(&env, &compressed);
        assert_eq!(versioned_hash[0], EIP4844_VERSIONED_HASH_VERSION_KZG);

        assert_eq!(
            verify_kzg_blob_proof(
                &env,
                &versioned_hash,
                &opening.z,
                &opening.y,
                &opening.commitment,
                &opening.proof,
                &srs_g2,
            ),
            Ok(true)
        );

        // Wrong version byte -> Ok(false).
        let mut bad_version = versioned_hash;
        bad_version[0] = 0x02;
        assert_eq!(
            verify_kzg_blob_proof(
                &env,
                &bad_version,
                &opening.z,
                &opening.y,
                &opening.commitment,
                &opening.proof,
                &srs_g2,
            ),
            Ok(false)
        );

        // Wrong hash body -> Ok(false).
        let mut bad_hash = versioned_hash;
        bad_hash[31] ^= 0xff;
        assert_eq!(
            verify_kzg_blob_proof(
                &env,
                &bad_hash,
                &opening.z,
                &opening.y,
                &opening.commitment,
                &opening.proof,
                &srs_g2,
            ),
            Ok(false)
        );
    }

    #[test]
    fn eip4844_official_g1_generator_compression_and_versioned_hash() {
        let env = Env::default();
        // Official BLS12-381 G1 generator compressed bytes (Zcash / Ethereum consensus spec).
        let expected_g1_compressed: [u8; 48] = [
            0x97, 0xf1, 0xd3, 0xa7, 0x31, 0x97, 0xd7, 0x94, 0x26, 0x95, 0x63, 0x8c, 0x4f, 0xa9,
            0xac, 0x0f, 0xc3, 0x68, 0x8c, 0x4f, 0x97, 0x74, 0xb9, 0x05, 0xa1, 0x4e, 0x3a, 0x3f,
            0x17, 0x1b, 0xac, 0x58, 0x6c, 0x55, 0xe8, 0x3f, 0xf9, 0x7a, 0x1a, 0xef, 0xfb, 0x3a,
            0xf0, 0x0a, 0xdb, 0x22, 0xc6, 0xbb,
        ];
        assert_eq!(compress_g1(&G1_GENERATOR_BYTES), Ok(expected_g1_compressed));

        // Point at infinity compresses to 0xc0 || 0x00*47.
        let mut expected_inf = [0u8; 48];
        expected_inf[0] = 0xc0;
        assert_eq!(compress_g1(&G1_IDENTITY_BYTES), Ok(expected_inf));

        // Versioned hash of G1 generator starts with 0x01 and matches sha256(compressed)[1..].
        let vh = kzg_commitment_to_versioned_hash(&env, &expected_g1_compressed);
        assert_eq!(vh[0], 0x01);
        let raw_sha = env
            .crypto()
            .sha256(&Bytes::from_array(&env, &expected_g1_compressed))
            .to_array();
        assert_eq!(&vh[1..], &raw_sha[1..]);
    }

    #[test]
    fn barycentric_evaluate_matches_direct_polynomial_evaluation() {
        let env = Env::default();
        env.cost_estimate().budget().reset_unlimited();
        let bls = env.crypto().bls12_381();

        // Construct a primitive 4th root of unity in BLS12-381 Fr:
        // r - 1 is divisible by 2^32, so 7^((r-1)/4) mod r is a primitive 4th root of unity.
        // We can compute omega_4 = g^((r-1)/4) or use a known 4th root of unity:
        // In BLS12-381 Fr, let's compute omega = 7^((r-1)/4) using repeated squaring via fr_pow.
        // Easier: omega_4 = sqrt(-1) mod r. Let's use the exact 4th root of unity in BLS12-381 Fr:
        // 0x16a2a19edfe81f20d09b681922c813b4b63683508c2280b93829971f439f0d2b
        let omega_4: [u8; 32] = [
            0x16, 0xa2, 0xa1, 0x9e, 0xdf, 0xe8, 0x1f, 0x20, 0xd0, 0x9b, 0x68, 0x19, 0x22, 0xc8,
            0x13, 0xb4, 0xb6, 0x36, 0x83, 0x50, 0x8c, 0x22, 0x80, 0xb9, 0x38, 0x29, 0x97, 0x1f,
            0x43, 0x9f, 0x0d, 0x2b,
        ];
        let w = parse_fr(&env, &omega_4).unwrap();
        let one = Bls12381Fr::from_u256(U256::from_u32(&env, 1));
        assert_eq!(bls.fr_pow(&w, 4), one);
        assert_ne!(bls.fr_pow(&w, 2), one);

        // Polynomial p(X) = 3 + 5X + 2X^2 + 7X^3
        let eval_poly = |x: &Bls12381Fr| -> Bls12381Fr {
            let c0 = Bls12381Fr::from_u256(U256::from_u32(&env, 3));
            let c1 = Bls12381Fr::from_u256(U256::from_u32(&env, 5));
            let c2 = Bls12381Fr::from_u256(U256::from_u32(&env, 2));
            let c3 = Bls12381Fr::from_u256(U256::from_u32(&env, 7));
            let x2 = bls.fr_mul(x, x);
            let x3 = bls.fr_mul(&x2, x);
            bls.fr_add(
                &bls.fr_add(&c0, &bls.fr_mul(&c1, x)),
                &bls.fr_add(&bls.fr_mul(&c2, &x2), &bls.fr_mul(&c3, &x3)),
            )
        };

        let mut evals = [[0u8; 32]; 4];
        let mut wi = one;
        for slot in &mut evals {
            *slot = eval_poly(&wi).to_bytes().to_array();
            wi = bls.fr_mul(&wi, &w);
        }

        // Evaluate at an out-of-domain point z = 12345.
        let z_fr = Bls12381Fr::from_u256(U256::from_u32(&env, 12345));
        let z_bytes = z_fr.to_bytes().to_array();
        let expected = eval_poly(&z_fr).to_bytes().to_array();
        assert_eq!(
            barycentric_evaluate(&env, &evals, &z_bytes, &omega_4),
            Ok(expected)
        );

        // Evaluate directly on a domain point z = omega^1 -> must return evals[1] without div-by-zero.
        assert_eq!(
            barycentric_evaluate(&env, &evals, &omega_4, &omega_4),
            Ok(evals[1])
        );

        // Non-power-of-two domain -> InvalidInput.
        assert_eq!(
            barycentric_evaluate(&env, &evals[..3], &z_bytes, &omega_4),
            Err(ZkError::InvalidInput)
        );
    }

    #[test]
    fn rejects_non_canonical_scalars_and_invalid_g1_g2_points() {
        let env = Env::default();

        // Scalar == r -> InvalidFieldElement.
        assert_eq!(
            parse_fr(&env, &BLS12_381_FR_MODULUS_BE),
            Err(ZkError::InvalidFieldElement)
        );

        // G1 with compression flag set -> DeserializationError.
        let mut bad_g1 = G1_GENERATOR_BYTES;
        bad_g1[0] |= 0x80;
        assert_eq!(
            validate_g1_bytes(&env, &bad_g1),
            Err(ZkError::DeserializationError)
        );

        // G1 with non-zero trailing bytes on infinity -> DeserializationError.
        let mut bad_inf = G1_IDENTITY_BYTES;
        bad_inf[95] = 1;
        assert_eq!(
            validate_g1_bytes(&env, &bad_inf),
            Err(ZkError::DeserializationError)
        );

        // G1 with X >= p -> InvalidFieldElement.
        let mut overflow_g1 = [0u8; 96];
        overflow_g1[0..48].copy_from_slice(&BLS12_381_FP_MODULUS_BE);
        assert_eq!(
            validate_g1_bytes(&env, &overflow_g1),
            Err(ZkError::InvalidFieldElement)
        );

        // G1 off-curve point -> InvalidInput.
        let mut off_curve_g1 = G1_GENERATOR_BYTES;
        off_curve_g1[95] ^= 0x01;
        assert_eq!(
            validate_g1_bytes(&env, &off_curve_g1),
            Err(ZkError::InvalidInput)
        );

        // G2 with sort flag set -> DeserializationError.
        let mut bad_g2 = G2_GENERATOR_BYTES;
        bad_g2[0] |= 0x20;
        assert_eq!(
            validate_g2_bytes(&env, &bad_g2),
            Err(ZkError::DeserializationError)
        );

        // G2 off-curve point -> InvalidInput.
        let mut off_curve_g2 = G2_GENERATOR_BYTES;
        off_curve_g2[191] ^= 0x01;
        assert_eq!(
            validate_g2_bytes(&env, &off_curve_g2),
            Err(ZkError::InvalidInput)
        );
    }
}
