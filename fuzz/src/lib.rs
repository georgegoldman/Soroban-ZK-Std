// SPDX-License-Identifier: Apache-2.0
//! Shared, panic-free decoders used by the `cargo-fuzz` targets.
//!
//! The targets exercise the byte-parsing surface that untrusted proofs and
//! verifying keys hit first. Every decoder here returns [`ZkError`] on
//! malformed input; none of them may panic. The Groth16 proof/VK decoders
//! delegate to the production library, while the PLONK, Bulletproofs and XDR
//! decoders implement the fixed big-endian layouts documented in their
//! respective modules so the targets can drive the same field/point parsing
//! primitives the verifiers use.

use ethnum::u256;
use soroban_zk_core::bulletproofs::{InnerProductProof, RangeProof};
use soroban_zk_core::plonk::PlonkProof;
use soroban_zk_core::{Bn254, G1Affine, ZkError};

/// Serialized size of one G1 point (`x || y`, 32 bytes each).
pub const G1_LEN: usize = 64;
/// Serialized size of one G2 point (`x.c1 || x.c0 || y.c1 || y.c0`).
pub const G2_LEN: usize = 128;
/// Serialized size of one scalar field element.
pub const FR_LEN: usize = 32;

/// Affine G2 coordinates `((x.c0, x.c1), (y.c0, y.c1))`.
pub type G2Coords = ((u256, u256), (u256, u256));

/// Number of inner-product rounds in a 64-bit Bulletproof: `log2(64)`.
pub const IP_ROUNDS: usize = 6;

/// Fixed serialized PLONK proof length: 9 G1 points + 8 Fr scalars.
pub const PLONK_PROOF_LEN: usize = 9 * G1_LEN + 8 * FR_LEN;
/// Fixed serialized Bulletproof length: 17 G1 points (5 commitments + 12
/// inner-product rounds) + 5 Fr scalars.
pub const BULLETPROOF_LEN: usize = 17 * G1_LEN + 5 * FR_LEN;

const ZERO_POINT: G1Affine = G1Affine {
    x: u256::from_words(0, 0),
    y: u256::from_words(0, 0),
};

/// Decodes a G1 point from exactly [`G1_LEN`] big-endian bytes, rejecting
/// coordinates outside the base field and points that are not on the curve.
pub fn decode_g1(bytes: &[u8]) -> Result<G1Affine, ZkError> {
    if bytes.len() != G1_LEN {
        return Err(ZkError::DeserializationError);
    }
    let x = Bn254::fq_from_bytes(read_array::<32>(&bytes[..32])?)
        .ok_or(ZkError::DeserializationError)?;
    let y = Bn254::fq_from_bytes(read_array::<32>(&bytes[32..])?)
        .ok_or(ZkError::DeserializationError)?;
    if !Bn254::is_valid_g1(x, y) {
        return Err(ZkError::DeserializationError);
    }
    Ok(G1Affine { x, y })
}

/// Decodes a G2 point from exactly [`G2_LEN`] big-endian bytes, rejecting
/// coordinates outside the base field and points that are not on the curve.
///
/// Subgroup membership is intentionally not checked here: that requires a full
/// 254-bit scalar multiplication per point, which would make coverage-guided
/// fuzzing too slow. The Groth16 VK target exercises the production decoder,
/// which performs the subgroup check.
pub fn decode_g2(bytes: &[u8]) -> Result<G2Coords, ZkError> {
    if bytes.len() != G2_LEN {
        return Err(ZkError::DeserializationError);
    }
    let x1 = Bn254::fq_from_bytes(read_array::<32>(&bytes[..32])?)
        .ok_or(ZkError::DeserializationError)?;
    let x0 = Bn254::fq_from_bytes(read_array::<32>(&bytes[32..64])?)
        .ok_or(ZkError::DeserializationError)?;
    let y1 = Bn254::fq_from_bytes(read_array::<32>(&bytes[64..96])?)
        .ok_or(ZkError::DeserializationError)?;
    let y0 = Bn254::fq_from_bytes(read_array::<32>(&bytes[96..])?)
        .ok_or(ZkError::DeserializationError)?;
    let x = (x0, x1);
    let y = (y0, y1);
    if !Bn254::is_on_curve(x, y) {
        return Err(ZkError::DeserializationError);
    }
    Ok((x, y))
}

/// Decodes an Fr scalar, rejecting values `>= FR_MODULUS`.
pub fn decode_fr(bytes: &[u8]) -> Result<u256, ZkError> {
    if bytes.len() != FR_LEN {
        return Err(ZkError::DeserializationError);
    }
    Bn254::fr_from_bytes(read_array::<32>(bytes)?).ok_or(ZkError::DeserializationError)
}

/// Decodes a PLONK proof from the fixed layout:
///
/// ```text
/// wire[0..3] (G1) || z (G1) || quotient[0..3] (G1)
///   || w_zeta (G1) || w_zeta_omega (G1)
///   || wire_evaluations[0..3] || sigma_evaluations[0..2]
///   || z_omega || quotient || linearization        (Fr each)
/// ```
pub fn decode_plonk_proof(bytes: &[u8]) -> Result<PlonkProof, ZkError> {
    if bytes.len() != PLONK_PROOF_LEN {
        return Err(ZkError::DeserializationError);
    }

    let mut points = [ZERO_POINT; 9];
    for (i, point) in points.iter_mut().enumerate() {
        *point = decode_g1(&bytes[i * G1_LEN..(i + 1) * G1_LEN])?;
    }

    let scalar_base = 9 * G1_LEN;
    let mut scalars = [u256::from_words(0, 0); 8];
    for (i, scalar) in scalars.iter_mut().enumerate() {
        let off = scalar_base + i * FR_LEN;
        *scalar = decode_fr(&bytes[off..off + FR_LEN])?;
    }

    Ok(PlonkProof {
        wire_commitments: [points[0], points[1], points[2]],
        z_commitment: points[3],
        quotient_commitments: [points[4], points[5], points[6]],
        w_zeta: points[7],
        w_zeta_omega: points[8],
        wire_evaluations: [scalars[0], scalars[1], scalars[2]],
        sigma_evaluations: [scalars[3], scalars[4]],
        z_omega_evaluation: scalars[5],
        quotient_evaluation: scalars[6],
        linearization_evaluation: scalars[7],
    })
}

/// Decodes a 64-bit Bulletproof from the fixed layout:
///
/// ```text
/// V || A || S || T1 || T2 (G1)
///   || tau_x || mu || t_hat (Fr)
///   || L[0..6] (G1) || R[0..6] (G1)
///   || a || b (Fr)
/// ```
pub fn decode_bulletproof(bytes: &[u8]) -> Result<RangeProof, ZkError> {
    if bytes.len() != BULLETPROOF_LEN {
        return Err(ZkError::DeserializationError);
    }

    let mut off = 0;
    let next_g1 = |off: &mut usize| -> Result<G1Affine, ZkError> {
        let point = decode_g1(&bytes[*off..*off + G1_LEN])?;
        *off += G1_LEN;
        Ok(point)
    };

    let v = next_g1(&mut off)?;
    let a = next_g1(&mut off)?;
    let s = next_g1(&mut off)?;
    let t1 = next_g1(&mut off)?;
    let t2 = next_g1(&mut off)?;

    let taux = decode_fr(&bytes[off..off + FR_LEN])?;
    off += FR_LEN;
    let mu = decode_fr(&bytes[off..off + FR_LEN])?;
    off += FR_LEN;
    let t_hat = decode_fr(&bytes[off..off + FR_LEN])?;
    off += FR_LEN;

    let mut l = [ZERO_POINT; IP_ROUNDS];
    for point in l.iter_mut() {
        *point = next_g1(&mut off)?;
    }
    let mut r = [ZERO_POINT; IP_ROUNDS];
    for point in r.iter_mut() {
        *point = next_g1(&mut off)?;
    }

    let ip_a = decode_fr(&bytes[off..off + FR_LEN])?;
    off += FR_LEN;
    let ip_b = decode_fr(&bytes[off..off + FR_LEN])?;
    debug_assert_eq!(off + FR_LEN, BULLETPROOF_LEN);

    Ok(RangeProof {
        v,
        a,
        s,
        t1,
        t2,
        taux,
        mu,
        t_hat,
        ip_proof: InnerProductProof {
            l,
            r,
            a: ip_a,
            b: ip_b,
        },
    })
}

/// Walks an XDR-style buffer of fixed-width field/point records.
///
/// Each step accepts a 64-byte G1 point, a 128-byte G2 point, or a 32-byte Fr
/// scalar, in that preference order. A trailing partial record or a 32-byte
/// word that does not decode as a field element is a clean
/// [`ZkError::DeserializationError`]. Returns the number of records decoded.
pub fn decode_xdr(bytes: &[u8]) -> Result<usize, ZkError> {
    if bytes.is_empty() || !bytes.len().is_multiple_of(32) {
        return Err(ZkError::DeserializationError);
    }

    let mut decoded = 0usize;
    let mut off = 0usize;
    while off < bytes.len() {
        let remaining = bytes.len() - off;

        if remaining >= G1_LEN && decode_g1(&bytes[off..off + G1_LEN]).is_ok() {
            off += G1_LEN;
            decoded += 1;
            continue;
        }
        if remaining >= G2_LEN && decode_g2(&bytes[off..off + G2_LEN]).is_ok() {
            off += G2_LEN;
            decoded += 1;
            continue;
        }
        if decode_fr(&bytes[off..off + FR_LEN]).is_ok() {
            off += FR_LEN;
            decoded += 1;
            continue;
        }

        return Err(ZkError::DeserializationError);
    }

    Ok(decoded)
}

#[inline]
fn read_array<const N: usize>(bytes: &[u8]) -> Result<[u8; N], ZkError> {
    bytes.try_into().map_err(|_| ZkError::DeserializationError)
}

#[cfg(test)]
mod tests {
    use super::*;

    const G1_GENERATOR: G1Affine = G1Affine {
        x: u256::from_words(0, 1),
        y: u256::from_words(0, 2),
    };

    fn g1_bytes() -> [u8; G1_LEN] {
        let mut out = [0u8; G1_LEN];
        out[..32].copy_from_slice(&G1_GENERATOR.x.to_be_bytes());
        out[32..].copy_from_slice(&G1_GENERATOR.y.to_be_bytes());
        out
    }

    fn one_bytes() -> [u8; FR_LEN] {
        u256::from_words(0, 1).to_be_bytes()
    }

    fn plonk_fixture() -> Vec<u8> {
        let mut out = Vec::new();
        for _ in 0..9 {
            out.extend_from_slice(&g1_bytes());
        }
        for _ in 0..8 {
            out.extend_from_slice(&one_bytes());
        }
        out
    }

    fn bulletproof_fixture() -> Vec<u8> {
        let mut out = Vec::new();
        for _ in 0..5 {
            out.extend_from_slice(&g1_bytes());
        }
        for _ in 0..3 {
            out.extend_from_slice(&one_bytes());
        }
        for _ in 0..12 {
            out.extend_from_slice(&g1_bytes());
        }
        for _ in 0..2 {
            out.extend_from_slice(&one_bytes());
        }
        out
    }

    #[test]
    fn g1_round_trips_and_rejects_wrong_length() {
        assert_eq!(decode_g1(&g1_bytes()), Ok(G1_GENERATOR));
        assert_eq!(decode_g1(&[]), Err(ZkError::DeserializationError));
        assert_eq!(
            decode_g1(&[0u8; G1_LEN - 1]),
            Err(ZkError::DeserializationError)
        );
    }

    #[test]
    fn g1_rejects_off_curve_and_zero_point() {
        assert_eq!(
            decode_g1(&[0u8; G1_LEN]),
            Err(ZkError::DeserializationError)
        );
        let mut bad = g1_bytes();
        bad[63] ^= 1;
        assert_eq!(decode_g1(&bad), Err(ZkError::DeserializationError));
    }

    #[test]
    fn fr_boundaries_are_enforced() {
        assert_eq!(decode_fr(&one_bytes()), Ok(u256::from_words(0, 1)));
        assert_eq!(
            decode_fr(&Bn254::FR_MODULUS.to_be_bytes()),
            Err(ZkError::DeserializationError)
        );
        assert_eq!(
            decode_fr(&[0xff; FR_LEN]),
            Err(ZkError::DeserializationError)
        );
    }

    #[test]
    fn plonk_fixture_decodes_and_bad_lengths_fail() {
        let proof = decode_plonk_proof(&plonk_fixture()).expect("fixture must decode");
        assert_eq!(proof.wire_commitments[0], G1_GENERATOR);
        assert_eq!(proof.linearization_evaluation, u256::from_words(0, 1));

        assert_eq!(decode_plonk_proof(&[]), Err(ZkError::DeserializationError));
        let mut truncated = plonk_fixture();
        truncated.pop();
        assert_eq!(
            decode_plonk_proof(&truncated),
            Err(ZkError::DeserializationError)
        );
    }

    #[test]
    fn plonk_fixture_rejects_out_of_range_scalar() {
        let mut bytes = plonk_fixture();
        let last = bytes.len() - FR_LEN;
        bytes[last..].copy_from_slice(&Bn254::FR_MODULUS.to_be_bytes());
        assert_eq!(
            decode_plonk_proof(&bytes),
            Err(ZkError::DeserializationError)
        );
    }

    #[test]
    fn bulletproof_fixture_decodes_and_bad_lengths_fail() {
        let proof = decode_bulletproof(&bulletproof_fixture()).expect("fixture must decode");
        assert_eq!(proof.v, G1_GENERATOR);
        assert_eq!(proof.ip_proof.a, u256::from_words(0, 1));
        assert_eq!(proof.ip_proof.b, u256::from_words(0, 1));

        assert_eq!(decode_bulletproof(&[]), Err(ZkError::DeserializationError));
        let mut truncated = bulletproof_fixture();
        truncated.pop();
        assert_eq!(
            decode_bulletproof(&truncated),
            Err(ZkError::DeserializationError)
        );
    }

    #[test]
    fn xdr_walks_points_scalars_and_rejects_partial_records() {
        let mut g1 = g1_bytes().to_vec();
        assert_eq!(decode_xdr(&g1), Ok(1));

        let scalar = one_bytes().to_vec();
        assert_eq!(decode_xdr(&scalar), Ok(1));

        g1.extend_from_slice(&scalar);
        assert_eq!(decode_xdr(&g1), Ok(2));

        assert_eq!(decode_xdr(&[]), Err(ZkError::DeserializationError));
        assert_eq!(decode_xdr(&[0u8; 33]), Err(ZkError::DeserializationError));
        assert_eq!(
            decode_xdr(&[0xff; FR_LEN]),
            Err(ZkError::DeserializationError)
        );
    }
}
