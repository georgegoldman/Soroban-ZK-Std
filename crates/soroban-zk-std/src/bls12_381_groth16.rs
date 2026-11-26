//! Native BLS12-381 Groth16 verification using Soroban CAP-0059.
//!
//! Every proof, verifying-key point, and public scalar is range checked before
//! the host MSM or pairing operation. Point checks include curve and subgroup
//! membership.

extern crate alloc;

use alloc::vec::Vec as AllocVec;
use soroban_sdk::{
    contracttype,
    crypto::bls12_381::{
        Bls12381Fr as HostFr, Bls12381G1Affine as HostG1, Bls12381G2Affine as HostG2,
    },
    Bytes, Env, Vec, U256,
};
use soroban_zk_core::ZkError;

use crate::bls12_381_kzg::{
    parse_fr, validate_g1_bytes, validate_g2_bytes, FR_SIZE, G1_UNCOMPRESSED_SIZE,
    G2_UNCOMPRESSED_SIZE,
};

/// Compressed BLS12-381 G1 encoding size.
pub const BLS_G1_COMPRESSED_SIZE: usize = 48;
/// Uncompressed BLS12-381 G1 encoding size used by CAP-0059.
pub const BLS_G1_UNCOMPRESSED_SIZE: usize = G1_UNCOMPRESSED_SIZE;
/// Compressed BLS12-381 G2 encoding size.
pub const BLS_G2_COMPRESSED_SIZE: usize = 96;
/// Uncompressed BLS12-381 G2 encoding size used by CAP-0059.
pub const BLS_G2_UNCOMPRESSED_SIZE: usize = G2_UNCOMPRESSED_SIZE;
/// Serialized Groth16 proof size (`A || B || C`).
pub const BLS_GROTH16_PROOF_SIZE: usize =
    BLS_G1_UNCOMPRESSED_SIZE * 2 + BLS_G2_UNCOMPRESSED_SIZE;

/// A G1 affine point in canonical CAP-0059 uncompressed encoding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Bls12381G1Affine {
    /// `X || Y`, each a 48-byte big-endian canonical Fp value.
    pub bytes: [u8; BLS_G1_UNCOMPRESSED_SIZE],
}

/// A G2 affine point in canonical CAP-0059 uncompressed encoding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Bls12381G2Affine {
    /// `X.c1 || X.c0 || Y.c1 || Y.c0`, each a 48-byte canonical Fp value.
    pub bytes: [u8; BLS_G2_UNCOMPRESSED_SIZE],
}

/// A BLS12-381 Groth16 proof.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Bls12381Groth16Proof {
    pub a: Bls12381G1Affine,
    pub b: Bls12381G2Affine,
    pub c: Bls12381G1Affine,
}

/// A BLS12-381 Groth16 verifying key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Bls12381VerifyingKey {
    pub alpha_g1: Bls12381G1Affine,
    pub beta_g2: Bls12381G2Affine,
    pub gamma_g2: Bls12381G2Affine,
    pub delta_g2: Bls12381G2Affine,
    /// `gamma_abc`, including the constant `IC[0]` point.
    pub ic: AllocVec<Bls12381G1Affine>,
}

impl Bls12381Groth16Proof {
    /// Decode `A || B || C` from CAP-0059 uncompressed point encodings.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ZkError> {
        if bytes.len() != BLS_GROTH16_PROOF_SIZE {
            return Err(ZkError::DeserializationError);
        }
        let mut a = [0; BLS_G1_UNCOMPRESSED_SIZE];
        let mut b = [0; BLS_G2_UNCOMPRESSED_SIZE];
        let mut c = [0; BLS_G1_UNCOMPRESSED_SIZE];
        a.copy_from_slice(&bytes[..BLS_G1_UNCOMPRESSED_SIZE]);
        let b_start = BLS_G1_UNCOMPRESSED_SIZE;
        b.copy_from_slice(&bytes[b_start..b_start + BLS_G2_UNCOMPRESSED_SIZE]);
        let c_start = b_start + BLS_G2_UNCOMPRESSED_SIZE;
        c.copy_from_slice(&bytes[c_start..]);
        Ok(Self {
            a: Bls12381G1Affine { bytes: a },
            b: Bls12381G2Affine { bytes: b },
            c: Bls12381G1Affine { bytes: c },
        })
    }

    /// Encode `A || B || C` in CAP-0059 uncompressed format.
    pub fn to_bytes(&self) -> [u8; BLS_GROTH16_PROOF_SIZE] {
        let mut out = [0; BLS_GROTH16_PROOF_SIZE];
        out[..BLS_G1_UNCOMPRESSED_SIZE].copy_from_slice(&self.a.bytes);
        let b_start = BLS_G1_UNCOMPRESSED_SIZE;
        out[b_start..b_start + BLS_G2_UNCOMPRESSED_SIZE].copy_from_slice(&self.b.bytes);
        out[b_start + BLS_G2_UNCOMPRESSED_SIZE..].copy_from_slice(&self.c.bytes);
        out
    }
}

/// Verify a Groth16 proof with `e(A,B) = e(alpha,beta) e(acc,gamma) e(C,delta)`.
pub fn bls12_381_groth16_verify(
    env: &Env,
    vk: &Bls12381VerifyingKey,
    proof: &Bls12381Groth16Proof,
    public_inputs: &[[u8; FR_SIZE]],
) -> Result<bool, ZkError> {
    if vk.ic.is_empty() || public_inputs.len() != vk.ic.len() - 1 {
        return Err(ZkError::InvalidInput);
    }

    let bls = env.crypto().bls12_381();
    let a = validate_g1_bytes(env, &proof.a.bytes)?;
    let b = validate_g2_bytes(env, &proof.b.bytes)?;
    let c = validate_g1_bytes(env, &proof.c.bytes)?;
    let alpha = validate_g1_bytes(env, &vk.alpha_g1.bytes)?;
    let beta = validate_g2_bytes(env, &vk.beta_g2.bytes)?;
    let gamma = validate_g2_bytes(env, &vk.gamma_g2.bytes)?;
    let delta = validate_g2_bytes(env, &vk.delta_g2.bytes)?;

    let mut ic_points: Vec<HostG1> = Vec::new(env);
    let mut scalars: Vec<HostFr> = Vec::new(env);
    let ic_zero = validate_g1_bytes(env, &vk.ic[0].bytes)?;
    ic_points.push_back(ic_zero.clone());
    scalars.push_back(HostFr::from_u256(U256::from_u32(env, 1)));
    for (point, input) in vk.ic[1..].iter().zip(public_inputs.iter()) {
        ic_points.push_back(validate_g1_bytes(env, &point.bytes)?);
        scalars.push_back(parse_fr(env, input)?);
    }
    let acc = bls.g1_msm(ic_points, scalars);
    let is_acc_zero = acc.to_bytes().to_array() == crate::bls12_381_kzg::G1_IDENTITY_BYTES;

    let mut g1_pairs: Vec<HostG1> = Vec::new(env);
    let mut g2_pairs: Vec<HostG2> = Vec::new(env);
    g1_pairs.push_back(a);
    g2_pairs.push_back(b);
    g1_pairs.push_back(-alpha);
    g2_pairs.push_back(beta);
    g1_pairs.push_back(-c);
    g2_pairs.push_back(delta);
    if !is_acc_zero {
        g1_pairs.push_back(-acc);
        g2_pairs.push_back(gamma);
    }
    Ok(bls.pairing_check(g1_pairs, g2_pairs))
}

/// Chunk size for persistent BLS verifying-key storage.
pub const BLS_VK_CHUNK_SIZE: usize = 32 * 1024;
/// Lower TTL bound for stored BLS verifying-key chunks.
pub const BLS_VK_TTL_THRESHOLD: u32 = 17_280;
/// TTL target for stored BLS verifying-key chunks.
pub const BLS_VK_TTL_AMOUNT: u32 = 518_400;

#[contracttype]
#[derive(Clone)]
pub enum BlsVkStorageKey {
    Meta,
    Chunk(u32),
}

#[contracttype]
#[derive(Clone)]
pub struct BlsVkMeta {
    pub chunk_count: u32,
    pub total_len: u32,
}

/// Save a validated BLS VK to persistent storage as TTL-extended chunks.
pub fn save_bls_vk(env: &Env, vk: &Bls12381VerifyingKey) -> Result<(), ZkError> {
    validate_vk(env, vk)?;
    let bytes = serialize_vk(env, vk);
    let total = bytes.len() as usize;
    let count = total.div_ceil(BLS_VK_CHUNK_SIZE);
    let store = env.storage().persistent();
    if let Some(old) = store.get::<BlsVkStorageKey, BlsVkMeta>(&BlsVkStorageKey::Meta) {
        for i in count as u32..old.chunk_count {
            store.remove(&BlsVkStorageKey::Chunk(i));
        }
    }
    for i in 0..count {
        let start = i * BLS_VK_CHUNK_SIZE;
        let end = core::cmp::min(total, start + BLS_VK_CHUNK_SIZE);
        let key = BlsVkStorageKey::Chunk(i as u32);
        store.set(&key, &bytes.slice(start as u32..end as u32));
        store.extend_ttl(&key, BLS_VK_TTL_THRESHOLD, BLS_VK_TTL_AMOUNT);
    }
    let meta = BlsVkMeta {
        chunk_count: count as u32,
        total_len: total as u32,
    };
    store.set(&BlsVkStorageKey::Meta, &meta);
    store.extend_ttl(
        &BlsVkStorageKey::Meta,
        BLS_VK_TTL_THRESHOLD,
        BLS_VK_TTL_AMOUNT,
    );
    Ok(())
}

/// Load and validate a BLS VK, extending the TTL of its header and each chunk.
pub fn load_bls_vk(env: &Env) -> Result<Bls12381VerifyingKey, ZkError> {
    let store = env.storage().persistent();
    let meta: BlsVkMeta = store
        .get(&BlsVkStorageKey::Meta)
        .ok_or(ZkError::StorageError)?;
    let header_len =
        2 * BLS_G1_UNCOMPRESSED_SIZE + 2 * BLS_G2_UNCOMPRESSED_SIZE + 4;
    let expected_chunks = (meta.total_len as usize).div_ceil(BLS_VK_CHUNK_SIZE);
    if (meta.total_len as usize) < header_len
        || meta.chunk_count == 0
        || meta.chunk_count as usize != expected_chunks
    {
        return Err(ZkError::DeserializationError);
    }
    store.extend_ttl(
        &BlsVkStorageKey::Meta,
        BLS_VK_TTL_THRESHOLD,
        BLS_VK_TTL_AMOUNT,
    );
    let mut bytes = Bytes::new(env);
    for i in 0..meta.chunk_count {
        let key = BlsVkStorageKey::Chunk(i);
        let chunk: Bytes = store.get(&key).ok_or(ZkError::StorageError)?;
        let start = (i as usize)
            .checked_mul(BLS_VK_CHUNK_SIZE)
            .ok_or(ZkError::DeserializationError)?;
        let expected_len = core::cmp::min(
            BLS_VK_CHUNK_SIZE,
            meta.total_len as usize - start,
        );
        if chunk.len() as usize != expected_len {
            return Err(ZkError::DeserializationError);
        }
        store.extend_ttl(&key, BLS_VK_TTL_THRESHOLD, BLS_VK_TTL_AMOUNT);
        bytes.append(&chunk);
    }
    if bytes.len() != meta.total_len {
        return Err(ZkError::DeserializationError);
    }
    deserialize_vk(env, &bytes)
}

fn validate_vk(env: &Env, vk: &Bls12381VerifyingKey) -> Result<(), ZkError> {
    if vk.ic.is_empty() {
        return Err(ZkError::InvalidInput);
    }
    validate_g1_bytes(env, &vk.alpha_g1.bytes)?;
    validate_g2_bytes(env, &vk.beta_g2.bytes)?;
    validate_g2_bytes(env, &vk.gamma_g2.bytes)?;
    validate_g2_bytes(env, &vk.delta_g2.bytes)?;
    for point in &vk.ic {
        validate_g1_bytes(env, &point.bytes)?;
    }
    Ok(())
}

fn serialize_vk(env: &Env, vk: &Bls12381VerifyingKey) -> Bytes {
    let mut bytes = Bytes::new(env);
    bytes.extend_from_array(&vk.alpha_g1.bytes);
    bytes.extend_from_array(&vk.beta_g2.bytes);
    bytes.extend_from_array(&vk.gamma_g2.bytes);
    bytes.extend_from_array(&vk.delta_g2.bytes);
    bytes.extend_from_array(&(vk.ic.len() as u32).to_be_bytes());
    for point in &vk.ic {
        bytes.extend_from_array(&point.bytes);
    }
    bytes
}

fn deserialize_vk(env: &Env, bytes: &Bytes) -> Result<Bls12381VerifyingKey, ZkError> {
    let raw: AllocVec<u8> = bytes.iter().collect();
    let header = 2 * BLS_G1_UNCOMPRESSED_SIZE + 2 * BLS_G2_UNCOMPRESSED_SIZE + 4;
    if raw.len() < header {
        return Err(ZkError::DeserializationError);
    }
    let mut offset = 0;
    let alpha_g1 = read_g1(&raw, &mut offset)?;
    let beta_g2 = read_g2(&raw, &mut offset)?;
    let gamma_g2 = read_g2(&raw, &mut offset)?;
    let delta_g2 = read_g2(&raw, &mut offset)?;
    let ic_len = u32::from_be_bytes(
        raw[offset..offset + 4]
            .try_into()
            .map_err(|_| ZkError::DeserializationError)?,
    ) as usize;
    offset += 4;
    let expected = ic_len
        .checked_mul(BLS_G1_UNCOMPRESSED_SIZE)
        .and_then(|n| n.checked_add(header))
        .ok_or(ZkError::DeserializationError)?;
    if ic_len == 0 || raw.len() != expected {
        return Err(ZkError::DeserializationError);
    }
    let mut ic = AllocVec::with_capacity(ic_len);
    for _ in 0..ic_len {
        ic.push(read_g1(&raw, &mut offset)?);
    }
    let vk = Bls12381VerifyingKey {
        alpha_g1,
        beta_g2,
        gamma_g2,
        delta_g2,
        ic,
    };
    validate_vk(env, &vk)?;
    Ok(vk)
}

fn read_g1(bytes: &[u8], offset: &mut usize) -> Result<Bls12381G1Affine, ZkError> {
    let end = offset
        .checked_add(BLS_G1_UNCOMPRESSED_SIZE)
        .ok_or(ZkError::DeserializationError)?;
    let slice = bytes
        .get(*offset..end)
        .ok_or(ZkError::DeserializationError)?;
    let mut point = [0; BLS_G1_UNCOMPRESSED_SIZE];
    point.copy_from_slice(slice);
    *offset = end;
    Ok(Bls12381G1Affine { bytes: point })
}

fn read_g2(bytes: &[u8], offset: &mut usize) -> Result<Bls12381G2Affine, ZkError> {
    let end = offset
        .checked_add(BLS_G2_UNCOMPRESSED_SIZE)
        .ok_or(ZkError::DeserializationError)?;
    let slice = bytes
        .get(*offset..end)
        .ok_or(ZkError::DeserializationError)?;
    let mut point = [0; BLS_G2_UNCOMPRESSED_SIZE];
    point.copy_from_slice(slice);
    *offset = end;
    Ok(Bls12381G2Affine { bytes: point })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::{Bls12_381, G1Affine as ArkG1Affine, G2Affine as ArkG2Affine};
    use ark_ec_05::{pairing::Pairing, AffineRepr, CurveGroup};
    use crate::bls12_381_kzg::{g1_generator, g2_generator, G1_IDENTITY_BYTES};

    fn test_vk(env: &Env) -> Bls12381VerifyingKey {
        let generator = Bls12381G1Affine {
            bytes: g1_generator(env).to_bytes().to_array(),
        };
        let identity = Bls12381G1Affine {
            bytes: G1_IDENTITY_BYTES,
        };
        let g2 = Bls12381G2Affine {
            bytes: g2_generator(env).to_bytes().to_array(),
        };
        Bls12381VerifyingKey {
            alpha_g1: generator,
            beta_g2: g2,
            gamma_g2: g2,
            delta_g2: g2,
            ic: alloc::vec![identity, generator],
        }
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn native_verifier_accepts_valid_relation_and_rejects_tampering() {
        let env = Env::default();
        env.cost_estimate().budget().reset_unlimited();
        let vk = test_vk(&env);
        let bls = env.crypto().bls12_381();
        let generator = validate_g1_bytes(&env, &vk.alpha_g1.bytes).expect("generator");
        let two = HostFr::from_u256(U256::from_u32(&env, 2));
        let proof = Bls12381Groth16Proof {
            a: Bls12381G1Affine {
                bytes: bls.g1_mul(&generator, &two).to_bytes().to_array(),
            },
            b: vk.beta_g2,
            c: Bls12381G1Affine {
                bytes: G1_IDENTITY_BYTES,
            },
        };
        let mut input = [0u8; FR_SIZE];
        input[FR_SIZE - 1] = 1;

        assert_eq!(bls12_381_groth16_verify(&env, &vk, &proof, &[input]), Ok(true));

        let ark_g1 = ArkG1Affine::generator();
        let ark_g2 = ArkG2Affine::generator();
        let ark_lhs = Bls12_381::pairing((ark_g1 + ark_g1).into_affine(), ark_g2);
        let ark_rhs =
            Bls12_381::pairing(ark_g1, ark_g2) + Bls12_381::pairing(ark_g1, ark_g2);
        assert_eq!(ark_lhs, ark_rhs);

        let tampered = Bls12381Groth16Proof {
            c: vk.ic[1],
            ..proof
        };
        assert_eq!(
            bls12_381_groth16_verify(&env, &vk, &tampered, &[input]),
            Ok(false)
        );
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn verifier_rejects_noncanonical_fields_and_invalid_points() {
        let env = Env::default();
        env.cost_estimate().budget().reset_unlimited();
        let vk = test_vk(&env);
        let proof = Bls12381Groth16Proof {
            a: vk.alpha_g1,
            b: vk.beta_g2,
            c: vk.alpha_g1,
        };
        assert_eq!(
            bls12_381_groth16_verify(
                &env,
                &vk,
                &proof,
                &[crate::bls12_381_kzg::BLS12_381_FR_MODULUS_BE]
            ),
            Err(ZkError::InvalidFieldElement)
        );

        let mut noncanonical_fp = [0u8; BLS_G1_UNCOMPRESSED_SIZE];
        noncanonical_fp[..48]
            .copy_from_slice(&crate::bls12_381_kzg::BLS12_381_FP_MODULUS_BE);
        let bad_fp_proof = Bls12381Groth16Proof {
            a: Bls12381G1Affine {
                bytes: noncanonical_fp,
            },
            ..proof
        };
        assert_eq!(
            bls12_381_groth16_verify(&env, &vk, &bad_fp_proof, &[[0; FR_SIZE]]),
            Err(ZkError::InvalidFieldElement)
        );

        let mut bad_vk = vk.clone();
        bad_vk.ic[1].bytes = [0; BLS_G1_UNCOMPRESSED_SIZE];
        assert_eq!(
            bls12_381_groth16_verify(&env, &bad_vk, &proof, &[[0; FR_SIZE]]),
            Err(ZkError::InvalidInput)
        );

        let mut off_subgroup = [0; BLS_G1_UNCOMPRESSED_SIZE];
        off_subgroup[BLS_G1_UNCOMPRESSED_SIZE - 1] = 2;
        let bad_proof = Bls12381Groth16Proof {
            a: Bls12381G1Affine {
                bytes: off_subgroup,
            },
            ..proof
        };
        assert_eq!(
            bls12_381_groth16_verify(&env, &vk, &bad_proof, &[[0; FR_SIZE]]),
            Err(ZkError::InvalidInput)
        );
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn chunked_vk_storage_round_trips_and_extends_ttl() {
        let env = Env::default();
        env.cost_estimate().budget().reset_unlimited();
        let vk = test_vk(&env);
        save_bls_vk(&env, &vk).expect("save");
        assert_eq!(load_bls_vk(&env), Ok(vk));
        assert!(
            env.storage()
                .persistent()
                .get_ttl(&BlsVkStorageKey::Meta)
                >= BLS_VK_TTL_THRESHOLD
        );
    }
}
