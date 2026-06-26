use ethnum::u256;
use soroban_sdk::crypto::bn254::{Bn254Fr as SdkFr, Bn254G1Affine as SdkG1Affine};
use soroban_sdk::{Bytes, BytesN, Env, Vec, U256};
use zk_core::{Bn254, G1Affine, ZkError};

use crate::pairing::{g1_to_bytes, pairing_check, G2Affine};

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
        if bytes.len() != 256 {
            return Err(ZkError::DeserializationError);
        }

        let a = g1_from_bytes(&bytes[..64])?;
        let b = g2_from_bytes(&bytes[64..192])?;
        let c = g1_from_bytes(&bytes[192..])?;

        Ok(Self { a, b, c })
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
    if vk.ic.is_empty() || public_inputs.len() != vk.ic.len() - 1 {
        return Err(ZkError::InvalidInput);
    }

    for input in public_inputs {
        if !Bn254::is_valid_scalar(*input) {
            return Err(ZkError::InvalidFieldElement);
        }
    }

    let acc = if public_inputs.is_empty() {
        vk.ic[0]
    } else {
        let msm = g1_msm(env, &vk.ic[1..], public_inputs)?;
        vk.ic[0].add(&msm)
    };

    pairing_check(
        env,
        &[
            (proof.a, proof.b),
            (neg_g1(vk.alpha_g1), vk.beta_g2),
            (neg_g1(acc), vk.gamma_g2),
            (neg_g1(proof.c), vk.delta_g2),
        ],
    )
}

fn g1_from_bytes(bytes: &[u8]) -> Result<G1Affine, ZkError> {
    if bytes.len() != 64 {
        return Err(ZkError::DeserializationError);
    }

    let mut x_bytes = [0u8; 32];
    let mut y_bytes = [0u8; 32];
    x_bytes.copy_from_slice(&bytes[..32]);
    y_bytes.copy_from_slice(&bytes[32..64]);

    let x = Bn254::fq_from_bytes(x_bytes).ok_or(ZkError::DeserializationError)?;
    let y = Bn254::fq_from_bytes(y_bytes).ok_or(ZkError::DeserializationError)?;

    if !Bn254::is_valid_g1_subgroup(x, y) {
        return Err(ZkError::DeserializationError);
    }

    Ok(G1Affine { x, y })
}

fn g2_from_bytes(bytes: &[u8]) -> Result<G2Affine, ZkError> {
    if bytes.len() != 128 {
        return Err(ZkError::DeserializationError);
    }

    let x1 = read_fq(&bytes[0..32])?;
    let x0 = read_fq(&bytes[32..64])?;
    let y1 = read_fq(&bytes[64..96])?;
    let y0 = read_fq(&bytes[96..128])?;

    Ok(G2Affine {
        x: (x0, x1),
        y: (y0, y1),
    })
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
    g1_from_bytes(&result.to_array())
}

fn neg_g1(point: G1Affine) -> G1Affine {
    if point.x == u256::from(0u8) && point.y == u256::from(0u8) {
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
    fn proof_from_bytes_rejects_invalid_g1() {
        let mut bytes = [0u8; 256];
        bytes[63] = 1;

        assert_eq!(
            Groth16Proof::from_bytes(&bytes),
            Err(ZkError::DeserializationError)
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
}
