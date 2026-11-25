use ethnum::u256;
use soroban_sdk::{Bytes, Env};
use soroban_zk_core::bulletproofs::{self, Generators};
use soroban_zk_core::halo2::{Halo2Domain, Halo2Opening};
use soroban_zk_core::halo2_ipa::{IpaProof, IpaRoundCommitments};
use soroban_zk_core::halo2_ipa_wrappers::{verify_evaluation, Halo2IpaOpeningProof};
use soroban_zk_core::ipa_generators::fold_generators_rounds;
use soroban_zk_core::{Bn254, G1Affine, KzgEvalProofInputs, ZkError};
use soroban_zk_std::groth16::{groth16_verify, Groth16Proof, Groth16VerifyingKey};
use soroban_zk_std::nullifier::{NullifierSet, NullifierStore};
use soroban_zk_std::pairing::G2Affine;
use soroban_zk_std::plonk_kzg::{verify_plonk_kzg, verify_plonk_kzg_batch};

use ark_bn254::{Bn254 as ArkBn254, Fr as ArkFr};
use ark_ff::{BigInteger, PrimeField};
use ark_groth16::Groth16;
use ark_relations::gr1cs::{
    ConstraintSynthesizer, ConstraintSystemRef, LinearCombination, SynthesisError,
};
use ark_snark::SNARK;
use ark_std::rand::{rngs::StdRng, SeedableRng};

fn g1() -> G1Affine {
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

fn neg_g1(point: G1Affine) -> G1Affine {
    G1Affine {
        x: point.x,
        y: Bn254::sub_fq(u256::from(0u8), point.y),
    }
}

fn g1_bytes(point: G1Affine) -> [u8; 64] {
    let mut bytes = [0; 64];
    bytes[..32].copy_from_slice(&point.x.to_be_bytes());
    bytes[32..].copy_from_slice(&point.y.to_be_bytes());
    bytes
}

fn proof_bytes(proof: Groth16Proof) -> [u8; 256] {
    let mut bytes = [0; 256];
    bytes[..64].copy_from_slice(&g1_bytes(proof.a));
    bytes[64..192].copy_from_slice(&proof.b.to_bytes());
    bytes[192..].copy_from_slice(&g1_bytes(proof.c));
    bytes
}

fn ark_fr(value: ArkFr) -> u256 {
    let bytes = value.into_bigint().to_bytes_be();
    let mut out = [0; 32];
    out[32 - bytes.len()..].copy_from_slice(&bytes);
    u256::from_be_bytes(out)
}

fn ark_fq(value: ark_bn254::Fq) -> u256 {
    let bytes = value.into_bigint().to_bytes_be();
    let mut out = [0; 32];
    out[32 - bytes.len()..].copy_from_slice(&bytes);
    u256::from_be_bytes(out)
}

fn ark_g1(point: ark_bn254::G1Affine) -> G1Affine {
    G1Affine {
        x: ark_fq(point.x),
        y: ark_fq(point.y),
    }
}

fn ark_g2(point: ark_bn254::G2Affine) -> G2Affine {
    G2Affine {
        x: (ark_fq(point.x.c0), ark_fq(point.x.c1)),
        y: (ark_fq(point.y.c0), ark_fq(point.y.c1)),
    }
}

#[derive(Clone)]
struct SquareCircuit {
    witness: Option<ArkFr>,
    output: Option<ArkFr>,
}

impl ConstraintSynthesizer<ArkFr> for SquareCircuit {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<ArkFr>,
    ) -> Result<(), SynthesisError> {
        let witness = cs.new_witness_variable(|| {
            self.witness.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let output =
            cs.new_input_variable(|| self.output.ok_or(SynthesisError::AssignmentMissing))?;
        cs.enforce_r1cs_constraint(
            || LinearCombination::from(witness),
            || LinearCombination::from(witness),
            || LinearCombination::from(output),
        )
    }
}

#[derive(Clone)]
struct LinearCircuit {
    witness: Option<ArkFr>,
    output: Option<ArkFr>,
}

impl ConstraintSynthesizer<ArkFr> for LinearCircuit {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<ArkFr>,
    ) -> Result<(), SynthesisError> {
        let witness = cs.new_witness_variable(|| {
            self.witness.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let output =
            cs.new_input_variable(|| self.output.ok_or(SynthesisError::AssignmentMissing))?;
        cs.enforce_r1cs_constraint(
            || LinearCombination::from(witness),
            || LinearCombination::from(output),
            || LinearCombination::from(witness),
        )
    }
}

struct GrothFixture {
    proof: Groth16Proof,
    alpha_g1: G1Affine,
    beta_g2: G2Affine,
    gamma_g2: G2Affine,
    delta_g2: G2Affine,
    ic: [G1Affine; 2],
    input: [u256; 1],
}

impl GrothFixture {
    fn vk(&self) -> Groth16VerifyingKey<'_> {
        Groth16VerifyingKey {
            alpha_g1: self.alpha_g1,
            beta_g2: self.beta_g2,
            gamma_g2: self.gamma_g2,
            delta_g2: self.delta_g2,
            ic: &self.ic,
        }
    }
}

fn groth16_fixture() -> GrothFixture {
    let mut rng = StdRng::seed_from_u64(580);
    let blank = SquareCircuit {
        witness: None,
        output: None,
    };
    let (pk, vk) =
        Groth16::<ArkBn254>::circuit_specific_setup(blank, &mut rng).expect("setup succeeds");
    let output = ArkFr::from(9u64);
    let ark_proof = Groth16::<ArkBn254>::prove(
        &pk,
        SquareCircuit {
            witness: Some(ArkFr::from(3u64)),
            output: Some(output),
        },
        &mut rng,
    )
    .expect("proof generation succeeds");
    let ic = [ark_g1(vk.gamma_abc_g1[0]), ark_g1(vk.gamma_abc_g1[1])];
    GrothFixture {
        proof: Groth16Proof {
            a: ark_g1(ark_proof.a),
            b: ark_g2(ark_proof.b),
            c: ark_g1(ark_proof.c),
        },
        alpha_g1: ark_g1(vk.alpha_g1),
        beta_g2: ark_g2(vk.beta_g2),
        gamma_g2: ark_g2(vk.gamma_g2),
        delta_g2: ark_g2(vk.delta_g2),
        ic,
        input: [ark_fr(output)],
    }
}

fn kzg_inputs<'a>(
    commitments: &'a [G1Affine],
    evaluations: &'a [u256],
) -> KzgEvalProofInputs<'a> {
    KzgEvalProofInputs {
        commitments,
        evaluations_at_zeta: evaluations,
        commitment_at_zeta_omega: g1(),
        evaluation_at_zeta_omega: u256::from(0u8),
        w_zeta: g1(),
        w_zeta_omega: g1(),
        v: u256::from(1u8),
        u: u256::from(0u8),
        zeta: u256::from(0u8),
        omega: u256::from(1u8),
    }
}

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
    if Bn254::mul_fq(Bn254::add_fq(x, x), y) != a.1 {
        y = Bn254::sub_fq(u256::from(0u8), y);
    }
    (Bn254::fq2_sq((x, y)) == a).then_some((x, y))
}

fn g2_off_subgroup() -> G2Affine {
    let beta = (Bn254::G2_B_REAL, Bn254::G2_B_IMAG);
    let mut x_re = u256::from(1u8);
    loop {
        let x = (x_re, u256::from(0u8));
        let rhs = Bn254::fq2_add(Bn254::fq2_mul(Bn254::fq2_sq(x), x), beta);
        if let Some(y) = fq2_sqrt(rhs) {
            if !Bn254::is_in_correct_subgroup(x, y) {
                return G2Affine { x, y };
            }
        }
        x_re = Bn254::add_fq(x_re, u256::from(1u8));
    }
}

#[test]
fn groth16_rejects_noncanonical_points_scalars_and_input_shapes() {
    let env = Env::default();
    let fixture = groth16_fixture();
    let proof = fixture.proof;
    let vk = fixture.vk();
    let input = fixture.input;
    assert_eq!(groth16_verify(&env, &vk, &proof, &input), Ok(true));
    assert_eq!(
        groth16_verify(&env, &vk, &proof, &[]),
        Err(ZkError::InvalidInput)
    );
    assert_eq!(
        groth16_verify(&env, &vk, &proof, &[input[0], u256::from(1u8)]),
        Err(ZkError::InvalidInput)
    );
    assert_eq!(
        groth16_verify(&env, &vk, &proof, &[Bn254::FR_MODULUS]),
        Err(ZkError::InvalidFieldElement)
    );
    assert_eq!(
        groth16_verify(
            &env,
            &vk,
            &proof,
            &[Bn254::FR_MODULUS + u256::from(1u8)]
        ),
        Err(ZkError::InvalidFieldElement)
    );
    assert_eq!(
        groth16_verify(&env, &vk, &proof, &[u256::MAX]),
        Err(ZkError::InvalidFieldElement)
    );

    let mut bad_a = proof;
    bad_a.a.x = Bn254::FQ_MODULUS + u256::from(1u8);
    assert_eq!(
        groth16_verify(&env, &vk, &bad_a, &input),
        Err(ZkError::InvalidInput)
    );
    let off_subgroup = g2_off_subgroup();
    assert!(Bn254::is_on_curve(off_subgroup.x, off_subgroup.y));
    assert!(!Bn254::is_in_correct_subgroup(
        off_subgroup.x,
        off_subgroup.y
    ));
    let mut bad_b = proof;
    bad_b.b = off_subgroup;
    assert_eq!(
        groth16_verify(&env, &vk, &bad_b, &input),
        Err(ZkError::InvalidInput)
    );
    let mut bad_b = proof;
    bad_b.b = G2Affine {
        x: (u256::from(0u8), u256::from(0u8)),
        y: (u256::from(0u8), u256::from(0u8)),
    };
    assert_eq!(
        groth16_verify(&env, &vk, &bad_b, &input),
        Err(ZkError::InvalidInput)
    );

    let mut encoded = proof_bytes(proof);
    encoded[..32].copy_from_slice(&(Bn254::FQ_MODULUS + u256::from(1u8)).to_be_bytes());
    assert_eq!(
        Groth16Proof::from_bytes(&encoded),
        Err(ZkError::DeserializationError)
    );
    let mut encoded = proof_bytes(proof);
    encoded[64..96].copy_from_slice(&(Bn254::FQ_MODULUS + u256::from(1u8)).to_be_bytes());
    assert_eq!(
        Groth16Proof::from_bytes(&encoded),
        Err(ZkError::DeserializationError)
    );
}

#[test]
fn groth16_rejects_identity_and_off_subgroup_proof_encodings() {
    let env = Env::default();
    let fixture = groth16_fixture();
    let proof = fixture.proof;
    let vk = fixture.vk();
    let input = fixture.input;

    let mut bad_a = proof;
    bad_a.a = identity();
    assert_eq!(
        groth16_verify(&env, &vk, &bad_a, &input),
        Err(ZkError::InvalidInput)
    );
    let mut bad_c = proof;
    bad_c.c = identity();
    assert_eq!(
        groth16_verify(&env, &vk, &bad_c, &input),
        Err(ZkError::InvalidInput)
    );

    let mut encoded = proof_bytes(proof);
    encoded[64..192].copy_from_slice(&g2_off_subgroup().to_bytes());
    assert_eq!(
        Groth16Proof::from_bytes(&encoded),
        Err(ZkError::DeserializationError)
    );
}

#[test]
fn groth16_cross_circuit_substitution_and_malleability_are_deterministic() {
    let env = Env::default();
    let fixture = groth16_fixture();
    let proof = fixture.proof;
    let vk = fixture.vk();
    let input = fixture.input;
    let mut rng = StdRng::seed_from_u64(581);
    let (_other_pk, other_vk) = Groth16::<ArkBn254>::circuit_specific_setup(
        LinearCircuit {
            witness: None,
            output: None,
        },
        &mut rng,
    )
    .expect("second circuit setup succeeds");
    let other_ic = [
        ark_g1(other_vk.gamma_abc_g1[0]),
        ark_g1(other_vk.gamma_abc_g1[1]),
    ];
    let other_vk = Groth16VerifyingKey {
        alpha_g1: ark_g1(other_vk.alpha_g1),
        beta_g2: ark_g2(other_vk.beta_g2),
        gamma_g2: ark_g2(other_vk.gamma_g2),
        delta_g2: ark_g2(other_vk.delta_g2),
        ic: &other_ic,
    };
    assert_eq!(
        groth16_verify(&env, &other_vk, &proof, &input),
        Ok(false)
    );

    let malleated = Groth16Proof {
        a: neg_g1(proof.a),
        b: G2Affine {
            x: proof.b.x,
            y: (
                Bn254::sub_fq(u256::from(0u8), proof.b.y.0),
                Bn254::sub_fq(u256::from(0u8), proof.b.y.1),
            ),
        },
        c: proof.c,
    };
    assert_eq!(groth16_verify(&env, &vk, &malleated, &input), Ok(true));

    let store_env = Env::default();
    let contract_id = store_env.register(soroban_zk_std::ZkContract, ());
    store_env.as_contract(&contract_id, || {
        let store = NullifierStore::new(&store_env);
        let inputs = Bytes::from_array(&store_env, &[7u8; 32]);
        let original = Bytes::from_array(&store_env, &proof_bytes(proof));
        let equivalent = Bytes::from_array(&store_env, &proof_bytes(malleated));
        assert_eq!(
            NullifierStore::derive_nullifier(&store_env, &original, &inputs),
            NullifierStore::derive_nullifier(&store_env, &equivalent, &inputs)
        );
        assert_eq!(store.mark_spent(&store_env, &original, &inputs), Ok(()));
        assert_eq!(
            store.mark_spent(&store_env, &equivalent, &inputs),
            Err(soroban_zk_std::ZkContractError::ReplayDetected)
        );
    });
}

#[test]
fn plonk_kzg_rejects_identity_points_noncanonical_scalars_and_bad_batches() {
    let env = Env::default();
    let commitments = [g1()];
    let evaluations = [u256::from(0u8)];
    let identity_commitment = [identity()];
    let noncanonical_commitment = [G1Affine {
        x: Bn254::FQ_MODULUS + u256::from(1u8),
        y: u256::from(2u8),
    }];
    let valid = kzg_inputs(&commitments, &evaluations);
    assert_eq!(verify_plonk_kzg(&env, &valid, G2Affine::generator()), Ok(true));

    let mut invalid = valid.clone();
    invalid.commitments = &identity_commitment;
    assert_eq!(
        verify_plonk_kzg(&env, &invalid, G2Affine::generator()),
        Err(ZkError::InvalidInput)
    );
    let mut invalid = valid.clone();
    invalid.commitments = &noncanonical_commitment;
    assert_eq!(
        verify_plonk_kzg(&env, &invalid, G2Affine::generator()),
        Err(ZkError::InvalidInput)
    );
    let mut invalid = valid.clone();
    invalid.commitment_at_zeta_omega = identity();
    assert_eq!(
        verify_plonk_kzg(&env, &invalid, G2Affine::generator()),
        Err(ZkError::InvalidInput)
    );
    let mut invalid = valid.clone();
    invalid.w_zeta = identity();
    assert_eq!(
        verify_plonk_kzg(&env, &invalid, G2Affine::generator()),
        Err(ZkError::InvalidInput)
    );
    let mut invalid = valid.clone();
    invalid.w_zeta_omega = identity();
    assert_eq!(
        verify_plonk_kzg(&env, &invalid, G2Affine::generator()),
        Err(ZkError::InvalidInput)
    );
    let mut invalid = valid.clone();
    invalid.zeta = Bn254::FR_MODULUS + u256::from(1u8);
    assert_eq!(
        verify_plonk_kzg(&env, &invalid, G2Affine::generator()),
        Err(ZkError::InvalidFieldElement)
    );
    let mut invalid = valid.clone();
    invalid.omega = u256::MAX;
    assert_eq!(
        verify_plonk_kzg(&env, &invalid, G2Affine::generator()),
        Err(ZkError::InvalidFieldElement)
    );

    let mut bad_eval = [u256::from(1u8)];
    let invalid_batch = kzg_inputs(&commitments, &bad_eval);
    let batch = [valid.clone(), invalid_batch];
    assert_eq!(
        verify_plonk_kzg_batch(&env, &batch, &[0x5a; 32], G2Affine::generator()),
        Ok(false)
    );
    let identity_batch = kzg_inputs(&identity_commitment, &evaluations);
    assert_eq!(
        verify_plonk_kzg_batch(
            &env,
            &[valid.clone(), identity_batch],
            &[0x5a; 32],
            G2Affine::generator()
        ),
        Err(ZkError::InvalidInput)
    );
    bad_eval[0] = Bn254::FR_MODULUS;
    let invalid_batch = kzg_inputs(&commitments, &bad_eval);
    assert_eq!(
        verify_plonk_kzg_batch(
            &env,
            &[kzg_inputs(&commitments, &evaluations), invalid_batch],
            &[0x5a; 32],
            G2Affine::generator()
        ),
        Err(ZkError::InvalidFieldElement)
    );
}

#[test]
fn halo2_ipa_rejects_identity_commitments_and_malformed_round_points() {
    let twice_g = g1().scalar_mul(u256::from(2u8));
    let generators_g =
        soroban_zk_core::ipa_generators::GeneratorVec::new([g1(), twice_g]);
    let generators_h =
        soroban_zk_core::ipa_generators::GeneratorVec::new([twice_g, g1()]);
    let domain = Halo2Domain {
        k: 1,
        n: 2,
        omega: Bn254::FR_MODULUS - u256::from(1u8),
    };
    let point = u256::from(7u8);
    let value = u256::from(4u8);
    let challenge = u256::from(3u8);
    let challenge_inverse = Bn254::invert(challenge);
    let challenges = [challenge];
    let round_l = g1();
    let round_r = twice_g;
    let final_a = u256::from(2u8);
    let final_b = u256::from(5u8);
    let u_point = g1().scalar_mul(u256::from(4u8));
    let (g_final, h_final) =
        fold_generators_rounds(&generators_g, &generators_h, &challenges).unwrap();
    let expected = g_final
        .scalar_mul(final_a)
        .add(&h_final.scalar_mul(final_b))
        .add(&u_point.scalar_mul(Bn254::mul(final_a, final_b)));
    let round_l_term = round_l.scalar_mul(Bn254::mul(challenge, challenge));
    let round_r_term = round_r.scalar_mul(Bn254::mul(
        challenge_inverse,
        challenge_inverse,
    ));
    let initial_commitment = expected
        .add(&neg_g1(round_l_term))
        .add(&neg_g1(round_r_term));
    let commitment = initial_commitment.add(&g1().scalar_mul(value));
    let mut opening = Halo2Opening {
        commitment,
        point,
        value,
        proof: g1(),
    };
    let round = IpaRoundCommitments::new(round_l, round_r);
    let ipa = IpaProof::<1>::new([round], final_a, final_b);
    let proof = Halo2IpaOpeningProof::new(ipa, u_point);
    assert_eq!(proof.validate(), Ok(()));
    assert_eq!(
        verify_evaluation(
            &domain,
            &opening,
            &proof,
            &generators_g,
            &generators_h,
            &challenges
        ),
        Ok(())
    );

    opening.value = Bn254::FR_MODULUS + u256::from(1u8);
    assert_eq!(
        verify_evaluation(
            &domain,
            &opening,
            &proof,
            &generators_g,
            &generators_h,
            &challenges
        ),
        Err(ZkError::InvalidFieldElement)
    );
    opening.value = value;
    opening.commitment = identity();
    assert_eq!(
        verify_evaluation(
            &domain,
            &opening,
            &proof,
            &generators_g,
            &generators_h,
            &challenges
        ),
        Err(ZkError::InvalidInput)
    );
    opening.commitment = g1();
    assert_eq!(
        verify_evaluation(
            &domain,
            &opening,
            &proof,
            &generators_g,
            &generators_h,
            &[Bn254::FR_MODULUS]
        ),
        Err(ZkError::InvalidFieldElement)
    );
    opening.commitment = g1();
    opening.proof = identity();
    assert_eq!(
        verify_evaluation(
            &domain,
            &opening,
            &proof,
            &generators_g,
            &generators_h,
            &challenges
        ),
        Err(ZkError::InvalidInput)
    );
    let identity_l = IpaRoundCommitments::new(identity(), g1());
    let invalid_l = Halo2IpaOpeningProof::new(
        IpaProof::<1>::new([identity_l], u256::from(1u8), u256::from(1u8)),
        g1(),
    );
    assert_eq!(invalid_l.validate(), Err(ZkError::InvalidInput));
    opening.proof = g1();
    assert_eq!(
        verify_evaluation(
            &domain,
            &opening,
            &invalid_l,
            &generators_g,
            &generators_h,
            &challenges
        ),
        Err(ZkError::InvalidInput)
    );
    let identity_round = IpaRoundCommitments::new(g1(), identity());
    let ipa = IpaProof::<1>::new([identity_round], u256::from(1u8), u256::from(1u8));
    let malformed = Halo2IpaOpeningProof::new(ipa, g1());
    assert_eq!(malformed.validate(), Err(ZkError::InvalidInput));
    opening.proof = g1();
    assert_ne!(
        verify_evaluation(
            &domain,
            &opening,
            &malformed,
            &generators_g,
            &generators_h,
            &challenges
        ),
        Ok(())
    );
}

#[test]
fn bulletproofs_reject_identity_commitments_and_out_of_range_scalars() {
    let generators = Generators::new();
    let mut proof = bulletproofs::prove(
        &generators,
        u256::from(42u8),
        u256::from(7u8),
        &[0x58; 64],
    )
    .expect("valid range proof is generated");
    assert!(bulletproofs::verify(&generators, &proof));

    let original = proof;
    proof.v = identity();
    assert!(!bulletproofs::verify(&generators, &proof));
    proof = original;
    proof.a = identity();
    assert!(!bulletproofs::verify(&generators, &proof));
    proof = original;
    proof.s = identity();
    assert!(!bulletproofs::verify(&generators, &proof));
    proof = original;
    proof.t1 = identity();
    assert!(!bulletproofs::verify(&generators, &proof));
    proof = original;
    proof.t2 = identity();
    assert!(!bulletproofs::verify(&generators, &proof));
    proof = original;
    proof.ip_proof.l[0] = identity();
    assert!(!bulletproofs::verify(&generators, &proof));
    proof = original;
    proof.ip_proof.r[0] = identity();
    assert!(!bulletproofs::verify(&generators, &proof));
    proof = original;
    proof.ip_proof.a = u256::MAX;
    assert!(!bulletproofs::verify(&generators, &proof));
}

#[test]
fn malformed_groth16_infinity_is_rejected_during_deserialization() {
    let fixture = groth16_fixture();
    let mut encoded = proof_bytes(fixture.proof);
    encoded[..64].fill(0);
    assert_eq!(
        Groth16Proof::from_bytes(&encoded),
        Err(ZkError::DeserializationError)
    );
}
