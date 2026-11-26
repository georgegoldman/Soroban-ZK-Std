#![cfg(test)]

extern crate std;

use super::*;
use ark_bn254::{Bn254 as ArkBn254, Fq as ArkFq, Fr as ArkFr};
use ark_ff::{BigInteger, PrimeField};
use ark_groth16::{Groth16, ProvingKey, VerifyingKey};
use ark_relations::gr1cs::{
    ConstraintSynthesizer, ConstraintSystemRef, LinearCombination, SynthesisError,
};
use ark_snark::SNARK;
use ark_std::rand::{rngs::StdRng, SeedableRng};
use soroban_sdk::testutils::{Address as _, Ledger};
use soroban_sdk::{contractclient, Address};
use soroban_zk_core::G1Affine;
use soroban_zk_std::pairing::G2Affine;
use soroban_zk_std::{vk_to_bytes, Groth16VerifyingKey as LocalVk};

#[contractclient(name = "VotingClient")]
trait VotingInterface {
    fn init(env: Env, admin: Address, verifying_key: Bytes) -> Result<(), VotingError>;
    fn create_proposal(
        env: Env,
        admin: Address,
        merkle_root: U256,
        end_ledger: u32,
    ) -> Result<u32, VotingError>;
    fn cast_vote(
        env: Env,
        proposal_id: u32,
        proof_bytes: Bytes,
        nullifier: U256,
        choice: u32,
    ) -> Result<(), VotingError>;
    fn finalize_proposal(env: Env, proposal_id: u32) -> Result<(), VotingError>;
    fn tally(env: Env, proposal_id: u32) -> Result<(u32, u32), VotingError>;
}

#[derive(Clone)]
struct BinaryChoiceCircuit {
    inputs: [ArkFr; 4],
}

impl ConstraintSynthesizer<ArkFr> for BinaryChoiceCircuit {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<ArkFr>,
    ) -> Result<(), SynthesisError> {
        for i in 0..3 {
            let input = cs.new_input_variable(|| Ok(self.inputs[i]))?;
            let square_value = self.inputs[i] * self.inputs[i];
            let square = cs.new_witness_variable(|| Ok(square_value))?;
            cs.enforce_constraint(
                || LinearCombination::from(input),
                || LinearCombination::from(input),
                || LinearCombination::from(square),
            )?;
        }
        let choice = cs.new_input_variable(|| Ok(self.inputs[3]))?;
        cs.enforce_constraint(
            || LinearCombination::from(choice),
            || LinearCombination::from(choice),
            || LinearCombination::from(choice),
        )
    }
}

struct Fixture {
    pk: ProvingKey<ArkBn254>,
    ark_vk: VerifyingKey<ArkBn254>,
    vk_bytes: Bytes,
}

fn fq_to_u256(value: ArkFq) -> u256 {
    let bytes = value.into_bigint().to_bytes_be();
    let mut out = [0u8; 32];
    out[32 - bytes.len()..].copy_from_slice(&bytes);
    u256::from_be_bytes(out)
}

fn g1(point: ark_bn254::G1Affine) -> G1Affine {
    G1Affine {
        x: fq_to_u256(point.x),
        y: fq_to_u256(point.y),
    }
}

fn g2(point: ark_bn254::G2Affine) -> G2Affine {
    G2Affine {
        x: (fq_to_u256(point.x.c0), fq_to_u256(point.x.c1)),
        y: (fq_to_u256(point.y.c0), fq_to_u256(point.y.c1)),
    }
}

fn fixture(env: &Env) -> Fixture {
    let circuit = BinaryChoiceCircuit {
        inputs: [ArkFr::from(0u64); 4],
    };
    let mut rng = StdRng::seed_from_u64(688);
    let (pk, ark_vk) =
        Groth16::<ArkBn254>::circuit_specific_setup(circuit, &mut rng).expect("setup");
    let ic: std::vec::Vec<G1Affine> = ark_vk.gamma_abc_g1.iter().map(|p| g1(*p)).collect();
    let local_vk = LocalVk {
        alpha_g1: g1(ark_vk.alpha_g1),
        beta_g2: g2(ark_vk.beta_g2),
        gamma_g2: g2(ark_vk.gamma_g2),
        delta_g2: g2(ark_vk.delta_g2),
        ic: &ic,
    };
    Fixture {
        pk,
        ark_vk,
        vk_bytes: vk_to_bytes(env, &local_vk),
    }
}

impl Fixture {
    fn proof(&self, env: &Env, inputs: [u64; 4]) -> Bytes {
        let public = [
            ArkFr::from(inputs[0]),
            ArkFr::from(inputs[1]),
            ArkFr::from(inputs[2]),
            ArkFr::from(inputs[3]),
        ];
        let circuit = BinaryChoiceCircuit { inputs: public };
        let mut rng = StdRng::seed_from_u64(inputs[2] + inputs[3] + 688);
        let proof = Groth16::<ArkBn254>::prove(&self.pk, circuit, &mut rng).expect("prove");
        assert!(Groth16::<ArkBn254>::verify(&self.ark_vk, &public, &proof).unwrap());
        let mut tampered = public;
        tampered[0] += ArkFr::from(1u64);
        assert!(!Groth16::<ArkBn254>::verify(&self.ark_vk, &tampered, &proof).unwrap());
        let local = Groth16Proof {
            a: g1(proof.a),
            b: g2(proof.b),
            c: g1(proof.c),
        };
        Bytes::from_array(env, &local.to_bytes())
    }
}

fn setup() -> (Env, Address, VotingClient, Fixture) {
    let env = Env::default();
    env.mock_all_auths();
    env.cost_estimate().budget().reset_unlimited();
    let fixture = fixture(&env);
    let admin = Address::generate(&env);
    let contract_id = env.register(ZkVoting, ());
    let client = VotingClient::new(&env, &contract_id);
    client.init(&admin, &fixture.vk_bytes).unwrap();
    (env, admin, client, fixture)
}

fn create(client: &VotingClient, admin: &Address, env: &Env) -> u32 {
    client.create_proposal(admin, &U256::from_u32(env, 10), &10_000)
        .unwrap()
}

#[test]
#[cfg_attr(miri, ignore)]
fn accepts_vote_rejects_replay_and_returns_correct_tally() {
    let (env, admin, client, fixture) = setup();
    let id = create(&client, &admin, &env);
    let proof = fixture.proof(&env, [id as u64, 10, 111, 1]);
    let nullifier = U256::from_u32(&env, 111);
    client.cast_vote(&id, &proof, &nullifier, &1).unwrap();
    assert_eq!(
        client.cast_vote(&id, &proof, &nullifier, &1),
        Err(VotingError::AlreadyVoted)
    );
    assert_eq!(client.tally(&id), Ok((1, 0)));

    let no_proof = fixture.proof(&env, [id as u64, 10, 112, 0]);
    client
        .cast_vote(&id, &no_proof, &U256::from_u32(&env, 112), &0)
        .unwrap();
    assert_eq!(client.tally(&id), Ok((1, 1)));
}

#[test]
#[cfg_attr(miri, ignore)]
fn rejects_proof_for_wrong_proposal_and_tampered_public_choice() {
    let (env, admin, client, fixture) = setup();
    let id = create(&client, &admin, &env);
    let wrong_proposal = fixture.proof(&env, [id as u64 + 1, 10, 121, 1]);
    assert_eq!(
        client.cast_vote(&id, &wrong_proposal, &U256::from_u32(&env, 121), &1),
        Err(VotingError::InvalidProof)
    );

    let proof = fixture.proof(&env, [id as u64, 10, 122, 1]);
    assert_eq!(
        client.cast_vote(&id, &proof, &U256::from_u32(&env, 122), &0),
        Err(VotingError::InvalidProof)
    );
}

#[test]
#[cfg_attr(miri, ignore)]
fn rejects_vote_after_end_and_finalizes_tally() {
    let (env, admin, client, fixture) = setup();
    let current = env.ledger().sequence();
    let id = client
        .create_proposal(&admin, &U256::from_u32(&env, 10), &(current + 1))
        .unwrap();
    let proof = fixture.proof(&env, [id as u64, 10, 131, 1]);
    env.ledger().with_mut(|ledger| {
        ledger.sequence_number = current + 2;
    });
    assert_eq!(
        client.cast_vote(&id, &proof, &U256::from_u32(&env, 131), &1),
        Err(VotingError::ProposalNotActive)
    );
    client.finalize_proposal(&id).unwrap();
    assert_eq!(
        client.finalize_proposal(&id),
        Err(VotingError::AlreadyFinalized)
    );
}

#[test]
#[cfg_attr(miri, ignore)]
fn rejects_malformed_proof_and_out_of_range_choice() {
    let (env, admin, client, _) = setup();
    let id = create(&client, &admin, &env);
    assert_eq!(
        client.cast_vote(&id, &Bytes::new(&env), &U256::from_u32(&env, 141), &1),
        Err(VotingError::MalformedProof)
    );
    assert_eq!(
        client.cast_vote(&id, &Bytes::from_array(&env, &[0; 256]), &U256::from_u32(&env, 142), &2),
        Err(VotingError::InvalidChoice)
    );
}
