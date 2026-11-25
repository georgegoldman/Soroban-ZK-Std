#![cfg(test)]

extern crate std;

use super::*;
use crate::circuit::{AirdropCircuit, Poseidon2Params, DEPTH, NULLIFIER_DOMAIN};
use ark_bn254::{Bn254 as ArkBn254, Fq as ArkFq, Fr as ArkFr};
use ark_ff::{BigInteger, PrimeField};
use ark_groth16::Groth16;
use ark_relations::gr1cs::{ConstraintSynthesizer, ConstraintSystem};
use ark_snark::SNARK;
use ark_std::rand::{rngs::StdRng, SeedableRng};
use soroban_sdk::testutils::{Address as _, Events as _};
use soroban_sdk::{Address, Bytes, Env, U256};
use soroban_zk_core::G1Affine;
use soroban_zk_std::{vk_to_bytes, G2Affine, Groth16VerifyingKey};

// BN254 scalar field modulus r, big-endian.
const FR_MODULUS: [u8; 32] = [
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
    0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91, 0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00, 0x00, 0x01,
];

/// Index of the claimant's leaf in the 16-leaf test tree.
const CLAIMANT_INDEX: usize = 5;

// ── Conversions ─────────────────────────────────────────────────────────────

fn fr_to_be(v: ArkFr) -> [u8; 32] {
    let bytes = v.into_bigint().to_bytes_be();
    let mut out = [0u8; 32];
    out[32 - bytes.len()..].copy_from_slice(&bytes);
    out
}

fn fq_to_u256(v: ArkFq) -> u256 {
    let bytes = v.into_bigint().to_bytes_be();
    let mut out = [0u8; 32];
    out[32 - bytes.len()..].copy_from_slice(&bytes);
    u256::from_be_bytes(out)
}

fn fr_to_host(env: &Env, v: ArkFr) -> U256 {
    U256::from_be_bytes(env, &Bytes::from_array(env, &fr_to_be(v)))
}

fn host_to_fr(v: &U256) -> ArkFr {
    let mut buf = [0u8; 32];
    v.to_be_bytes().copy_into_slice(&mut buf);
    ArkFr::from_be_bytes_mod_order(&buf)
}

fn g1(p: ark_bn254::G1Affine) -> G1Affine {
    G1Affine {
        x: fq_to_u256(p.x),
        y: fq_to_u256(p.y),
    }
}

fn g2(p: ark_bn254::G2Affine) -> G2Affine {
    G2Affine {
        x: (fq_to_u256(p.x.c0), fq_to_u256(p.x.c1)),
        y: (fq_to_u256(p.y.c0), fq_to_u256(p.y.c1)),
    }
}

fn g1_bytes(p: &G1Affine) -> [u8; 64] {
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(&p.x.to_be_bytes());
    out[32..].copy_from_slice(&p.y.to_be_bytes());
    out
}

// ── Poseidon2 parameters straight from the library ──────────────────────────

fn poseidon2_params(env: &Env) -> Poseidon2Params {
    // `cache::round_constants` lives in instance storage, so read it inside a
    // throwaway contract instance (not the one under test).
    let scratch = env.register(AirdropClaim, ());
    let (rc_host, diag_host) = env.as_contract(&scratch, || {
        (
            soroban_zk_std::cache::round_constants(env),
            soroban_zk_std::cache::mat_diag(env),
        )
    });
    assert_eq!(rc_host.len(), 64);
    let mut rc = [[ArkFr::from(0u64); 3]; 64];
    for (r, row) in rc_host.iter().enumerate() {
        for (i, v) in row.iter().enumerate() {
            rc[r][i] = host_to_fr(&v);
        }
    }
    let mut diag = [ArkFr::from(0u64); 3];
    for (i, v) in diag_host.iter().enumerate() {
        diag[i] = host_to_fr(&v);
    }
    Poseidon2Params { rc, diag }
}

// ── Fixture: a real Groth16 proof for the airdrop circuit ────────────────────

struct Fixture {
    vk_bytes: Bytes,
    proof: Bytes,
    root: U256,
    nullifier: U256,
}

struct Tree {
    root: ArkFr,
    siblings: [ArkFr; DEPTH],
    path_bits: [bool; DEPTH],
}

fn build_tree(p: &Poseidon2Params, leaves: &[ArkFr], index: usize) -> Tree {
    let mut level: std::vec::Vec<ArkFr> = leaves.to_vec();
    let mut idx = index;
    let mut siblings = [ArkFr::from(0u64); DEPTH];
    let mut path_bits = [false; DEPTH];
    for d in 0..DEPTH {
        siblings[d] = level[idx ^ 1];
        path_bits[d] = idx & 1 == 1;
        level = level.chunks(2).map(|c| p.hash(&[c[0], c[1]])).collect();
        idx >>= 1;
    }
    Tree {
        root: level[0],
        siblings,
        path_bits,
    }
}

fn claimant_secret() -> ArkFr {
    ArkFr::from(0x0068_4a1d_u64)
}

/// Builds the eligibility tree, runs a circuit-specific Groth16 setup and proves
/// a claim of leaf `CLAIMANT_INDEX` bound to `recipient`.
fn fixture(env: &Env, recipient: &Address) -> Fixture {
    let params = poseidon2_params(env);
    let secret = claimant_secret();

    let mut leaves = [ArkFr::from(0u64); 1 << DEPTH];
    for (i, leaf) in leaves.iter_mut().enumerate() {
        *leaf = if i == CLAIMANT_INDEX {
            params.hash(&[secret])
        } else {
            params.hash(&[ArkFr::from(10_000 + i as u64)])
        };
    }
    let tree = build_tree(&params, &leaves, CLAIMANT_INDEX);
    let nullifier = params.hash(&[secret, ArkFr::from(NULLIFIER_DOMAIN)]);
    let recipient_fr = host_to_fr(&recipient_to_field(env, recipient));

    let circuit = AirdropCircuit {
        params,
        merkle_root: tree.root,
        nullifier,
        recipient: recipient_fr,
        secret,
        siblings: tree.siblings,
        path_bits: tree.path_bits,
    };

    let mut rng = StdRng::seed_from_u64(684);
    let (pk, vk) = Groth16::<ArkBn254>::circuit_specific_setup(circuit.clone(), &mut rng)
        .expect("groth16 setup");
    let proof = Groth16::<ArkBn254>::prove(&pk, circuit, &mut rng).expect("groth16 prove");
    assert!(
        Groth16::<ArkBn254>::verify(&vk, &[tree.root, nullifier, recipient_fr], &proof).unwrap()
    );

    let ic: std::vec::Vec<G1Affine> = vk.gamma_abc_g1.iter().map(|p| g1(*p)).collect();
    let local_vk = Groth16VerifyingKey {
        alpha_g1: g1(vk.alpha_g1),
        beta_g2: g2(vk.beta_g2),
        gamma_g2: g2(vk.gamma_g2),
        delta_g2: g2(vk.delta_g2),
        ic: &ic,
    };

    let mut proof_bytes = [0u8; 256];
    proof_bytes[..64].copy_from_slice(&g1_bytes(&g1(proof.a)));
    proof_bytes[64..192].copy_from_slice(&g2(proof.b).to_bytes());
    proof_bytes[192..].copy_from_slice(&g1_bytes(&g1(proof.c)));

    Fixture {
        vk_bytes: vk_to_bytes(env, &local_vk),
        proof: Bytes::from_array(env, &proof_bytes),
        root: fr_to_host(env, tree.root),
        nullifier: fr_to_host(env, nullifier),
    }
}

/// Fresh environment with all auths mocked, an admin, and an unconfigured contract.
fn setup() -> (Env, Address, Address) {
    let env = Env::default();
    env.mock_all_auths();
    let id = env.register(AirdropClaim, ());
    let admin = Address::generate(&env);
    (env, admin, id)
}

// ── Reference circuit sanity ─────────────────────────────────────────────────

#[test]
fn reference_poseidon2_matches_library() {
    let env = Env::default();
    env.cost_estimate().budget().reset_unlimited();
    let params = poseidon2_params(&env);
    for inputs in [
        std::vec![ArkFr::from(7u64)],
        std::vec![ArkFr::from(1u64), ArkFr::from(2u64)],
        std::vec![ArkFr::from(3u64), ArkFr::from(4u64), ArkFr::from(5u64)],
    ] {
        let host: std::vec::Vec<U256> = inputs.iter().map(|v| fr_to_host(&env, *v)).collect();
        let expected = soroban_zk_std::poseidon2::hash_to_field(&env, &host);
        assert_eq!(fr_to_host(&env, params.hash(&inputs)), expected);
    }
}

#[test]
fn reference_circuit_is_satisfied_and_rejects_wrong_root() {
    let env = Env::default();
    env.cost_estimate().budget().reset_unlimited();
    let params = poseidon2_params(&env);
    let secret = claimant_secret();
    let leaves: std::vec::Vec<ArkFr> = (0..(1u64 << DEPTH))
        .map(|i| {
            if i as usize == CLAIMANT_INDEX {
                params.hash(&[secret])
            } else {
                params.hash(&[ArkFr::from(10_000 + i)])
            }
        })
        .collect();
    let tree = build_tree(&params, &leaves, CLAIMANT_INDEX);
    let circuit = AirdropCircuit {
        merkle_root: tree.root,
        nullifier: params.hash(&[secret, ArkFr::from(NULLIFIER_DOMAIN)]),
        recipient: ArkFr::from(42u64),
        secret,
        siblings: tree.siblings,
        path_bits: tree.path_bits,
        params,
    };

    let cs = ConstraintSystem::<ArkFr>::new_ref();
    circuit.clone().generate_constraints(cs.clone()).unwrap();
    assert!(cs.is_satisfied().unwrap());

    let mut bad = circuit;
    bad.merkle_root += ArkFr::from(1u64);
    let cs = ConstraintSystem::<ArkFr>::new_ref();
    bad.generate_constraints(cs.clone()).unwrap();
    assert!(!cs.is_satisfied().unwrap());
}

// ── Happy path ──────────────────────────────────────────────────────────────

#[test]
fn valid_claim_succeeds_and_marks_nullifier() {
    let (env, admin, id) = setup();
    let client = AirdropClaimClient::new(&env, &id);
    let recipient = Address::generate(&env);
    let f = fixture(&env, &recipient);

    client.init(&admin, &f.root, &f.vk_bytes);
    assert_eq!(client.merkle_root(), f.root);
    assert_eq!(client.admin(), admin);
    assert!(!client.is_claimed(&f.nullifier));

    client.claim(&f.proof, &f.nullifier, &recipient);
    // Exactly one `Claimed` event from the claim invocation.
    assert_eq!(
        env.events()
            .all()
            .filter_by_contract(&client.address)
            .events()
            .len(),
        1
    );

    assert!(client.is_claimed(&f.nullifier));
}

#[test]
fn recipient_field_is_canonical_and_matches_helper() {
    let (env, _admin, id) = setup();
    let client = AirdropClaimClient::new(&env, &id);
    let recipient = Address::generate(&env);
    let field = client.recipient_field(&recipient);
    assert_eq!(field, recipient_to_field(&env, &recipient));
    let mut buf = [0u8; 32];
    field.to_be_bytes().copy_into_slice(&mut buf);
    assert_eq!(buf[0], 0, "top byte must be cleared so the value is < r");
    assert_ne!(field, client.recipient_field(&Address::generate(&env)));
}

// ── Negative paths ──────────────────────────────────────────────────────────

#[test]
fn double_claim_is_rejected() {
    let (env, admin, id) = setup();
    let client = AirdropClaimClient::new(&env, &id);
    let recipient = Address::generate(&env);
    let f = fixture(&env, &recipient);
    client.init(&admin, &f.root, &f.vk_bytes);

    client.claim(&f.proof, &f.nullifier, &recipient);
    assert_eq!(
        client.try_claim(&f.proof, &f.nullifier, &recipient),
        Err(Ok(AirdropError::AlreadyClaimed))
    );
}

#[test]
fn claim_against_wrong_root_is_rejected() {
    let (env, admin, id) = setup();
    let client = AirdropClaimClient::new(&env, &id);
    let recipient = Address::generate(&env);
    let f = fixture(&env, &recipient);

    // The admin committed to a different tree than the one the proof is for.
    let other_root = fr_to_host(&env, host_to_fr(&f.root) + ArkFr::from(1u64));
    client.init(&admin, &other_root, &f.vk_bytes);

    assert_eq!(
        client.try_claim(&f.proof, &f.nullifier, &recipient),
        Err(Ok(AirdropError::InvalidProof))
    );
    assert!(!client.is_claimed(&f.nullifier));
}

#[test]
fn claim_with_mismatched_recipient_is_rejected() {
    let (env, admin, id) = setup();
    let client = AirdropClaimClient::new(&env, &id);
    let recipient = Address::generate(&env);
    let attacker = Address::generate(&env);
    let f = fixture(&env, &recipient);
    client.init(&admin, &f.root, &f.vk_bytes);

    // A front-runner replays the proof with their own address.
    assert_eq!(
        client.try_claim(&f.proof, &f.nullifier, &attacker),
        Err(Ok(AirdropError::InvalidProof))
    );
    // The failed attempt must not burn the nullifier: the real owner still claims.
    assert!(!client.is_claimed(&f.nullifier));
    client.claim(&f.proof, &f.nullifier, &recipient);
}

#[test]
fn claim_with_mismatched_nullifier_is_rejected() {
    let (env, admin, id) = setup();
    let client = AirdropClaimClient::new(&env, &id);
    let recipient = Address::generate(&env);
    let f = fixture(&env, &recipient);
    client.init(&admin, &f.root, &f.vk_bytes);

    let other = fr_to_host(&env, host_to_fr(&f.nullifier) + ArkFr::from(1u64));
    assert_eq!(
        client.try_claim(&f.proof, &other, &recipient),
        Err(Ok(AirdropError::InvalidProof))
    );
    assert!(!client.is_claimed(&other));
}

#[test]
fn claim_on_uninitialised_contract_fails() {
    let (env, _admin, id) = setup();
    let client = AirdropClaimClient::new(&env, &id);
    let proof = Bytes::from_array(&env, &[0u8; 256]);
    let nullifier = U256::from_u128(&env, 1);
    let recipient = Address::generate(&env);

    assert_eq!(
        client.try_claim(&proof, &nullifier, &recipient),
        Err(Ok(AirdropError::NotInitialized))
    );
    assert_eq!(
        client.try_merkle_root(),
        Err(Ok(AirdropError::NotInitialized))
    );
    assert_eq!(client.try_admin(), Err(Ok(AirdropError::NotInitialized)));
}

#[test]
fn malformed_proof_is_rejected() {
    let (env, admin, id) = setup();
    let client = AirdropClaimClient::new(&env, &id);
    let recipient = Address::generate(&env);
    let f = fixture(&env, &recipient);
    client.init(&admin, &f.root, &f.vk_bytes);

    // Boundary: one byte short and one byte long.
    let short = f.proof.slice(0..255);
    let mut long = f.proof.clone();
    long.push_back(0);
    // Right length, but coordinates are not curve points.
    let garbage = Bytes::from_array(&env, &[0xffu8; 256]);
    for bad in [short, long, garbage, Bytes::new(&env)] {
        assert_eq!(
            client.try_claim(&bad, &f.nullifier, &recipient),
            Err(Ok(AirdropError::MalformedProof))
        );
    }
    assert!(!client.is_claimed(&f.nullifier));
}

#[test]
fn non_canonical_nullifier_is_rejected() {
    let (env, admin, id) = setup();
    let client = AirdropClaimClient::new(&env, &id);
    let recipient = Address::generate(&env);
    let f = fixture(&env, &recipient);
    client.init(&admin, &f.root, &f.vk_bytes);

    // r itself is the first non-canonical value; r + nullifier would alias it.
    let r = U256::from_be_bytes(&env, &Bytes::from_array(&env, &FR_MODULUS));
    assert_eq!(
        client.try_claim(&f.proof, &r, &recipient),
        Err(Ok(AirdropError::InvalidFieldElement))
    );
    let aliased = f.nullifier.add(&r);
    assert_eq!(
        client.try_claim(&f.proof, &aliased, &recipient),
        Err(Ok(AirdropError::InvalidFieldElement))
    );
}

#[test]
fn init_twice_is_rejected() {
    let (env, admin, id) = setup();
    let client = AirdropClaimClient::new(&env, &id);
    let recipient = Address::generate(&env);
    let f = fixture(&env, &recipient);
    client.init(&admin, &f.root, &f.vk_bytes);
    assert_eq!(
        client.try_init(&admin, &f.root, &f.vk_bytes),
        Err(Ok(AirdropError::AlreadyInitialized))
    );
}

#[test]
fn init_rejects_bad_verifying_key() {
    let (env, admin, id) = setup();
    let client = AirdropClaimClient::new(&env, &id);
    let recipient = Address::generate(&env);
    let f = fixture(&env, &recipient);

    // Truncated by one byte.
    let truncated = f.vk_bytes.slice(0..f.vk_bytes.len() - 1);
    // VK for a 2-input circuit (drop the last IC point, fix the count).
    let mut two_inputs = f.vk_bytes.slice(0..448);
    two_inputs.extend_from_array(&3u32.to_be_bytes());
    two_inputs.append(&f.vk_bytes.slice(452..452 + 3 * 64));
    // Right length, but the IC count field lies (huge value must not overflow).
    let mut lying_count = f.vk_bytes.slice(0..448);
    lying_count.extend_from_array(&u32::MAX.to_be_bytes());
    lying_count.append(&f.vk_bytes.slice(452..VK_LEN));
    // Right shape, but alpha is not a curve point.
    let mut bad_point = Bytes::from_array(&env, &[0xffu8; 64]);
    bad_point.append(&f.vk_bytes.slice(64..VK_LEN));

    for bad in [
        truncated,
        two_inputs,
        lying_count,
        bad_point,
        Bytes::new(&env),
    ] {
        assert_eq!(
            client.try_init(&admin, &f.root, &bad),
            Err(Ok(AirdropError::InvalidVerifyingKey))
        );
    }
    // Nothing was stored by the failed attempts.
    assert_eq!(
        client.try_merkle_root(),
        Err(Ok(AirdropError::NotInitialized))
    );
}

#[test]
fn init_rejects_non_canonical_root() {
    let (env, admin, id) = setup();
    let client = AirdropClaimClient::new(&env, &id);
    let recipient = Address::generate(&env);
    let f = fixture(&env, &recipient);
    let r = U256::from_be_bytes(&env, &Bytes::from_array(&env, &FR_MODULUS));
    assert_eq!(
        client.try_init(&admin, &r, &f.vk_bytes),
        Err(Ok(AirdropError::InvalidFieldElement))
    );
}

#[test]
fn init_requires_admin_auth() {
    let env = Env::default();
    let id = env.register(AirdropClaim, ());
    let client = AirdropClaimClient::new(&env, &id);
    let admin = Address::generate(&env);
    let recipient = Address::generate(&env);
    let f = fixture(&env, &recipient);

    // No `mock_all_auths`: the admin did not sign, so the host aborts the call.
    assert!(client.try_init(&admin, &f.root, &f.vk_bytes).is_err());
    assert_eq!(
        client.try_merkle_root(),
        Err(Ok(AirdropError::NotInitialized))
    );
}
