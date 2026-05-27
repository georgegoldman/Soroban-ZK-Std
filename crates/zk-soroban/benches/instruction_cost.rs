#![cfg(test)]

use ethnum::u256;
use soroban_sdk::{Env, U256};
use zk_core::{Bn254, G1Affine, G1Projective};
use zk_soroban::pairing::{pairing_check, G2Affine};
use zk_soroban::poseidon2::hash_to_field;

const MAX_INSTRUCTIONS: u64 = 100_000_000;
const TOTAL_BUDGET: u64 = 400_000_000;

fn check_cost(cost: u64, name: &str) {
    std::println!("{}: {} instructions", name, cost);
    assert!(
        cost <= MAX_INSTRUCTIONS,
        "{} exceeded 100M instructions (cost: {})",
        name,
        cost
    );
}

fn setup_env() -> Env {
    let env = Env::default();
    env.cost_estimate().budget().reset_unlimited();
    env
}

/// BN254 G1 generator point.
fn g1_generator() -> G1Affine {
    G1Affine {
        x: u256::from(1u8),
        y: u256::from(2u8),
    }
}

/// Negation of the BN254 G1 generator: (x, p - y)
/// p = 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47
fn g1_generator_neg() -> G1Affine {
    G1Affine {
        x: u256::from(1u8),
        y: u256::from_str_radix(
            "30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd45",
            16,
        )
        .unwrap(),
    }
}

/// Standard BN254 G2 generator (consistent with pairing.rs).
fn g2_generator() -> G2Affine {
    G2Affine {
        x: (
            u256::from_str_radix(
                "10822403556616783d294cae447f68c351084c519bc131644754784460d3d548",
                16,
            )
            .unwrap(),
            u256::from_str_radix(
                "012c40590818290663486c8f967a1262d47155ec1608677c77d0a64983050961",
                16,
            )
            .unwrap(),
        ),
        y: (
            u256::from_str_radix(
                "0689357dbd07bdc858f01f28fd87f6b6e11802996d9ed800f1351194380126d4",
                16,
            )
            .unwrap(),
            u256::from_str_radix(
                "24f0c4314c4083a290e2124576307135e6179426f497401c37b60514f7b603d3",
                16,
            )
            .unwrap(),
        ),
    }
}

#[test]
fn bench_fr_add() {
    let a = u256::from(100u32);
    let b = u256::from(200u32);

    let env = setup_env();
    let start = env.cost_estimate().budget().cpu_instruction_cost();
    let _ = Bn254::add(a, b);
    let cost = env.cost_estimate().budget().cpu_instruction_cost() - start;

    check_cost(cost, "Fr::add");
}

#[test]
fn bench_fr_mul() {
    let a = u256::from(100u32);
    let b = u256::from(200u32);

    let env = setup_env();
    let start = env.cost_estimate().budget().cpu_instruction_cost();
    let _ = Bn254::mul(a, b);
    let cost = env.cost_estimate().budget().cpu_instruction_cost() - start;

    check_cost(cost, "Fr::mul");
}

#[test]
fn bench_fr_invert() {
    let a = u256::from(100u32);

    let env = setup_env();
    let start = env.cost_estimate().budget().cpu_instruction_cost();
    let _ = Bn254::invert(a);
    let cost = env.cost_estimate().budget().cpu_instruction_cost() - start;

    check_cost(cost, "Fr::invert");
}

#[test]
fn bench_g1_scalar_mul() {
    // Use the actual G1 generator, not the identity — scalar_mul(identity, k) == identity
    // for all k, which is a trivially cheap no-op and not representative.
    let point = G1Projective::from(g1_generator());
    let scalar = u256::from(100u32);

    let env = setup_env();
    let start = env.cost_estimate().budget().cpu_instruction_cost();
    let _ = Bn254::g1_scalar_mul(point, scalar);
    let cost = env.cost_estimate().budget().cpu_instruction_cost() - start;

    check_cost(cost, "g1_scalar_mul");
}

/// Simulates an MSM of size `n` by accumulating `n` scalar multiplications.
/// Each call creates a fresh env so budgets don't bleed between sizes.
fn mock_g1_msm(n: usize) -> u64 {
    let point = G1Projective::from(g1_generator());
    let scalar = u256::from(100u32);

    let env = setup_env();
    let start = env.cost_estimate().budget().cpu_instruction_cost();
    let mut acc = G1Projective::identity();
    for _ in 0..n {
        let res = Bn254::g1_scalar_mul(point, scalar);
        acc = acc.add(&res);
    }
    let _ = acc; // prevent optimizer from eliding the loop
    env.cost_estimate().budget().cpu_instruction_cost() - start
}

#[test]
fn bench_g1_msm() {
    // These are reported but not individually gated at MAX_INSTRUCTIONS,
    // since larger MSMs are expected to exceed the single-op budget.
    std::println!("g1_msm_2: {} instructions", mock_g1_msm(2));
    std::println!("g1_msm_4: {} instructions", mock_g1_msm(4));
    std::println!("g1_msm_8: {} instructions", mock_g1_msm(8));
}

fn mock_poseidon2_hash(n: usize) -> u64 {
    let env = setup_env();
    let mut inputs = std::vec::Vec::new();
    for i in 0..n {
        inputs.push(U256::from_u32(&env, i as u32));
    }

    let start = env.cost_estimate().budget().cpu_instruction_cost();
    let _ = hash_to_field(&env, &inputs);
    env.cost_estimate().budget().cpu_instruction_cost() - start
}

#[test]
fn bench_poseidon2_hash() {
    check_cost(mock_poseidon2_hash(1), "poseidon2_hash_1");
    check_cost(mock_poseidon2_hash(2), "poseidon2_hash_2");
    check_cost(mock_poseidon2_hash(4), "poseidon2_hash_4");
}

/// Benchmarks a simulated Groth16 verification with 1 public input.
///
/// A real Groth16 verifier does:
///   1. An MSM of size (num_public_inputs + 1) to compute the public input accumulator.
///   2. A 4-pairing check: e(A, B) * e(-vk_alpha, vk_beta) * e(acc, vk_gamma) * e(C, vk_delta) == 1
///
/// Here we use (G1, G2) / (-G1, G2) as stand-ins for the distinct key points since we
/// don't have a real proving key. The important thing is that the pairing inputs are
/// structurally valid and distinct to exercise the full code path.
#[test]
fn bench_groth16_verify() {
    let env = setup_env();

    let g1 = g1_generator();
    let neg_g1 = g1_generator_neg();
    let g2 = g2_generator();

    // 4-pairing input representative of a Groth16 check with 1 public input.
    // Pairs: (A, B), (-alpha, beta), (acc, gamma), (C, delta)
    // Using (g1, g2) and (neg_g1, g2) as stand-ins for the key points.
    let pairs = std::vec![(g1, g2), (neg_g1, g2), (g1, g2), (neg_g1, g2)];

    let start = env.cost_estimate().budget().cpu_instruction_cost();

    // Step 1: MSM for the public input accumulator (size 2 for 1 public input).
    let point = G1Projective::from(g1_generator());
    let scalar = u256::from(100u32);
    let mut acc = G1Projective::identity();
    for _ in 0..2 {
        let res = Bn254::g1_scalar_mul(point, scalar);
        acc = acc.add(&res);
    }
    let _ = acc;

    // Step 2: 4-pairing check.
    let _ = pairing_check(&env, &pairs);

    let cost = env.cost_estimate().budget().cpu_instruction_cost() - start;
    std::println!("groth16_verify: {} instructions", cost);
    assert!(
        cost <= TOTAL_BUDGET,
        "groth16_verify exceeded 400M budget (cost: {})",
        cost
    );
}
