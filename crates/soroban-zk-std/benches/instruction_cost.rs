#![cfg(test)]

use ethnum::u256;
use soroban_sdk::{Bytes, Env, U256};
use soroban_zk_core::{Bn254, G1Affine, G1Projective};
use soroban_zk_std::groth16::Groth16VerifyingKey;
use soroban_zk_std::pairing::{pairing_check, G2Affine};
use soroban_zk_std::poseidon2::hash_to_field;
use soroban_zk_std::vk::{load_vk, save_vk, G1_GENERATOR as VK_G1, G2_GENERATOR as VK_G2};
use soroban_zk_std::ZkContract;

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
            // X c0 (real) - Put this first
            u256::from_str_radix(
                "1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed",
                16,
            )
            .unwrap(),
            // X c1 (imaginary) - Put this second
            u256::from_str_radix(
                "198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2",
                16,
            )
            .unwrap(),
        ),
        y: (
            // Y c0 (real) - Put this first
            u256::from_str_radix(
                "12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa",
                16,
            )
            .unwrap(),
            // Y c1 (imaginary) - Put this second
            u256::from_str_radix(
                "090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b",
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

/// Before/after comparison for issue #360: the Montgomery multiplication engine
/// (`Bn254::mul`) versus the pre-optimization reference (`Bn254::mul_mod_legacy`).
///
/// Reports the per-multiplication CPU instruction cost of each and the
/// speed-up factor. Running this on a release WASM build demonstrates the
/// instruction-footprint reduction that keeps ZK proof verification inside the
/// Soroban transaction budget.
#[test]
fn bench_fr_mul_montgomery_vs_legacy() {
    let a = u256::from(0x1234567890abcdefu64);
    let b = u256::from(0xfedcba0987654321u64);

    // Montgomery engine (new).
    let env = setup_env();
    let start = env.cost_estimate().budget().cpu_instruction_cost();
    for _ in 0..1000 {
        std::hint::black_box(Bn254::mul(a, b));
    }
    let montgomery_cost = (env.cost_estimate().budget().cpu_instruction_cost() - start) / 1000;

    // Reference shift-and-add / Karatsuba path (old).
    let env = setup_env();
    let start = env.cost_estimate().budget().cpu_instruction_cost();
    for _ in 0..1000 {
        std::hint::black_box(Bn254::mul_mod_legacy(a, b));
    }
    let legacy_cost = (env.cost_estimate().budget().cpu_instruction_cost() - start) / 1000;

    std::println!("Fr::mul (Montgomery): {} instructions/mul", montgomery_cost);
    std::println!("Fr::mul_mod_legacy:   {} instructions/mul", legacy_cost);
    let speedup = legacy_cost as f64 / montgomery_cost.max(1) as f64;
    std::println!("Montgomery speed-up factor: {:.2}x", speedup);

    // Both must agree numerically (the optimization must preserve semantics).
    assert_eq!(Bn254::mul(a, b), Bn254::mul_mod_legacy(a, b));

    // The new path must be strictly cheaper per multiplication.
    assert!(
        montgomery_cost < legacy_cost,
        "Montgomery mul ({}) was not cheaper than legacy ({})",
        montgomery_cost,
        legacy_cost
    );
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

/// Measures the instruction cost of a native CAP-0075 `bn254_multi_pairing_check`
/// call (via [`pairing_check`]) for a given number of pairs. Each pair is a
/// structurally valid `(G1, G2)` so the host path is fully exercised.
fn mock_pairing_check(n: usize) -> u64 {
    let g1 = g1_generator();
    let neg_g1 = g1_generator_neg();
    let g2 = g2_generator();

    let mut pairs: std::vec::Vec<(G1Affine, G2Affine)> = std::vec::Vec::new();
    for i in 0..n {
        let g1pt = if i % 2 == 0 { g1 } else { neg_g1 };
        pairs.push((g1pt, g2));
    }

    let env = setup_env();
    let start = env.cost_estimate().budget().cpu_instruction_cost();
    let _ = pairing_check(&env, &pairs);
    env.cost_estimate().budget().cpu_instruction_cost() - start
}

#[test]
fn bench_pairing_check() {
    // Tracks total + per-pair marginal cost to document the asymptotic behavior
    // of the native pairing host function.
    let mut prev: Option<u64> = None;
    for n in [1usize, 2, 4, 8] {
        let cost = mock_pairing_check(n);
        match prev {
            Some(p) if n > 1 => {
                let per_pair = cost.saturating_sub(p) / ((n / 2) as u64);
                std::println!(
                    "pairing_check_{}: {} instructions (≈{} per extra pair)",
                    n,
                    cost,
                    per_pair
                );
            }
            _ => std::println!("pairing_check_{}: {} instructions", n, cost),
        }
        check_cost(cost, &format!("pairing_check_{}", n));
        prev = Some(cost);
    }
}

/// Measures the instruction cost of reading a fixed-size payload from
/// `StorageType::Instance` versus `StorageType::Persistent`, documenting the
/// per-read gas/CPU difference between the two storage types (Issue #369).
#[test]
fn bench_vk_instance_vs_persistent() {
    let n: usize = 32 * 1024; // one VK chunk (32 KiB)
    let env = setup_env();
    let id = env.register(ZkContract, ());
    let key = soroban_sdk::Symbol::new(&env, "benchvk");

    let data: std::vec::Vec<u8> = (0..n).map(|_| 0xABu8).collect();
    let payload = Bytes::from_slice(&env, &data);

    // Warm both stores (not measured).
    env.as_contract(&id, || {
        env.storage().instance().set(&key, &payload);
        env.storage().persistent().set(&key, &payload);
    });

    let inst_cost = env.as_contract(&id, || {
        let start = env.cost_estimate().budget().cpu_instruction_cost();
        let _: Bytes = env.storage().instance().get(&key).unwrap();
        env.cost_estimate().budget().cpu_instruction_cost() - start
    });

    let pers_cost = env.as_contract(&id, || {
        let start = env.cost_estimate().budget().cpu_instruction_cost();
        let _: Bytes = env.storage().persistent().get(&key).unwrap();
        env.cost_estimate().budget().cpu_instruction_cost() - start
    });

    std::println!("vk_read_instance: {} instructions", inst_cost);
    std::println!("vk_read_persistent: {} instructions", pers_cost);
    std::println!(
        "vk_read_persistent_overhead: {} instructions",
        pers_cost.saturating_sub(inst_cost)
    );
    check_cost(inst_cost, "vk_read_instance");
    check_cost(pers_cost, "vk_read_persistent");
}

/// Measures the full chunked save + load cost of a verification key via the
/// `vk` module, for a key whose `ic` vector forces multiple 32 KiB chunks.
#[test]
fn bench_vk_chunked_roundtrip() {
    // 1024 ic points ≈ 64 KiB, which spans two 32 KiB chunks.
    let ic_len = 1024usize;
    let env = setup_env();
    let id = env.register(ZkContract, ());

    let ic: std::vec::Vec<G1Affine> = std::vec![VK_G1; ic_len];
    let vk = Groth16VerifyingKey {
        alpha_g1: VK_G1,
        beta_g2: VK_G2,
        gamma_g2: VK_G2,
        delta_g2: VK_G2,
        ic: &ic,
    };

    env.as_contract(&id, || {
        let start = env.cost_estimate().budget().cpu_instruction_cost();
        save_vk(&env, &vk).unwrap();
        let cost_write = env.cost_estimate().budget().cpu_instruction_cost() - start;

        let start = env.cost_estimate().budget().cpu_instruction_cost();
        let loaded = load_vk(&env).unwrap();
        let cost_read = env.cost_estimate().budget().cpu_instruction_cost() - start;

        std::println!("vk_save ({} ic pts): {} instructions", ic_len, cost_write);
        std::println!("vk_load ({} ic pts): {} instructions", ic_len, cost_read);
        assert_eq!(loaded.ic.len(), ic_len);
        check_cost(cost_write, "vk_save");
        check_cost(cost_read, "vk_load");

        // Cleanup hook must purge the chunks.
        soroban_zk_std::vk::clear_vk(&env);
        assert!(load_vk(&env).is_err());
    });
}
