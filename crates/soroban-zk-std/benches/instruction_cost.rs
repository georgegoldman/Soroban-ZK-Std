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

// ── Groth16 instruction-budget benchmarks (Protocol 25 native pairing) ────────
//
// Soroban contracts run under a 400M CPU instruction budget per transaction.
// For Protocol 25, the `bn254_multi_pairing_check` host function is a native
// implementation, making the 4-pair check the dominant cost. These benchmarks
// verify that groth16_verify stays well below 400M (target: < 20M instructions
// for the pairing-only path with native CAP-0075 support).
//
// Each benchmark simulates the two-step Groth16 verification flow:
//   1. G1 MSM of size (n_inputs + 1) to accumulate the public-input contribution.
//   2. A single `bn254_multi_pairing_check` of 4 pairs.
//
// We use (G1_generator, G2_generator) as structurally valid stand-ins so the
// full host code path is exercised without needing an actual proving key.

// Protocol 25 native pairing target: < 20M instructions on a live node with the
// CAP-0075 native pairing host function. In the Soroban SDK mock environment used
// by `cargo test` the pairing is emulated in software and costs ~29M instructions,
// so CI uses a relaxed 100M gate. The 20M figure is documented as the production
// target and is validated manually against a live network or a full-stack testnet.
const GROTH16_BUDGET_TARGET: u64 = 100_000_000; // CI gate (mock env); live target < 20M

/// Runs a synthetic Groth16 verification for `n_inputs` public inputs and
/// returns the measured CPU instruction count.
fn mock_groth16_verify(n_inputs: usize) -> u64 {
    let env = setup_env();
    let g1 = g1_generator();
    let neg_g1 = g1_generator_neg();
    let g2 = g2_generator();

    // 4-pair check is constant regardless of n_inputs — it's always:
    //   e(A, B) * e(-alpha, beta) * e(acc, gamma) * e(C, delta)
    let pairs = std::vec![(g1, g2), (neg_g1, g2), (g1, g2), (neg_g1, g2)];

    let start = env.cost_estimate().budget().cpu_instruction_cost();

    // Step 1: MSM of size (n_inputs + 1) for the public-input accumulator IC_0 + Σ s_i·IC_i.
    let point = G1Projective::from(g1_generator());
    let scalar = u256::from(100u32);
    let mut acc = G1Projective::identity();
    for _ in 0..(n_inputs + 1) {
        let res = Bn254::g1_scalar_mul(point, scalar);
        acc = acc.add(&res);
    }
    let _ = acc;

    // Step 2: 4-pairing check (the cryptographically dominant step).
    let _ = pairing_check(&env, &pairs);

    env.cost_estimate().budget().cpu_instruction_cost() - start
}

/// Groth16 instruction-budget benchmark — 1 public input.
///
/// Asserts the full verification (MSM(2) + 4-pair check) is well below the
/// 400M transaction limit. The < 100M CI gate proves we are nowhere near the
/// budget wall; the production target of < 20M is achieved on a live Protocol
/// 25 node where CAP-0075 runs natively rather than in the mock emulator.
#[test]
fn bench_groth16_verify_1_input() {
    let cost = mock_groth16_verify(1);
    std::println!("groth16_verify (1 input): {} instructions", cost);
    assert!(
        cost < TOTAL_BUDGET,
        "groth16_verify_1 exceeded 400M budget (cost: {})",
        cost
    );
    assert!(
        cost < GROTH16_BUDGET_TARGET,
        "groth16_verify_1 exceeded 100M CI gate (cost: {}). \
         Check that the native CAP-0075 pairing host function is active.",
        cost
    );
}

/// Groth16 instruction-budget benchmark — 2 public inputs.
///
/// With 2 inputs the MSM size grows to 3. Asserts cost remains < 100M (CI gate).
#[test]
fn bench_groth16_verify_2_inputs() {
    let cost = mock_groth16_verify(2);
    std::println!("groth16_verify (2 inputs): {} instructions", cost);
    assert!(
        cost < TOTAL_BUDGET,
        "groth16_verify_2 exceeded 400M budget (cost: {})",
        cost
    );
    assert!(
        cost < GROTH16_BUDGET_TARGET,
        "groth16_verify_2 exceeded 100M CI gate (cost: {}). \
         Check that the native CAP-0075 pairing host function is active.",
        cost
    );
}

/// Groth16 instruction-budget benchmark — 4 public inputs.
///
/// With 4 inputs the MSM size grows to 5. Asserts cost remains < 100M (CI gate).
#[test]
fn bench_groth16_verify_4_inputs() {
    let cost = mock_groth16_verify(4);
    std::println!("groth16_verify (4 inputs): {} instructions", cost);
    assert!(
        cost < TOTAL_BUDGET,
        "groth16_verify_4 exceeded 400M budget (cost: {})",
        cost
    );
    assert!(
        cost < GROTH16_BUDGET_TARGET,
        "groth16_verify_4 exceeded 100M CI gate (cost: {}). \
         Check that the native CAP-0075 pairing host function is active.",
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

// ── Issue #612: expanded primitive coverage ──────────────────────────────────
//
// These benches run the library natively inside the Soroban test `Env`, so the
// budget only charges **host** work (pairing / Poseidon2 host functions,
// storage, host objects). Pure-Rust arithmetic compiled into a contract is
// charged per WASM instruction on-chain and does not show up here. The
// WASM-metered figures published in `BENCHMARK.md`, `GAS.md`, and
// `benchmark_gas_tables.mdx` come from running the same calls inside a
// compiled `wasm32v1-none` contract; see `BENCHMARK.md` for the method.

/// Runs `f` with a reset unlimited budget and returns `(cpu, mem)` charged.
fn measure<F: FnOnce()>(env: &Env, f: F) -> (u64, u64) {
    env.cost_estimate().budget().reset_unlimited();
    let budget = env.cost_estimate().budget();
    let (cpu0, mem0) = (budget.cpu_instruction_cost(), budget.memory_bytes_cost());
    f();
    let budget = env.cost_estimate().budget();
    (
        budget.cpu_instruction_cost() - cpu0,
        budget.memory_bytes_cost() - mem0,
    )
}

fn kzg_bundle<'a>(
    commitments: &'a [G1Affine],
    evaluations: &'a [u256],
    salt: u32,
) -> soroban_zk_core::KzgEvalProofInputs<'a> {
    soroban_zk_core::KzgEvalProofInputs {
        commitments,
        evaluations_at_zeta: evaluations,
        commitment_at_zeta_omega: g1_generator(),
        evaluation_at_zeta_omega: u256::from(5u32 + salt),
        w_zeta: g1_generator(),
        w_zeta_omega: g1_generator_neg(),
        v: u256::from(7u32 + salt),
        u: u256::from(11u32 + salt),
        zeta: u256::from(13u32 + salt),
        omega: u256::from(17u32 + salt),
    }
}

/// PLONK-KZG opening check: one proof, then batches of 5 and 20 proofs folded
/// into a single aggregated pairing. Happy path plus the empty-batch rejection.
#[test]
fn bench_plonk_kzg_single_and_batch() {
    use soroban_zk_std::plonk_kzg::{verify_plonk_kzg, verify_plonk_kzg_batch};
    let env = setup_env();
    let commitments = [g1_generator()];
    let evaluations = [u256::from(3u8)];

    let single = kzg_bundle(&commitments, &evaluations, 0);
    let (cpu, mem) = measure(&env, || {
        assert!(verify_plonk_kzg(&env, &single, g2_generator()).is_ok());
    });
    std::println!(
        "plonk_kzg_verify_single: {} instructions, {} bytes",
        cpu,
        mem
    );
    check_cost(cpu, "plonk_kzg_verify_single");

    for m in [5usize, 20] {
        let bundles: std::vec::Vec<_> = (0..m as u32)
            .map(|i| kzg_bundle(&commitments, &evaluations, i))
            .collect();
        let (cpu, mem) = measure(&env, || {
            assert!(verify_plonk_kzg_batch(&env, &bundles, &[9u8; 32], g2_generator()).is_ok());
        });
        std::println!(
            "plonk_kzg_verify_batch_{}: {} instructions, {} bytes",
            m,
            cpu,
            mem
        );
        check_cost(cpu, &format!("plonk_kzg_verify_batch_{}", m));
    }

    // Negative: an empty batch is rejected without a pairing call.
    let (cpu, _) = measure(&env, || {
        assert!(verify_plonk_kzg_batch(&env, &[], &[9u8; 32], g2_generator()).is_err());
    });
    assert!(
        cpu < 1_000_000,
        "empty batch must short-circuit (cost: {})",
        cpu
    );
}

/// Halo2 permutation-key instance cache: write and warm read for a 16×4 grid,
/// plus the boundary case of a zero-sized grid being rejected.
#[test]
fn bench_halo2_permutation_key_cache() {
    use soroban_zk_std::halo2::{
        cache_permutation_key, identity_permutation_key, load_permutation_key,
    };
    let env = setup_env();
    let id = env.register(ZkContract, ());
    env.as_contract(&id, || {
        let key = identity_permutation_key(&env, 16, 4).unwrap();
        let (write, _) = measure(&env, || cache_permutation_key(&env, &key).unwrap());
        let (read, _) = measure(&env, || {
            assert!(load_permutation_key(&env, 16, 4).is_some());
        });
        std::println!("halo2_perm_key_cache_write_16x4: {} instructions", write);
        std::println!("halo2_perm_key_cache_read_16x4: {} instructions", read);
        check_cost(write, "halo2_perm_key_cache_write_16x4");
        check_cost(read, "halo2_perm_key_cache_read_16x4");
        // Boundary / negative: an empty grid never produces a key, and a
        // miss on an uncached grid returns None.
        assert!(identity_permutation_key(&env, 0, 4).is_err());
        assert!(load_permutation_key(&env, 8, 8).is_none());
    });
}

/// Poseidon2 2-to-1 hash: constants rebuilt from code vs read from the
/// instance cache (Issue #124). Both must agree on the output.
#[test]
fn bench_poseidon2_cached_vs_uncached() {
    use soroban_zk_std::poseidon2::hash_to_field_cached;
    let env = setup_env();
    let id = env.register(ZkContract, ());
    env.as_contract(&id, || {
        let inputs = [U256::from_u32(&env, 1), U256::from_u32(&env, 2)];
        let mut uncached_out = None;
        let (uncached, _) = measure(&env, || uncached_out = Some(hash_to_field(&env, &inputs)));
        // Cold call populates the cache; the next call is the warm read.
        let (cold, _) = measure(&env, || {
            let _ = hash_to_field_cached(&env, &inputs);
        });
        let mut warm_out = None;
        let (warm, _) = measure(&env, || {
            warm_out = Some(hash_to_field_cached(&env, &inputs))
        });
        std::println!("poseidon2_hash2_uncached: {} instructions", uncached);
        std::println!("poseidon2_hash2_cached_cold: {} instructions", cold);
        std::println!("poseidon2_hash2_cached_warm: {} instructions", warm);
        assert_eq!(
            uncached_out, warm_out,
            "cached and uncached hashes must agree"
        );
        check_cost(uncached, "poseidon2_hash2_uncached");
        check_cost(cold, "poseidon2_hash2_cached_cold");
        check_cost(warm, "poseidon2_hash2_cached_warm");
    });
}

/// Rescue-Prime 2-to-1 hash: uncached vs instance-cached constants.
#[test]
fn bench_rescue_prime_cached_vs_uncached() {
    use soroban_zk_std::{rescue_prime_hash, rescue_prime_hash_cached};
    let env = setup_env();
    let id = env.register(ZkContract, ());
    env.as_contract(&id, || {
        let inputs = [U256::from_u32(&env, 1), U256::from_u32(&env, 2)];
        let mut a = None;
        let (uncached, _) = measure(&env, || a = Some(rescue_prime_hash(&env, &inputs)));
        let _ = rescue_prime_hash_cached(&env, &inputs);
        let mut b = None;
        let (warm, _) = measure(&env, || b = Some(rescue_prime_hash_cached(&env, &inputs)));
        std::println!("rescue_prime_hash2_uncached: {} instructions", uncached);
        std::println!("rescue_prime_hash2_cached_warm: {} instructions", warm);
        assert_eq!(a, b, "cached and uncached hashes must agree");
        check_cost(uncached, "rescue_prime_hash2_uncached");
        check_cost(warm, "rescue_prime_hash2_cached_warm");
    });
}

/// NullifierStore: first spend (persistent write), lookup, and the replay
/// rejection, which must not write.
#[test]
fn bench_nullifier_store() {
    use soroban_zk_std::nullifier::{NullifierSet, NullifierStore};
    let env = setup_env();
    let id = env.register(ZkContract, ());
    env.as_contract(&id, || {
        let store = NullifierStore::new(&env);
        let proof = Bytes::from_array(&env, &[0x11u8; 256]);
        let inputs = Bytes::from_array(&env, &[0x22u8; 32]);
        let (spend, _) = measure(&env, || store.mark_spent(&env, &proof, &inputs).unwrap());
        let (check, _) = measure(&env, || assert!(store.is_spent(&env, &proof, &inputs)));
        let (replay, _) = measure(&env, || {
            assert!(store.mark_spent(&env, &proof, &inputs).is_err());
        });
        std::println!("nullifier_mark_spent: {} instructions", spend);
        std::println!("nullifier_is_spent: {} instructions", check);
        std::println!("nullifier_replay_rejected: {} instructions", replay);
        check_cost(spend, "nullifier_mark_spent");
        check_cost(check, "nullifier_is_spent");
        check_cost(replay, "nullifier_replay_rejected");
    });
}
