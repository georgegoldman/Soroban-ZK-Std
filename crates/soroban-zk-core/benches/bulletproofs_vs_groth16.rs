//! Gas profiling: Bulletproofs vs Groth16 (Issue #449)
//!
//! This benchmark suite profiles and compares the WASM instruction-cycle costs
//! of the Bulletproof range-proof verifier against a representative Groth16
//! verification flow.  It also isolates each major sub-operation of the
//! Bulletproof verifier so bottlenecks can be identified individually.
//!
//! # Running
//! ```bash
//! cargo bench -p soroban-zk-core --bench bulletproofs_vs_groth16
//! # Save a baseline before optimisation:
//! cargo bench -p soroban-zk-core --bench bulletproofs_vs_groth16 -- --save-baseline pre_opt
//! # Compare after optimisation:
//! cargo bench -p soroban-zk-core --bench bulletproofs_vs_groth16 -- --baseline pre_opt
//! ```
//!
//! # Soroban instruction budget
//! - Single-operation budget:  100,000,000 instructions
//! - Composite (pairing) budget: 400,000,000 instructions
//!
//! # What is measured
//!
//! ## Bulletproofs sub-operations
//! | Benchmark                   | What it isolates                                      |
//! |-----------------------------|-------------------------------------------------------|
//! | `BP/Generators::new`        | Deterministic hash-to-curve for all 129 gen points   |
//! | `CMP/f_inv::naive_K6`       | 6 separate Fermat inversions (old IPA scalar path)   |
//! | `CMP/f_inv::batch_K6`       | Montgomery batch inversion of K=6 values (new path)  |
//! | `BP/MSM::naive`             | N=64 MSM via scalar_mul→affine (old path)            |
//! | `BP/MSM::projective`        | N=64 MSM staying fully in projective (new path)      |
//! | `BP/Verify::single`         | Full single-proof verify (optimised)                 |
//! | `BP/Verify::batch_2`        | Batch verify of 2 proofs                             |
//! | `BP/Verify::batch_4`        | Batch verify of 4 proofs                             |
//! | `BP/Verify::batch_8`        | Batch verify of 8 proofs                             |
//!
//! ## Groth16 representative operations
//! | Benchmark                   | What it isolates                                      |
//! |-----------------------------|-------------------------------------------------------|
//! | `G16/MSM::accumulator_n1`   | MSM(2) public-input accumulator (1 public input)     |
//! | `G16/MSM::accumulator_n4`   | MSM(5) public-input accumulator (4 public inputs)    |
//! | `G16/PairingPrep::neg`      | G1 negation overhead before the 4-pair pairing call  |
//!
//! ## Head-to-head comparison
//! | Benchmark                   | What it measures                                      |
//! |-----------------------------|-------------------------------------------------------|
//! | `CMP/BP_verify_single`      | BP single verify total wall-clock                    |
//! | `CMP/G16_MSM2_accumulator`  | Groth16 MSM(2) accumulator component                 |
//! | `CMP/f_inv::single`         | Baseline: cost of one Fermat inversion               |

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use ethnum::u256;
use soroban_zk_core::bulletproofs::{self, Generators};
use soroban_zk_core::{Bn254, G1Affine, G1Projective};

// ─────────────────────────────────────────────────────────────────────────────
// Shared fixtures
// ─────────────────────────────────────────────────────────────────────────────

/// Number of IPA folding rounds for N=64.
const IP_ROUNDS: usize = 6;

/// BN254 G1 generator (x=1, y=2).
fn g1_gen() -> G1Affine {
    G1Affine {
        x: u256::from(1u8),
        y: u256::from(2u8),
    }
}

/// Deterministic non-zero Fr scalar from index `i`.
fn scalar(i: u64) -> u256 {
    let raw = u256::from(i.wrapping_add(1)) * u256::from(0x0102030405060708u64);
    let v = raw % Bn254::FR_MODULUS;
    if v == u256::from(0u8) {
        u256::from(1u8)
    } else {
        v
    }
}

/// Build one valid (proof, generators) pair for benchmarking.
fn proof_and_gens() -> (soroban_zk_core::bulletproofs::RangeProof, Generators) {
    let gens = Generators::new();
    let v = u256::from(0xdeadbeef_u64);
    let gamma = u256::from(42u8);
    let randomness = [7u8; 64];
    let proof = bulletproofs::prove(&gens, v, gamma, &randomness)
        .expect("prove must succeed for a 64-bit value");
    (proof, gens)
}

/// Build `count` distinct valid proofs (shared generators).
fn proofs_and_gens(
    count: usize,
) -> (
    std::vec::Vec<soroban_zk_core::bulletproofs::RangeProof>,
    Generators,
) {
    let gens = Generators::new();
    let mut proofs = std::vec::Vec::with_capacity(count);
    for i in 0..count {
        let v = u256::from(i as u64 + 1);
        let gamma = u256::from(i as u64 + 100);
        let randomness = [(i as u8).wrapping_add(1); 64];
        let p = bulletproofs::prove(&gens, v, gamma, &randomness).expect("prove must succeed");
        proofs.push(p);
    }
    (proofs, gens)
}

// ─────────────────────────────────────────────────────────────────────────────
// f_inv cost baseline
// ─────────────────────────────────────────────────────────────────────────────

/// One Fermat inversion (a^(r-2) mod r) — the baseline cost every other
/// optimization is measured against.  Each call costs ~5.5 M WASM instructions.
fn bench_f_inv_single(c: &mut Criterion) {
    let a = scalar(7);
    c.bench_function("CMP/f_inv::single", |b| {
        b.iter(|| Bn254::invert(black_box(a)));
    });
}

/// **Key optimization comparison** — 6 separate inversions (old IPA scalar
/// path) vs 1 inversion + 10 multiplications (Montgomery batch trick, new
/// path).  Expected saving: 5 × ~5.5 M ≈ **27.5 M instructions** per
/// IPA verify.
fn bench_f_inv_batch_k6(c: &mut Criterion) {
    let xs: [u256; IP_ROUNDS] = core::array::from_fn(|i| scalar(i as u64 + 1));

    let mut group = c.benchmark_group("CMP/f_inv");

    // ── Old path: K individual Fermat inversions ──────────────────────────
    group.bench_function("naive_K6", |b| {
        b.iter(|| {
            let mut out = [u256::from(0u8); IP_ROUNDS];
            for i in 0..IP_ROUNDS {
                out[i] = Bn254::invert(black_box(xs[i]));
            }
            black_box(out)
        });
    });

    // ── New path: Montgomery batch trick — 1 inv + 2(K-1) muls ───────────
    group.bench_function("batch_K6", |b| {
        b.iter(|| {
            // Prefix products: prefix[i] = xs[0] * ... * xs[i]
            let mut prefix = [u256::from(0u8); IP_ROUNDS];
            prefix[0] = xs[0];
            for i in 1..IP_ROUNDS {
                prefix[i] = Bn254::mul(prefix[i - 1], xs[i]);
            }
            // Single inversion of the full product.
            let mut acc_inv = Bn254::invert(black_box(prefix[IP_ROUNDS - 1]));
            // Reverse pass: recover individual inverses.
            let mut out = [u256::from(0u8); IP_ROUNDS];
            for i in (1..IP_ROUNDS).rev() {
                out[i] = Bn254::mul(acc_inv, prefix[i - 1]);
                acc_inv = Bn254::mul(acc_inv, xs[i]);
            }
            out[0] = acc_inv;
            black_box(out)
        });
    });

    group.finish();
}

// ─────────────────────────────────────────────────────────────────────────────
// MSM: naive (to_affine per scalar-mul) vs projective
// ─────────────────────────────────────────────────────────────────────────────

/// **Old MSM path** — each `scalar_mul` call converts the result back to affine
/// via one `Fq::invert` (~5.85 M instructions).  For N=64 this accumulates
/// to 64 × 5.85 M ≈ **374 M instructions** just in affine conversions.
fn bench_msm_naive_n64(c: &mut Criterion) {
    let points: [G1Affine; 64] = core::array::from_fn(|i| {
        Bn254::g1_scalar_mul(G1Projective::from(g1_gen()), scalar(i as u64)).to_affine()
    });
    let scalars_arr: [u256; 64] = core::array::from_fn(|i| scalar(i as u64 + 100));

    c.bench_function("BP/MSM::naive", |b| {
        b.iter(|| {
            let mut acc = G1Projective::identity();
            for i in 0..64usize {
                // Old path: G1Affine::scalar_mul → to_affine inside the loop.
                let scaled = black_box(points[i]).scalar_mul(black_box(scalars_arr[i]));
                acc = acc.add(&G1Projective::from(scaled));
            }
            black_box(acc.to_affine())
        });
    });
}

/// **New MSM path** — stays fully in projective coordinates throughout.
/// Single `to_affine()` only at the very end.  Eliminates the 374 M
/// affine-conversion overhead of the naive path.
fn bench_msm_projective_n64(c: &mut Criterion) {
    let points: [G1Affine; 64] = core::array::from_fn(|i| {
        Bn254::g1_scalar_mul(G1Projective::from(g1_gen()), scalar(i as u64)).to_affine()
    });
    let scalars_arr: [u256; 64] = core::array::from_fn(|i| scalar(i as u64 + 100));

    c.bench_function("BP/MSM::projective", |b| {
        b.iter(|| {
            let mut acc = G1Projective::identity();
            for i in 0..64usize {
                // New path: g1_scalar_mul keeps the result in projective.
                let scaled = Bn254::g1_scalar_mul(
                    G1Projective::from(black_box(points[i])),
                    black_box(scalars_arr[i]),
                );
                acc = acc.add(&scaled);
            }
            // Single to_affine at the end.
            black_box(acc.to_affine())
        });
    });
}

// ─────────────────────────────────────────────────────────────────────────────
// Generators::new — hash-to-curve cost
// ─────────────────────────────────────────────────────────────────────────────

/// Constructing the generator set runs 129 hash-to-curve iterations.  This
/// is a one-time setup cost — contracts that cache the generators in instance
/// storage pay this once per contract lifetime.
fn bench_generators_new(c: &mut Criterion) {
    c.bench_function("BP/Generators::new", |b| {
        b.iter(|| black_box(Generators::new()));
    });
}

// ─────────────────────────────────────────────────────────────────────────────
// Full Bulletproof verify — single & batch
// ─────────────────────────────────────────────────────────────────────────────

fn bench_bp_verify_single(c: &mut Criterion) {
    let (proof, gens) = proof_and_gens();
    c.bench_function("BP/Verify::single", |b| {
        b.iter(|| bulletproofs::verify(black_box(&gens), black_box(&proof)));
    });
}

fn bench_bp_verify_batch(c: &mut Criterion) {
    let mut group = c.benchmark_group("BP/Verify");
    for &count in &[2usize, 4, 8] {
        let (proofs, gens) = proofs_and_gens(count);
        group.bench_with_input(BenchmarkId::new("batch", count), &count, |b, _| {
            b.iter(|| bulletproofs::verify_batch(black_box(&gens), black_box(&proofs)));
        });
    }
    group.finish();
}

// ─────────────────────────────────────────────────────────────────────────────
// Groth16 representative operations
// ─────────────────────────────────────────────────────────────────────────────

/// MSM public-input accumulator for a Groth16 verifier.
///
/// - n=1 public input → MSM(2): `IC_0 + s_1 * IC_1`
/// - n=4 public inputs → MSM(5): `IC_0 + s_1*IC_1 + ... + s_4*IC_4`
///
/// This is the dominant WASM guest cost in Groth16 verification; the pairing
/// check itself (~29.3 M instructions) is a native host function call.
fn bench_g16_msm_accumulator(c: &mut Criterion) {
    let g = g1_gen();
    let mut group = c.benchmark_group("G16/MSM");

    for &n_pub in &[1usize, 4] {
        let msm_size = n_pub + 1;
        let points: std::vec::Vec<G1Affine> = (0..msm_size)
            .map(|i| {
                Bn254::g1_scalar_mul(G1Projective::from(g), scalar(i as u64 + 200)).to_affine()
            })
            .collect();
        let sclrs: std::vec::Vec<u256> = (0..msm_size).map(|i| scalar(i as u64 + 300)).collect();

        group.bench_with_input(
            BenchmarkId::new("accumulator", format!("n{}", n_pub)),
            &n_pub,
            |b, _| {
                b.iter(|| {
                    // IC_0 (no scalar) + Σ s_i * IC_i
                    let mut acc = G1Projective::from(black_box(points[0]));
                    for i in 1..msm_size {
                        let term = Bn254::g1_scalar_mul(
                            G1Projective::from(black_box(points[i])),
                            black_box(sclrs[i]),
                        );
                        acc = acc.add(&term);
                    }
                    black_box(acc.to_affine())
                });
            },
        );
    }
    group.finish();
}

/// G1 point negation — the three negations a Groth16 verifier performs before
/// the 4-pair pairing call (negate alpha_g1, acc, and proof.C).  This is cheap
/// (three Fq subtractions) and is measured here for completeness.
fn bench_g16_pairing_prep(c: &mut Criterion) {
    let g = g1_gen();
    c.bench_function("G16/PairingPrep::neg", |b| {
        b.iter(|| {
            // Three G1 negations: (x, y) → (x, -y mod Fq)
            let neg = |pt: G1Affine| G1Affine {
                x: pt.x,
                y: Bn254::sub_fq(u256::from(0u8), pt.y),
            };
            let n1 = neg(black_box(g));
            let n2 = neg(black_box(g));
            let n3 = neg(black_box(g));
            black_box((n1, n2, n3))
        });
    });
}

// ─────────────────────────────────────────────────────────────────────────────
// Head-to-head: BP single verify vs Groth16 MSM(2) accumulator
// ─────────────────────────────────────────────────────────────────────────────

/// **Primary comparison benchmark.**
///
/// Places the Bulletproof single-proof verifier side-by-side with the Groth16
/// MSM(2) accumulator in the same benchmark group so Criterion reports the
/// relative wall-clock cost directly.
///
/// Note: this compares BP's *entire* verify cost against only the MSM
/// component of Groth16.  For a fully apples-to-apples total, add the
/// ~29.3 M host pairing cost (from GAS.md) to the Groth16 number.
fn bench_head_to_head(c: &mut Criterion) {
    let (bp_proof, bp_gens) = proof_and_gens();

    // Groth16 MSM(2) fixture.
    let g = g1_gen();
    let ic0 = Bn254::g1_scalar_mul(G1Projective::from(g), scalar(500)).to_affine();
    let ic1 = Bn254::g1_scalar_mul(G1Projective::from(g), scalar(501)).to_affine();
    let pub_input = scalar(10);

    let mut group = c.benchmark_group("CMP");

    group.bench_function("BP_verify_single", |b| {
        b.iter(|| bulletproofs::verify(black_box(&bp_gens), black_box(&bp_proof)));
    });

    group.bench_function("G16_MSM2_accumulator", |b| {
        b.iter(|| {
            let term =
                Bn254::g1_scalar_mul(G1Projective::from(black_box(ic1)), black_box(pub_input));
            let acc = G1Projective::from(black_box(ic0)).add(&term);
            black_box(acc.to_affine())
        });
    });

    group.finish();
}

// ─────────────────────────────────────────────────────────────────────────────
// Criterion entry point
// ─────────────────────────────────────────────────────────────────────────────

criterion_group!(benches_baseline, bench_f_inv_single, bench_f_inv_batch_k6,);

criterion_group!(benches_msm, bench_msm_naive_n64, bench_msm_projective_n64,);

criterion_group!(
    benches_bp,
    bench_generators_new,
    bench_bp_verify_single,
    bench_bp_verify_batch,
);

criterion_group!(
    benches_g16,
    bench_g16_msm_accumulator,
    bench_g16_pairing_prep,
);

criterion_group!(benches_cmp, bench_head_to_head);

criterion_main!(
    benches_baseline,
    benches_msm,
    benches_bp,
    benches_g16,
    benches_cmp,
);
