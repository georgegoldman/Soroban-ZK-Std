//! Criterion benchmark comparing the Montgomery `mul_mod` engine (issue #360)
//! against the pre-optimization reference (`mul_mod_legacy`).
//!
//! Montgomery reduction replaces the shift-and-add / Karatsuba reduction with
//! cheap shifts and additions, so each field multiplication executes far fewer
//! CPU instructions. This bench measures wall-clock time as a proxy for the
//! Soroban CPU-instruction cost documented in `instruction_cost.rs`.
//!
//! # Reproducibility
//! Run with:
//!   cargo bench -p soroban-zk-core --bench montgomery_ops
//!
//! For the true Soroban CPU-instruction figure, see
//! `crates/soroban-zk-std/benches/instruction_cost.rs`
//! (`bench_fr_mul_montgomery_vs_legacy`).

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use ethnum::u256;
use soroban_zk_core::poseidon2::Poseidon2Sponge;
use soroban_zk_core::{Bn254, DensePolynomial, FqMont, FrMont};

fn bench_montgomery_vs_legacy(c: &mut Criterion) {
    // Representative scalar-field operands.
    let a = u256::from_words(
        0x1234_5678_9abc_def0_1234_5678_9abc_def0_u128,
        0xfedc_ba09_8765_4321_fedc_ba09_8765_4321_u128,
    );
    let b = u256::from_words(
        0x0f1e_2d3c_4b5a_6978_0f1e_2d3c_4b5a_6978_u128,
        0x8070_6050_4030_2010_8070_6050_4030_2010_u128,
    );

    let mut group = c.benchmark_group("fr_mul");

    group.bench_function("montgomery", |bench| {
        bench.iter(|| black_box(Bn254::mul(black_box(a), black_box(b))))
    });

    group.bench_function("legacy", |bench| {
        bench.iter(|| black_box(Bn254::mul_mod_legacy(black_box(a), black_box(b))))
    });

    group.finish();
}

/// Issue #575 — boundary `u256` API vs persistent Montgomery-domain types.
///
/// The `u256_api/*` cases exist on `main` too and give the before/after
/// comparison; the `persistent/*` cases measure the new `FrMont`/`FqMont`
/// operations, which never leave Montgomery form.
fn bench_persistent_domain(c: &mut Criterion) {
    let a = u256::from_words(
        0x1234_5678_9abc_def0_1234_5678_9abc_def0_u128,
        0xfedc_ba09_8765_4321_fedc_ba09_8765_4321_u128,
    );
    let b = u256::from_words(
        0x0f1e_2d3c_4b5a_6978_0f1e_2d3c_4b5a_6978_u128,
        0x8070_6050_4030_2010_8070_6050_4030_2010_u128,
    );
    let mut group = c.benchmark_group("mont575");

    // ---- shared API (before/after) -------------------------------------
    group.bench_function("u256_api/fr_mul", |bn| {
        bn.iter(|| black_box(Bn254::mul(black_box(a), black_box(b))))
    });
    group.bench_function("u256_api/fq_mul", |bn| {
        bn.iter(|| black_box(Bn254::mul_fq(black_box(a), black_box(b))))
    });
    group.bench_function("u256_api/fr_invert", |bn| {
        bn.iter(|| black_box(Bn254::invert(black_box(a))))
    });
    group.bench_function("u256_api/fq_invert", |bn| {
        bn.iter(|| black_box(Bn254::invert_fq(black_box(a))))
    });
    group.bench_function("u256_api/poseidon2_absorb2_squeeze", |bn| {
        bn.iter(|| {
            let mut sp = Poseidon2Sponge::new();
            sp.absorb(&[black_box(a), black_box(b)]);
            black_box(sp.squeeze())
        })
    });
    let coeffs = [a, b, a, b, a, b, a, b, a, b, a, b, a, b, a, b];
    let poly = DensePolynomial::<32>::from_coefficients_slice(&coeffs).unwrap();
    group.bench_function("u256_api/poly16_evaluate", |bn| {
        bn.iter(|| black_box(poly.evaluate(black_box(b))))
    });
    group.bench_function("u256_api/poly16_mul", |bn| {
        bn.iter(|| black_box(poly.try_mul(black_box(&poly))))
    });

    // ---- persistent Montgomery domain (new in #575) ---------------------
    let fa = FrMont::from_u256(a).unwrap();
    let fb = FrMont::from_u256(b).unwrap();
    let qa = FqMont::from_u256(a).unwrap();
    let qb = FqMont::from_u256(b).unwrap();
    group.bench_function("persistent/fr_mul", |bn| {
        bn.iter(|| black_box(black_box(fa).mul(&black_box(fb))))
    });
    group.bench_function("persistent/fq_mul", |bn| {
        bn.iter(|| black_box(black_box(qa).mul(&black_box(qb))))
    });
    group.bench_function("persistent/fr_add", |bn| {
        bn.iter(|| black_box(black_box(fa).add(&black_box(fb))))
    });
    group.bench_function("persistent/fr_inv", |bn| {
        bn.iter(|| black_box(black_box(fa).inv()))
    });
    group.bench_function("persistent/fr_from_to_u256", |bn| {
        bn.iter(|| black_box(FrMont::from_u256(black_box(a)).map(|x| x.to_u256())))
    });

    group.finish();
}

criterion_group!(benches, bench_montgomery_vs_legacy, bench_persistent_domain);
criterion_main!(benches);
