//! Criterion benchmarks for zk-core G1 point arithmetic primitives.
//!
//! These benchmarks measure wall-clock time for the core BN254 operations.
//! Results are used to produce the instruction budget estimates documented
//! in GAS.md at the repository root.
//!
//! # Reproducibility
//! Run with:
//!   cargo bench -p zk-core
//!
//! Results are written to target/criterion/. Use the same machine and
//! environment across runs for comparable numbers.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use ethnum::u256;
use zk_core::{Bn254, G1Affine, G1Projective};

// ---------------------------------------------------------------------------
// Fixed deterministic inputs
// ---------------------------------------------------------------------------

/// BN254 G1 generator (x=1, y=2).
fn gen() -> G1Affine {
    G1Affine {
        x: u256::from(1u8),
        y: u256::from(2u8),
    }
}

/// 2*G — deterministic second point derived from the generator.
fn two_g() -> G1Affine {
    G1Affine {
        x: u256::from_str_hex("0x030644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd3")
            .unwrap(),
        y: u256::from_str_hex("0x15ed738c0e0a7c92e7845f96b2ae9c0a68a6a449e3538fc7ff3ebf7a5a18a2c4")
            .unwrap(),
    }
}

/// A non-trivial deterministic scalar (2^128 + 1) well below the group order.
fn scalar_medium() -> u256 {
    u256::from_words(1u128, 1u128)
}

/// Group order r of BN254 minus 1 (worst-case scalar bit pattern).
fn scalar_r_minus_one() -> u256 {
    // r - 1 = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000
    u256::from_words(
        0x30644e72e131a029b85045b68181585d_u128,
        0x2833e84879b9709143e1f593f0000000_u128,
    )
}

// ---------------------------------------------------------------------------
// Benchmarks
// ---------------------------------------------------------------------------

/// Benchmark: G1 point addition (projective Jacobian add).
fn bench_g1_add(c: &mut Criterion) {
    let p = G1Projective::from(gen());
    let q = G1Projective::from(two_g());

    c.bench_function("G1Add", |b| {
        b.iter(|| black_box(p).add(black_box(&q)));
    });
}

/// Benchmark: G1 projective point doubling.
///
/// Uses a point with non-trivial Z (result of one add) so the measurement
/// exercises the full field arithmetic path rather than the Z=1 shortcut.
fn bench_g1_double(c: &mut Criterion) {
    // 3*G has a non-trivial Z coordinate — representative of mid-computation state
    let p = {
        let g = G1Projective::from(gen());
        let two_g = g.double();
        two_g.add(&g) // 3*G: non-trivial Z
    };

    c.bench_function("G1Double", |b| {
        b.iter(|| black_box(p).double());
    });
}

/// Benchmark: G1 scalar multiplication with varying scalar sizes.
///
/// Three representative scalars:
///   - scalar=2 (trivial, minimal bit work)
///   - scalar=2^128+1 (medium, half the bits set)
///   - scalar=r-1 (worst-case, all 254 bits exercised)
fn bench_g1_scalar_mul(c: &mut Criterion) {
    let p = G1Projective::from(gen());

    let scalars: &[(&str, u256)] = &[
        ("scalar=2", u256::from(2u8)),
        ("scalar=medium(2^128+1)", scalar_medium()),
        ("scalar=r-1(worst_case)", scalar_r_minus_one()),
    ];

    let mut group = c.benchmark_group("G1ScalarMul");
    for (label, scalar) in scalars {
        group.bench_with_input(BenchmarkId::new("G1ScalarMul", label), scalar, |b, s| {
            b.iter(|| Bn254::g1_scalar_mul(black_box(p), black_box(*s)));
        });
    }
    group.finish();
}

/// Benchmark: Fq field multiplication (Montgomery-style via binary method).
fn bench_fq_mul(c: &mut Criterion) {
    // Two arbitrary Fq elements (non-zero, less than p)
    let a = u256::from_words(
        0x0000000000000000000000000000000a_u128,
        0x000000000000000000000000000000ff_u128,
    );
    let b = u256::from_words(
        0x00000000000000000000000000000123_u128,
        0x0000000000000000000000000000abcd_u128,
    );

    c.bench_function("FqMul", |b_bench| {
        b_bench.iter(|| Bn254::mul_fq(black_box(a), black_box(b)));
    });
}

/// Benchmark: Fq field inversion (Fermat's little theorem: a^(p-2) mod p).
fn bench_fq_invert(c: &mut Criterion) {
    let a = u256::from_words(
        0x0000000000000000000000000000000a_u128,
        0x000000000000000000000000000000ff_u128,
    );

    c.bench_function("FqInvert", |b| {
        b.iter(|| Bn254::invert_fq(black_box(a)));
    });
}

/// Benchmark: projective-to-affine conversion (requires one Fq inversion).
fn bench_to_affine(c: &mut Criterion) {
    let p = G1Projective::from(gen()).double().double(); // non-trivial z

    c.bench_function("G1ProjectiveToAffine", |b| {
        b.iter(|| black_box(p).to_affine());
    });
}

/// Benchmark: Fr scalar field multiplication.
fn bench_fr_mul(c: &mut Criterion) {
    let a = u256::from(12345u32);
    let b = u256::from(67890u32);

    c.bench_function("FrMul", |b_bench| {
        b_bench.iter(|| Bn254::mul(black_box(a), black_box(b)));
    });
}

criterion_group!(
    benches,
    bench_g1_add,
    bench_g1_double,
    bench_g1_scalar_mul,
    bench_fq_mul,
    bench_fq_invert,
    bench_to_affine,
    bench_fr_mul,
);
criterion_main!(benches);
