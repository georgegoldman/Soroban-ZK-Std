//! Criterion benchmarks for soroban-zk-core G1 point arithmetic primitives.
//!
//! These benchmarks measure wall-clock time for the core BN254 operations.
//! Results are used to produce the instruction budget estimates documented
//! in GAS.md at the repository root.
//!
//! # Reproducibility
//! Run with:
//!   cargo bench -p soroban-zk-core
//!
//! Results are written to target/criterion/. Use the same machine and
//! environment across runs for comparable numbers.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use ethnum::u256;
use soroban_zk_core::{batch_to_affine, g1_msm_pippenger, Bn254, G1Affine, G1Projective};

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

/// Benchmark: KZG commitment generation for small polynomial sizes.
fn bench_kzg_commit(c: &mut Criterion) {
    use soroban_zk_core::{kzg_commit, DensePolynomial};

    let g = gen();
    let two_g = two_g();

    // Size 2: polynomial [a, b] against SRS [G, 2G]
    let srs_2 = [g, two_g];
    let poly_2 =
        DensePolynomial::<4>::from_coefficients_slice(&[u256::from(3u64), u256::from(5u64)])
            .unwrap();

    c.bench_function("KzgCommit_size2", |b| {
        b.iter(|| black_box(kzg_commit(black_box(&poly_2), black_box(&srs_2))));
    });

    // Size 4: polynomial [a, b, c, d] against SRS [G, 2G, 3G, 4G]
    let three_g = Bn254::g1_scalar_mul(G1Projective::from(g), u256::from(3u64)).to_affine();
    let four_g = Bn254::g1_scalar_mul(G1Projective::from(g), u256::from(4u64)).to_affine();
    let srs_4 = [g, two_g, three_g, four_g];
    let poly_4 = DensePolynomial::<4>::from_coefficients_slice(&[
        u256::from(1u64),
        u256::from(2u64),
        u256::from(3u64),
        u256::from(4u64),
    ])
    .unwrap();

    c.bench_function("KzgCommit_size4", |b| {
        b.iter(|| black_box(kzg_commit(black_box(&poly_4), black_box(&srs_4))));
    });
}

/// Affine encoding of the point at infinity, used to pre-fill output buffers.
fn infinity() -> G1Affine {
    G1Affine {
        x: u256::from(0u8),
        y: u256::from(0u8),
    }
}

/// `n` deterministic Jacobian points `k * G` (k = 1..=n) with non-trivial Z.
fn projective_points(n: usize) -> Vec<G1Projective> {
    let g = G1Projective::from(gen());
    let mut cur = g;
    (0..n)
        .map(|_| {
            let p = cur;
            cur = cur.add(&g);
            p
        })
        .collect()
}

/// `n` deterministic scalars below the group order (SplitMix64-derived).
fn pseudo_scalars(n: usize) -> Vec<u256> {
    let mut state = 0x0584_u64;
    let mut next = || {
        state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        (z ^ (z >> 31)) as u128
    };
    (0..n)
        .map(|_| {
            let hi = (next() << 64) | next();
            let lo = (next() << 64) | next();
            u256::from_words(hi, lo) % Bn254::FR_MODULUS
        })
        .collect()
}

/// Benchmark: converting `n` projective points to affine — one Fermat
/// inversion per point versus Montgomery's simultaneous inversion
/// (`batch_to_affine`: a single inversion for the whole slice).
fn bench_batch_to_affine(c: &mut Criterion) {
    let mut group = c.benchmark_group("BatchToAffine");
    for n in [16usize, 64, 128] {
        let proj = projective_points(n);

        group.bench_with_input(BenchmarkId::new("individual", n), &proj, |b, proj| {
            b.iter(|| {
                let mut acc = 0u8;
                for p in black_box(proj) {
                    acc ^= p.to_affine().x.as_u8();
                }
                acc
            });
        });

        group.bench_with_input(BenchmarkId::new("batch", n), &proj, |b, proj| {
            let mut out = vec![infinity(); proj.len()];
            b.iter(|| {
                batch_to_affine(black_box(proj), &mut out).unwrap();
                out[0].x.as_u8()
            });
        });
    }
    group.finish();
}

/// Benchmark: G1 multi-scalar multiplication — one double-and-add scalar
/// multiplication per term versus the bounded-stack Pippenger bucket method
/// (4-bit windows below 96 terms, 5-bit windows from 96 terms on).
fn bench_g1_msm(c: &mut Criterion) {
    let mut group = c.benchmark_group("G1Msm");
    group.sample_size(10);
    for n in [16usize, 64, 128] {
        let points = {
            let proj = projective_points(n);
            let mut out = vec![infinity(); n];
            batch_to_affine(&proj, &mut out).unwrap();
            out
        };
        let scalars = pseudo_scalars(n);

        group.bench_with_input(
            BenchmarkId::new("naive_scalar_mul", n),
            &(&points, &scalars),
            |b, (pts, sc)| {
                b.iter(|| {
                    let mut acc = G1Projective::identity();
                    for (p, s) in black_box(pts).iter().zip(black_box(sc).iter()) {
                        acc = acc.add(&Bn254::g1_scalar_mul(G1Projective::from(*p), *s));
                    }
                    acc
                });
            },
        );

        group.bench_with_input(
            BenchmarkId::new("pippenger", n),
            &(&points, &scalars),
            |b, (pts, sc)| {
                b.iter(|| g1_msm_pippenger(black_box(pts), black_box(sc)).unwrap());
            },
        );
    }
    group.finish();
}

/// Benchmark: Radix-2 Cooley-Tukey NTT and INTT for `n = 2^8` and `n = 2^10`.
fn bench_ntt(c: &mut Criterion) {
    use soroban_zk_core::{intt_in_place, ntt_in_place, primitive_root_of_unity};

    let mut group = c.benchmark_group("Ntt");
    group.sample_size(10);
    for n in [256usize, 1024] {
        let omega = primitive_root_of_unity(n).unwrap();
        let base = pseudo_scalars(n);

        group.bench_with_input(BenchmarkId::new("NttForward", n), &base, |b, input| {
            let mut buf = input.clone();
            b.iter(|| {
                buf.copy_from_slice(input);
                ntt_in_place(black_box(&mut buf), black_box(omega)).unwrap();
                buf[0]
            });
        });

        group.bench_with_input(BenchmarkId::new("NttInverse", n), &base, |b, input| {
            let mut buf = input.clone();
            b.iter(|| {
                buf.copy_from_slice(input);
                intt_in_place(black_box(&mut buf), black_box(omega)).unwrap();
                buf[0]
            });
        });
    }
    group.finish();
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
    bench_kzg_commit,
    bench_batch_to_affine,
    bench_g1_msm,
    bench_ntt,
);
criterion_main!(benches);
