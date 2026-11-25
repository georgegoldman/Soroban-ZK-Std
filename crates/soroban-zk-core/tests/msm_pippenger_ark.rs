//! Issue #584 — differential tests of the bounded-stack Pippenger MSM and the
//! Montgomery batch affine normalisation against `ark_bn254`.
//!
//! Every result is computed independently with arkworks (naive per-term
//! multiplication + group addition) and compared bit-for-bit with
//! `soroban-zk-core`. Inputs are deterministic (SplitMix64) so a failure is
//! reproducible from the printed size/case alone.

use ark_bn254::{Fq as ArkFq, Fr as ArkFr, G1Affine as ArkAffine, G1Projective as ArkG1};
use ark_ec::{AffineRepr, CurveGroup, PrimeGroup};
use ark_ff::{BigInteger, PrimeField, Zero};
use ethnum::u256;
use soroban_zk_core::{
    batch_to_affine, g1_msm_pippenger, kzg_commit, Bn254, DensePolynomial, G1Affine, G1Projective,
    ZkError,
};

/// Sizes mandated by the issue's acceptance criteria.
const SIZES: [usize; 5] = [1, 2, 16, 64, 128];

const INFINITY: G1Affine = G1Affine {
    x: u256::from_words(0, 0),
    y: u256::from_words(0, 0),
};

// ----------------------------------------------------------------------------
// Deterministic PRNG and ark <-> core conversions
// ----------------------------------------------------------------------------

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Uniform 256-bit value, deliberately not reduced modulo `r`.
    fn raw_u256(&mut self) -> u256 {
        let hi = ((self.next() as u128) << 64) | self.next() as u128;
        let lo = ((self.next() as u128) << 64) | self.next() as u128;
        u256::from_words(hi, lo)
    }

    fn scalar(&mut self) -> u256 {
        self.raw_u256() % Bn254::FR_MODULUS
    }
}

fn ark_fr(x: u256) -> ArkFr {
    ArkFr::from_be_bytes_mod_order(&x.to_be_bytes())
}

fn ark_fq_to_u256(x: ArkFq) -> u256 {
    let bytes = x.into_bigint().to_bytes_be();
    let arr: [u8; 32] = bytes.try_into().expect("BN254 Fq is 32 bytes");
    u256::from_be_bytes(arr)
}

/// ark affine -> core affine, with infinity encoded as `(0, 0)`.
fn to_core_affine(p: ArkAffine) -> G1Affine {
    match p.xy() {
        Some((x, y)) => G1Affine {
            x: ark_fq_to_u256(x),
            y: ark_fq_to_u256(y),
        },
        None => INFINITY,
    }
}

/// ark Jacobian projective -> core projective (same `(X/Z², Y/Z³)` convention).
fn to_core_projective(p: &ArkG1) -> G1Projective {
    G1Projective {
        x: ark_fq_to_u256(p.x),
        y: ark_fq_to_u256(p.y),
        z: ark_fq_to_u256(p.z),
    }
}

/// `n` random points `k_i * G` (as ark affine and core affine).
fn random_points(rng: &mut Rng, n: usize) -> (Vec<ArkAffine>, Vec<G1Affine>) {
    let ark: Vec<ArkAffine> = (0..n)
        .map(|_| (ArkG1::generator() * ark_fr(rng.scalar())).into_affine())
        .collect();
    let core = ark.iter().map(|p| to_core_affine(*p)).collect();
    (ark, core)
}

fn random_scalars(rng: &mut Rng, n: usize) -> Vec<u256> {
    (0..n).map(|_| rng.scalar()).collect()
}

/// Reference MSM using only arkworks arithmetic.
fn ark_msm(points: &[ArkAffine], scalars: &[u256]) -> G1Affine {
    let mut acc = ArkG1::zero();
    for (p, s) in points.iter().zip(scalars) {
        acc += p.mul_bigint(ark_fr(*s).into_bigint());
    }
    to_core_affine(acc.into_affine())
}

/// Runs the core MSM and normalises through `batch_to_affine` (exercising both
/// new routines end to end).
fn core_msm(points: &[G1Affine], scalars: &[u256]) -> G1Affine {
    let proj = g1_msm_pippenger(points, scalars).expect("equal lengths");
    let mut out = [INFINITY];
    batch_to_affine(&[proj], &mut out).expect("1 == 1");
    out[0]
}

fn check(case: &str, ark_points: &[ArkAffine], points: &[G1Affine], scalars: &[u256]) {
    assert_eq!(
        core_msm(points, scalars),
        ark_msm(ark_points, scalars),
        "{case}: n={}",
        points.len()
    );
}

// ----------------------------------------------------------------------------
// g1_msm_pippenger vs ark_bn254
// ----------------------------------------------------------------------------

#[test]
#[cfg_attr(miri, ignore)]
fn msm_random_scalars_and_points() {
    let mut rng = Rng(584_001);
    for n in SIZES {
        let (ap, cp) = random_points(&mut rng, n);
        let sc = random_scalars(&mut rng, n);
        check("random", &ap, &cp, &sc);
    }
}

#[test]
#[cfg_attr(miri, ignore)]
fn msm_with_zero_scalars() {
    let mut rng = Rng(584_002);
    for n in SIZES {
        let (ap, cp) = random_points(&mut rng, n);

        // Every third scalar is zero.
        let mut sc = random_scalars(&mut rng, n);
        for s in sc.iter_mut().step_by(3) {
            *s = u256::from(0u8);
        }
        check("every-third-zero", &ap, &cp, &sc);

        // Only the last scalar is non-zero.
        let mut sc = vec![u256::from(0u8); n];
        sc[n - 1] = rng.scalar();
        check("single-nonzero", &ap, &cp, &sc);

        // All zero => identity (affine infinity).
        let sc = vec![u256::from(0u8); n];
        check("all-zero", &ap, &cp, &sc);
        assert_eq!(core_msm(&cp, &sc), INFINITY);
    }
}

#[test]
#[cfg_attr(miri, ignore)]
fn msm_with_duplicate_points() {
    let mut rng = Rng(584_003);
    for n in SIZES {
        let (base_ark, base_core) = random_points(&mut rng, 3);

        // Few distinct points repeated across the vector.
        let ap: Vec<ArkAffine> = (0..n).map(|i| base_ark[i % 3]).collect();
        let cp: Vec<G1Affine> = (0..n).map(|i| base_core[i % 3]).collect();
        let sc = random_scalars(&mut rng, n);
        check("duplicates", &ap, &cp, &sc);

        // The very same point and scalar everywhere: result is n * (s * P).
        let s = rng.scalar();
        let ap: Vec<ArkAffine> = vec![base_ark[0]; n];
        let cp: Vec<G1Affine> = vec![base_core[0]; n];
        check("identical-terms", &ap, &cp, &vec![s; n]);

        // P*s and (-P)*s cancel exactly.
        if n >= 2 {
            let neg = G1Affine {
                x: base_core[0].x,
                y: Bn254::sub_fq(u256::from(0u8), base_core[0].y),
            };
            let mut cp = vec![base_core[0]; n];
            let mut ap = vec![base_ark[0]; n];
            for i in (1..n).step_by(2) {
                cp[i] = neg;
                ap[i] = -base_ark[0];
            }
            check("inverse-pairs", &ap, &cp, &vec![s; n]);
        }
    }
}

#[test]
#[cfg_attr(miri, ignore)]
fn msm_boundary_scalars() {
    let mut rng = Rng(584_004);
    let r_minus_1 = Bn254::FR_MODULUS - u256::from(1u8);
    for n in SIZES {
        let (ap, cp) = random_points(&mut rng, n);
        let special = [
            u256::from(1u8),
            u256::from(2u8),
            r_minus_1,
            Bn254::FR_MODULUS,                   // == 0 (mod r)
            Bn254::FR_MODULUS + u256::from(1u8), // == 1 (mod r)
            u256::from_words(0, 1u128 << 127),   // straddles the 128-bit word
            u256::from_words(1u128 << 125, 0),   // high word only
            u256::MAX,                           // far above r
        ];
        let sc: Vec<u256> = (0..n).map(|i| special[i % special.len()]).collect();
        check("boundary", &ap, &cp, &sc);

        // Unreduced random 256-bit scalars (most are >= r).
        let sc: Vec<u256> = (0..n).map(|_| rng.raw_u256()).collect();
        check("unreduced", &ap, &cp, &sc);
    }
}

#[test]
#[cfg_attr(miri, ignore)]
fn msm_with_points_at_infinity() {
    let mut rng = Rng(584_005);
    for n in SIZES {
        let (mut ap, mut cp) = random_points(&mut rng, n);
        for i in (0..n).step_by(4) {
            ap[i] = ArkAffine::zero();
            cp[i] = INFINITY;
        }
        let sc = random_scalars(&mut rng, n);
        check("infinity-points", &ap, &cp, &sc);
    }
}

#[test]
fn msm_empty_is_identity() {
    let proj = g1_msm_pippenger(&[], &[]).unwrap();
    assert!(proj.is_identity());
}

#[test]
fn msm_rejects_length_mismatch() {
    let g = G1Affine {
        x: u256::from(1u8),
        y: u256::from(2u8),
    };
    let one = u256::from(1u8);
    assert_eq!(
        g1_msm_pippenger(&[g, g, g], &[one, one]),
        Err(ZkError::InvalidInput)
    );
    assert_eq!(g1_msm_pippenger(&[g], &[]), Err(ZkError::InvalidInput));
    assert_eq!(g1_msm_pippenger(&[], &[one]), Err(ZkError::InvalidInput));
}

// ----------------------------------------------------------------------------
// batch_to_affine vs ark_bn254
// ----------------------------------------------------------------------------

/// Random Jacobian points with a non-trivial `Z` (sum of two multiples).
fn random_jacobian(rng: &mut Rng, n: usize) -> Vec<ArkG1> {
    (0..n)
        .map(|_| {
            let a = ArkG1::generator() * ark_fr(rng.scalar());
            let b = ArkG1::generator() * ark_fr(rng.scalar());
            a + b
        })
        .collect()
}

fn check_batch(case: &str, ark_proj: &[ArkG1]) {
    let proj: Vec<G1Projective> = ark_proj.iter().map(to_core_projective).collect();
    let mut out = vec![INFINITY; proj.len()];
    batch_to_affine(&proj, &mut out).expect("equal lengths");
    for (i, (a, got)) in ark_proj.iter().zip(&out).enumerate() {
        assert_eq!(
            *got,
            to_core_affine(a.into_affine()),
            "{case}: n={} index={i}",
            proj.len()
        );
    }
}

#[test]
#[cfg_attr(miri, ignore)]
fn batch_to_affine_matches_ark() {
    let mut rng = Rng(584_101);
    for n in SIZES {
        check_batch("random", &random_jacobian(&mut rng, n));
    }
}

#[test]
#[cfg_attr(miri, ignore)]
fn batch_to_affine_identity_points_at_every_position() {
    let mut rng = Rng(584_102);
    for n in SIZES {
        let base = random_jacobian(&mut rng, n);

        // First, last, and every third element is the identity.
        let mut v = base.clone();
        v[0] = ArkG1::zero();
        check_batch("identity-first", &v);

        let mut v = base.clone();
        v[n - 1] = ArkG1::zero();
        check_batch("identity-last", &v);

        let mut v = base.clone();
        for p in v.iter_mut().step_by(3) {
            *p = ArkG1::zero();
        }
        check_batch("identity-every-third", &v);

        // Adjacent identities in the middle.
        if n >= 4 {
            let mut v = base.clone();
            v[n / 2] = ArkG1::zero();
            v[n / 2 - 1] = ArkG1::zero();
            check_batch("identity-adjacent", &v);
        }

        // Every point is the identity.
        check_batch("all-identity", &vec![ArkG1::zero(); n]);
    }
}

#[test]
fn batch_to_affine_empty_and_mismatch() {
    let mut empty: [G1Affine; 0] = [];
    assert_eq!(batch_to_affine(&[], &mut empty), Ok(()));

    let proj = [G1Projective::identity(); 3];
    let mut short = [INFINITY; 2];
    assert_eq!(
        batch_to_affine(&proj, &mut short),
        Err(ZkError::InvalidInput)
    );
    let mut long = [INFINITY; 4];
    assert_eq!(
        batch_to_affine(&proj, &mut long),
        Err(ZkError::InvalidInput)
    );
}

// ----------------------------------------------------------------------------
// kzg_commit vs ark_bn254
// ----------------------------------------------------------------------------

#[test]
#[cfg_attr(miri, ignore)]
fn kzg_commit_matches_ark() {
    let mut rng = Rng(584_201);
    let (srs_ark, srs) = random_points(&mut rng, 128);
    for n in SIZES {
        let mut coeffs = random_scalars(&mut rng, n);
        // Interior zero coefficients (trailing zeros are trimmed by the type).
        for c in coeffs.iter_mut().skip(1).step_by(4) {
            *c = u256::from(0u8);
        }
        let poly = DensePolynomial::<128>::from_coefficients_slice(&coeffs).unwrap();
        let got = kzg_commit(&poly, &srs).unwrap();
        assert_eq!(
            got,
            ark_msm(&srs_ark[..poly.len], poly.coeffs()),
            "kzg_commit n={n}"
        );
    }
}

#[test]
fn kzg_commit_rejects_polynomial_longer_than_srs() {
    let mut rng = Rng(584_202);
    let (_, srs) = random_points(&mut rng, 4);
    let coeffs = vec![u256::from(1u8); 8];
    let poly = DensePolynomial::<8>::from_coefficients_slice(&coeffs).unwrap();
    assert_eq!(kzg_commit(&poly, &srs), Err(ZkError::InvalidInput));
}

#[test]
fn kzg_commit_zero_polynomial_is_infinity() {
    let mut rng = Rng(584_203);
    let (_, srs) = random_points(&mut rng, 4);
    let poly = DensePolynomial::<8>::zero();
    assert_eq!(kzg_commit(&poly, &srs), Ok(INFINITY));
}
