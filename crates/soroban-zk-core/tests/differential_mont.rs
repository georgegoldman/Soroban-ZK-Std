//! Issue #575 — differential tests for the persistent Montgomery domain.
//!
//! * `FrMont` / `FqMont` arithmetic is checked bit-for-bit against arkworks
//!   (ark-bn254 0.6) on random values and on the boundaries `0, 1, N − 1`.
//! * Non-canonical inputs are rejected by `from_u256` (no panic) and
//!   `inv(0)` returns `None`.
//! * The legacy `u256` `Bn254` API, now built on top of the Montgomery types,
//!   is checked against `Bn254::mul_mod_legacy` (the untouched reference
//!   multiplication) and arkworks, including on non-canonical inputs.
//! * `G1Projective` / `G2Projective` `double`, `add` and scalar multiplication
//!   are checked coordinate-for-coordinate against a verbatim copy of the
//!   pre-#575 implementation, so projective (not just affine) outputs are
//!   unchanged.

use ark_bn254::{Fq as ArkFq, Fr as ArkFr, G1Projective as ArkG1};
use ark_ec::{CurveGroup, PrimeGroup};
use ark_ff::{BigInteger, Field, PrimeField};
use ethnum::u256;
use proptest::prelude::*;
use soroban_zk_core::{Bn254, FqMont, FrMont, G1Projective, G2Projective};

fn ark_fr(x: u256) -> ArkFr {
    ArkFr::from_be_bytes_mod_order(&x.to_be_bytes())
}
fn ark_fq(x: u256) -> ArkFq {
    ArkFq::from_be_bytes_mod_order(&x.to_be_bytes())
}
fn from_ark<B: PrimeField>(x: B) -> u256 {
    let bytes = x.into_bigint().to_bytes_be();
    let arr: [u8; 32] = bytes.try_into().expect("32 bytes");
    u256::from_be_bytes(arr)
}

fn r() -> u256 {
    Bn254::FR_MODULUS
}
fn q() -> u256 {
    Bn254::FQ_MODULUS
}

/// Boundary values reduced into the field with modulus `n`.
fn boundaries(n: u256) -> [u256; 6] {
    let one = u256::ONE;
    [
        u256::ZERO,
        one,
        u256::from(2u8),
        n - one,
        n - u256::from(2u8),
        n >> 1u32,
    ]
}

// ---------------------------------------------------------------------------
// FrMont / FqMont vs arkworks
// ---------------------------------------------------------------------------

macro_rules! check_field_ops {
    ($T:ty, $ark:ident, $a:expr, $b:expr) => {{
        let (a, b): (u256, u256) = ($a, $b);
        let ma = <$T>::from_u256(a).expect("canonical");
        let mb = <$T>::from_u256(b).expect("canonical");
        let (aa, ab) = ($ark(a), $ark(b));
        assert_eq!(ma.to_u256(), a, "round trip");
        assert_eq!(ma.add(&mb).to_u256(), from_ark(aa + ab), "add");
        assert_eq!(ma.sub(&mb).to_u256(), from_ark(aa - ab), "sub");
        assert_eq!(ma.mul(&mb).to_u256(), from_ark(aa * ab), "mul");
        assert_eq!(
            (ma * mb + ma - mb).to_u256(),
            from_ark(aa * ab + aa - ab),
            "ops"
        );
        assert_eq!(ma.square().to_u256(), from_ark(aa.square()), "square");
        assert_eq!(ma.neg().to_u256(), from_ark(-aa), "neg");
        assert_eq!((-ma).to_u256(), from_ark(-aa), "neg op");
        assert_eq!(ma.double().to_u256(), from_ark(aa + aa), "double");
        match aa.inverse() {
            Some(inv) => assert_eq!(ma.inv().map(|x| x.to_u256()), Some(from_ark(inv)), "inv"),
            None => assert_eq!(ma.inv(), None, "inv(0)"),
        }
        let e = b;
        assert_eq!(
            ma.pow_vartime(e).to_u256(),
            from_ark(aa.pow(ark_ff::BigInt::<4>::new(e_limbs(e)))),
            "pow"
        );
    }};
}

fn e_limbs(e: u256) -> [u64; 4] {
    let (hi, lo) = e.into_words();
    [lo as u64, (lo >> 64) as u64, hi as u64, (hi >> 64) as u64]
}

#[test]
fn fr_mont_boundaries_match_arkworks() {
    for &a in &boundaries(r()) {
        for &b in &boundaries(r()) {
            check_field_ops!(FrMont, ark_fr, a, b);
        }
    }
}

#[test]
fn fq_mont_boundaries_match_arkworks() {
    for &a in &boundaries(q()) {
        for &b in &boundaries(q()) {
            check_field_ops!(FqMont, ark_fq, a, b);
        }
    }
}

#[test]
fn non_canonical_inputs_are_rejected_without_panic() {
    let one = u256::ONE;
    for v in [r(), r() + one, q(), u256::MAX] {
        assert_eq!(FrMont::from_u256(v), None);
    }
    for v in [q(), q() + one, u256::MAX] {
        assert_eq!(FqMont::from_u256(v), None);
    }
    // q − 1 is a valid Fq element but ≥ r.
    assert_eq!(FrMont::from_u256(q() - one), None);
    assert!(FqMont::from_u256(q() - one).is_some());
    assert!(FrMont::from_u256(r() - one).is_some());
}

#[test]
fn inv_of_zero_is_none() {
    assert_eq!(FrMont::ZERO.inv(), None);
    assert_eq!(FqMont::ZERO.inv(), None);
    assert_eq!(FrMont::from_u256(u256::ZERO).and_then(|z| z.inv()), None);
}

#[test]
fn constants() {
    assert_eq!(FrMont::ONE.to_u256(), u256::ONE);
    assert_eq!(FqMont::ONE.to_u256(), u256::ONE);
    assert_eq!(FrMont::ZERO.to_u256(), u256::ZERO);
    assert_eq!(FqMont::ZERO.to_u256(), u256::ZERO);
    assert_eq!(FrMont::default(), FrMont::ZERO);
    // R2 represents R mod N; R mod N == 2^256 mod N.
    assert_eq!(
        FrMont::R2.to_u256(),
        from_ark(ark_fr(u256::MAX) + ArkFr::from(1u8))
    );
    assert_eq!(
        FqMont::R2.to_u256(),
        from_ark(ark_fq(u256::MAX) + ArkFq::from(1u8))
    );
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn fr_mont_random_matches_arkworks(a in any::<[u8; 32]>(), b in any::<[u8; 32]>()) {
        let a = u256::from_be_bytes(a) % r();
        let b = u256::from_be_bytes(b) % r();
        check_field_ops!(FrMont, ark_fr, a, b);
    }

    #[test]
    fn fq_mont_random_matches_arkworks(a in any::<[u8; 32]>(), b in any::<[u8; 32]>()) {
        let a = u256::from_be_bytes(a) % q();
        let b = u256::from_be_bytes(b) % q();
        check_field_ops!(FqMont, ark_fq, a, b);
    }

    #[test]
    fn mont_round_trip_and_reduced_ctor(a in any::<[u8; 32]>()) {
        let x = u256::from_be_bytes(a);
        prop_assert_eq!(FrMont::from_u256_reduced(x).to_u256(), x % r());
        prop_assert_eq!(FqMont::from_u256_reduced(x).to_u256(), x % q());
        match FrMont::from_u256(x) {
            Some(m) => { prop_assert!(x < r()); prop_assert_eq!(m.to_u256(), x); }
            None => prop_assert!(x >= r()),
        }
        match FqMont::from_u256(x) {
            Some(m) => {
                prop_assert!(x < q());
                prop_assert_eq!(m.to_u256(), x);
                prop_assert_eq!(FqMont::from_raw_limbs(m.to_raw_limbs()), Some(m));
            }
            None => prop_assert!(x >= q()),
        }
    }

    // -----------------------------------------------------------------------
    // Legacy u256 API: identical results, including non-canonical inputs.
    // -----------------------------------------------------------------------

    #[test]
    fn bn254_mul_unchanged_on_any_u256(a in any::<[u8; 32]>(), b in any::<[u8; 32]>()) {
        let (a, b) = (u256::from_be_bytes(a), u256::from_be_bytes(b));
        // mul_mod_legacy is the untouched pre-Montgomery reference; it
        // expects reduced inputs, exactly as the old `mul_mod` supplied them.
        prop_assert_eq!(Bn254::mul(a, b), Bn254::mul_mod_legacy(a % r(), b % r()));
        prop_assert_eq!(Bn254::mul_fq(a, b), from_ark(ark_fq(a) * ark_fq(b)));
        prop_assert_eq!(Bn254::mul(a, b), from_ark(ark_fr(a) * ark_fr(b)));
    }

    #[test]
    fn bn254_pow_invert_unchanged(a in any::<[u8; 32]>(), e in any::<[u8; 32]>()) {
        let (a, e) = (u256::from_be_bytes(a), u256::from_be_bytes(e));
        let el = ark_ff::BigInt::<4>::new(e_limbs(e));
        prop_assert_eq!(Bn254::pow(a, e), from_ark(ark_fr(a).pow(el)));
        prop_assert_eq!(Bn254::pow_fq(a, e), from_ark(ark_fq(a).pow(el)));
        let inv_r = ark_fr(a).inverse().map(from_ark).unwrap_or(u256::ZERO);
        let inv_q = ark_fq(a).inverse().map(from_ark).unwrap_or(u256::ZERO);
        prop_assert_eq!(Bn254::invert(a), inv_r);
        prop_assert_eq!(Bn254::invert_fq(a), inv_q);
    }

    #[test]
    fn bn254_montgomery_helpers_unchanged(a in any::<[u8; 32]>()) {
        let a = u256::from_be_bytes(a);
        // aR mod N == a · (2^256 mod N) mod N
        let r_fr = ark_fr(u256::MAX) + ArkFr::from(1u8);
        let r_fq = ark_fq(u256::MAX) + ArkFq::from(1u8);
        prop_assert_eq!(Bn254::to_montgomery(a), from_ark(ark_fr(a) * r_fr));
        prop_assert_eq!(Bn254::to_montgomery_fq(a), from_ark(ark_fq(a) * r_fq));
        prop_assert_eq!(Bn254::from_montgomery(a), from_ark(ark_fr(a) * r_fr.inverse().unwrap()));
        prop_assert_eq!(Bn254::from_montgomery_fq(a), from_ark(ark_fq(a) * r_fq.inverse().unwrap()));
        prop_assert_eq!(Bn254::from_montgomery(Bn254::to_montgomery(a)), a % r());
    }
}

#[test]
fn bn254_boundaries_unchanged() {
    let one = u256::ONE;
    let vals = [
        u256::ZERO,
        one,
        r() - one,
        r(),
        r() + one,
        q() - one,
        q(),
        u256::MAX,
    ];
    for &a in &vals {
        for &b in &vals {
            assert_eq!(Bn254::mul(a, b), Bn254::mul_mod_legacy(a % r(), b % r()));
            assert_eq!(Bn254::mul_fq(a, b), from_ark(ark_fq(a) * ark_fq(b)));
        }
        assert_eq!(Bn254::pow(a, u256::ZERO), one);
        assert_eq!(Bn254::pow_fq(a, u256::ZERO), one);
    }
    assert_eq!(Bn254::invert(u256::ZERO), u256::ZERO);
    assert_eq!(Bn254::invert(r()), u256::ZERO);
    assert_eq!(Bn254::invert_fq(u256::ZERO), u256::ZERO);
}

// ---------------------------------------------------------------------------
// Projective point arithmetic: verbatim pre-#575 reference implementation.
// ---------------------------------------------------------------------------

mod legacy {
    use super::*;

    pub fn g1_double(p: &G1Projective) -> G1Projective {
        if p.z == u256::from(0u8) {
            return *p;
        }
        let xx = Bn254::mul_fq(p.x, p.x);
        let yy = Bn254::mul_fq(p.y, p.y);
        let yyyy = Bn254::mul_fq(yy, yy);
        let xy2 = Bn254::mul_fq(p.x, yy);
        let s = Bn254::mul_fq(xy2, u256::from(4u8));
        let m = Bn254::mul_fq(xx, u256::from(3u8));
        let m2 = Bn254::mul_fq(m, m);
        let s2 = Bn254::add_fq(s, s);
        let t = Bn254::sub_fq(m2, s2);
        let s_minus_t = Bn254::sub_fq(s, t);
        let m_times_sm_t = Bn254::mul_fq(m, s_minus_t);
        let yyyy8 = Bn254::mul_fq(yyyy, u256::from(8u8));
        let y3 = Bn254::sub_fq(m_times_sm_t, yyyy8);
        let yz = Bn254::mul_fq(p.y, p.z);
        let z3 = Bn254::add_fq(yz, yz);
        G1Projective { x: t, y: y3, z: z3 }
    }

    pub fn g1_add(a: &G1Projective, b: &G1Projective) -> G1Projective {
        if a.z == u256::from(0u8) {
            return *b;
        }
        if b.z == u256::from(0u8) {
            return *a;
        }
        let z1z1 = Bn254::mul_fq(a.z, a.z);
        let z2z2 = Bn254::mul_fq(b.z, b.z);
        let u1 = Bn254::mul_fq(a.x, z2z2);
        let u2 = Bn254::mul_fq(b.x, z1z1);
        let s1 = Bn254::mul_fq(a.y, Bn254::mul_fq(b.z, z2z2));
        let s2 = Bn254::mul_fq(b.y, Bn254::mul_fq(a.z, z1z1));
        if u1 == u2 {
            return if s1 == s2 {
                g1_double(a)
            } else {
                G1Projective::identity()
            };
        }
        let h = Bn254::sub_fq(u2, u1);
        let r = Bn254::sub_fq(s2, s1);
        let h2 = Bn254::mul_fq(h, h);
        let h3 = Bn254::mul_fq(h2, h);
        let u1_h2 = Bn254::mul_fq(u1, h2);
        let r2 = Bn254::mul_fq(r, r);
        let x3 = Bn254::sub_fq(Bn254::sub_fq(r2, h3), Bn254::add_fq(u1_h2, u1_h2));
        let y3 = Bn254::sub_fq(
            Bn254::mul_fq(r, Bn254::sub_fq(u1_h2, x3)),
            Bn254::mul_fq(s1, h3),
        );
        let z3 = Bn254::mul_fq(h, Bn254::mul_fq(a.z, b.z));
        G1Projective {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    pub fn g1_scalar_mul(point: G1Projective, scalar: u256) -> G1Projective {
        let scalar = scalar % Bn254::FR_MODULUS;
        if scalar == 0 {
            return G1Projective::identity();
        }
        if scalar == 1 {
            return point;
        }
        let mut result = G1Projective::identity();
        for i in (0..254u32).rev() {
            result = g1_double(&result);
            let added = g1_add(&result, &point);
            let bit: u128 = ((scalar >> i) & u256::ONE).as_u128();
            result = G1Projective::ct_select(bit, added, result);
        }
        result
    }

    type F2 = (u256, u256);
    fn c(v: u8) -> F2 {
        (u256::from(v), u256::ZERO)
    }

    pub fn g2_double(p: &G2Projective) -> G2Projective {
        if p.is_identity() {
            return *p;
        }
        let xx = Bn254::fq2_sq(p.x);
        let yy = Bn254::fq2_sq(p.y);
        let yyyy = Bn254::fq2_sq(yy);
        let s = Bn254::fq2_mul(Bn254::fq2_mul(p.x, yy), c(4));
        let m = Bn254::fq2_mul(xx, c(3));
        let t = Bn254::fq2_sub(Bn254::fq2_sq(m), Bn254::fq2_add(s, s));
        let y3 = Bn254::fq2_sub(
            Bn254::fq2_mul(m, Bn254::fq2_sub(s, t)),
            Bn254::fq2_mul(yyyy, c(8)),
        );
        let yz = Bn254::fq2_mul(p.y, p.z);
        G2Projective {
            x: t,
            y: y3,
            z: Bn254::fq2_add(yz, yz),
        }
    }

    pub fn g2_add(a: &G2Projective, b: &G2Projective) -> G2Projective {
        if a.is_identity() {
            return *b;
        }
        if b.is_identity() {
            return *a;
        }
        let z1z1 = Bn254::fq2_sq(a.z);
        let z2z2 = Bn254::fq2_sq(b.z);
        let u1 = Bn254::fq2_mul(a.x, z2z2);
        let u2 = Bn254::fq2_mul(b.x, z1z1);
        let s1 = Bn254::fq2_mul(a.y, Bn254::fq2_mul(b.z, z2z2));
        let s2 = Bn254::fq2_mul(b.y, Bn254::fq2_mul(a.z, z1z1));
        if u1 == u2 {
            return if s1 == s2 {
                g2_double(a)
            } else {
                G2Projective::identity()
            };
        }
        let h = Bn254::fq2_sub(u2, u1);
        let r = Bn254::fq2_sub(s2, s1);
        let h2 = Bn254::fq2_sq(h);
        let h3 = Bn254::fq2_mul(h2, h);
        let u1_h2 = Bn254::fq2_mul(u1, h2);
        let x3 = Bn254::fq2_sub(
            Bn254::fq2_sub(Bn254::fq2_sq(r), h3),
            Bn254::fq2_add(u1_h2, u1_h2),
        );
        let y3 = Bn254::fq2_sub(
            Bn254::fq2_mul(r, Bn254::fq2_sub(u1_h2, x3)),
            Bn254::fq2_mul(s1, h3),
        );
        let z3 = Bn254::fq2_mul(h, Bn254::fq2_mul(a.z, b.z));
        G2Projective {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    pub fn g2_scalar_mul(point: G2Projective, scalar: u256) -> G2Projective {
        let scalar = scalar % Bn254::FR_MODULUS;
        if scalar == 0 {
            return G2Projective::identity();
        }
        if scalar == 1 {
            return point;
        }
        let mut result = G2Projective::identity();
        for i in (0..254u32).rev() {
            result = g2_double(&result);
            let added = g2_add(&result, &point);
            let bit: u128 = ((scalar >> i) & u256::ONE).as_u128();
            result = G2Projective::ct_select(bit, added, result);
        }
        result
    }
}

fn g1_gen() -> G1Projective {
    G1Projective {
        x: u256::ONE,
        y: u256::from(2u8),
        z: u256::ONE,
    }
}

fn g2_gen() -> G2Projective {
    let x0 =
        u256::from_str_hex("0x1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed")
            .expect("hex");
    let x1 =
        u256::from_str_hex("0x198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2")
            .expect("hex");
    let y0 =
        u256::from_str_hex("0x12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa")
            .expect("hex");
    let y1 =
        u256::from_str_hex("0x090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b")
            .expect("hex");
    G2Projective {
        x: (x0, x1),
        y: (y0, y1),
        z: (u256::ONE, u256::ZERO),
    }
}

#[test]
fn g1_double_add_identical_to_legacy() {
    let g = g1_gen();
    let id = G1Projective::identity();
    let g2 = g.double();
    assert_eq!(g2, legacy::g1_double(&g));
    assert_eq!(g2.add(&g), legacy::g1_add(&g2, &g));
    assert_eq!(g.add(&g), legacy::g1_add(&g, &g)); // P == Q → double
    let neg = G1Projective {
        x: g.x,
        y: q() - g.y,
        z: g.z,
    };
    assert_eq!(g.add(&neg), legacy::g1_add(&g, &neg)); // P == −Q → identity
    assert_eq!(g.add(&id), g);
    assert_eq!(id.add(&g), g);
    assert_eq!(id.double(), legacy::g1_double(&id));
    // Non-canonical encodings still behave exactly like before.
    let weird = G1Projective {
        x: g.x + q(),
        y: g.y,
        z: q(),
    };
    assert_eq!(weird.double(), legacy::g1_double(&weird));
    assert_eq!(weird.add(&g), legacy::g1_add(&weird, &g));
    assert_eq!(
        Bn254::g1_scalar_mul(weird, u256::from(5u8)),
        legacy::g1_scalar_mul(weird, u256::from(5u8))
    );
}

#[test]
#[cfg_attr(miri, ignore)]
fn g2_double_add_identical_to_legacy() {
    let g = g2_gen();
    let g2 = g.double();
    assert_eq!(g2, legacy::g2_double(&g));
    assert_eq!(g2.add(&g), legacy::g2_add(&g2, &g));
    assert_eq!(g.add(&g), legacy::g2_add(&g, &g));
    assert_eq!(G2Projective::identity().double(), G2Projective::identity());
    let k = u256::from(0xdead_beef_u64);
    assert_eq!(Bn254::g2_scalar_mul(g, k), legacy::g2_scalar_mul(g, k));
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(12))]

    #[test]
    #[cfg_attr(miri, ignore)]
    fn g1_scalar_mul_identical_to_legacy(s in any::<[u8; 32]>()) {
        let s = u256::from_be_bytes(s);
        let ours = Bn254::g1_scalar_mul(g1_gen(), s);
        prop_assert_eq!(ours, legacy::g1_scalar_mul(g1_gen(), s));
        // and against arkworks in affine form
        let aff = ours.to_affine();
        let ark = (ArkG1::generator() * ark_fr(s)).into_affine();
        if !ours.is_identity() {
            prop_assert_eq!(aff.x, from_ark(ark.x));
            prop_assert_eq!(aff.y, from_ark(ark.y));
        }
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn g2_scalar_mul_identical_to_legacy(s in any::<[u8; 32]>()) {
        let s = u256::from_be_bytes(s);
        prop_assert_eq!(Bn254::g2_scalar_mul(g2_gen(), s), legacy::g2_scalar_mul(g2_gen(), s));
    }
}
