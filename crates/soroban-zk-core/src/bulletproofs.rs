//! Bulletproofs-style 64-bit range proof verifier & batch validation.
//!
//! This module implements the Inner-Product Argument (IPA) at the core of
//! Bulletproofs and a 64-bit range-proof verification engine tailored for the
//! Soroban WASM runtime. All routines are `no_std`, allocation-free, and use
//! fixed-size arrays so the inner-product reduction scales strictly
//! logarithmically (`O(log n)`) without deep recursion.
//!
//! Generators are derived through a deterministic hash-to-curve so that no
//! discrete logarithm between the commitment base `G`, the blinding base `H`
//! and the vector generators `g`/`h` is known (soundness requirement).
//!
//! The Fiat-Shamir transcript uses a Poseidon2 sponge over BN254 Fr (t=3,
//! d=5, rate=2) as the challenge oracle, compatible with CAP-0075. The batch
//! weight oracle (`verify_batch`) uses SHA-256 for collision-resistant
//! per-proof weight derivation.

#![allow(clippy::needless_range_loop)]

use crate::{Bn254, G1Affine, G1Projective};
use ethnum::u256;
use sha2::{Digest, Sha256};

/// Bit-length of the proven range. Values `v` must satisfy `0 <= v < 2^NBITS`.
pub const NBITS: usize = 64;
/// Length of the bit/commitment vectors (`a_L`, `a_R`, `g`, `h`).
const N: usize = NBITS;
/// Number of inner-product recursion rounds: `log2(N)`.
const IP_ROUNDS: usize = 64usize.trailing_zeros() as usize;

/// `2^64` — the exclusive upper bound of the proven range.
pub const TWO64: u256 = u256::from_words(0u128, 0x10000000000000000u128);

/// The BN254 G1 generator used as the value base `G` (x = 1, y = 2).
const G_VALUE: G1Affine = G1Affine {
    x: u256::from_words(0, 1),
    y: u256::from_words(0, 2),
};

/// The identity/point-at-infinity in affine coordinates.
const IDENTITY: G1Affine = G1Affine {
    x: u256::from_words(0u128, 0u128),
    y: u256::from_words(0u128, 0u128),
};

// ===========================================================================
// Field & point helpers (WASM-friendly, allocation-free)
// ===========================================================================

#[inline(always)]
fn f_add(a: u256, b: u256) -> u256 {
    Bn254::add(a, b)
}
#[inline(always)]
fn f_sub(a: u256, b: u256) -> u256 {
    Bn254::sub(a, b)
}
#[inline(always)]
fn f_mul(a: u256, b: u256) -> u256 {
    Bn254::mul(a, b)
}
#[inline(always)]
fn f_inv(a: u256) -> u256 {
    Bn254::invert(a)
}

/// `acc + s * pt` in the G1 group (projective accumulation, no allocation).
#[inline(always)]
fn add_scaled(acc: G1Projective, pt: &G1Affine, s: u256) -> G1Projective {
    acc.add(&G1Projective::from(pt.scalar_mul(s)))
}

/// `s1 * p1 + s2 * p2`.
#[inline(always)]
fn lin_comb(p1: G1Affine, s1: u256, p2: G1Affine, s2: u256) -> G1Projective {
    G1Projective::from(p1.scalar_mul(s1)).add(&G1Projective::from(p2.scalar_mul(s2)))
}

/// Multi-scalar multiplication `sum_i scalars[i] * points[i]` (the core WASM
/// primitive used everywhere). Constant memory footprint, fixed length.
#[cfg(any(test, feature = "prover"))]
fn msm(points: &[G1Affine], scalars: &[u256]) -> G1Projective {
    let mut acc = G1Projective::identity();
    for i in 0..points.len() {
        acc = add_scaled(acc, &points[i], scalars[i]);
    }
    acc
}

/// Sum of a slice of points (all coefficients = 1).
fn sum_points(points: &[G1Affine]) -> G1Projective {
    let mut acc = G1Projective::identity();
    for p in points {
        acc = acc.add(&G1Projective::from(*p));
    }
    acc
}

/// Inner product of two equal-length vectors over the scalar field.
#[cfg(any(test, feature = "prover"))]
fn inner_prod(a: &[u256], b: &[u256]) -> u256 {
    let mut acc = u256::from(0u8);
    for i in 0..a.len() {
        acc = f_add(acc, f_mul(a[i], b[i]));
    }
    acc
}

/// Negate a projective point (`-P`).
fn neg_proj(p: G1Projective) -> G1Projective {
    let aff = p.to_affine();
    let ny = if aff.y == u256::from(0u8) {
        u256::from(0u8)
    } else {
        Bn254::sub_fq(u256::from(0u8), aff.y)
    };
    G1Projective::from(G1Affine { x: aff.x, y: ny })
}

// ===========================================================================
// Fiat-Shamir transcript (Poseidon2 sponge)
// ===========================================================================

use crate::poseidon2;

/// A Fiat-Shamir transcript backed by a Poseidon2 sponge over BN254 Fr.
struct Transcript {
    sponge: poseidon2::Poseidon2Sponge,
}

impl Transcript {
    fn new() -> Self {
        Self {
            sponge: poseidon2::Poseidon2Sponge::new(),
        }
    }

    #[allow(dead_code)]
    fn absorb_scalar(&mut self, s: u256) {
        self.sponge.absorb(&[s]);
    }

    fn absorb_point(&mut self, p: &G1Affine) {
        self.sponge.absorb(&[p.x, p.y]);
    }

    /// Produce the next challenge scalar in `[0, r)`.
    fn challenge(&mut self) -> u256 {
        self.sponge.squeeze()
    }
}

// ===========================================================================
// Hash-to-curve (try-and-increment) for sound generator derivation
// ===========================================================================

/// Modular exponentiation over the base field `Fq` (used for square roots).
fn pow_fq(mut base: u256, mut exp: u256) -> u256 {
    let mut res = u256::from(1u8);
    while exp > u256::from(0u8) {
        if exp & u256::from(1u8) != u256::from(0u8) {
            res = Bn254::mul_fq(res, base);
        }
        base = Bn254::mul_fq(base, base);
        exp >>= 1;
    }
    res
}

/// Returns `(x, y)` on the BN254 curve `y^2 = x^3 + 3` if `x` is a valid
/// x-coordinate with a quadratic-residue RHS, else `None`.
fn g1_from_x(x: u256) -> Option<G1Affine> {
    if x >= Bn254::FQ_MODULUS {
        return None;
    }
    let x3 = Bn254::mul_fq(Bn254::mul_fq(x, x), x);
    let rhs = Bn254::add_fq(x3, Bn254::G1_B);
    // BN254 Fq is 3 mod 4, so sqrt(a) = a^((q+1)/4).
    let exp = (Bn254::FQ_MODULUS + u256::from(1u8)) >> 2;
    let y = pow_fq(rhs, exp);
    if Bn254::mul_fq(y, y) != rhs {
        return None;
    }
    Some(G1Affine { x, y })
}

/// Deterministic hash of arbitrary bytes into `Fq` using Poseidon2.
fn hash_to_fq(bytes: &[u8]) -> u256 {
    poseidon2::hash_to_fq(bytes)
}

/// Try-and-increment hash-to-curve producing a fixed, sound G1 point.
fn hash_to_curve(seed: &[u8]) -> G1Affine {
    let mut x = hash_to_fq(seed);
    loop {
        if let Some(pt) = g1_from_x(x) {
            return pt;
        }
        x = Bn254::add_fq(x, u256::from(1u8));
    }
}

/// Deterministic per-index generator point derived from a tag byte + index.
fn gen_point(tag: u8, index: u32) -> G1Affine {
    let mut buf = [0u8; 5];
    buf[0] = tag;
    buf[1..5].copy_from_slice(&index.to_be_bytes());
    hash_to_curve(&buf)
}

// ===========================================================================
// Generators
// ===========================================================================

/// The public generator set required for range-proof proving & verification.
///
/// * `G` (value base) is the fixed BN254 generator.
/// * `h_blind` is the Pedersen blinding base, derived via hash-to-curve so its
///   discrete log relative to `G` is unknown.
/// * `g`, `h` are the vector commitment bases.
#[derive(Clone, Copy)]
pub struct Generators {
    pub g: [G1Affine; N],
    pub h: [G1Affine; N],
    pub h_blind: G1Affine,
}

impl Generators {
    /// Derive the full generator set deterministically (independent of any
    /// trusted setup).
    pub fn new() -> Self {
        let mut g = [IDENTITY; N];
        let mut h = [IDENTITY; N];
        for i in 0..N {
            g[i] = gen_point(b'g', i as u32);
            h[i] = gen_point(b'h', i as u32);
        }
        Self {
            g,
            h,
            h_blind: gen_point(b'H', 0),
        }
    }
}

impl Default for Generators {
    fn default() -> Self {
        Self::new()
    }
}

// ===========================================================================
// Proof structures
// ===========================================================================

/// Inner-product argument: `log2(N)` folding points plus the final scalars.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct InnerProductProof {
    pub l: [G1Affine; IP_ROUNDS],
    pub r: [G1Affine; IP_ROUNDS],
    pub a: u256,
    pub b: u256,
}

/// A 64-bit range proof for a single committed value `V = v*G + gamma*H`.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct RangeProof {
    /// Pedersen commitment to the value being proven in range.
    pub v: G1Affine,
    pub a: G1Affine,
    pub s: G1Affine,
    pub t1: G1Affine,
    pub t2: G1Affine,
    /// `tau_x` — blinding of the polynomial t-check.
    pub taux: u256,
    /// `mu` — blinding of the inner-product commitment `P`.
    pub mu: u256,
    /// `t_hat` — claimed evaluation `<l(x), r(x)>`.
    pub t_hat: u256,
    pub ip_proof: InnerProductProof,
}

// ===========================================================================
// Inner-product argument (recursion-free, O(log n))
// ===========================================================================

/// Proves `P = <a, g> + <b, h> + (a*b)*Q` by recursive folding.
#[cfg(any(test, feature = "prover"))]
fn ipa_prove(
    p0: G1Affine,
    g0: [G1Affine; N],
    h0: [G1Affine; N],
    a0: [u256; N],
    b0: [u256; N],
    q: &G1Affine,
) -> InnerProductProof {
    let mut g = g0;
    let mut h = h0;
    let mut a = a0;
    let mut b = b0;
    let mut p = G1Projective::from(p0);
    let mut l = [IDENTITY; IP_ROUNDS];
    let mut r = [IDENTITY; IP_ROUNDS];

    let mut tr = Transcript::new();
    tr.absorb_point(&p0);

    let mut n = N;
    let mut round = 0;
    while n > 1 {
        let half = n / 2;

        // Slices are only used to compute the round points; released before the
        // in-place fold below mutates `a`/`b`.
        let (lp, rp) = {
            let a_l = &a[0..half];
            let a_r = &a[half..n];
            let b_l = &b[0..half];
            let b_r = &b[half..n];
            let g_l = &g[0..half];
            let g_r = &g[half..n];
            let h_l = &h[0..half];
            let h_r = &h[half..n];

            let c_l = inner_prod(a_l, b_r);
            let c_r = inner_prod(a_r, b_l);

            let mut l_pt = msm(g_r, a_l);
            l_pt = l_pt.add(&msm(h_l, b_r));
            l_pt = add_scaled(l_pt, q, c_l);

            let mut r_pt = msm(g_l, a_r);
            r_pt = r_pt.add(&msm(h_r, b_l));
            r_pt = add_scaled(r_pt, q, c_r);

            (l_pt.to_affine(), r_pt.to_affine())
        };

        l[round] = lp;
        r[round] = rp;

        tr.absorb_point(&lp);
        tr.absorb_point(&rp);
        let x = tr.challenge();
        let x_inv = f_inv(x);
        let x2 = f_mul(x, x);
        let x2_inv = f_mul(x_inv, x_inv);

        for i in 0..half {
            let ai_l = a[i];
            let ai_r = a[half + i];
            let bi_l = b[i];
            let bi_r = b[half + i];
            a[i] = f_add(f_mul(ai_l, x), f_mul(ai_r, x_inv));
            b[i] = f_add(f_mul(bi_l, x_inv), f_mul(bi_r, x));
            g[i] = lin_comb(g[i], x_inv, g[half + i], x).to_affine();
            h[i] = lin_comb(h[i], x, h[half + i], x_inv).to_affine();
        }

        p = add_scaled(p, &lp, x2);
        p = add_scaled(p, &rp, x2_inv);

        n = half;
        round += 1;
    }

    InnerProductProof {
        l,
        r,
        a: a[0],
        b: b[0],
    }
}

/// Folds the generators of an inner-product argument and returns the final
/// base points `g[0]`, `h[0]` together with the folded commitment `p` and the
/// claimed final scalars `a`, `b` from `proof`. The caller checks
/// `p == a*g[0] + b*h[0] + (a*b)*Q`.
fn ipa_fold(
    p0: G1Affine,
    g0: [G1Affine; N],
    h0: [G1Affine; N],
    proof: &InnerProductProof,
) -> (G1Projective, G1Affine, G1Affine, u256, u256) {
    let mut g = g0;
    let mut h = h0;
    let mut p = G1Projective::from(p0);

    let mut tr = Transcript::new();
    tr.absorb_point(&p0);

    let mut n = N;
    let mut round = 0;
    while n > 1 {
        let half = n / 2;
        let lp = proof.l[round];
        let rp = proof.r[round];
        tr.absorb_point(&lp);
        tr.absorb_point(&rp);
        let x = tr.challenge();
        let x_inv = f_inv(x);
        let x2 = f_mul(x, x);
        let x2_inv = f_mul(x_inv, x_inv);

        for i in 0..half {
            g[i] = lin_comb(g[i], x_inv, g[half + i], x).to_affine();
            h[i] = lin_comb(h[i], x, h[half + i], x_inv).to_affine();
        }
        p = add_scaled(p, &lp, x2);
        p = add_scaled(p, &rp, x2_inv);

        n = half;
        round += 1;
    }

    (p, g[0], h[0], proof.a, proof.b)
}

/// Verifies an inner-product argument.
#[cfg(test)]
fn ipa_verify(
    p0: G1Affine,
    g0: [G1Affine; N],
    h0: [G1Affine; N],
    q: &G1Affine,
    proof: &InnerProductProof,
) -> bool {
    let (p, g0f, h0f, a, b) = ipa_fold(p0, g0, h0, proof);
    let ab = f_mul(a, b);
    let mut target = G1Projective::from(g0f.scalar_mul(a));
    target = add_scaled(target, &h0f, b);
    target = add_scaled(target, q, ab);
    // Check p == target  <=>  p - target == infinity
    let diff = p.add(&neg_proj(target));
    diff.is_identity()
}

// ===========================================================================
// Range-proof glue (shared helper used by both prover & verifier)
// ===========================================================================

/// `h_tilde[i] = y^{-i} * h[i]`, used to absorb the `y^n` weighting into the
/// `h` generators.
fn compute_h_tilde(h: &[G1Affine; N], y: u256) -> [G1Affine; N] {
    let y_inv = f_inv(y);
    let mut out = [IDENTITY; N];
    let mut yp = u256::from(1u8);
    for i in 0..N {
        out[i] = h[i].scalar_mul(yp);
        yp = f_mul(yp, y_inv);
    }
    out
}

/// Reconstructs the inner-product commitment point `P` from the public data.
/// This is the exact relation that binds the bit vectors to the proof; the
/// prover and verifier MUST compute it identically.
#[allow(clippy::too_many_arguments)]
fn compute_p(
    gens: &Generators,
    a: &G1Affine,
    s: &G1Affine,
    y: u256,
    z: u256,
    x: u256,
    t_hat: u256,
    mu: u256,
) -> G1Affine {
    let sum_g = sum_points(&gens.g);
    let sum_h = sum_points(&gens.h);

    // Σ (2^i * h_tilde_i)
    let h_tilde = compute_h_tilde(&gens.h, y);
    let mut sum_2_htilde = G1Projective::identity();
    let mut two = u256::from(1u8);
    for i in 0..N {
        sum_2_htilde = add_scaled(sum_2_htilde, &h_tilde[i], two);
        two = f_mul(two, u256::from(2u8));
    }

    let mut p = G1Projective::from(*a);
    p = add_scaled(p, s, x);
    p = add_scaled(p, &gens.h_blind, f_sub(t_hat, mu));
    p = add_scaled(p, &sum_g.to_affine(), f_sub(u256::from(0u8), z));
    p = add_scaled(p, &sum_h.to_affine(), z);
    p = add_scaled(p, &sum_2_htilde.to_affine(), f_mul(z, z));
    p.to_affine()
}

/// Derives the range-proof Fiat-Shamir challenges `(y, z, x)` identically for
/// prover and verifier.
fn derive_challenges(proof: &RangeProof) -> (u256, u256, u256) {
    let mut tr = Transcript::new();
    tr.absorb_point(&proof.v);
    tr.absorb_point(&proof.a);
    tr.absorb_point(&proof.s);
    let y = tr.challenge();
    let z = tr.challenge();
    tr.absorb_point(&proof.t1);
    tr.absorb_point(&proof.t2);
    let x = tr.challenge();
    (y, z, x)
}

// ===========================================================================
// Prover (gated: tests + `prover` feature)
// ===========================================================================

#[cfg(any(test, feature = "prover"))]
mod prover {
    use super::*;
    use crate::ZkError;

    /// Deterministic scalar stream from a 64-byte CSPRNG sequence.
    /// Production deployments MUST use a real random source for blinding
    /// factors.
    fn derive_scalar(randomness: &[u8; 64], idx: u32) -> Result<u256, ZkError> {
        let mut buf = [0u8; 72];
        buf[0..64].copy_from_slice(randomness);
        buf[64..68].copy_from_slice(&idx.to_be_bytes());
        buf[68..72].copy_from_slice(b"bpSc");
        let scalar = hash_to_fq(&buf) % Bn254::FR_MODULUS;
        if scalar == u256::from(0u8) {
            return Err(ZkError::InvalidInput);
        }
        Ok(scalar)
    }

    /// Commit to `v` with blinding `gamma`: `V = v*G + gamma*H`.
    pub fn commit_value(gens: &Generators, v: u256, gamma: u256) -> G1Affine {
        let vg = G_VALUE.scalar_mul(v);
        let gh = gens.h_blind.scalar_mul(gamma);
        G1Projective::from(vg)
            .add(&G1Projective::from(gh))
            .to_affine()
    }

    /// Produce a 64-bit range proof for `v`. Returns [`ZkError::InvalidInput`]
    /// if `v >= 2^64` (out of range / would require >64 bits).
    pub fn prove(
        gens: &Generators,
        v: u256,
        gamma: u256,
        randomness: &[u8; 64],
    ) -> Result<RangeProof, ZkError> {
        if v >= TWO64 {
            return Err(ZkError::InvalidInput);
        }

        let mut a_l = [u256::from(0u8); N];
        let mut a_r = [u256::from(0u8); N];
        let mut tv = v;
        for i in 0..N {
            let bit = tv & u256::from(1u8);
            a_l[i] = bit;
            a_r[i] = if bit == u256::from(0u8) {
                Bn254::FR_MODULUS - u256::from(1u8)
            } else {
                u256::from(0u8)
            };
            tv >>= 1;
        }

        let alpha = derive_scalar(randomness, 0)?;
        let rho = derive_scalar(randomness, 1)?;
        let mut s_l = [u256::from(0u8); N];
        let mut s_r = [u256::from(0u8); N];
        for i in 0..N {
            s_l[i] = derive_scalar(randomness, 2 + i as u32)?;
            s_r[i] = derive_scalar(randomness, 2 + N as u32 + i as u32)?;
        }

        let a_pt = {
            let acc = msm(&gens.g, &a_l);
            let acc = acc.add(&msm(&gens.h, &a_r));
            add_scaled(acc, &gens.h_blind, alpha).to_affine()
        };
        let s_pt = {
            let acc = msm(&gens.g, &s_l);
            let acc = acc.add(&msm(&gens.h, &s_r));
            add_scaled(acc, &gens.h_blind, rho).to_affine()
        };
        let v_pt = commit_value(gens, v, gamma);

        let mut tr = Transcript::new();
        tr.absorb_point(&v_pt);
        tr.absorb_point(&a_pt);
        tr.absorb_point(&s_pt);
        let y = tr.challenge();
        let z = tr.challenge();

        let mut y_vec = [u256::from(0u8); N];
        let mut yp = u256::from(1u8);
        for i in 0..N {
            y_vec[i] = yp;
            yp = f_mul(yp, y);
        }
        let z2 = f_mul(z, z);

        // Canonical Bulletproofs polynomials:
        //   l(X) = a_L - z*1 + X*s_L
        //   r(X) = y^n ∘ (a_R + z*1 + X*s_R) + z^2 * 2^n
        let mut base_r = [u256::from(0u8); N];
        let mut base_rs = [u256::from(0u8); N];
        let mut two = u256::from(1u8);
        for i in 0..N {
            let yr = f_mul(y_vec[i], a_r[i]);
            let zy = f_mul(z, y_vec[i]);
            base_r[i] = f_add(f_add(yr, zy), f_mul(z2, two));
            base_rs[i] = f_mul(y_vec[i], s_r[i]);
            two = f_mul(two, u256::from(2u8));
        }

        // t1 = <a_L - z*1, base_rs> + <s_L, base_r>
        let mut sum_base_rs = u256::from(0u8);
        for i in 0..N {
            sum_base_rs = f_add(sum_base_rs, base_rs[i]);
        }
        let t1 = f_sub(
            f_add(inner_prod(&a_l, &base_rs), inner_prod(&s_l, &base_r)),
            f_mul(z, sum_base_rs),
        );
        let t2 = inner_prod(&s_l, &base_rs);

        let tau1 = derive_scalar(randomness, 2 + 2 * N as u32 + 0)?;
        let tau2 = derive_scalar(randomness, 2 + 2 * N as u32 + 1)?;

        let t1_pt = add_scaled(
            G1Projective::from(G_VALUE.scalar_mul(t1)),
            &gens.h_blind,
            tau1,
        )
        .to_affine();
        let t2_pt = add_scaled(
            G1Projective::from(G_VALUE.scalar_mul(t2)),
            &gens.h_blind,
            tau2,
        )
        .to_affine();

        tr.absorb_point(&t1_pt);
        tr.absorb_point(&t2_pt);
        let x = tr.challenge();

        let mut l_x = [u256::from(0u8); N];
        let mut r_x = [u256::from(0u8); N];
        for i in 0..N {
            l_x[i] = f_add(f_sub(a_l[i], z), f_mul(x, s_l[i]));
            r_x[i] = f_add(base_r[i], f_mul(x, base_rs[i]));
        }
        let t_hat = inner_prod(&l_x, &r_x);
        let x2 = f_mul(x, x);
        let taux = f_add(f_add(f_mul(x2, tau2), f_mul(x, tau1)), f_mul(z2, gamma));
        let mu = f_add(alpha, f_mul(x, rho));

        let p = compute_p(gens, &a_pt, &s_pt, y, z, x, t_hat, mu);
        let h_tilde = compute_h_tilde(&gens.h, y);
        let ip_proof = ipa_prove(p, gens.g, h_tilde, l_x, r_x, &gens.h_blind);

        Ok(RangeProof {
            v: v_pt,
            a: a_pt,
            s: s_pt,
            t1: t1_pt,
            t2: t2_pt,
            taux,
            mu,
            t_hat,
            ip_proof,
        })
    }
}

#[cfg(any(test, feature = "prover"))]
pub use prover::{commit_value, prove};

// ===========================================================================
// Verifier
// ===========================================================================

/// Computes the combined residual point of all range-proof equations. The
/// proof is valid iff this point equals the identity.
///
/// * t-check:  `(t_hat - delta)*G + taux*H - x^2*T2 - x*T1 - z^2*V == 0`
/// * ipa:      `P - a*gf - b*hf - (a*b)*H == 0`
fn compute_residual(gens: &Generators, proof: &RangeProof) -> G1Projective {
    let (y, z, x) = derive_challenges(proof);
    let z2 = f_mul(z, z);

    // delta = (z - z^2) * (1 + y + ... + y^{n-1}) - z^3 * (2^n - 1)
    let delta = {
        let mut yp = u256::from(1u8);
        let mut sy = u256::from(0u8);
        for _ in 0..N {
            sy = f_add(sy, yp);
            yp = f_mul(yp, y);
        }
        let vmax = f_sub(TWO64, u256::from_words(0u128, 1u128));
        let z3 = f_mul(f_mul(z, z), z);
        f_sub(f_mul(f_sub(z, z2), sy), f_mul(z3, vmax))
    };

    // E1 (t-check residual)
    let x2 = f_mul(x, x);
    let mut e1 = G1Projective::from(G_VALUE.scalar_mul(f_sub(proof.t_hat, delta)));
    e1 = add_scaled(e1, &gens.h_blind, proof.taux);
    e1 = add_scaled(e1, &proof.t2, f_sub(u256::from(0u8), x2));
    e1 = add_scaled(e1, &proof.t1, f_sub(u256::from(0u8), x));
    e1 = add_scaled(e1, &proof.v, f_sub(u256::from(0u8), z2));

    // E2 (ipa residual)
    let p = compute_p(gens, &proof.a, &proof.s, y, z, x, proof.t_hat, proof.mu);
    let h_tilde = compute_h_tilde(&gens.h, y);
    let (pf, gf, hf, a, b) = ipa_fold(p, gens.g, h_tilde, &proof.ip_proof);
    let mut target = G1Projective::from(gf.scalar_mul(a));
    target = add_scaled(target, &hf, b);
    target = add_scaled(target, &gens.h_blind, f_mul(a, b));
    let e2 = pf.add(&neg_proj(target));

    e1.add(&e2)
}

/// Verify a single 64-bit range proof.
pub fn verify(gens: &Generators, proof: &RangeProof) -> bool {
    compute_residual(gens, proof).is_identity()
}

/// Verify a batch of range proofs via random linear combination.
///
/// All per-proof residual equations are collapsed into a single multi-scalar
/// multiplication using independent Fiat-Shamir-derived weights, so the cost
/// grows with the total work (no per-proof independent pairing/MSM overhead at
/// the verification-equality stage).
pub fn verify_batch(gens: &Generators, proofs: &[RangeProof]) -> bool {
    if proofs.is_empty() {
        return true;
    }

    // Seed the batch weight oracle from every proof.
    let mut seed_tr = Transcript::new();
    for p in proofs {
        seed_tr.absorb_point(&p.v);
        seed_tr.absorb_point(&p.a);
        seed_tr.absorb_point(&p.ip_proof.l[0]);
    }
    let base = seed_tr.challenge();

    let mut acc = G1Projective::identity();
    for (j, p) in proofs.iter().enumerate() {
        // Weight r_j = SHA-256(base || j) — collision-resistant, unpredictable.
        let mut hasher = Sha256::new();
        hasher.update(&base.to_be_bytes());
        hasher.update(&(j as u32).to_be_bytes());
        let hash = hasher.finalize();
        let rj = u256::from_words(
            u128::from_be_bytes(hash[0..16].try_into().unwrap()),
            u128::from_be_bytes(hash[16..32].try_into().unwrap()),
        ) % Bn254::FR_MODULUS;

        let res = compute_residual(gens, p);
        acc = add_scaled(acc, &res.to_affine(), rj);
    }
    acc.is_identity()
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ZkError;

    fn gens() -> Generators {
        Generators::new()
    }

    #[test]
    fn generators_are_on_curve() {
        let g = gens();
        assert!(Bn254::is_valid_g1(g.h_blind.x, g.h_blind.y));
        for i in 0..N {
            assert!(Bn254::is_valid_g1(g.g[i].x, g.g[i].y));
            assert!(Bn254::is_valid_g1(g.h[i].x, g.h[i].y));
        }
        // Distinctness sanity.
        assert_ne!(g.g[0], g.g[1]);
        assert_ne!(g.h[0], g.h[1]);
        assert_ne!(g.g[0], g.h[0]);
    }

    #[test]
    fn ipa_round_trip() {
        let g = gens();
        let q = g.h_blind;
        let mut a = [u256::from(0u8); N];
        let mut b = [u256::from(0u8); N];
        for i in 0..N {
            a[i] = (u256::from(i as u64) + u256::from(1u8)) % Bn254::FR_MODULUS;
            b[i] = (u256::from((N - i) as u64) + u256::from(3u8)) % Bn254::FR_MODULUS;
        }
        // P = <a,g> + <b,h> + <a,b>*Q
        let mut p = msm(&g.g, &a);
        p = p.add(&msm(&g.h, &b));
        let ab = inner_prod(&a, &b);
        p = add_scaled(p, &q, ab);
        let proof = ipa_prove(p.to_affine(), g.g, g.h, a, b, &q);
        assert!(ipa_verify(p.to_affine(), g.g, g.h, &q, &proof));
    }

    #[test]
    fn ipa_tampered_fails() {
        let g = gens();
        let q = g.h_blind;
        let a = [u256::from(2u8); N];
        let b = [u256::from(3u8); N];
        let mut p = msm(&g.g, &a);
        p = p.add(&msm(&g.h, &b));
        p = add_scaled(p, &q, inner_prod(&a, &b));
        let mut proof = ipa_prove(p.to_affine(), g.g, g.h, a, b, &q);
        // Tamper with final scalar.
        proof.a = f_add(proof.a, u256::from(1u8));
        assert!(!ipa_verify(p.to_affine(), g.g, g.h, &q, &proof));
    }

    #[test]
    fn range_proof_zero_valid() {
        let g = gens();
        let proof = prove(&g, u256::from(0u8), u256::from(777u32), &[1u8; 64]).unwrap();
        assert!(verify(&g, &proof));
    }

    #[test]
    fn range_proof_max_valid() {
        let g = gens();
        let max = TWO64 - u256::from(1u8);
        let proof = prove(&g, max, u256::from(12345u32), &[2u8; 64]).unwrap();
        assert!(verify(&g, &proof));
    }

    #[test]
    fn range_proof_mid_value_valid() {
        let g = gens();
        let v = u256::from(0xdeadbeefcafeu128);
        let proof = prove(&g, v, u256::from(99u32), &[3u8; 64]).unwrap();
        assert!(verify(&g, &proof));
    }

    #[test]
    fn range_proof_overflow_rejected() {
        let g = gens();
        // Exactly 2^64 is out of the 64-bit range.
        let res = prove(&g, TWO64, u256::from(1u8), &[4u8; 64]);
        assert_eq!(res, Err(ZkError::InvalidInput));
        // A value well above 2^64 (modular representation) is also rejected.
        let above = TWO64 + u256::from(0x1234u16);
        let res2 = prove(&g, above, u256::from(1u8), &[5u8; 64]);
        assert_eq!(res2, Err(ZkError::InvalidInput));
    }

    #[test]
    fn range_proof_negative_modular_rejected() {
        let g = gens();
        // A "negative" value mapped into the field as r - 1 is far above 2^64
        // and therefore not a valid 64-bit unsigned integer.
        let neg_field = Bn254::FR_MODULUS - u256::from(1u8);
        let res = prove(&g, neg_field, u256::from(1u8), &[6u8; 64]);
        assert_eq!(res, Err(ZkError::InvalidInput));
    }

    #[test]
    fn range_proof_tampered_fails() {
        let g = gens();
        let mut proof = prove(&g, u256::from(42u8), u256::from(7u8), &[8u8; 64]).unwrap();
        // Flip the claimed inner product.
        proof.t_hat = f_add(proof.t_hat, u256::from(1u8));
        assert!(!verify(&g, &proof));
    }

    #[test]
    fn range_proof_wrong_commitment_fails() {
        let g = gens();
        let mut proof = prove(&g, u256::from(42u8), u256::from(7u8), &[9u8; 64]).unwrap();
        // Swap to a different valid-looking commitment (should not verify).
        proof.v = commit_value(&g, u256::from(43u8), u256::from(7u8));
        assert!(!verify(&g, &proof));
    }

    #[test]
    fn batch_all_valid() {
        let g = gens();
        let proofs = [
            prove(&g, u256::from(0u8), u256::from(1u8), &[11u8; 64]).unwrap(),
            prove(&g, TWO64 - u256::from(1u8), u256::from(2u8), &[12u8; 64]).unwrap(),
            prove(&g, u256::from(0xabcdu128), u256::from(3u8), &[13u8; 64]).unwrap(),
        ];
        assert!(verify_batch(&g, &proofs));
    }

    #[test]
    fn batch_with_invalid_fails() {
        let g = gens();
        let mut good = prove(&g, u256::from(5u8), u256::from(1u8), &[14u8; 64]).unwrap();
        let bad = prove(&g, u256::from(6u8), u256::from(1u8), &[15u8; 64]).unwrap();
        good.t_hat = f_add(good.t_hat, u256::from(1u8));
        let proofs = [good, bad];
        assert!(!verify_batch(&g, &proofs));
    }

    #[test]
    fn batch_empty_is_true() {
        let g = gens();
        let empty: [RangeProof; 0] = [];
        assert!(verify_batch(&g, &empty));
    }
}
