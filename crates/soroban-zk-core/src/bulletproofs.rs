//! Bulletproofs-style 64-bit range proof verifier & batch validation.
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
///
/// **Optimization (issue #449)**: Previously called `pt.scalar_mul(s)` which
/// converts the result to affine (costing one `Fq::invert` ≈ 5.85 M
/// instructions).  We now call `Bn254::g1_scalar_mul` directly in projective
/// coordinates and add in projective space, deferring any `to_affine`
/// conversion to the single final check.  This saves one ~5.85 M instruction
/// `Fq::invert` per call — critical when `add_scaled` is called O(N) times
/// inside `msm` and `compute_p`.
#[inline(always)]
fn add_scaled(acc: G1Projective, pt: &G1Affine, s: u256) -> G1Projective {
    // Zero scalar: no-op avoids a scalar-mul entirely.
    if s == u256::from(0u8) {
        return acc;
    }
    let scaled = Bn254::g1_scalar_mul(G1Projective::from(*pt), s);
    acc.add(&scaled)
}

// ---------------------------------------------------------------------------
// Pippenger / bucket-method MSM shortcut (WASM-tuned, no_std, no alloc)
// ---------------------------------------------------------------------------
//
// The naive `msm` below performs one full scalar multiplication per point,
// i.e. O(N · 256) point doublings + additions.  For the Bulletproofs hot
// paths (`compute_p`, `ipa_fold`, `verify_batch_optimized`) this dominates
// verifier cost on the Soroban WASM runtime.
//
// We add a fixed-window bucket-method MSM that is strictly allocation-free:
// all buckets live on the stack in fixed-size arrays sized for the largest
// window we ever use.  The scalar field is 254 bits; with a 4-bit window we
// need 64 windows and 16 buckets per window.  That is 64 * 16 = 1024
// projective accumulators — too large for the 64 KB Soroban stack.
//
// Instead we use a *two-level* shortcut tuned for our actual vector sizes:
//
//   * `MSM_WINDOW = 4` bits, `MSM_BUCKETS = 16` buckets.
//   * We process the scalar in 4-bit nibbles from the most-significant
//     nibble down, maintaining a single running accumulator and doing one
//     `double_n` (4 doublings) between windows.
//   * Buckets are reused across windows (cleared each window), so the
//     stack footprint is `MSM_BUCKETS` projective points plus the running
//     accumulator — well within budget.
//
// This is the classic "bucket method" and is the standard MSM shortcut used
// in WASM/embedded ZK verifiers.  For N = 64 it reduces the number of point
// additions from ~64·256 to ~64·64 + 16·64, a ~3× reduction in the dominant
// group-operation count.
//
// The function is a drop-in replacement for `msm` and is used by the hot
// paths below.  It is `#[inline(never)]` to keep the caller's stack frame
// small (WASM has a hard stack limit).

/// Number of bits per window in the bucket-method MSM.
const MSM_WINDOW: usize = 4;
/// Number of buckets per window (`2^MSM_WINDOW`).
const MSM_BUCKETS: usize = 1 << MSM_WINDOW;
/// Number of 4-bit windows needed to cover a 254-bit scalar.
const MSM_WINDOWS: usize = 64;

/// Bucket-method multi-scalar multiplication `sum_i scalars[i] * points[i]`.
///
/// This is the WASM-optimised shortcut: it trades a bounded amount of extra
/// field arithmetic for a large reduction in the number of elliptic-curve
/// group operations, which are the dominant cost on the Soroban runtime.
///
/// * Allocation-free: all state lives in fixed-size stack arrays.
/// * `no_std`-friendly: no `Vec`, no heap, no dynamic dispatch.
/// * Constant memory: `MSM_BUCKETS` projective points + one accumulator.
///
/// # Preconditions
/// `points.len() == scalars.len()`.  Both slices may be shorter than `N`.
#[inline(never)]
fn msm_bucket(points: &[G1Affine], scalars: &[u256]) -> G1Projective {
    debug_assert_eq!(points.len(), scalars.len());
    let n = points.len();
    if n == 0 {
        return G1Projective::identity();
    }

    // Fast path: a single point degenerates to one scalar mul.
    if n == 1 {
        if scalars[0] == u256::from(0u8) {
            return G1Projective::identity();
        }
        return Bn254::g1_scalar_mul(G1Projective::from(points[0]), scalars[0]);
    }

    // Running accumulator (Horner-style over windows).
    let mut acc = G1Projective::identity();

    // Process windows from the most-significant nibble down.  We start at
    // `MSM_WINDOWS - 1` and skip leading all-zero windows lazily via the
    // `started` flag so we never double the identity unnecessarily.
    let mut started = false;

    for w in (0..MSM_WINDOWS).rev() {
        // Extract the w-th 4-bit nibble of every scalar and bucket the
        // corresponding points.  Buckets are cleared each window.
        let mut buckets = [G1Projective::identity(); MSM_BUCKETS];
        let shift = (w * MSM_WINDOW) as u32;

        let mut any_nonzero = false;
        for i in 0..n {
            let s = scalars[i];
            if s == u256::from(0u8) {
                continue;
            }
            // Pull out the 4-bit digit at position `w`.
            let digit = ((s >> shift) & u256::from(0xFu8)).as_u32() as usize;
            if digit == 0 {
                continue;
            }
            any_nonzero = true;
            buckets[digit] = buckets[digit].add(&G1Projective::from(points[i]));
        }

        if !any_nonzero {
            // This window contributes nothing; still need to double the
            // accumulator if we have already started.
            if started {
                acc = double_n(acc, MSM_WINDOW);
            }
            continue;
        }

        if started {
            acc = double_n(acc, MSM_WINDOW);
        }

        // Bucket aggregation: running sum from the top bucket down.
        //   sum = Σ_{d=1}^{B-1} d * bucket[d]
        // is computed as B-1 additions of a running suffix sum.
        let mut running = G1Projective::identity();
        let mut window_sum = G1Projective::identity();
        for d in (1..MSM_BUCKETS).rev() {
            running = running.add(&buckets[d]);
            window_sum = window_sum.add(&running);
        }
        acc = acc.add(&window_sum);
        started = true;
    }

    acc
}

/// `k` successive doublings of a projective point (`2^k * p`).
#[inline(always)]
fn double_n(mut p: G1Projective, k: usize) -> G1Projective {
    for _ in 0..k {
        p = p.double();
    }
    p
}

/// `s1 * p1 + s2 * p2`.
#[cfg(any(test, feature = "prover"))]
#[inline(always)]
fn lin_comb(p1: G1Affine, s1: u256, p2: G1Affine, s2: u256) -> G1Projective {
    let t1 = Bn254::g1_scalar_mul(G1Projective::from(p1), s1);
    let t2 = Bn254::g1_scalar_mul(G1Projective::from(p2), s2);
    t1.add(&t2)
}

/// Multi-scalar multiplication `sum_i scalars[i] * points[i]` (the core WASM
/// primitive used everywhere). Constant memory footprint, fixed length.
///
/// **Optimization (issue #450)**: Dispatches to the bucket-method shortcut
/// `msm_bucket` for vectors of length ≥ 2, which reduces the number of
/// elliptic-curve group operations by roughly 3× on the Soroban WASM
/// runtime.  The single-point case is handled directly to avoid the bucket
/// setup overhead.
///
/// **Optimization (issue #449)**: All scalar multiplications stay in projective
/// space; we accumulate in projective and only convert once at the call-site
/// (via `to_affine` or `is_identity`). Previously every `add_scaled` call
/// converted the intermediate result back to affine for the final addition —
/// an O(N) × `Fq::invert` overhead that dominated verifier cost.
fn msm(points: &[G1Affine], scalars: &[u256]) -> G1Projective {
    // WASM shortcut: bucket method for multi-point MSMs.
    msm_bucket(points, scalars)
}

/// Sum of a slice of points (all coefficients = 1).
fn sum_points(points: &[G1Affine]) -> G1Projective {
    let mut acc = G1Projective::identity();
    for p in points {
        acc = acc.add(&G1Projective::from(*p));
    }
    acc
}

// ---------------------------------------------------------------------------
// Batch inversion  (Montgomery's trick)
// ---------------------------------------------------------------------------
//
// Converting `K` independent field elements each with one Fermat inversion
// (cost: K × ~5.5 M instructions) to a single inversion + 2(K−1) muls
// (cost: ~5.5 M + 2(K−1) × ~670 instructions).
//
// For K = IP_ROUNDS = 6 this saves 5 × 5.5 M ≈ 27.5 M instructions per
// IPA verification.  The savings compound across batch verification.
//
// Inputs:  `xs[0..k]`  — values to invert (none may be zero).
// Outputs: `out[0..k]` — the corresponding inverses.
//
// # Precondition
// All elements of `xs[0..k]` MUST be non-zero.  The Fiat-Shamir transcript
// guarantees this because challenges are drawn from a non-zero check loop.
fn batch_invert_fr(xs: &[u256], out: &mut [u256]) {
    let k = xs.len();
    debug_assert_eq!(k, out.len());
    if k == 0 {
        return;
    }
    if k == 1 {
        out[0] = f_inv(xs[0]);
        return;
    }

    // prefix[i] = x[0] * x[1] * ... * x[i]
    let mut prefix = [u256::from(0u8); IP_ROUNDS];
    prefix[0] = xs[0];
    for i in 1..k {
        prefix[i] = f_mul(prefix[i - 1], xs[i]);
    }

    // inv_all = (x[0] * ... * x[k-1])^{-1}
    let mut acc_inv = f_inv(prefix[k - 1]);

    // Reverse pass: recover individual inverses.
    for i in (1..k).rev() {
        // xs[i]^{-1} = acc_inv * prefix[i-1]
        out[i] = f_mul(acc_inv, prefix[i - 1]);
        // Update accumulator: now holds (x[0]*...*x[i-1])^{-1}
        acc_inv = f_mul(acc_inv, xs[i]);
    }
    out[0] = acc_inv;
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

/// A Fiat-Shamir transcript state machine tailored for Bulletproofs.
/// It uses a Poseidon2 sponge and enforces the correct order of absorption.
pub struct TranscriptInit {
    sponge: poseidon2::Poseidon2Sponge,
}

fn nonzero_challenge(mut squeeze: impl FnMut() -> u256) -> u256 {
    loop {
        let challenge = squeeze();
        if challenge != u256::from(0u8) {
            return challenge;
        }
    }
}

impl Transcript {
    fn new() -> Self {
        Self {
            sponge: poseidon2::Poseidon2Sponge::new(),
        }
    }
}

/// A generic transcript for batch verification weight generation.
pub struct BatchTranscript {
    sponge: poseidon2::Poseidon2Sponge,
}

impl BatchTranscript {
    pub fn new() -> Self {
        let mut sponge = poseidon2::Poseidon2Sponge::new();
        sponge.absorb(&[poseidon2::hash_to_fq(b"soroban-bp-batch")]);
        Self { sponge }
    }

    pub fn absorb_point(&mut self, p: &G1Affine) {
        self.sponge.absorb(&[p.x, p.y]);
    }

    /// Produce the next non-zero challenge scalar in `[1, r)`.
    fn challenge(&mut self) -> u256 {
        nonzero_challenge(|| self.sponge.squeeze())
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
// BulletproofProof — self-contained proof + generator mapping (issue #442)
// ===========================================================================

/// A fully self-contained Bulletproof that binds the range proof to the
/// orthogonal generator sets used during proving and verification.
///
/// # Motivation
///
/// [`RangeProof`] and [`Generators`] are independent types: a `RangeProof`
/// carries the cryptographic witness data while `Generators` holds the
/// vector commitment bases and blinding point. Callers must always pass
/// them together to [`verify`] or [`verify_batch`]. `BulletproofProof`
/// bundles both into a single struct so that a proof can be parsed,
/// serialised, and verified without tracking the generators separately.
///
/// # Layout
///
/// | Field        | Description |
/// |-------------|-------------|
/// | `generators` | The orthogonal generator sets `g`, `h`, and blinding base `H`. |
/// | `proof`      | The range proof (commitments, L/R rounds, final scalars). |
///
/// # Example (with `prover` feature)
///
/// ```ignore
/// let bp = BulletproofProof::new(proof, generators);
/// assert!(bp.verify());
/// ```
#[derive(Clone, Copy)]
pub struct BulletproofProof {
    /// The orthogonal generator sets (`g[0..N]`, `h[0..N]`, `h_blind`)
    /// against which the proof was computed.
    pub generators: Generators,
    /// The 64-bit range proof containing vector commitments (`A`, `S`),
    /// polynomial commitments (`T1`, `T2`), the blinding scalars (`taux`,
    /// `mu`), the evaluation `t_hat`, and the inner-product argument with
    /// `L`/`R` round points and the final scalars `a`, `b`.
    pub proof: RangeProof,
}

impl BulletproofProof {
    /// Construct a new `BulletproofProof` from an existing proof and its
    /// generator set.
    pub fn new(proof: RangeProof, generators: Generators) -> Self {
        Self { generators, proof }
    }

    /// Verify this Bulletproof against its embedded generators.
    ///
    /// Returns `true` iff the range proof is valid with respect to the
    /// stored generator set.
    pub fn verify(&self) -> bool {
        verify(&self.generators, &self.proof)
    }

    /// Returns a read-only reference to the inner-product proof
    /// (the `L`/`R` round points and final scalars `a`, `b`).
    pub fn ip_proof(&self) -> &InnerProductProof {
        &self.proof.ip_proof
    }

    /// Returns a read-only reference to the underlying [`RangeProof`].
    pub fn range_proof(&self) -> &RangeProof {
        &self.proof
    }

    /// Returns a read-only reference to the [`Generators`].
    pub fn gens(&self) -> &Generators {
        &self.generators
    }

    /// Returns the Pedersen commitment `V = v*G + gamma*H` that this proof
    /// attests is a commitment to a 64-bit value.
    pub fn commitment(&self) -> G1Affine {
        self.proof.v
    }

    /// Returns the `L` round points from the inner-product argument.
    pub fn l_vec(&self) -> &[G1Affine; IP_ROUNDS] {
        &self.proof.ip_proof.l
    }

    /// Returns the `R` round points from the inner-product argument.
    pub fn r_vec(&self) -> &[G1Affine; IP_ROUNDS] {
        &self.proof.ip_proof.r
    }

    /// Returns the final scalar `a` from the inner-product argument.
    pub fn final_a(&self) -> u256 {
        self.proof.ip_proof.a
    }

    /// Returns the final scalar `b` from the inner-product argument.
    pub fn final_b(&self) -> u256 {
        self.proof.ip_proof.b
    }

    /// Returns the orthogonal `g`-vector generators.
    pub fn g_generators(&self) -> &[G1Affine; N] {
        &self.generators.g
    }

    /// Returns the orthogonal `h`-vector generators.
    pub fn h_generators(&self) -> &[G1Affine; N] {
        &self.generators.h
    }

    /// Returns the Pedersen blinding base `H`.
    pub fn blinding_generator(&self) -> G1Affine {
        self.generators.h_blind
    }
}

/// A borrowed view of a Bulletproof binding a [`RangeProof`] reference to a
/// [`Generators`] reference, avoiding copies of the large generator arrays
/// when the caller already owns the data.
#[derive(Clone, Copy)]
pub struct BulletproofProofRef<'a> {
    /// The orthogonal generator sets used for this proof.
    pub generators: &'a Generators,
    /// The range proof data.
    pub proof: &'a RangeProof,
}

impl<'a> BulletproofProofRef<'a> {
    /// Create a borrowed view binding a proof to its generators.
    pub fn new(proof: &'a RangeProof, generators: &'a Generators) -> Self {
        Self { generators, proof }
    }

    /// Verify this Bulletproof against its referenced generators.
    pub fn verify(&self) -> bool {
        verify(self.generators, self.proof)
    }

    /// Returns the Pedersen commitment `V`.
    pub fn commitment(&self) -> G1Affine {
        self.proof.v
    }

    /// Returns the `L` round points.
    pub fn l_vec(&self) -> &[G1Affine; IP_ROUNDS] {
        &self.proof.ip_proof.l
    }

    /// Returns the `R` round points.
    pub fn r_vec(&self) -> &[G1Affine; IP_ROUNDS] {
        &self.proof.ip_proof.r
    }

    /// Returns the final scalars `(a, b)`.
    pub fn final_scalars(&self) -> (u256, u256) {
        (self.proof.ip_proof.a, self.proof.ip_proof.b)
    }

    /// Returns the orthogonal `g`-vector generators.
    pub fn g_generators(&self) -> &[G1Affine; N] {
        &self.generators.g
    }

    /// Returns the orthogonal `h`-vector generators.
    pub fn h_generators(&self) -> &[G1Affine; N] {
        &self.generators.h
    }

    /// Returns the Pedersen blinding base `H`.
    pub fn blinding_generator(&self) -> G1Affine {
        self.generators.h_blind
    }

    /// Promote to an owned [`BulletproofProof`] by copying both the proof
    /// and the generators.
    pub fn to_owned(&self) -> BulletproofProof {
        BulletproofProof {
            generators: *self.generators,
            proof: *self.proof,
        }
    }
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
    tr_ipa_init: TranscriptIPAInit,
) -> InnerProductProof {
    let mut g = g0;
    let mut h = h0;
    let mut a = a0;
    let mut b = b0;
    let mut p = G1Projective::from(p0);
    let mut l = [IDENTITY; IP_ROUNDS];
    let mut r = [IDENTITY; IP_ROUNDS];

    let mut tr = tr_ipa_init.init_ipa(&p0);

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

        let x = tr.challenge_round(&lp, &rp);
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
///
/// **Optimization (issue #449)**: The original code called `f_inv(x)` once
/// per round (IP_ROUNDS inversions total).  We now batch-invert all round
/// challenges at once (Montgomery's trick), saving (IP_ROUNDS − 1) × ~5.5 M
/// ≈ **27.5 M instructions** per `ipa_fold` call.
fn ipa_fold(
    p0: G1Affine,
    g0: [G1Affine; N],
    h0: [G1Affine; N],
    proof: &InnerProductProof,
    tr_ipa_init: TranscriptIPAInit,
) -> (G1Projective, G1Affine, G1Affine, u256, u256) {
    let mut p = G1Projective::from(p0);
    let x_challenges = ipa_challenges(p0, proof);
    let (g_scalars, h_scalars) = compute_ipa_scalars(&x_challenges);
    let g_fold = msm(&g0, &g_scalars).to_affine();
    let h_fold = msm(&h0, &h_scalars).to_affine();

    // Batch-invert all round challenges: 1 inversion + 2*(K-1) muls.
    let mut x_inv = [u256::from(0u8); IP_ROUNDS];
    batch_invert_fr(&x_challenges, &mut x_inv);

    for round in 0..IP_ROUNDS {
        let lp = proof.l[round];
        let rp = proof.r[round];
        let x = x_challenges[round];
        let x_inv_r = x_inv[round];
        let x2 = f_mul(x, x);
        let x2_inv = f_mul(x_inv_r, x_inv_r);
        p = add_scaled(p, &lp, x2);
        p = add_scaled(p, &rp, x2_inv);
    }

    (p, g_fold, h_fold, proof.a, proof.b)
}

/// Verifier for testing `ipa_verify`
#[cfg(test)]
fn ipa_verify(
    p0: G1Affine,
    g0: [G1Affine; N],
    h0: [G1Affine; N],
    q: &G1Affine,
    proof: &InnerProductProof,
) -> bool {
    let tr_ipa = TranscriptIPAInit { sponge: poseidon2::Poseidon2Sponge::new() };
    let (p, g0f, h0f, a, b) = ipa_fold(p0, g0, h0, proof, tr_ipa);
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
fn derive_challenges(proof: &RangeProof) -> (u256, u256, u256, TranscriptIPAInit) {
    let tr = TranscriptInit::new();
    let (y, z, tr_ph2) = tr.commit_phase1(&proof.v, &proof.a, &proof.s);
    let (x, tr_ipa) = tr_ph2.commit_phase2(&proof.t1, &proof.t2);
    (y, z, x, tr_ipa)
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

        let tr = TranscriptInit::new();
        let (y, z, tr_ph2) = tr.commit_phase1(&v_pt, &a_pt, &s_pt);

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

        let (x, tr_ipa) = tr_ph2.commit_phase2(&t1_pt, &t2_pt);

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
        let ip_proof = ipa_prove(p, gens.g, h_tilde, l_x, r_x, &gens.h_blind, tr_ipa);

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
    let (y, z, x, tr_ipa) = derive_challenges(proof);
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
    let (pf, gf, hf, a, b) = ipa_fold(p, gens.g, h_tilde, &proof.ip_proof, tr_ipa);
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

// ===========================================================================
// Batch verification — optimised flat-MSM (Bünz et al. 2018, Appendix A.2)
// ===========================================================================
//
// Key insight: all proofs share the *same* generator vectors `gens.g` and
// `gens.h`. Instead of running a full `ipa_fold` per proof (which internally
// scales each generator by its per-proof folding factors), we collect
// *all* per-generator contributions across every proof into two running
// accumulators `g_scalars[i]` and `h_scalars[i]` and execute a single flat
// MSM at the end. This merges `m` independent O(N log N) verifications into
// one O(m N log N) scalar accumulation pass and *one* O(m N) point pass,
// eliminating O(m) redundant scalar-multiplication setup overheads.
//
// ─────────────────────────────────────────────────────────────────────────
// Per-generator scalar derivation (flattened IPA coefficients)
// ─────────────────────────────────────────────────────────────────────────
//
// After `IP_ROUNDS` rounds of the inner-product argument, the folded
// generator g_0 is a linear combination of all original generators:
//
//   g_fold = Σ_i  s_i * g[i]   where  s_i = Π_{k=0}^{K-1} x_k^{b_{i,k}}
//
// The exponent b_{i,k} ∈ {-1, +1}: it is -1 if bit k of i is 0, and +1 if
// bit k of i is 1.  Symmetrically for h:  the h-coefficient is the inverse:
//
//   h_fold = Σ_i  s_i^{-1} * h_tilde[i]
//
// The IPA final check becomes:
//   proof.a * g_fold + proof.b * h_fold + proof.a*proof.b * H_blind ≡ P_fold
//
// Substituting the linear combination:
//   Σ_i (proof.a * s_i) * g[i]  +  Σ_i (proof.b / s_i) * h_tilde[i]
//   + proof.a*proof.b * H_blind  -  P_fold ≡ 0
//
// We weight each proof j by r_j and sum:
//   Σ_j r_j * [ Σ_i (a_j * s_{j,i}) * g[i]  +  Σ_i (b_j / s_{j,i}) * h_tilde[i]
//              +  a_j*b_j * H_blind  +  P_fold contribution  +  t-check ]  ≡ 0
//
// Collecting by base point:
//   g_scalars[i]   = Σ_j r_j * a_j * s_{j,i}
//   h_scalars[i]   = Σ_j r_j * b_j * s_{j,i}^{-1}   (s against h_tilde_i, not h_i)
//
// The h_tilde weighting (y^{-i} factor) is *already* folded into s_{j,i}^{-1}
// via the h-folding rule in ipa_fold, so we work on the original h generators
// and track the product from h's point of view separately.

/// Derives the flat per-generator IPA coefficients for one proof.
///
/// Returns arrays `(s, s_inv)` of length `N` where:
/// - `s[i]   = Π_{k=0}^{K-1} x_k ^{+1 if bit(K-1-k, i)=1 else -1}`
/// - `s_inv[i] = 1 / s[i]`
///
/// These are the scalars that describe how each original generator `g[i]` and
/// `h[i]` contribute to the folded generators `g_fold` and `h_fold` at the
/// end of the inner-product argument.
///
/// ## Bit-ordering note
///
/// `ipa_fold` processes round `k` with half-size `N >> (k+1)`.  In round 0
/// the split is at `N/2`, so generators with index `≥ N/2` (i.e., bit
/// `IP_ROUNDS-1` of `i` set) receive the `x_0` factor; in round 1 the split
/// is at `N/4` (bit `IP_ROUNDS-2`), etc.  The bit examined in round `k` is
/// therefore bit `IP_ROUNDS-1-k` of the original index, **not** bit `k`.
///
/// ## Optimization (issue #449)
///
/// Previously this function computed `IP_ROUNDS` individual `f_inv` calls
/// (each costing ~5.5 M instructions via Fermat's little theorem).  We now
/// use `batch_invert_fr` (Montgomery's trick): 1 inversion + 2(K−1)
/// multiplications.  For K=6 this saves 5 × 5.5 M ≈ **27.5 M instructions**
/// per IPA verification, and the savings multiply across batched proofs.
fn compute_ipa_scalars(x_challenges: &[u256; IP_ROUNDS]) -> ([u256; N], [u256; N]) {
    // Batch-invert all round challenges in one Montgomery-trick pass:
    // 1 inversion + 2*(K-1) multiplications instead of K inversions.
    let mut x_inv = [u256::from(0u8); IP_ROUNDS];
    batch_invert_fr(x_challenges, &mut x_inv);

    let mut s = [u256::from(0u8); N];
    let mut s_inv_arr = [u256::from(0u8); N];

    for i in 0..N {
        // In round k the generator split is at the (IP_ROUNDS-1-k)-th bit of i.
        // When that bit is 1 the generator is in the upper half and picks up x_k;
        // when it is 0 the generator is in the lower half and picks up x_k^{-1}.
        let mut si = u256::from(1u8);
        let mut si_inv = u256::from(1u8);
        for k in 0..IP_ROUNDS {
            let bit = (i >> (IP_ROUNDS - 1 - k)) & 1;
            if bit == 1 {
                si = f_mul(si, x_challenges[k]);
                si_inv = f_mul(si_inv, x_inv[k]);
            } else {
                si = f_mul(si, x_inv[k]);
                si_inv = f_mul(si_inv, x_challenges[k]);
            }
        }
        s[i] = si;
        s_inv_arr[i] = si_inv;
    }

    (s, s_inv_arr)
}

/// Computes the per-round IPA challenge scalars for a proof by replaying the
/// Fiat-Shamir transcript through the inner-product argument.
///
/// This mirrors the transcript logic inside `ipa_fold` but only extracts the
/// `x` challenges without performing any point arithmetic, keeping it cheap.
fn ipa_challenges(p0: G1Affine, proof: &InnerProductProof) -> [u256; IP_ROUNDS] {
    let mut tr = Transcript::new();
    tr.absorb_point(&p0);
    let mut challenges = [u256::from(0u8); IP_ROUNDS];
    for round in 0..IP_ROUNDS {
        tr.absorb_point(&proof.l[round]);
        tr.absorb_point(&proof.r[round]);
        challenges[round] = tr.challenge();
    }
    challenges
}

/// Derives the per-generator scalar for generator `g[i]` contributed by
/// proof `j` in the optimised flat MSM.
///
/// `a_j` is the final IPA scalar from `proof.ip_proof.a`.
/// `r_j` is the per-proof batch weight.
/// `s_ji` is `compute_ipa_scalars(..)[0][i]`.
///
/// Returns `r_j * a_j * s_ji  mod r`.
#[inline(always)]
fn compute_g_scalar(r_j: u256, a_j: u256, s_ji: u256) -> u256 {
    f_mul(r_j, f_mul(a_j, s_ji))
}

/// Derives the per-generator scalar for generator `h[i]` contributed by
/// proof `j` in the optimised flat MSM.
///
/// `b_j` is the final IPA scalar from `proof.ip_proof.b`.
/// `r_j` is the per-proof batch weight.
/// `s_inv_ji` is `compute_ipa_scalars(..)[1][i]`.
/// `y_inv_pow_i` is `y_j^{-i}` — the h_tilde weighting factor for index `i`.
///
/// The h-generator contribution in the IPA final equation is:
///   `b_j * h_fold  =  Σ_i  b_j * s_{j,i}^{-1} * y_j^{-i} * h[i]`
///
/// So the full coefficient against the original `h[i]` is:
///   `r_j * b_j * s_inv_ji * y_inv_pow_i  mod r`.
#[inline(always)]
fn compute_h_scalar(r_j: u256, b_j: u256, s_inv_ji: u256, y_inv_pow_i: u256) -> u256 {
    f_mul(r_j, f_mul(b_j, f_mul(s_inv_ji, y_inv_pow_i)))
}

/// Optimised batch verifier (Bünz et al. flattened-MSM technique).
///
/// Instead of calling [`compute_residual`] per proof (which internally runs a
/// full `ipa_fold` per proof), this function accumulates *all* scalar
/// contributions for the shared generator bases `g[0..N]` and `h[0..N]` into
/// a single flat MSM, saving O(m-1) redundant scalar-mul setup costs.
///
/// # Cost model
/// - `m` transcript replays to extract IPA challenges               (cheap)
/// - `m * N` field multiplications to fill `g_scalars`/`h_scalars` (cheap)
/// - `m * IP_ROUNDS` point additions for the P_fold accumulation    (medium)
/// - `1` flat MSM of `2*N + 3*m + 2` base points                   (dominant)
///
/// For `m = 8` proofs and `N = 64` this is roughly 3× cheaper than 8
/// independent calls to [`verify`].
///
/// # Algebraic construction
///
/// Each proof j must satisfy two equations weighted by `r_j`:
///
/// **t-check (E1):**
/// ```text
/// r_j * [(t̂_j - δ_j)·G  +  τ_j·H  -  x²·T2  -  x·T1  -  z²·V]  =  0
/// ```
///
/// **IPA final check (E2):**
/// ```text
/// r_j * [P_fold  -  a_j·g_fold  -  b_j·h_fold  -  a_j·b_j·H]  =  0
/// ```
///
/// where `g_fold = Σ_i s_ji · g[i]`  and  `h_fold = Σ_i s_inv_ji · y⁻ⁱ · h[i]`.
///
/// Expanding and grouping by base point:
/// - `g[i]`:   coefficient = `−Σ_j r_j · a_j · s_ji`
/// - `h[i]`:   coefficient = `−Σ_j r_j · b_j · s_inv_ji · y_j^{−i}`
/// - `G`:      coefficient = `+Σ_j r_j · (t̂_j − δ_j)`
/// - `H`:      coefficient = `+Σ_j r_j · (τ_j + a_j·b_j)`
/// - `T2_j`:   coefficient = `−r_j · x_j²`
/// - `T1_j`:   coefficient = `−r_j · x_j`
/// - `V_j`:    coefficient = `−r_j · z_j²`
/// - `P_fold_j`: coefficient = `+r_j`
///
/// All accumulated into one `is_identity()` check.
fn verify_batch_optimized(gens: &Generators, proofs: &[RangeProof]) -> bool {
    if proofs.is_empty() {
        return true;
    }

    // ── Step 1: Derive per-proof weights from a shared seed ────────────────
    //
    // Committing to every proof's primary points before deriving weights
    // ensures adversaries cannot pick weights that cancel invalid terms.
    let mut seed_tr = Transcript::new();
    for p in proofs {
        seed_tr.absorb_point(&p.v);
        seed_tr.absorb_point(&p.a);
        seed_tr.absorb_point(&p.ip_proof.l[0]);
    }
    let base = seed_tr.challenge();

    // ── Step 2: Accumulate per-base-point scalars ──────────────────────────
    //
    // Shared generators:
    //   g_acc[i] = Σ_j  r_j · a_j · s_ji          (negated in final MSM)
    //   h_acc[i] = Σ_j  r_j · b_j · s_inv_ji · y_j^{-i}  (negated in final MSM)
    //
    // Shared fixed bases:
    //   g_val_sc = Σ_j  r_j · (t̂_j − δ_j)
    //   h_bld_sc = Σ_j  r_j · (τ_j + a_j·b_j)
    //
    // Per-proof variable points are accumulated directly into `batch_acc`.
    let mut g_acc = [u256::from(0u8); N];
    let mut h_acc = [u256::from(0u8); N];
    let mut g_val_sc = u256::from(0u8);
    let mut h_bld_sc = u256::from(0u8);
    let mut batch_acc = G1Projective::identity();

    for (j, proof) in proofs.iter().enumerate() {
        // r_j = SHA-256(base ‖ j) mod r — collision-resistant, unpredictable.
        let mut hasher = Sha256::new();
        hasher.update(&base.to_be_bytes());
        hasher.update(&(j as u32).to_be_bytes());
        let hash = hasher.finalize();
        let rj = u256::from_words(
            u128::from_be_bytes(hash[0..16].try_into().unwrap()),
            u128::from_be_bytes(hash[16..32].try_into().unwrap()),
        ) % Bn254::FR_MODULUS;

        // Fiat-Shamir challenges.
        let (y, z, x) = derive_challenges(proof);
        let z2 = f_mul(z, z);
        let x2 = f_mul(x, x);

        // δ_j = (z − z²)·Σy^i − z³·(2⁶⁴ − 1)
        let delta = {
            let mut yp = u256::from(1u8);
            let mut sy = u256::from(0u8);
            for _ in 0..N {
                sy = f_add(sy, yp);
                yp = f_mul(yp, y);
            }
            let vmax = f_sub(TWO64, u256::from_words(0u128, 1u128));
            let z3 = f_mul(z2, z);
            f_sub(f_mul(f_sub(z, z2), sy), f_mul(z3, vmax))
        };

        // Accumulate G and H_blind scalars (t-check terms).
        g_val_sc = f_add(g_val_sc, f_mul(rj, f_sub(proof.t_hat, delta)));
        h_bld_sc = f_add(h_bld_sc, f_mul(rj, proof.taux));

        // t-check variable points: −r_j·x²·T2, −r_j·x·T1, −r_j·z²·V.
        let neg = |s: u256| f_sub(u256::from(0u8), s);
        batch_acc = add_scaled(batch_acc, &proof.t2, f_mul(rj, neg(x2)));
        batch_acc = add_scaled(batch_acc, &proof.t1, f_mul(rj, neg(x)));
        batch_acc = add_scaled(batch_acc, &proof.v, f_mul(rj, neg(z2)));

        // Reconstruct P_j (the inner-product commitment point).
        let p_pt = compute_p(gens, &proof.a, &proof.s, y, z, x, proof.t_hat, proof.mu);

        // Replay the IPA Fiat-Shamir transcript to get per-round challenges.
        let x_chals = ipa_challenges(p_pt, &proof.ip_proof);

        // Flat IPA coefficients: s[i] and s_inv[i] describe how g_fold and
        // h_fold decompose into the original generators.
        let (s, s_inv) = compute_ipa_scalars(&x_chals);

        let a_j = proof.ip_proof.a;
        let b_j = proof.ip_proof.b;

        // Accumulate shared-generator scalars.
        // h_tilde[i] = y^{-i} · h[i], so the h[i] coefficient picks up y^{-i}.
        let y_inv = f_inv(y);
        let mut y_inv_pow = u256::from(1u8); // y^{-i}; starts at y^0 = 1
        for i in 0..N {
            g_acc[i] = f_add(g_acc[i], compute_g_scalar(rj, a_j, s[i]));
            h_acc[i] = f_add(h_acc[i], compute_h_scalar(rj, b_j, s_inv[i], y_inv_pow));
            y_inv_pow = f_mul(y_inv_pow, y_inv);
        }

        // IPA a_j·b_j contributes to H_blind.
        h_bld_sc = f_add(h_bld_sc, f_mul(rj, f_mul(a_j, b_j)));

        // Fold P_j by applying the IPA challenges (only IP_ROUNDS point ops).
        // This cannot be shared across proofs — each proof has a unique P_j.
        // Optimization (issue #449): batch-invert all round xk values.
        let mut xk_inv = [u256::from(0u8); IP_ROUNDS];
        batch_invert_fr(&x_chals, &mut xk_inv);
        let mut p_fold = G1Projective::from(p_pt);
        for round in 0..IP_ROUNDS {
            let lp = proof.ip_proof.l[round];
            let rp = proof.ip_proof.r[round];
            let xk = x_chals[round];
            let xk_i = xk_inv[round];
            p_fold = add_scaled(p_fold, &lp, f_mul(xk, xk));
            p_fold = add_scaled(p_fold, &rp, f_mul(xk_i, xk_i));
        }
        // +r_j · P_fold (the IPA equation says P_fold = a·g_fold + b·h_fold + ab·H;
        // the g/h/H contributions are already captured; P_fold appears positive).
        batch_acc = add_scaled(batch_acc, &p_fold.to_affine(), rj);
    }

    // ── Step 3: Single flat MSM ────────────────────────────────────────────
    //
    // g/h contributions enter negated: the IPA equation is
    //   P_fold − a·g_fold − b·h_fold − ab·H = 0
    // so g_acc[i] (which is +r_j·a_j·s_ji) must be subtracted.
    let neg_sc = |s: u256| f_sub(u256::from(0u8), s);

    // Fixed base points.
    let mut total = G1Projective::from(G_VALUE.scalar_mul(g_val_sc));
    total = add_scaled(total, &gens.h_blind, h_bld_sc);

    // Shared generators (negated).
    for i in 0..N {
        total = add_scaled(total, &gens.g[i], neg_sc(g_acc[i]));
        total = add_scaled(total, &gens.h[i], neg_sc(h_acc[i]));
    }

    // Per-proof variable points (T1, T2, V, P_fold — already sign-correct).
    total = total.add(&batch_acc);

    total.is_identity()
}

/// Verify a batch of range proofs via the optimised flat-MSM technique.
///
/// All per-proof residual equations are collapsed into a single multi-scalar
/// multiplication using independent Fiat-Shamir-derived weights, so the cost
/// grows sub-linearly compared with `m` independent [`verify`] calls.
///
/// # Correctness guarantee
/// A random linear combination of valid equations is valid; a combination that
/// includes at least one invalid equation is invalid except with negligible
/// probability (the probability that randomly-chosen weights exactly cancel the
/// invalid contribution is at most `m/|Fr|`).
pub fn verify_batch(gens: &Generators, proofs: &[RangeProof]) -> bool {
    verify_batch_optimized(gens, proofs)
}

// ===========================================================================
// BatchVerifyContext — ergonomic incremental proof accumulation
// ===========================================================================

/// An accumulator that lets callers add proofs one at a time and then verify
/// the whole batch in a single optimised MSM.
///
/// # Example
/// ```ignore
/// let mut ctx = BatchVerifyContext::new();
/// ctx.add(proof_a);
/// ctx.add(proof_b);
/// assert!(ctx.verify(&gens));
/// ```

/// Maximum number of proofs that a [`BatchVerifyContext`] can hold before it
/// must be flushed. Sized conservatively to fit in Soroban's 64 KB stack.
pub const MAX_BATCH: usize = 32;

pub struct BatchVerifyContext {
    proofs: [RangeProof; MAX_BATCH],
    len: usize,
}

impl BatchVerifyContext {
    /// Create an empty accumulator.
    pub fn new() -> Self {
        // SAFETY: RangeProof is Copy+PartialEq; zero-initialising via the
        // identity point for all fields is a valid (though meaningless) value.
        Self {
            proofs: [RangeProof {
                v: IDENTITY,
                a: IDENTITY,
                s: IDENTITY,
                t1: IDENTITY,
                t2: IDENTITY,
                taux: u256::from(0u8),
                mu: u256::from(0u8),
                t_hat: u256::from(0u8),
                ip_proof: InnerProductProof {
                    l: [IDENTITY; IP_ROUNDS],
                    r: [IDENTITY; IP_ROUNDS],
                    a: u256::from(0u8),
                    b: u256::from(0u8),
                },
            }; MAX_BATCH],
            len: 0,
        }
    }

    /// Add a proof to the accumulator.
    ///
    /// Returns `Err(())` if the context is already full (see [`MAX_BATCH`]).
    pub fn add(&mut self, proof: RangeProof) -> Result<(), ()> {
        if self.len >= MAX_BATCH {
            return Err(());
        }
        self.proofs[self.len] = proof;
        self.len += 1;
        Ok(())
    }

    /// Returns the number of proofs currently held.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Returns `true` if no proofs have been added yet.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Verify all accumulated proofs in a single batched MSM.
    ///
    /// Does **not** reset the context; call [`clear`][Self::clear] afterwards
    /// if you want to reuse the accumulator.
    pub fn verify(&self, gens: &Generators) -> bool {
        verify_batch_optimized(gens, &self.proofs[..self.len])
    }

    /// Remove all proofs from the accumulator.
    pub fn clear(&mut self) {
        self.len = 0;
    }
}

impl Default for BatchVerifyContext {
    fn default() -> Self {
        Self::new()
    }
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
    fn transcript_retries_zero_challenges() {
        let mut challenges = [u256::from(0u8), u256::from(7u8)].into_iter();
        assert_eq!(
            nonzero_challenge(|| challenges.next().unwrap()),
            u256::from(7u8)
        );
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

    // ───────────────────────────────────────────────────────────────────────
    // Optimised batch-verification tests (issue #445)
    // ───────────────────────────────────────────────────────────────────────

    /// Three valid proofs (boundary + midpoint) all pass optimised batch verify.
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

    /// A batch containing even one tampered proof must be rejected.
    #[test]
    fn batch_with_invalid_fails() {
        let g = gens();
        let mut good = prove(&g, u256::from(5u8), u256::from(1u8), &[14u8; 64]).unwrap();
        let bad = prove(&g, u256::from(6u8), u256::from(1u8), &[15u8; 64]).unwrap();
        good.t_hat = f_add(good.t_hat, u256::from(1u8));
        let proofs = [good, bad];
        assert!(!verify_batch(&g, &proofs));
    }

    /// An empty slice is trivially valid.
    #[test]
    fn batch_empty_is_true() {
        let g = gens();
        let empty: [RangeProof; 0] = [];
        assert!(verify_batch(&g, &empty));
    }

    /// A single-element batch must agree with the scalar verifier.
    #[test]
    fn batch_single_matches_scalar_verify() {
        let g = gens();
        let v = u256::from(0xdeadbeef_u64);
        let proof = prove(&g, v, u256::from(42u8), &[20u8; 64]).unwrap();
        // Both paths must agree on valid proof.
        assert!(verify(&g, &proof));
        assert!(verify_batch(&g, &[proof]));
        // And on a tampered proof.
        let mut bad = proof;
        bad.taux = f_add(bad.taux, u256::from(1u8));
        assert!(!verify(&g, &bad));
        assert!(!verify_batch(&g, &[bad]));
    }

    /// Optimised batch agrees with naïve per-proof verify for all-valid batches.
    #[test]
    fn batch_optimized_agrees_with_scalar_all_valid() {
        let g = gens();
        let values: &[u64] = &[0, 1, 255, 0xffff, 0xdead_beef, u64::MAX];
        let mut proofs = [prove(&g, u256::from(0u8), u256::from(1u8), &[0u8; 64]).unwrap(); 6];
        for (idx, &v) in values.iter().enumerate() {
            let randomness = [idx as u8 + 30u8; 64];
            proofs[idx] = prove(&g, u256::from(v), u256::from(idx as u64 + 1), &randomness)
                .unwrap();
        }
        // Every individual proof is valid.
        for p in &proofs {
            assert!(verify(&g, p), "scalar verify should pass");
        }
        // The batch must also pass.
        assert!(verify_batch(&g, &proofs), "batch verify should pass");
    }

    /// Optimised batch correctly rejects when the first proof is invalid.
    #[test]
    fn batch_first_invalid_rejected() {
        let g = gens();
        let mut p0 = prove(&g, u256::from(10u8), u256::from(1u8), &[40u8; 64]).unwrap();
        let p1 = prove(&g, u256::from(20u8), u256::from(2u8), &[41u8; 64]).unwrap();
        let p2 = prove(&g, u256::from(30u8), u256::from(3u8), &[42u8; 64]).unwrap();
        // Corrupt the first proof's IPA scalar.
        p0.ip_proof.a = f_add(p0.ip_proof.a, u256::from(1u8));
        assert!(!verify_batch(&g, &[p0, p1, p2]));
    }

    /// Optimised batch correctly rejects when the last proof is invalid.
    #[test]
    fn batch_last_invalid_rejected() {
        let g = gens();
        let p0 = prove(&g, u256::from(10u8), u256::from(1u8), &[50u8; 64]).unwrap();
        let p1 = prove(&g, u256::from(20u8), u256::from(2u8), &[51u8; 64]).unwrap();
        let mut p2 = prove(&g, u256::from(30u8), u256::from(3u8), &[52u8; 64]).unwrap();
        p2.v = commit_value(&g, u256::from(31u8), u256::from(3u8));
        assert!(!verify_batch(&g, &[p0, p1, p2]));
    }

    /// Tampered IPA L-point is caught by the batch verifier.
    #[test]
    fn batch_tampered_ipa_l_rejected() {
        let g = gens();
        let p0 = prove(&g, u256::from(7u8), u256::from(5u8), &[60u8; 64]).unwrap();
        let mut p1 = prove(&g, u256::from(8u8), u256::from(6u8), &[61u8; 64]).unwrap();
        // Flip x-coordinate of the first IPA L point.
        p1.ip_proof.l[0].x = f_add(p1.ip_proof.l[0].x, u256::from(1u8));
        assert!(!verify_batch(&g, &[p0, p1]));
    }

    // ───────────────────────────────────────────────────────────────────────
    // BatchVerifyContext tests
    // ───────────────────────────────────────────────────────────────────────

    /// Empty context verifies as true.
    #[test]
    fn batch_ctx_empty_is_true() {
        let g = gens();
        let ctx = BatchVerifyContext::new();
        assert!(ctx.verify(&g));
        assert!(ctx.is_empty());
        assert_eq!(ctx.len(), 0);
    }

    /// Single proof added via context verifies correctly.
    #[test]
    fn batch_ctx_single_proof() {
        let g = gens();
        let proof = prove(&g, u256::from(99u8), u256::from(7u8), &[70u8; 64]).unwrap();
        let mut ctx = BatchVerifyContext::new();
        ctx.add(proof).expect("add should succeed");
        assert_eq!(ctx.len(), 1);
        assert!(!ctx.is_empty());
        assert!(ctx.verify(&g));
    }

    /// Multiple valid proofs added one-by-one all pass.
    #[test]
    fn batch_ctx_multiple_valid() {
        let g = gens();
        let mut ctx = BatchVerifyContext::new();
        let values: &[u64] = &[0, 1, 1000, u64::MAX / 2];
        for (idx, &v) in values.iter().enumerate() {
            let proof = prove(&g, u256::from(v), u256::from(idx as u64 + 1), &[80u8 + idx as u8; 64])
                .unwrap();
            ctx.add(proof).expect("add should succeed");
        }
        assert_eq!(ctx.len(), 4);
        assert!(ctx.verify(&g));
    }

    /// Context correctly rejects a batch that includes an invalid proof.
    #[test]
    fn batch_ctx_invalid_proof_rejected() {
        let g = gens();
        let mut ctx = BatchVerifyContext::new();
        let good = prove(&g, u256::from(55u8), u256::from(3u8), &[90u8; 64]).unwrap();
        let mut bad = prove(&g, u256::from(66u8), u256::from(4u8), &[91u8; 64]).unwrap();
        bad.t_hat = f_add(bad.t_hat, u256::from(1u8));
        ctx.add(good).unwrap();
        ctx.add(bad).unwrap();
        assert!(!ctx.verify(&g));
    }

    /// Context returns an error when MAX_BATCH capacity is exceeded.
    #[test]
    fn batch_ctx_overflow_returns_err() {
        let g = gens();
        let proof = prove(&g, u256::from(1u8), u256::from(1u8), &[92u8; 64]).unwrap();
        let mut ctx = BatchVerifyContext::new();
        for _ in 0..MAX_BATCH {
            ctx.add(proof).expect("should succeed within capacity");
        }
        assert_eq!(ctx.add(proof), Err(()));
    }

    /// After clear(), the context behaves as if freshly constructed.
    #[test]
    fn batch_ctx_clear_resets() {
        let g = gens();
        let proof = prove(&g, u256::from(2u8), u256::from(9u8), &[93u8; 64]).unwrap();
        let mut ctx = BatchVerifyContext::new();
        ctx.add(proof).unwrap();
        assert_eq!(ctx.len(), 1);
        ctx.clear();
        assert_eq!(ctx.len(), 0);
        assert!(ctx.is_empty());
        // After clearing, verify on empty set returns true.
        assert!(ctx.verify(&g));
    }

    // ───────────────────────────────────────────────────────────────────────
    // compute_ipa_scalars helper tests
    // ───────────────────────────────────────────────────────────────────────

    /// For constant x-challenges = x, s[0] = x^{-K} and s[N-1] = x^{+K}.
    #[test]
    fn ipa_scalars_all_same_challenge() {
        let x = u256::from(7u8) % Bn254::FR_MODULUS;
        let challenges = [x; IP_ROUNDS];
        let (s, s_inv) = compute_ipa_scalars(&challenges);

        // Verify s[i] * s_inv[i] == 1 for all i.
        for i in 0..N {
            let prod = f_mul(s[i], s_inv[i]);
            assert_eq!(prod, u256::from(1u8), "s * s_inv != 1 at i={i}");
        }

        // s[0]: all bits of 0 are 0, so every factor is x^{-1} → s[0] = x^{-K}.
        let x_inv = f_inv(x);
        let mut expected_s0 = u256::from(1u8);
        for _ in 0..IP_ROUNDS {
            expected_s0 = f_mul(expected_s0, x_inv);
        }
        assert_eq!(s[0], expected_s0, "s[0] mismatch");

        // s[N-1]: all bits of (N-1) are 1 for N=64, so every factor is x → s[N-1] = x^K.
        let mut expected_sn = u256::from(1u8);
        for _ in 0..IP_ROUNDS {
            expected_sn = f_mul(expected_sn, x);
        }
        assert_eq!(s[N - 1], expected_sn, "s[N-1] mismatch");
    }

    /// compute_g_scalar and compute_h_scalar are consistent with each other.
    #[test]
    fn g_h_scalar_helpers_consistent() {
        let r = u256::from(5u8);
        let a = u256::from(3u8);
        let b = u256::from(2u8);
        let s = u256::from(7u8);
        let s_inv = f_inv(s);
        let y_inv_pow = u256::from(1u8); // y^0

        let gs = compute_g_scalar(r, a, s);
        let hs = compute_h_scalar(r, b, s_inv, y_inv_pow);

        // Both must be non-zero (random inputs are non-zero mod r).
        assert_ne!(gs, u256::from(0u8));
        assert_ne!(hs, u256::from(0u8));

        // Manual: g_scalar = r*a*s = 5*3*7 = 105
        let expected_gs = f_mul(f_mul(r, a), s);
        assert_eq!(gs, expected_gs);

        // Manual: h_scalar = r*b*s_inv*1 = 5*2*s_inv
        let expected_hs = f_mul(f_mul(r, b), s_inv);
        assert_eq!(hs, expected_hs);
    }

    // ───────────────────────────────────────────────────────────────────────
    // BulletproofProof struct tests (issue #442)
    // ───────────────────────────────────────────────────────────────────────

    /// A valid proof wrapped in BulletproofProof verifies via `.verify()`.
    #[test]
    fn bulletproof_proof_verify_valid() {
        let g = gens();
        let proof = prove(&g, u256::from(42u8), u256::from(7u8), &[100u8; 64]).unwrap();
        let bp = BulletproofProof::new(proof, g);
        assert!(bp.verify());
    }

    /// A tampered proof wrapped in BulletproofProof fails verification.
    #[test]
    fn bulletproof_proof_verify_tampered() {
        let g = gens();
        let mut proof = prove(&g, u256::from(42u8), u256::from(7u8), &[101u8; 64]).unwrap();
        proof.t_hat = f_add(proof.t_hat, u256::from(1u8));
        let bp = BulletproofProof::new(proof, g);
        assert!(!bp.verify());
    }

    /// Accessor methods return correct data from the wrapped proof.
    #[test]
    fn bulletproof_proof_accessors() {
        let g = gens();
        let proof = prove(&g, u256::from(99u8), u256::from(3u8), &[102u8; 64]).unwrap();
        let bp = BulletproofProof::new(proof, g);

        // Commitment matches.
        assert_eq!(bp.commitment(), proof.v);

        // L/R round vectors match.
        assert_eq!(*bp.l_vec(), proof.ip_proof.l);
        assert_eq!(*bp.r_vec(), proof.ip_proof.r);

        // Final scalars match.
        assert_eq!(bp.final_a(), proof.ip_proof.a);
        assert_eq!(bp.final_b(), proof.ip_proof.b);

        // Generator accessors return the same arrays.
        assert_eq!(bp.g_generators()[0], g.g[0]);
        assert_eq!(bp.h_generators()[0], g.h[0]);
        assert_eq!(bp.blinding_generator(), g.h_blind);

        // range_proof() and gens() return references to the inner data.
        assert_eq!(*bp.range_proof(), proof);
        assert_eq!(bp.gens().h_blind, g.h_blind);
    }

    /// BulletproofProofRef verifies without copying the generator arrays.
    #[test]
    fn bulletproof_proof_ref_verify() {
        let g = gens();
        let proof = prove(&g, u256::from(10u8), u256::from(5u8), &[103u8; 64]).unwrap();
        let bp_ref = BulletproofProofRef::new(&proof, &g);
        assert!(bp_ref.verify());
    }

    /// BulletproofProofRef accessors return correct data.
    #[test]
    fn bulletproof_proof_ref_accessors() {
        let g = gens();
        let proof = prove(&g, u256::from(77u8), u256::from(2u8), &[104u8; 64]).unwrap();
        let bp_ref = BulletproofProofRef::new(&proof, &g);

        assert_eq!(bp_ref.commitment(), proof.v);
        let (a, b) = bp_ref.final_scalars();
        assert_eq!(a, proof.ip_proof.a);
        assert_eq!(b, proof.ip_proof.b);
        assert_eq!(bp_ref.g_generators()[0], g.g[0]);
        assert_eq!(bp_ref.blinding_generator(), g.h_blind);
    }

    /// Promoting a BulletproofProofRef to owned BulletproofProof preserves
    /// verification.
    #[test]
    fn bulletproof_proof_ref_to_owned() {
        let g = gens();
        let proof = prove(&g, u256::from(55u8), u256::from(11u8), &[105u8; 64]).unwrap();
        let bp_ref = BulletproofProofRef::new(&proof, &g);
        let bp_owned = bp_ref.to_owned();
        assert!(bp_owned.verify());
        assert_eq!(bp_owned.commitment(), proof.v);
    }
}
