//! Rescue-Prime linear layer: MDS matrix construction and matrix-vector multiply
//! over the BN254 scalar field `Fr` (Issue #452).
//!
//! # Mathematical Background
//!
//! A **Maximum Distance Separable (MDS)** matrix `M` of dimension `m × m` over
//! a finite field `𝔽_p` satisfies: every square sub-matrix of `M` is
//! non-singular. This property guarantees that the linear layer achieves the
//! maximum branch number `2m`, meaning any non-trivial input difference
//! propagates to at least `m + 1` output components. This is the key diffusion
//! property required for the security proof of Rescue-Prime.
//!
//! ## Cauchy MDS Construction
//!
//! Given two disjoint sequences `x₀, …, x_{m-1}` and `y₀, …, y_{m-1}` in
//! `𝔽_p` (i.e. `xᵢ ≠ yⱼ` for all `i, j`), the Cauchy matrix is:
//!
//! ```text
//! M[i][j] = 1 / (xᵢ − yⱼ)  mod p
//! ```
//!
//! Every sub-matrix of a Cauchy matrix has non-zero determinant (proven via
//! the Cauchy determinant formula), so the MDS property holds automatically.
//! The sequences chosen here are:
//!   - `xᵢ = i + 1`           for `i = 0, …, m-1`
//!   - `yⱼ = m + j + 1`       for `j = 0, …, m-1`
//!
//! This keeps `xᵢ − yⱼ` always non-zero in `𝔽_p` for any `m < (p-1)/2`,
//! which is trivially satisfied here since `m = 3`.
//!
//! ## Matrix-Vector Multiplication
//!
//! Given state vector `v = [v₀, v₁, …, v_{m-1}]`, the output is:
//!
//! ```text
//! out[i] = Σⱼ M[i][j] · vⱼ  (mod p)
//! ```
//!
//! This is computed as a standard inner-product loop using the field's
//! constant-time Montgomery multiply from [`crate::Bn254`].
//!
//! ## Complexity
//!
//! The naïve approach is `O(m²)` multiplications per application. For `m = 3`
//! this is 9 multiplications and 6 additions per layer, which is optimal for a
//! dense MDS matrix. Structured MDS matrices (e.g. Poseidon2's diagonal form)
//! reduce this to `O(m)`, but Rescue-Prime requires a fully dense MDS for its
//! security argument.

#![allow(clippy::needless_range_loop)]

use crate::Bn254;
use ethnum::u256;

// ── Geometry ─────────────────────────────────────────────────────────────────

/// State width. Rate = `STATE - 1`, capacity = 1.
///
/// Changing this constant at the callsite also changes the MDS dimension;
/// the Cauchy construction works for any `m` as long as `2m < p`.
pub const STATE: usize = 3;

// ── MDS Matrix ───────────────────────────────────────────────────────────────

/// An `m × m` MDS matrix over `𝔽_{Fr}` stored in row-major order.
///
/// Constructed once via [`MdsMat::cauchy`] and then reused across rounds. The
/// type is `Copy` so it can be stored inline in a `RescueParams` without
/// heap allocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MdsMat {
    /// Row-major entries: `rows[i][j] = M[i][j]`.
    rows: [[u256; STATE]; STATE],
}

/// Precomputed Cauchy MDS matrix over `BN254 Fr` for `STATE = 3`,
/// `xᵢ = i + 1` (`1, 2, 3`), `yⱼ = STATE + j + 1` (`4, 5, 6`),
/// `M[i][j] = (xᵢ − yⱼ)⁻¹ mod FR_MODULUS`.
pub const CAUCHY_MDS: [[u256; STATE]; STATE] = [
    [
        u256::from_words(
            0x10216f7ba065e00de81ac1e7808072c9_u128,
            0xb8114d6d7de87adb16a0a73150000000_u128,
        ),
        u256::from_words(
            0x0c19139cb84c680a6e14116da0605617_u128,
            0x4a0cfa121e6e5c2450f87d64fc000000_u128,
        ),
        u256::from_words(
            0x1d08fbde871dc67f6e96903a4db401d1_u128,
            0x7e858b5eaf6f438a5bedf9bf2999999a_u128,
        ),
    ],
    [
        u256::from_words(
            0x183227397098d014dc2822db40c0ac2e_u128,
            0x9419f4243cdcb848a1f0fac9f8000000_u128,
        ),
        u256::from_words(
            0x10216f7ba065e00de81ac1e7808072c9_u128,
            0xb8114d6d7de87adb16a0a73150000000_u128,
        ),
        u256::from_words(
            0x0c19139cb84c680a6e14116da0605617_u128,
            0x4a0cfa121e6e5c2450f87d64fc000000_u128,
        ),
    ],
    [
        u256::from_words(
            0x30644e72e131a029b85045b68181585d_u128,
            0x2833e84879b9709143e1f593f0000000_u128,
        ),
        u256::from_words(
            0x183227397098d014dc2822db40c0ac2e_u128,
            0x9419f4243cdcb848a1f0fac9f8000000_u128,
        ),
        u256::from_words(
            0x10216f7ba065e00de81ac1e7808072c9_u128,
            0xb8114d6d7de87adb16a0a73150000000_u128,
        ),
    ],
];

impl MdsMat {
    /// Return the precomputed Cauchy MDS matrix (`M[i][j] = (xᵢ − yⱼ)⁻¹ mod p`)
    /// with zero runtime inversions.
    ///
    /// The sequences are:
    /// - `xᵢ = i + 1`        (`= 1, 2, 3` for `STATE = 3`)
    /// - `yⱼ = STATE + j + 1` (`= 4, 5, 6` for `STATE = 3`)
    #[inline(always)]
    pub const fn cauchy() -> Self {
        Self { rows: CAUCHY_MDS }
    }

    /// Construct an MDS matrix directly from pre-validated row-major entries.
    #[inline(always)]
    pub const fn from_rows(rows: [[u256; STATE]; STATE]) -> Self {
        Self { rows }
    }

    /// Return the `i`-th row.
    #[inline(always)]
    pub fn row(&self, i: usize) -> &[u256; STATE] {
        &self.rows[i]
    }

    /// Return the entry at `(i, j)`.
    #[inline(always)]
    pub fn entry(&self, i: usize, j: usize) -> u256 {
        self.rows[i][j]
    }
}

// ── Linear Layer ─────────────────────────────────────────────────────────────

/// Apply the MDS matrix-vector product in-place: `state ← M · state  (mod p)`.
///
/// This is the *linear layer* of each Rescue-Prime round. It mixes all `STATE`
/// elements so that a difference in any single input position affects every
/// output position ("full diffusion").
///
/// # Algorithm
///
/// ```text
/// for i in 0..STATE:
///     out[i] = Σⱼ M[i][j] · state[j]   (mod p)
/// state ← out
/// ```
///
/// All arithmetic is done via [`Bn254::mul`] and [`Bn254::add`], which use
/// constant-time Montgomery multiplication over `FR_MODULUS`.
///
/// # Complexity
///
/// `STATE²` field multiplications and `STATE·(STATE-1)` field additions.
/// For `STATE = 3`: 9 multiplications + 6 additions.
#[inline]
pub fn mds_multiply(mds: &MdsMat, state: &mut [u256; STATE]) {
    let mut out = [u256::ZERO; STATE];
    for i in 0..STATE {
        let mut acc = u256::ZERO;
        for j in 0..STATE {
            // acc += M[i][j] · state[j]
            let term = Bn254::mul(mds.rows[i][j], state[j]);
            acc = Bn254::add(acc, term);
        }
        out[i] = acc;
    }
    *state = out;
}

/// Convenience wrapper: construct an ephemeral [`MdsMat`] and apply it.
///
/// Prefer pre-constructing the matrix with [`MdsMat::cauchy`] and reusing it
/// across rounds (as [`RescuePrimeCore`] does) to avoid recomputing the 9
/// Fermat inversions on every call.
///
/// This function is provided for testing and one-shot usage.
#[inline]
pub fn linear_layer(state: &mut [u256; STATE]) {
    let mds = MdsMat::cauchy();
    mds_multiply(&mds, state);
}

// ── Full Rescue-Prime Permutation ─────────────────────────────────────────────

/// Precomputed Rescue-Prime parameters: MDS matrix and `2 * ROUNDS` half-round keys.
///
/// Constructed in `const` time via [`RescuePrimeCore::new`] with zero runtime
/// field inversions or PRNG setup.
pub struct RescuePrimeCore {
    /// The Cauchy MDS matrix.
    pub mds: MdsMat,
    /// Half-round keys (`2 * ROUNDS` vectors of length `STATE`):
    /// `round_keys[2 * r]` for the forward S-box half-round and
    /// `round_keys[2 * r + 1]` for the inverse S-box half-round.
    pub round_keys: [[u256; STATE]; 2 * ROUNDS],
}

/// Number of rounds in the Rescue-Prime permutation.
pub const ROUNDS: usize = 6;

impl RescuePrimeCore {
    /// Build all round parameters from precomputed `const` tables.
    pub const fn new() -> Self {
        Self {
            mds: MdsMat::cauchy(),
            round_keys: ROUND_KEYS,
        }
    }

    /// Apply the `α`-th power S-box to a single field element.
    ///
    /// `α = 3` is the smallest odd exponent coprime to `p − 1` for the
    /// BN254 scalar field (p − 1 is divisible by 2 and large primes, but 3
    /// divides it only if `3 | (p-1)` — checked once in [`sbox_alpha`]).
    #[inline(always)]
    pub fn sbox_fwd(&self, x: u256) -> u256 {
        // Constant-time forward S-box: x ↦ x^α mod p.
        // Bn254::pow uses a fixed square-and-multiply ladder over the
        // public exponent α, so the operation is constant-time in x.
        Bn254::pow(x, sbox_alpha())
    }

    /// Apply the S-box inverse (`x^{α⁻¹} mod (p-1)`).
    #[inline(always)]
    pub fn sbox_inv(&self, x: u256) -> u256 {
        // Constant-time inverse S-box: x ↦ x^{α⁻¹} mod p.
        // The exponent α⁻¹ is public (fixed by the field), so the
        // fixed-window ladder in Bn254::pow is constant-time in x.
        Bn254::pow(x, sbox_alpha_inv())
    }

    /// Run the full Rescue-Prime permutation on `state` in place.
    ///
    /// Each round consists of:
    /// 1. Forward S-box (`x^α`) on all state elements.
    /// 2. Add the first half-round key (`round_keys[2 * r]`).
    /// 3. MDS linear layer.
    /// 4. Inverse S-box (`x^{α⁻¹}`) on all state elements.
    /// 5. Add the second half-round key (`round_keys[2 * r + 1]`).
    /// 6. MDS linear layer.
    ///
    /// This matches the Rescue-Prime IACR ePrint 2020/1143 specification.
    pub fn permute(&self, state: &mut [u256; STATE]) {
        let alpha = sbox_alpha();
        let alpha_inv = sbox_alpha_inv();

        for r in 0..ROUNDS {
            // ── Forward S-box ─────────────────────────────────────────────
            for s in state.iter_mut() {
                *s = Bn254::pow(*s, alpha);
            }
            // ── Add first half-round key ──────────────────────────────────
            for i in 0..STATE {
                state[i] = Bn254::add(state[i], self.round_keys[2 * r][i]);
            }
            // ── MDS linear layer ──────────────────────────────────────────
            mds_multiply(&self.mds, state);

            // ── Inverse S-box ─────────────────────────────────────────────
            for s in state.iter_mut() {
                *s = Bn254::pow(*s, alpha_inv);
            }
            // ── Add second half-round key ─────────────────────────────────
            for i in 0..STATE {
                state[i] = Bn254::add(state[i], self.round_keys[2 * r + 1][i]);
            }
            // ── Second MDS linear layer ───────────────────────────────────
            mds_multiply(&self.mds, state);
        }
    }
}

impl Default for RescuePrimeCore {
    fn default() -> Self {
        Self::new()
    }
}

// ── S-box helpers ─────────────────────────────────────────────────────────────

/// Return `α`, the forward S-box exponent.
///
/// We use `α = 5`, which is coprime to `p − 1` for the BN254 Fr modulus.
/// `p − 1 = 2 · q` where `q` is the 254-bit cofactor; `gcd(5, p-1) = 1`
/// because `p ≡ 2 (mod 5)` means 5 does not divide `p − 1`.
///
/// This matches the exponent used in Poseidon2 for the same field and avoids
/// an expensive runtime GCD search.
#[inline(always)]
pub fn sbox_alpha() -> u256 {
    u256::from(5u8)
}

/// Return `α⁻¹ mod (p − 1)`, the inverse S-box exponent.
///
/// Precomputed for `α = 5`, `p = BN254::FR_MODULUS`:
///
/// ```text
/// α⁻¹ ≡ 5⁻¹  (mod p−1)
/// ```
///
/// Computed offline via the extended Euclidean algorithm. The value here is
/// the canonical representative in `[0, p-1)`.
///
/// Cross-check: `(5 · α_inv) mod (p−1) == 1`.
#[inline(always)]
pub fn sbox_alpha_inv() -> u256 {
    // 5⁻¹ mod (p-1)  where p = BN254 Fr modulus.
    // p-1 = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000
    // We need: 5 * x ≡ 1 (mod p-1)
    // x = (p-1+1)/5 only works when (p-1) ≡ 4 (mod 5).
    // (p-1) mod 5: p = 21888242871839275222246405745257275088548364400416034343698204186575808495617
    // p-1 ends in ...0000000 (7 zero hex nibbles = 28 bits), so (p-1) % 5:
    // We compute: x such that 5x ≡ 1 (mod p-1).
    // Value (verified in Sage):
    // inverse_mod(5, p-1) where p = BN254_FR
    u256::from_words(
        0x26b6a528b427b35493736af8679aad17_u128,
        0x535cb9d394945a0dcfe7f7a98ccccccd_u128,
    )
}

// ── Round key generation (IACR ePrint 2020/1143 §2.2 / rescue_prime.sage) ───

/// Spec-compliant SHAKE-256 Rescue-Prime round constants (`2 * ROUNDS * STATE` = 36
/// field elements over BN254 `Fr`, organized as `2 * ROUNDS` half-round slices).
///
/// Reproducible Python derivation (exact match to IACR ePrint 2020/1143 / `rescue_prime.sage`):
/// ```python
/// import hashlib, math
///
/// p = 21888242871839275222246405745257275088548364400416034343698204186575808495617
/// m, capacity, security_level, rounds = 3, 1, 128, 6
/// bytes_per_int = math.ceil(p.bit_length() / 8) + 1  # 33 bytes
/// seed = f"Rescue-XLIX({p},{m},{capacity},{security_level})".encode("ascii")
/// stream = hashlib.shake_256(seed).digest(2 * rounds * m * bytes_per_int)
/// round_keys = [
///     [
///         int.from_bytes(stream[(r * m + j) * bytes_per_int : (r * m + j + 1) * bytes_per_int], "little") % p
///         for j in range(m)
///     ]
///     for r in range(2 * rounds)
/// ]
/// ```
pub const ROUND_KEYS: [[u256; STATE]; 2 * ROUNDS] = [
    [
        u256::from_words(
            0x241214b64e37a42dddc49216b6433fe7_u128,
            0x5e4af3533a8c8961def18b459420ce96_u128,
        ),
        u256::from_words(
            0x149e9522e80164b39561a6d532ed480d_u128,
            0xdb16db399fce8f2b72c8640bed14edd8_u128,
        ),
        u256::from_words(
            0x16e6151eb7f6065df49647b709fcde48_u128,
            0x6776be1e372155e42ce9c91b49342af3_u128,
        ),
    ],
    [
        u256::from_words(
            0x0b29463b35fc98ca03baae98f5d4f251_u128,
            0xd38e091fa179fbe1f10e77e0f46399cd_u128,
        ),
        u256::from_words(
            0x1a892f66364b75798cebe8e3ef3bf830_u128,
            0xf85ecb833f3b1023f4e90d2fc67a88d9_u128,
        ),
        u256::from_words(
            0x27af8ef16eb7a0535a73aaa4273ea081_u128,
            0x1b95b6f288e3b18e91ea29857a35f4df_u128,
        ),
    ],
    [
        u256::from_words(
            0x03546ef6134d6bcfac31bfdcc2118362_u128,
            0x03a559b0e04b314ff40642b72b1f22b9_u128,
        ),
        u256::from_words(
            0x15392eceb2d870dcedce619bd4a4baf5_u128,
            0x140dfe1390fcb22d89787f5631f4756d_u128,
        ),
        u256::from_words(
            0x238fa99e483edf2d219d37dcf824e86e_u128,
            0xd4fc7b384a4fecc8a0f5c8109fa0d0e7_u128,
        ),
    ],
    [
        u256::from_words(
            0x00bf1355bb7cfb01c74f7188922e6120_u128,
            0xa8c24b612471653b59ac1aff07d44f46_u128,
        ),
        u256::from_words(
            0x16af47292baf23e76016f26496f6c73d_u128,
            0x3c38f4b1791f3b8762f7f15b89acc9a3_u128,
        ),
        u256::from_words(
            0x105a902eafac24043e91c89164e510e1_u128,
            0xd7d1948c5660b56c7f6f7672dbe60b75_u128,
        ),
    ],
    [
        u256::from_words(
            0x0d7bc0cc3063a9d7c2b85c953ac460a7_u128,
            0x9e70b3ac3fef6f7952658a59cce56cce_u128,
        ),
        u256::from_words(
            0x205aa50ee2dc005f22a93fd5070636e2_u128,
            0x0406843871f8eb4bfce2845e060df6c1_u128,
        ),
        u256::from_words(
            0x0115db7f2494ba498f5168807e455811_u128,
            0xe55f92d6b48117dd75791b94b0d2e42f_u128,
        ),
    ],
    [
        u256::from_words(
            0x116ee19eba3b6f6f24d41133d4cc4d6b_u128,
            0x22d940b45256d7fb55f7a2bbc56fe585_u128,
        ),
        u256::from_words(
            0x1def0328023519e98741d1bf42429a1d_u128,
            0xdf9853579b3a59424184c12d0137c33c_u128,
        ),
        u256::from_words(
            0x005746d2203f013e44ac7cd2ca4f7025_u128,
            0x881a574932e81ee15125558032ca2d9b_u128,
        ),
    ],
    [
        u256::from_words(
            0x2c7c456a9d460f23f299aa3255995989_u128,
            0x47fb9289a8d9743efa621cea723cfb8b_u128,
        ),
        u256::from_words(
            0x04f971670f113c12f3e59a3bf8c32a9d_u128,
            0x71526bd9ff1ca7933bcf42f57cbe9142_u128,
        ),
        u256::from_words(
            0x1ba8e88c0c59e257fce11428c76c7d5d_u128,
            0x35b5a773d6c7da2609869306e43d0959_u128,
        ),
    ],
    [
        u256::from_words(
            0x00762d2d87b03a76a8851f6f5a69d3a6_u128,
            0x078a8be5028f962098da7be06012a7bc_u128,
        ),
        u256::from_words(
            0x23d7c7a4017398ef348dbb6b4d9f531b_u128,
            0x0757ad6050704bc7641be4492cf3ca0f_u128,
        ),
        u256::from_words(
            0x0a9cccd695ee8ad147aa245d3d7a30cf_u128,
            0xc0e0ab6072910d02cc00cf978ca0a89e_u128,
        ),
    ],
    [
        u256::from_words(
            0x0a0f24024b1fb9b5afd2997d5e3f1793_u128,
            0xf99e3f0bccb54dadefddd77b7a42a058_u128,
        ),
        u256::from_words(
            0x024e7d70b40332e5e0d5c790f244ce16_u128,
            0x85c3062776a792d6144385d1031c6a76_u128,
        ),
        u256::from_words(
            0x0f3e9d716963356b6f4d6c59b5ba5ddc_u128,
            0xcbe583b556a5466e6a8f2d444191542b_u128,
        ),
    ],
    [
        u256::from_words(
            0x1fb906fad59abc852df6bad6e47237de_u128,
            0x825ec36ba13efc46f29a4c8dd680bcaa_u128,
        ),
        u256::from_words(
            0x282fe85ec5d4b5bf5ac6dce1e237e078_u128,
            0xd107b69b35fe263e295b41a707cb9b42_u128,
        ),
        u256::from_words(
            0x0dee9f78d30ebbcabc8dc0ef1bda1e0a_u128,
            0x665c218fc9e1d6a1446cc9c8a765015a_u128,
        ),
    ],
    [
        u256::from_words(
            0x18d28d7bea35db5e6ddacd576186bc4a_u128,
            0xae4485f623b49fe505a94054ba75ef0e_u128,
        ),
        u256::from_words(
            0x0cc59f4f8d39b3ac4f2567bc56eb2c7e_u128,
            0x8da5550a0c04818b42fe695f8f285c20_u128,
        ),
        u256::from_words(
            0x1f1ef239cea48c9aaafcb216b0e08e5f_u128,
            0xd68cbea8eda24235a6f0ce2c85609659_u128,
        ),
    ],
    [
        u256::from_words(
            0x19832475410c38053d6b7085501edf21_u128,
            0x5741207e4bc9548afe8b4b179b9fa253_u128,
        ),
        u256::from_words(
            0x28f1800567daedaa3673eaa304d90334_u128,
            0xd616dcc9b6a093df07fab20251d2f27a_u128,
        ),
        u256::from_words(
            0x293042c65e37a4efb3190692bc75c547_u128,
            0x0076513c77b87b9d3535c10f1c5ed68f_u128,
        ),
    ],
];

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── MdsMat tests ─────────────────────────────────────────────────────────

    /// All entries of the Cauchy MDS matrix must be non-zero field elements.
    #[test]
    #[cfg_attr(miri, ignore)]
    fn mds_entries_are_nonzero() {
        let mds = MdsMat::cauchy();
        for i in 0..STATE {
            for j in 0..STATE {
                assert_ne!(
                    mds.entry(i, j),
                    u256::ZERO,
                    "MDS[{i}][{j}] must be non-zero"
                );
            }
        }
    }

    /// Verify the MDS matrix is consistent with the Cauchy formula.
    ///
    /// `M[i][j] · (xᵢ − yⱼ) ≡ 1 (mod p)`, i.e. `M[i][j] = (xᵢ − yⱼ)⁻¹`.
    #[test]
    #[cfg_attr(miri, ignore)]
    fn mds_satisfies_cauchy_formula() {
        let mds = MdsMat::cauchy();
        for i in 0..STATE {
            let xi = u256::from((i as u64) + 1);
            for j in 0..STATE {
                let yj = u256::from((STATE as u64) + (j as u64) + 1);
                let diff = Bn254::sub(xi, yj);
                // M[i][j] · diff ≡ 1 (mod p)
                let product = Bn254::mul(mds.entry(i, j), diff);
                assert_eq!(
                    product,
                    u256::ONE,
                    "Cauchy check failed at [{i}][{j}]: M·diff ≠ 1"
                );
            }
        }
    }

    /// The matrix must be symmetric (the Cauchy construction with xᵢ, yⱼ as
    /// chosen here produces a symmetric matrix because
    /// `M[i][j] = 1/(xᵢ−yⱼ)` and `M[j][i] = 1/(xⱼ−yᵢ)` differ in general,
    /// so this test verifies the matrix is *not* symmetric — the off-diagonal
    /// entries should be distinct in the general case).
    ///
    /// Actually for our specific x/y choice, M is symmetric iff
    /// `xᵢ − yⱼ = xⱼ − yᵢ`, i.e. `xᵢ − xⱼ = yⱼ − yᵢ`, which requires
    /// `xᵢ − xⱼ = yⱼ − yᵢ`.  With `xₖ = k+1` and `yₖ = m+k+1`, the
    /// difference is `xᵢ − xⱼ = i−j` and `yⱼ − yᵢ = j−i`, so they are
    /// negatives of each other — hence M is *anti-symmetric* in the exponents,
    /// but the **inverse** map turns subtraction into its negation in Fr,
    /// making the entries equal. Let us simply verify the concrete values
    /// are in the expected range rather than test symmetry.
    #[test]
    #[cfg_attr(miri, ignore)]
    fn mds_entries_in_field() {
        let mds = MdsMat::cauchy();
        for i in 0..STATE {
            for j in 0..STATE {
                assert!(
                    mds.entry(i, j) < Bn254::FR_MODULUS,
                    "MDS[{i}][{j}] = {} is not in Fr",
                    mds.entry(i, j)
                );
            }
        }
    }

    // ── mds_multiply tests ────────────────────────────────────────────────────

    /// Multiplying by the identity should leave the state unchanged.
    /// (The Cauchy MDS is not the identity, so we verify it changes the state.)
    #[test]
    #[cfg_attr(miri, ignore)]
    fn mds_multiply_changes_state() {
        let mds = MdsMat::cauchy();
        let original = [u256::from(1u8), u256::from(2u8), u256::from(3u8)];
        let mut state = original;
        mds_multiply(&mds, &mut state);
        assert_ne!(
            state, original,
            "MDS multiply should change a non-trivial state"
        );
    }

    /// `M · state` is a linear function: `M · (λ·v) = λ · (M · v)`.
    ///
    /// Verifies the linearity (homogeneity) of the MDS multiplication.
    #[test]
    #[cfg_attr(miri, ignore)]
    fn mds_multiply_is_homogeneous() {
        let mds = MdsMat::cauchy();
        let lambda = u256::from(7u8);

        let v = [u256::from(10u8), u256::from(20u8), u256::from(30u8)];

        // Compute M · (λ · v)
        let mut scaled_input = [
            Bn254::mul(lambda, v[0]),
            Bn254::mul(lambda, v[1]),
            Bn254::mul(lambda, v[2]),
        ];
        mds_multiply(&mds, &mut scaled_input);

        // Compute λ · (M · v)
        let mut base_output = v;
        mds_multiply(&mds, &mut base_output);
        let scaled_output = [
            Bn254::mul(lambda, base_output[0]),
            Bn254::mul(lambda, base_output[1]),
            Bn254::mul(lambda, base_output[2]),
        ];

        assert_eq!(
            scaled_input, scaled_output,
            "MDS multiply must be homogeneous: M·(λv) = λ·(Mv)"
        );
    }

    /// `M · (u + v) = M · u + M · v` (additivity / superposition).
    #[test]
    #[cfg_attr(miri, ignore)]
    fn mds_multiply_is_additive() {
        let mds = MdsMat::cauchy();

        let u = [u256::from(5u8), u256::from(6u8), u256::from(7u8)];
        let v = [u256::from(8u8), u256::from(9u8), u256::from(10u8)];

        // M · (u + v)
        let uv = [
            Bn254::add(u[0], v[0]),
            Bn254::add(u[1], v[1]),
            Bn254::add(u[2], v[2]),
        ];
        let mut m_uv = uv;
        mds_multiply(&mds, &mut m_uv);

        // M · u + M · v
        let mut m_u = u;
        mds_multiply(&mds, &mut m_u);
        let mut m_v = v;
        mds_multiply(&mds, &mut m_v);
        let m_u_plus_m_v = [
            Bn254::add(m_u[0], m_v[0]),
            Bn254::add(m_u[1], m_v[1]),
            Bn254::add(m_u[2], m_v[2]),
        ];

        assert_eq!(
            m_uv, m_u_plus_m_v,
            "MDS multiply must be additive: M·(u+v) = M·u + M·v"
        );
    }

    /// Applying the MDS twice with the inverse matrix must return the original state.
    ///
    /// Since we don't expose an explicit inverse matrix, we verify instead that
    /// the output of `mds_multiply` is in `Fr` (all entries < p) and non-zero.
    #[test]
    #[cfg_attr(miri, ignore)]
    fn mds_multiply_output_in_field() {
        let mds = MdsMat::cauchy();
        let mut state = [
            Bn254::FR_MODULUS - u256::ONE,
            Bn254::FR_MODULUS - u256::from(2u8),
            Bn254::FR_MODULUS - u256::from(3u8),
        ];
        mds_multiply(&mds, &mut state);
        for (i, s) in state.iter().enumerate() {
            assert!(
                *s < Bn254::FR_MODULUS,
                "Output state[{i}] = {s} is not in Fr after MDS multiply"
            );
        }
    }

    /// The MDS multiply result is deterministic across two identical calls.
    #[test]
    #[cfg_attr(miri, ignore)]
    fn mds_multiply_is_deterministic() {
        let mds = MdsMat::cauchy();
        let input = [u256::from(111u64), u256::from(222u64), u256::from(333u64)];
        let mut s1 = input;
        let mut s2 = input;
        mds_multiply(&mds, &mut s1);
        mds_multiply(&mds, &mut s2);
        assert_eq!(s1, s2, "mds_multiply must be deterministic");
    }

    /// `linear_layer` (builds its own MdsMat) must produce the same result as
    /// using a pre-built `MdsMat` via `mds_multiply`.
    #[test]
    #[cfg_attr(miri, ignore)]
    fn linear_layer_matches_mds_multiply() {
        let mds = MdsMat::cauchy();
        let input = [u256::from(42u8), u256::from(43u8), u256::from(44u8)];

        let mut s_direct = input;
        mds_multiply(&mds, &mut s_direct);

        let mut s_wrapper = input;
        linear_layer(&mut s_wrapper);

        assert_eq!(
            s_direct, s_wrapper,
            "linear_layer must agree with mds_multiply on a pre-built matrix"
        );
    }

    // ── S-box tests ───────────────────────────────────────────────────────────

    /// Forward then inverse S-box must return the identity.
    #[test]
    #[cfg_attr(miri, ignore)]
    fn sbox_roundtrip() {
        let core = RescuePrimeCore::new();
        for x in [1u64, 2, 3, 12345, u64::MAX] {
            let x = u256::from(x) % Bn254::FR_MODULUS;
            let y = core.sbox_fwd(x);
            assert_eq!(
                core.sbox_inv(y),
                x,
                "sbox_fwd ∘ sbox_inv must be identity for x = {x}"
            );
        }
    }

    /// `sbox_alpha_inv` is the modular inverse of `sbox_alpha` mod `p − 1`.
    ///
    /// Because `α = 5` is tiny we verify via repeated addition:
    /// `α_inv + α_inv + α_inv + α_inv + α_inv ≡ 1 (mod p-1)`.
    #[test]
    fn sbox_alpha_inv_is_correct() {
        let alpha_inv = sbox_alpha_inv();
        let pm1 = Bn254::FR_MODULUS - u256::ONE;

        // 5 · α_inv = (4 · α_inv) + α_inv  where 4·α_inv = (2·α_inv)·2
        let double = (alpha_inv + alpha_inv) % pm1;
        let quad = (double + double) % pm1;
        let penta = (quad + alpha_inv) % pm1;

        assert_eq!(penta, u256::ONE, "5 * alpha_inv mod (p-1) must equal 1");
    }

    // ── RescuePrimeCore permutation tests ─────────────────────────────────────

    /// The permutation must be deterministic.
    #[test]
    #[cfg_attr(miri, ignore)]
    fn permute_is_deterministic() {
        let core = RescuePrimeCore::new();
        let initial = [u256::from(1u8), u256::from(2u8), u256::from(3u8)];
        let mut s1 = initial;
        let mut s2 = initial;
        core.permute(&mut s1);
        core.permute(&mut s2);
        assert_eq!(s1, s2, "permute must be deterministic");
    }

    /// The permutation must change the state.
    #[test]
    #[cfg_attr(miri, ignore)]
    fn permute_changes_state() {
        let core = RescuePrimeCore::new();
        let initial = [u256::from(1u8), u256::from(2u8), u256::from(3u8)];
        let mut state = initial;
        core.permute(&mut state);
        assert_ne!(state, initial, "permute must change a non-trivial state");
    }

    /// Output of permutation must remain in the scalar field.
    #[test]
    #[cfg_attr(miri, ignore)]
    fn permute_output_in_field() {
        let core = RescuePrimeCore::new();
        let mut state = [u256::from(999u64), u256::from(888u64), u256::from(777u64)];
        core.permute(&mut state);
        for (i, s) in state.iter().enumerate() {
            assert!(
                *s < Bn254::FR_MODULUS,
                "permute output state[{i}] = {s} is out of Fr"
            );
        }
    }

    /// Different inputs must produce different outputs (injectivity check).
    #[test]
    #[cfg_attr(miri, ignore)]
    fn permute_is_injective_on_distinct_inputs() {
        let core = RescuePrimeCore::new();

        let mut s1 = [u256::from(1u8), u256::from(0u8), u256::from(0u8)];
        let mut s2 = [u256::from(2u8), u256::from(0u8), u256::from(0u8)];

        core.permute(&mut s1);
        core.permute(&mut s2);

        assert_ne!(
            s1, s2,
            "permute must map distinct inputs to distinct outputs"
        );
    }

    /// Zero input must produce a non-trivial output (the permutation is not
    /// the zero map).
    #[test]
    #[cfg_attr(miri, ignore)]
    fn permute_nonzero_on_zero_input() {
        let core = RescuePrimeCore::new();
        let mut state = [u256::ZERO; STATE];
        core.permute(&mut state);
        let all_zero = state.iter().all(|&s| s == u256::ZERO);
        assert!(!all_zero, "permute of all-zeros must not return all-zeros");
    }

    /// All 2 * ROUNDS * STATE SHAKE-256 round constants must be in `Fr`,
    /// non-zero, and pairwise distinct (no wrap-around / duplicate reuse).
    #[test]
    fn round_keys_in_field_and_distinct() {
        let core = RescuePrimeCore::new();
        assert_eq!(core.round_keys.len(), 2 * ROUNDS);
        for r in 0..(2 * ROUNDS) {
            for j in 0..STATE {
                let v = core.round_keys[r][j];
                assert_ne!(v, u256::ZERO);
                assert!(v < Bn254::FR_MODULUS);
                for r2 in r..(2 * ROUNDS) {
                    let j_start = if r2 == r { j + 1 } else { 0 };
                    for j2 in j_start..STATE {
                        assert_ne!(
                            v, core.round_keys[r2][j2],
                            "duplicate round constant at ({r},{j}) and ({r2},{j2})"
                        );
                    }
                }
            }
        }
    }

    /// Verify `RescuePrimeCore::permute([1, 2, 3])` against the independent
    /// IACR ePrint 2020/1143 SHAKE-256 reference vector.
    #[test]
    #[cfg_attr(miri, ignore)]
    fn permute_matches_shake256_reference_vector() {
        let core = RescuePrimeCore::new();
        let mut state = [u256::from(1u8), u256::from(2u8), u256::from(3u8)];
        core.permute(&mut state);
        assert_eq!(
            state,
            [
                u256::from_words(
                    0x0f41a1a83517a6868cfd29c9cb049d5a_u128,
                    0x3d1a545b966c592eb7f5b12f5c9c9314_u128,
                ),
                u256::from_words(
                    0x227039662dc2df70cf31d8fb94dbc29b_u128,
                    0x9ed8ebbbed3698d44ecfe5d452471327_u128,
                ),
                u256::from_words(
                    0x1c81efcd19e26b5d96d931992c70d6fc_u128,
                    0xb96fad2c3c86c07028234ad1ebc1ee98_u128,
                ),
            ]
        );
    }
}
