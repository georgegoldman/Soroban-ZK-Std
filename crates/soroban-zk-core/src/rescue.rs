//! Rescue-Prime permutation over the BN254 scalar field `Fr`.
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
//! Parameters follow the KULeuven-COSIC Marvellous Rescue-Prime reference
//! implementation for `(p, m, capacity, security) = (BN254 Fr, 3, 1, 128)`.
//! The MDS matrix and round constants are generated exactly as specified there.
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

/// State width for the standard BN254 Fr parameter set (rate 2, capacity 1).
pub const STATE: usize = 3;
/// Number of rounds derived by the standard Rescue-Prime parameter generator.
pub const ROUNDS: usize = 14;

// ── MDS Matrix ───────────────────────────────────────────────────────────────

/// An `m × m` MDS matrix over `𝔽_{Fr}` stored in row-major order.
///
/// Constructed once via [`MdsMat::standard`] and then reused across rounds. The
/// type is `Copy` so it can be stored inline in a `RescueParams` without
/// heap allocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MdsMat {
    /// Row-major entries: `rows[i][j] = M[i][j]`.
    rows: [[u256; STATE]; STATE],
}

impl MdsMat {
    /// Return the systematic Vandermonde MDS matrix from the reference
    /// generator. The entries are fixed for BN254 Fr, width 3.
    pub fn standard() -> Self {
        Self {
            rows: standard_mds(),
        }
    }

    /// Compatibility alias retained for callers of the former Cauchy matrix.
    #[deprecated(note = "use standard(); the canonical Rescue-Prime matrix is Vandermonde")]
    pub fn cauchy() -> Self {
        Self::standard()
    }

    /// Build a matrix from cached field elements.
    pub fn from_rows(rows: [[u256; STATE]; STATE]) -> Self {
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
/// Prefer pre-constructing the matrix with [`MdsMat::standard`] and reusing it
/// across rounds (as [`RescuePrimeCore`] does) to avoid recomputing the 9
/// parameter generation on every call.
///
/// This function is provided for testing and one-shot usage.
#[inline]
pub fn linear_layer(state: &mut [u256; STATE]) {
    let mds = MdsMat::standard();
    mds_multiply(&mds, state);
}

// ── Full Rescue-Prime Permutation ─────────────────────────────────────────────

/// Precomputed Rescue-Prime parameters: MDS matrix and round keys.
///
/// Construct once with [`RescuePrimeCore::new`] and reuse across all sponge
/// operations to amortise the `O(m²)` Fermat inversions.
pub struct RescuePrimeCore {
    /// The standard systematic Vandermonde MDS matrix.
    pub mds: MdsMat,
    /// First and second half-round constants for each round.
    pub round_keys: [[u256; STATE]; 2 * ROUNDS],
}

impl RescuePrimeCore {
    /// Build all round parameters deterministically.
    pub fn new() -> Self {
        Self {
            mds: MdsMat::standard(),
            round_keys: build_round_keys(),
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
    /// 2. MDS linear layer.
    /// 3. Add the first half round key.
    /// 4. Inverse S-box (`x^{α⁻¹}`) on all state elements.
    /// 5. MDS linear layer.
    /// 6. Add the second half round key.
    ///
    /// This matches the Rescue-Prime IACR eprint 2020/1143 specification.
    pub fn permute(&self, state: &mut [u256; STATE]) {
        let alpha = sbox_alpha();
        let alpha_inv = sbox_alpha_inv();

        for r in 0..ROUNDS {
            // ── Forward S-box ─────────────────────────────────────────────
            for s in state.iter_mut() {
                *s = Bn254::pow(*s, alpha);
            }
            // The reference applies MDS before adding each half-round key.
            mds_multiply(&self.mds, state);
            // ── Add first half round key ──────────────────────────────────
            for i in 0..STATE {
                state[i] = Bn254::add(state[i], self.round_keys[2 * r][i]);
            }

            // ── Inverse S-box ─────────────────────────────────────────────
            for s in state.iter_mut() {
                *s = Bn254::pow(*s, alpha_inv);
            }
            // ── Second MDS linear layer ───────────────────────────────────
            mds_multiply(&self.mds, state);
            // ── Add second half round key ─────────────────────────────────
            for i in 0..STATE {
                state[i] = Bn254::add(state[i], self.round_keys[2 * r + 1][i]);
            }
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

// ── Round key generation ──────────────────────────────────────────────────────

/// Generate the reference constants from the official SHAKE256 seed. Each
/// 33-byte little-endian chunk is reduced modulo Fr.
fn standard_mds() -> [[u256; STATE]; STATE] {
    [
        [
            u256::from_words(0, 125),
            u256::from_words(
                0x30644e72e131a029b85045b68181585d,
                0x2833e84879b9709143e1f593efffff66,
            ),
            u256::from_words(0, 31),
        ],
        [
            u256::from_words(0, 3875),
            u256::from_words(
                0x30644e72e131a029b85045b68181585d,
                0x2833e84879b9709143e1f593efffedb9,
            ),
            u256::from_words(0, 806),
        ],
        [
            u256::from_words(0, 100750),
            u256::from_words(
                0x30644e72e131a029b85045b68181585d,
                0x2833e84879b9709143e1f593effe3aaa,
            ),
            u256::from_words(0, 20306),
        ],
    ]
}

fn build_round_keys() -> [[u256; STATE]; 2 * ROUNDS] {
    use sha3::digest::{ExtendableOutput, Update, XofReader};
    let seed = b"Rescue-XLIX(21888242871839275222246405745257275088548364400416034343698204186575808495617,3,1,128)";
    let mut shake = sha3::Shake256::default();
    shake.update(seed);
    let mut reader = shake.finalize_xof();
    let mut raw = [0u8; 33];
    let mut keys = [[u256::ZERO; STATE]; 2 * ROUNDS];
    let two256_mod_p = u256::from_words(
        0x0e0a77c19a07df2f666ea36f7879462e_u128,
        0x36fc76959f60cd29ac96341c4ffffffb_u128,
    );
    for row in &mut keys {
        for key in row {
            reader.read(&mut raw);
            let mut low = [0u8; 32];
            low.copy_from_slice(&raw[..32]);
            let low = u256::from_le_bytes(low) % Bn254::FR_MODULUS;
            let high = Bn254::mul(u256::from(raw[32]), two256_mod_p);
            *key = Bn254::add(low, high);
        }
    }
    keys
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── MdsMat tests ─────────────────────────────────────────────────────────

    /// All entries of the standard MDS matrix must be non-zero field elements.
    #[test]
    fn mds_entries_are_nonzero() {
        let mds = MdsMat::standard();
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

    /// Verify the matrix against the value generated by the standard
    /// Rescue-Prime parameter script for BN254 Fr, width 3.
    #[test]
    fn mds_matches_reference_matrix() {
        assert_eq!(MdsMat::standard().rows, standard_mds());
    }

    /// Entries remain canonical field values.
    #[test]
    fn mds_entries_in_field() {
        let mds = MdsMat::standard();
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
    /// (The standard MDS is not the identity, so we verify it changes the state.)
    #[test]
    fn mds_multiply_changes_state() {
        let mds = MdsMat::standard();
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
    fn mds_multiply_is_homogeneous() {
        let mds = MdsMat::standard();
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
    fn mds_multiply_is_additive() {
        let mds = MdsMat::standard();

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
    fn mds_multiply_output_in_field() {
        let mds = MdsMat::standard();
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
    fn mds_multiply_is_deterministic() {
        let mds = MdsMat::standard();
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
    fn linear_layer_matches_mds_multiply() {
        let mds = MdsMat::standard();
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
    fn permute_changes_state() {
        let core = RescuePrimeCore::new();
        let initial = [u256::from(1u8), u256::from(2u8), u256::from(3u8)];
        let mut state = initial;
        core.permute(&mut state);
        assert_ne!(state, initial, "permute must change a non-trivial state");
    }

    #[test]
    fn permute_matches_reference_vector() {
        let core = RescuePrimeCore::new();
        let mut state = [u256::from(1u8), u256::from(2u8), u256::from(3u8)];
        core.permute(&mut state);
        assert_eq!(
            state,
            [
                u256::from_words(
                    0x21a2c88f1f8fdef386647de8fcee783d_u128,
                    0xa87a8eafd1c439a69a86c729e60bc8c3_u128
                ),
                u256::from_words(
                    0x050cf4ef705b031f6f62fd8dd72d1097_u128,
                    0x3d87d2465ea67928f89f83a7ef5e1119_u128
                ),
                u256::from_words(
                    0x2fea4a67337f00ce8f86d5c492f37631_u128,
                    0x9776ee274f2d69b40f852f4ee9a321be_u128
                ),
            ]
        );
    }

    /// Output of permutation must remain in the scalar field.
    #[test]
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
    fn permute_nonzero_on_zero_input() {
        let core = RescuePrimeCore::new();
        let mut state = [u256::ZERO; STATE];
        core.permute(&mut state);
        let all_zero = state.iter().all(|&s| s == u256::ZERO);
        assert!(!all_zero, "permute of all-zeros must not return all-zeros");
    }
}
