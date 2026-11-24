//! Halo2-style verifier primitives for PLONKish arithmetization.
//!
//! These are the foundational, `no_std`-compatible building blocks required to
//! verify Halo2-style proofs on Soroban:
//!
//! ## Gate / permutation layer (field arithmetic)
//!
//! * [`VerificationKey`] — generic over the circuit dimensions, holding the
//!   custom-gate configuration and the row/column permutation (`sigma`) argument.
//! * [`CustomGate`] / [`GateTerm`] — a stack-only representation of a custom gate
//!   as a sum of monomials over (column, rotation) witness cells.
//! * Permutation (grand-product) argument — [`VerificationKey::verify_permutation`]
//!   evaluates the β/γ challenge product over all cells.
//! * [`Accumulator`] — the recursion/accumulation state container that folds
//!   incoming commitments and folded scalar values without heap allocation.
//!
//! ## Commitment / verification-key layer (Issue #431)
//!
//! * [`Halo2Params`] — the *outer* Halo2 verification key that binds domain
//!   parameters, KZG setup, fixed-column commitments, and permutation
//!   commitments into a single validated structure.
//! * [`Halo2Domain`] — evaluation-domain parameters (`k`, `n = 2^k`, `ω`),
//!   including a helper to evaluate the vanishing polynomial `Z_H(x)`.
//! * [`Halo2CommitmentSetup`] — KZG structured reference string (`g`, `h`,
//!   `s_g2 = [τ]₂`) required for polynomial opening verification.
//! * [`Halo2G2Affine`] — a `no_std` G2 point in Fp² with EIP-197 serialization,
//!   layout-compatible with `soroban-zk-std::pairing::G2Affine`.
//! * [`Halo2Opening`] — a single polynomial opening (commitment, challenge,
//!   evaluation, proof) validated before a multi-pairing check.
//!
//! Every struct is sized up-front via `const` generics and operates on slices /
//! fixed arrays, so there are zero heap allocations and no `clone`s on the hot
//! path — meeting Soroban's strict CPU/heap budget.
//!
//! `N` is the total number of cells (`R * C`); it is supplied explicitly by the
//! caller because const-generic arithmetic (`R * C`) is not permitted in array /
//! const-generic positions.

use ethnum::u256;

use crate::{Bn254, G1Affine, ZkError};

/// A single monomial within a [`CustomGate`].
///
/// `coeff * ∏_{f < degree} evals[(row + factors[f].1) mod R][factors[f].0]`
///
/// A `degree == 0` term contributes its bare `coeff` (a constant term).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GateTerm<const F: usize> {
    pub coeff: u256,
    /// `(column, rotation_in_rows)` pairs; only the first `degree` are used.
    pub factors: [(usize, i16); F],
    pub degree: usize,
}

impl<const F: usize> GateTerm<F> {
    /// Build a monomial from a coefficient and a slice of `(col, rotation)` pairs.
    /// Returns `Err(ZkError::InvalidInput)` if `factors.len() > F`.
    pub fn from_factors(coeff: u256, factors: &[(usize, i16)]) -> Result<Self, ZkError> {
        if factors.len() > F {
            return Err(ZkError::InvalidInput);
        }
        let mut arr: [(usize, i16); F] = core::array::from_fn(|_| (0usize, 0i16));
        arr[..factors.len()].copy_from_slice(factors);
        Ok(Self {
            coeff,
            factors: arr,
            degree: factors.len(),
        })
    }
}

/// A custom gate: a sum of [`GateTerm`]s that must evaluate to zero over the
/// proof's column evaluations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CustomGate<const T: usize, const F: usize> {
    pub terms: [GateTerm<F>; T],
    pub num_terms: usize,
}

impl<const T: usize, const F: usize> CustomGate<T, F> {
    /// Build a gate from a slice of terms; `Err` if `terms.len() > T`.
    pub fn from_terms(terms: &[GateTerm<F>]) -> Result<Self, ZkError> {
        if terms.len() > T {
            return Err(ZkError::InvalidInput);
        }
        let filler = GateTerm::<F> {
            coeff: u256::from(0u8),
            factors: core::array::from_fn(|_| (0usize, 0i16)),
            degree: 0,
        };
        let arr: [GateTerm<F>; T] =
            core::array::from_fn(|i| if i < terms.len() { terms[i] } else { filler });
        Ok(Self {
            terms: arr,
            num_terms: terms.len(),
        })
    }
}

/// Builds a fixed-capacity custom gate from vanishing-constraint monomials.
///
/// Each term is written as `coefficient => [(column, rotation), ...]`; factors
/// are multiplied together and all terms are summed. The resulting gate
/// evaluates to zero on every row when the constraint holds. This macro
/// constructs the same allocation-free representation consumed by
/// [`VerificationKey::evaluate_gates`].
///
/// The first two arguments set the maximum number of terms and factors per
/// term. The macro returns `Result<CustomGate<...>, ZkError>` because a term
/// can exceed the declared factor capacity or the gate can exceed its term
/// capacity.
///
/// ```ignore
/// let gate = custom_gate!(3, 2;
///     coefficient_a => [(0, 0), (1, 0)],
///     coefficient_b => [(2, 0)],
///     coefficient_c => [],
/// )?;
/// ```
#[macro_export]
macro_rules! custom_gate {
    ($max_terms:literal, $max_factors:literal; $(
        $coefficient:expr => [$(($column:expr, $rotation:expr)),* $(,)?]
    ),+ $(,)?) => {{
        (|| -> Result<
            $crate::halo2::CustomGate<{ $max_terms }, { $max_factors }>,
            $crate::ZkError,
        > {
            let terms = [$(
                $crate::halo2::GateTerm::<{ $max_factors }>::from_factors(
                    $coefficient,
                    &[$(($column, $rotation)),*],
                )?,
            )+];
            $crate::halo2::CustomGate::<{ $max_terms }, { $max_factors }>::from_terms(&terms)
        })()
    }};
}

/// Halo2-style verification key, generic over the circuit dimensions.
///
/// * `R` — number of rows (the evaluation domain size, a power of two).
/// * `C` — number of columns (advice + fixed + instance combined for the check).
/// * `N` — total number of cells (`R * C`); supplied explicitly (see module docs).
/// * `G` — maximum number of custom gates.
/// * `T` — maximum number of terms per gate.
/// * `F` — maximum number of factors per term.
///
/// `permutation_sigma` is the permutation argument over the `N` cells, indexed
/// column-major: `cell = col * R + row`. `sigma[i] = j` means cell `i` is mapped
/// to cell `j`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerificationKey<
    const R: usize,
    const C: usize,
    const N: usize,
    const G: usize,
    const T: usize,
    const F: usize,
> {
    pub domain_size: usize,
    pub custom_gates: [CustomGate<T, F>; G],
    pub num_gates: usize,
    pub permutation_sigma: [usize; N],
    pub permutation_cols: usize,
}

impl<
        const R: usize,
        const C: usize,
        const N: usize,
        const G: usize,
        const T: usize,
        const F: usize,
    > VerificationKey<R, C, N, G, T, F>
{
    /// Structural validation of the key: dimensions, gate bounds, permutation
    /// range, and column-index bounds. This is the "parsing/validation code
    /// path" that must run before any evaluation.
    pub fn validate(&self) -> Result<(), ZkError> {
        if R == 0 || C == 0 || N != R * C || self.domain_size != R {
            return Err(ZkError::InvalidInput);
        }
        if self.num_gates > G {
            return Err(ZkError::InvalidInput);
        }
        if self.permutation_cols > C {
            return Err(ZkError::InvalidInput);
        }
        for &s in self.permutation_sigma.iter() {
            if s >= N {
                return Err(ZkError::InvalidInput);
            }
        }
        for g in 0..self.num_gates {
            let gate = &self.custom_gates[g];
            if gate.num_terms > T {
                return Err(ZkError::InvalidInput);
            }
            for t in 0..gate.num_terms {
                let term = &gate.terms[t];
                if term.degree > F {
                    return Err(ZkError::InvalidInput);
                }
                for f in 0..term.degree {
                    if term.factors[f].0 >= C {
                        return Err(ZkError::InvalidInput);
                    }
                }
            }
        }
        Ok(())
    }

    /// Evaluate every custom gate over the column evaluations `evals[row][col]`.
    /// Returns `Err(ZkError::InvalidInput)` if any gate evaluates to a non-zero
    /// value (i.e. the proof violates a constraint).
    pub fn evaluate_gates(&self, evals: &[[u256; C]; R]) -> Result<(), ZkError> {
        let zero = u256::from(0u8);
        for row in 0..R {
            for g in 0..self.num_gates {
                let gate = &self.custom_gates[g];
                let mut sum = zero;
                for t in 0..gate.num_terms {
                    let term = &gate.terms[t];
                    let mut prod = term.coeff;
                    for f in 0..term.degree {
                        let (col, rot) = term.factors[f];
                        let rr = rot_index(row, rot, R);
                        prod = Bn254::mul(prod, evals[rr][col]);
                    }
                    sum = Bn254::add(sum, prod);
                }
                if sum != zero {
                    return Err(ZkError::InvalidInput);
                }
            }
        }
        Ok(())
    }

    /// Evaluate the permutation grand-product `Z(ζ)` for the given challenges
    /// `β` and `γ`. `values` must contain the `N` cell evaluations in
    /// column-major order (`cell = col * R + row`).
    pub fn evaluate_permutation(
        &self,
        values: &[u256],
        beta: u256,
        gamma: u256,
    ) -> Result<u256, ZkError> {
        if values.len() != N {
            return Err(ZkError::InvalidInput);
        }
        let one = u256::from(1u8);
        let mut z = one;
        for i in 0..N {
            let vi = values[i];
            let sigma_i = self.permutation_sigma[i];
            let num = Bn254::add(vi, Bn254::add(Bn254::mul(beta, idx(sigma_i as u64)), gamma));
            let den = Bn254::add(vi, Bn254::add(Bn254::mul(beta, idx(i as u64)), gamma));
            if den == u256::from(0u8) {
                return Err(ZkError::InvalidFieldElement);
            }
            let den_inv = Bn254::invert(den);
            z = Bn254::mul(z, Bn254::mul(num, den_inv));
        }
        Ok(z)
    }

    /// Verify the permutation argument: the full grand product must equal `1`
    /// (true iff `sigma` is a valid permutation/bijective mapping of the cells).
    pub fn verify_permutation(
        &self,
        values: &[u256],
        beta: u256,
        gamma: u256,
    ) -> Result<(), ZkError> {
        let z = self.evaluate_permutation(values, beta, gamma)?;
        if z == u256::from(1u8) {
            Ok(())
        } else {
            Err(ZkError::InvalidInput)
        }
    }

    /// Full verification: custom-gate evaluation followed by the permutation
    /// argument over the flattened column evaluations.
    pub fn verify(&self, evals: &[[u256; C]; R], beta: u256, gamma: u256) -> Result<(), ZkError> {
        self.evaluate_gates(evals)?;
        let mut values: [u256; N] = core::array::from_fn(|_| u256::from(0u8));
        for col in 0..C {
            for row in 0..R {
                values[col * R + row] = evals[row][col];
            }
        }
        self.verify_permutation(&values, beta, gamma)
    }

    /// Evaluate the vanishing polynomial `t(X) = X^n - 1` for a domain of size `n`
    /// at the given evaluation point `x`.
    pub fn evaluate_vanishing_polynomial(&self, x: u256) -> u256 {
        let x_n = Bn254::pow(x, u256::from(self.domain_size as u64));
        Bn254::sub(x_n, u256::from(1u8))
    }
}

/// Maps a (row, rotation) pair to a concrete row index with modular wrap-around.
#[inline(always)]
fn rot_index(row: usize, rot: i16, rows: usize) -> usize {
    let r = (row as i32 + rot as i32).rem_euclid(rows as i32);
    r as usize
}

/// Converts a cell index to a field element (safe for `N < 2^64`).
#[inline(always)]
fn idx(i: u64) -> u256 {
    u256::from(i)
}

/// Recursion / accumulation state for folding multiple Halo2 (or IPA/KZG) proofs
/// into a single running accumulator — required to track recursive state updates
/// on Soroban without re-verifying each proof from scratch.
///
/// The accumulator is split into a `G1Affine` commitment half (KZG/IPA) and a
/// scalar `value` half, both folded additively. All state is fixed-size; no heap
/// allocation occurs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Accumulator {
    pub commitment: G1Affine,
    pub value: u256,
    pub count: u32,
}

impl Accumulator {
    /// A fresh accumulator at the additive identity.
    pub fn new() -> Self {
        Self {
            commitment: G1Affine {
                x: u256::from(0u8),
                y: u256::from(0u8),
            },
            value: u256::from(0u8),
            count: 0,
        }
    }

    /// Fold an incoming commitment into the running accumulation (additive).
    ///
    /// The first fold seeds the accumulator (avoids relying on a distinguished
    /// identity point, which is represented as `(0,0)` in this codebase and is not
    /// a valid `G1Affine::add` operand); subsequent folds accumulate additively.
    pub fn fold_commitment(&mut self, comm: &G1Affine) {
        if self.count == 0 {
            self.commitment = *comm;
        } else {
            self.commitment = self.commitment.add(comm);
        }
        self.count += 1;
    }

    /// Fold an incoming scalar value into the running accumulation (additive).
    pub fn fold_value(&mut self, v: u256) {
        self.value = Bn254::add(self.value, v);
        self.count += 1;
    }

    /// Current accumulated commitment (KZG/IPA accumulator state).
    pub fn commitment(&self) -> G1Affine {
        self.commitment
    }

    /// Current accumulated scalar (folded proof value).
    pub fn value(&self) -> u256 {
        self.value
    }
}

impl Default for Accumulator {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Halo2 Verification Key Parameter Structs (Issue #431)
//
// These structs represent the *outer* Halo2 verification key envelope that sits
// above the gate/permutation checker defined by [`VerificationKey`].  In the
// Halo2 protocol (PSE / zcash variants) the verifier needs:
//
//  1. A polynomial commitment *setup* (KZG or IPA generators).
//  2. Per-column commitments for fixed columns and selectors (committed during
//     circuit-key generation).
//  3. Per-column permutation commitments (`sigma` polynomials as G1 points).
//  4. The evaluation domain parameters (`k`, `n = 2^k`, `omega`).
//
// All structs are sized via const generics so they live entirely on the stack —
// no heap allocations — satisfying Soroban's strict WASM memory budget.
//
// ## Const-generic parameters
//
// | Parameter | Meaning |
// |-----------|---------|
// | `FC`      | Number of fixed columns (including selectors committed separately) |
// | `SC`      | Number of selector columns |
// | `PC`      | Number of permuted columns (advice + fixed columns in permutation) |
// | `N`       | Domain size `2^k`; must equal `1 << k` |
//
// `N` (the Lagrange basis size) must be supplied explicitly because
// const-generic expressions (`1 << k`) are not yet stable in array positions.
// ============================================================================

/// A BN254 G2 affine point in the Fp² extension field, stored as two Fp
/// coordinates each represented as `(real: u256, imag: u256)`.
///
/// This mirrors the layout of `G2Affine` in `soroban-zk-std::pairing` so the
/// two types are trivially interoperable via field-by-field copy — no
/// re-encoding needed when bridging the two crates.
///
/// The point is considered the *point at infinity* (additive identity) when
/// both `x` and `y` are `(0, 0)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Halo2G2Affine {
    /// X coordinate in Fp²: `(x_real, x_imag)` where the element is
    /// `x_real + x_imag·u`.
    pub x: (u256, u256),
    /// Y coordinate in Fp²: `(y_real, y_imag)`.
    pub y: (u256, u256),
}

impl Halo2G2Affine {
    /// The point at infinity (additive identity of G2).
    pub const IDENTITY: Self = Self {
        x: (u256::from_words(0, 0), u256::from_words(0, 0)),
        y: (u256::from_words(0, 0), u256::from_words(0, 0)),
    };

    /// Returns `true` if this is the point at infinity.
    #[inline(always)]
    pub fn is_identity(&self) -> bool {
        *self == Self::IDENTITY
    }

    /// Serializes the point into 128 bytes using the EIP-197 / CAP-0074 layout:
    ///
    /// ```text
    /// bytes[  0.. 32] = x.1 (imaginary, big-endian)
    /// bytes[ 32.. 64] = x.0 (real,      big-endian)
    /// bytes[ 64.. 96] = y.1 (imaginary, big-endian)
    /// bytes[ 96..128] = y.0 (real,      big-endian)
    /// ```
    pub fn to_bytes(&self) -> [u8; 128] {
        let mut out = [0u8; 128];
        out[0..32].copy_from_slice(&self.x.1.to_be_bytes());
        out[32..64].copy_from_slice(&self.x.0.to_be_bytes());
        out[64..96].copy_from_slice(&self.y.1.to_be_bytes());
        out[96..128].copy_from_slice(&self.y.0.to_be_bytes());
        out
    }

    /// Deserializes a point from 128 bytes (EIP-197 / CAP-0074 layout).
    ///
    /// Returns `Err(ZkError::DeserializationError)` if `bytes.len() != 128`.
    /// No curve-membership check is performed here; call `validate` afterwards
    /// if you need to confirm the point is on G2.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ZkError> {
        if bytes.len() != 128 {
            return Err(ZkError::DeserializationError);
        }
        let x1 = u256::from_be_bytes(
            bytes[0..32]
                .try_into()
                .map_err(|_| ZkError::DeserializationError)?,
        );
        let x0 = u256::from_be_bytes(
            bytes[32..64]
                .try_into()
                .map_err(|_| ZkError::DeserializationError)?,
        );
        let y1 = u256::from_be_bytes(
            bytes[64..96]
                .try_into()
                .map_err(|_| ZkError::DeserializationError)?,
        );
        let y0 = u256::from_be_bytes(
            bytes[96..128]
                .try_into()
                .map_err(|_| ZkError::DeserializationError)?,
        );
        Ok(Self {
            x: (x0, x1),
            y: (y0, y1),
        })
    }
}

/// KZG polynomial commitment setup parameters ("structured reference string").
///
/// In KZG-based Halo2 the verifier only needs two elements from the toxic-waste
/// ceremony: the G1 generator `g` (= [1]₁) and the G2 *tau* point `h`
/// (= [τ]₂).  The product `e(g, h)` is pre-computed once during key generation
/// and stored as `s_g2` so the verifier can evaluate the pairing equation
/// without re-computing it each time.
///
/// For IPA-based Halo2 (Pasta curves / Halo Infinity) the `h` / `s_g2` fields
/// are not used; populate them with `Halo2G2Affine::IDENTITY` /
/// `G1Affine { x: 0, y: 0 }` respectively.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Halo2CommitmentSetup {
    /// G1 generator: the base commitment point `[1]₁`.
    pub g: G1Affine,
    /// G2 generator: `[1]₂`, the standard second-group generator.
    pub h: Halo2G2Affine,
    /// `[τ]₂` — the G2 element encoding the toxic-waste scalar `τ` from the
    /// KZG trusted setup.  Used in the opening equation:
    /// `e(commitment − v·g, g₂) = e(proof, [τ]₂ − z·g₂)`.
    pub s_g2: Halo2G2Affine,
}

impl Halo2CommitmentSetup {
    /// Validates the setup: `g` must not be the identity, and `h` / `s_g2`
    /// must differ from each other (a setup where `[1]₂ == [τ]₂` would imply
    /// `τ = 1`, which is a degenerate ceremony).
    pub fn validate(&self) -> Result<(), ZkError> {
        // g must be a non-identity G1 point.
        if self.g.x == u256::from(0u8) && self.g.y == u256::from(0u8) {
            return Err(ZkError::InvalidInput);
        }
        // A degenerate setup where τ = 1 (h == s_g2) must be rejected.
        if self.h == self.s_g2 {
            return Err(ZkError::InvalidInput);
        }
        Ok(())
    }
}

/// The evaluation domain for a Halo2 circuit.
///
/// Halo2 uses a multiplicative subgroup of size `n = 2^k` of the BN254 scalar
/// field Fr.  `omega` (ω) is the primitive `n`-th root of unity that generates
/// this subgroup: `H = { 1, ω, ω², …, ωⁿ⁻¹ }`.
///
/// The domain is used to:
/// * evaluate polynomials at specific coset positions during the Fiat–Shamir
///   transcript,
/// * compute the vanishing polynomial `Z_H(X) = Xⁿ − 1`, and
/// * relate the evaluation index `i` to the domain point `ωⁱ`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Halo2Domain {
    /// `k` such that `n = 2^k`.  Maximum supported value is 28 (matches Halo2
    /// library maximum and keeps `n` below 2^29 to fit in a `u32`).
    pub k: u8,
    /// `n = 2^k`, the number of rows / domain size.
    pub n: u64,
    /// Primitive `n`-th root of unity in Fr.  Must satisfy `omegaⁿ ≡ 1 (mod r)`
    /// and `omega^(n/2) ≢ 1 (mod r)` for `n > 1`.
    pub omega: u256,
}

impl Halo2Domain {
    /// Validates the domain: checks that `n == 1 << k`, that `k <= 28`, and
    /// that `omega` is a non-zero field element.
    pub fn validate(&self) -> Result<(), ZkError> {
        if self.k > 28 {
            return Err(ZkError::InvalidInput);
        }
        let expected_n: u64 = 1u64
            .checked_shl(self.k as u32)
            .ok_or(ZkError::InvalidInput)?;
        if self.n != expected_n {
            return Err(ZkError::InvalidInput);
        }
        if self.omega == u256::from(0u8) || self.omega >= Bn254::FR_MODULUS {
            return Err(ZkError::InvalidFieldElement);
        }
        Ok(())
    }

    /// Evaluates the vanishing polynomial at `x`: `Z_H(x) = x^n − 1 mod r`.
    ///
    /// This is used by the verifier to confirm that constraint polynomials
    /// vanish over the entire domain without evaluating each constraint
    /// individually.
    pub fn evaluate_vanishing(&self, x: u256) -> u256 {
        // x^n mod r via repeated squaring (n = 2^k, so k squarings suffice).
        let mut result = x;
        for _ in 0..self.k {
            result = Bn254::mul(result, result);
        }
        // Subtract 1 using field subtraction to handle the wrap-around.
        Bn254::sub(result, u256::from(1u8))
    }

    /// Evaluates the degree-`< n` parts of a split quotient polynomial at `zeta`.
    ///
    /// For `t(X) = Σ parts[i](X) · X^(i·n)`, returns
    /// `t(zeta) = Σ parts[i](zeta) · (zeta^n)^i`.
    pub fn evaluate_quotient_parts(&self, parts: &[&[u256]], zeta: u256) -> Result<u256, ZkError> {
        self.validate()?;
        if parts.is_empty() {
            return Err(ZkError::InvalidInput);
        }
        if zeta >= Bn254::FR_MODULUS {
            return Err(ZkError::InvalidFieldElement);
        }

        let mut zeta_n_power = u256::from(1u8);
        let zeta_n = Bn254::pow(zeta, u256::from(self.n));
        let mut quotient_value = u256::from(0u8);
        for part in parts {
            if part.len() as u64 > self.n {
                return Err(ZkError::InvalidInput);
            }

            let mut part_value = u256::from(0u8);
            for coefficient in part.iter().rev() {
                if *coefficient >= Bn254::FR_MODULUS {
                    return Err(ZkError::InvalidFieldElement);
                }
                part_value = Bn254::add(Bn254::mul(part_value, zeta), *coefficient);
            }
            quotient_value = Bn254::add(quotient_value, Bn254::mul(part_value, zeta_n_power));
            zeta_n_power = Bn254::mul(zeta_n_power, zeta_n);
        }

        Ok(quotient_value)
    }
}

/// The complete Halo2 verification key, combining domain parameters, KZG
/// commitment setup, and the per-column commitments produced during circuit
/// key generation.
///
/// ## Const-generic parameters
///
/// * `FC` — number of fixed columns (excluding selectors; selectors are
///   separately counted in `SC`).
/// * `SC` — number of selector columns compressed into fixed-polynomial
///   commitments.
/// * `PC` — number of columns included in the permutation argument
///   (typically all advice columns plus any fixed columns referenced in copy
///   constraints).
///
/// All commitment arrays live on the stack; for large circuits with many fixed
/// columns or large permutation argument sets, increase these constants.
///
/// ## Relationship to [`VerificationKey`]
///
/// [`VerificationKey`] handles the *field-arithmetic* side: evaluating custom
/// gates and the grand-product permutation argument over raw field elements.
/// `Halo2Params` holds the *commitment* side: the G1/G2 points needed to open
/// polynomial commitments and bind the circuit topology to the proof.  A full
/// Halo2 verifier uses both.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Halo2Params<const FC: usize, const SC: usize, const PC: usize> {
    /// Polynomial commitment setup (generators and KZG tau point).
    pub setup: Halo2CommitmentSetup,
    /// Evaluation domain (`k`, `n`, `ω`).
    pub domain: Halo2Domain,
    /// Commitments to fixed columns (column index → G1 commitment).
    ///
    /// `fixed_commitments[i]` is the KZG commitment to the `i`-th fixed
    /// polynomial `q_i(X)` evaluated over the domain.  This covers selector
    /// polynomials that have been merged into fixed columns during key
    /// compression.
    pub fixed_commitments: [G1Affine; FC],
    /// Commitments to selector columns *before* compression.
    ///
    /// Some Halo2 backends (e.g. PSE's `halo2_proofs`) expose the raw selector
    /// commitments separately from the fixed-column commitments so tooling can
    /// inspect individual selectors.  Set `SC = 0` if not needed.
    pub selector_commitments: [G1Affine; SC],
    /// Commitments to the permutation polynomials `σ_i(X)` over the domain.
    ///
    /// `permutation_commitments[i]` binds the `i`-th column's permutation
    /// (copy constraint wiring) to the verification key.  The permutation
    /// argument grand-product check is performed against these commitments.
    pub permutation_commitments: [G1Affine; PC],
}

impl<const FC: usize, const SC: usize, const PC: usize> Halo2Params<FC, SC, PC> {
    /// Validates all sub-components of the verification key.
    ///
    /// Checks performed (in order):
    /// 1. [`Halo2CommitmentSetup::validate`] — setup generators are non-trivial.
    /// 2. [`Halo2Domain::validate`] — `k`, `n`, and `ω` are self-consistent.
    /// 3. No fixed commitment is the identity point (a zero commitment indicates
    ///    an uninitialized key).
    /// 4. No permutation commitment is the identity point.
    ///
    /// Selector commitments may be identity (`SC = 0` is fine; identity
    /// selectors indicate disabled selectors, which is a valid circuit state).
    pub fn validate(&self) -> Result<(), ZkError> {
        self.setup.validate()?;
        self.domain.validate()?;

        // Fixed commitments must be non-identity — a zero point signals that
        // the key was not fully populated, which would silently skip a constraint.
        for commitment in &self.fixed_commitments {
            if commitment.x == u256::from(0u8) && commitment.y == u256::from(0u8) {
                return Err(ZkError::InvalidInput);
            }
        }

        // Permutation commitments must also be non-identity.
        for commitment in &self.permutation_commitments {
            if commitment.x == u256::from(0u8) && commitment.y == u256::from(0u8) {
                return Err(ZkError::InvalidInput);
            }
        }

        Ok(())
    }

    /// Returns `true` if the verification key has been fully populated
    /// (all required commitment arrays are non-empty and validation passes).
    pub fn is_ready(&self) -> bool {
        self.validate().is_ok()
    }
}

/// A Halo2 proof transcript element carrying a single polynomial opening.
///
/// During Halo2 verification the verifier receives claimed evaluations of
/// committed polynomials at challenge points.  `Halo2Opening` bundles the
/// commitment, the challenge point, the claimed value, and the proof (the KZG
/// "quotient" commitment `W`) into a single verifiable unit.
///
/// A batch of these openings is verified in a single multi-pairing check via
/// the Soroban `bn254_multi_pairing_check` host function.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Halo2Opening {
    /// The polynomial commitment `C = [p(X)]`.
    pub commitment: G1Affine,
    /// The evaluation challenge `z` (a scalar in Fr).
    pub point: u256,
    /// The claimed evaluation `v = p(z)` (a scalar in Fr).
    pub value: u256,
    /// The KZG opening proof `W = [(p(X) − v) / (X − z)]` in G1.
    pub proof: G1Affine,
}

impl Halo2Opening {
    /// Validates the opening: `point` and `value` must be valid Fr elements,
    /// and neither `commitment` nor `proof` may be the identity point.
    pub fn validate(&self) -> Result<(), ZkError> {
        if self.point >= Bn254::FR_MODULUS {
            return Err(ZkError::InvalidFieldElement);
        }
        if self.value >= Bn254::FR_MODULUS {
            return Err(ZkError::InvalidFieldElement);
        }
        let identity_x = u256::from(0u8);
        let identity_y = u256::from(0u8);
        if self.commitment.x == identity_x && self.commitment.y == identity_y {
            return Err(ZkError::InvalidInput);
        }
        if self.proof.x == identity_x && self.proof.y == identity_y {
            return Err(ZkError::InvalidInput);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn neg_one() -> u256 {
        Bn254::sub(u256::from(0u8), u256::from(1u8))
    }

    // ------------------------------------------------------------------------
    // Phase 1: custom-gate parsing, validation, and evaluation loop.
    // ------------------------------------------------------------------------

    #[test]
    fn custom_gate_add_sub_constraint_holds() {
        // Gate: a + b - c = 0 over 3 columns.
        let gate = crate::custom_gate!(3, 1;
            u256::from(1u8) => [(0usize, 0i16)],
            u256::from(1u8) => [(1usize, 0i16)],
            neg_one() => [(2usize, 0i16)],
        )
        .unwrap();

        let vk = VerificationKey::<2, 3, 6, 1, 3, 1> {
            domain_size: 2,
            custom_gates: [gate],
            num_gates: 1,
            permutation_sigma: [0, 1, 2, 3, 4, 5],
            permutation_cols: 3,
        };
        assert!(vk.validate().is_ok());

        // Satisfying evaluation: row0 = (2,3,5), row1 = (4,5,9).
        let evals = [
            [u256::from(2u8), u256::from(3u8), u256::from(5u8)],
            [u256::from(4u8), u256::from(5u8), u256::from(9u8)],
        ];
        assert!(vk.evaluate_gates(&evals).is_ok());

        // Breaking the constraint must be rejected.
        let bad = [
            [u256::from(2u8), u256::from(3u8), u256::from(5u8)],
            [u256::from(4u8), u256::from(5u8), u256::from(8u8)], // 4+5 != 8
        ];
        assert_eq!(vk.evaluate_gates(&bad), Err(ZkError::InvalidInput));
    }

    #[test]
    fn validation_rejects_out_of_bounds_columns() {
        let t0 = GateTerm::from_factors(u256::from(1u8), &[(3usize, 0i16)]).unwrap();
        let gate = CustomGate::<1, 1>::from_terms(&[t0]).unwrap();
        let vk = VerificationKey::<1, 3, 3, 1, 1, 1> {
            domain_size: 1,
            custom_gates: [gate],
            num_gates: 1,
            permutation_sigma: [0, 1, 2],
            permutation_cols: 3,
        };
        // Column 3 is out of range for a 3-column key.
        assert_eq!(vk.validate(), Err(ZkError::InvalidInput));
    }

    // ------------------------------------------------------------------------
    // Phase 2: permutation (grand-product) argument.
    // ------------------------------------------------------------------------

    #[test]
    fn permutation_identity_and_cycle_yield_product_one() {
        let vk = VerificationKey::<3, 1, 3, 0, 0, 0> {
            domain_size: 3,
            custom_gates: [],
            num_gates: 0,
            permutation_sigma: [0, 1, 2], // identity
            permutation_cols: 1,
        };
        assert!(vk.validate().is_ok());

        let values = [u256::from(10u8), u256::from(20u8), u256::from(30u8)];
        let beta = u256::from(2u8);
        let gamma = u256::from(3u8);

        // Identity permutation => grand product == 1.
        assert_eq!(
            vk.evaluate_permutation(&values, beta, gamma).unwrap(),
            u256::from(1u8)
        );
        assert!(vk.verify_permutation(&values, beta, gamma).is_ok());

        // A 3-cycle with equal cell values preserves the copy constraint
        // (v_i == v_{σ(i)} for all i), so the grand product is still 1.
        let equal_values = [u256::from(7u8), u256::from(7u8), u256::from(7u8)];
        let vk_cycle = VerificationKey::<3, 1, 3, 0, 0, 0> {
            permutation_sigma: [1, 2, 0],
            ..vk
        };
        assert_eq!(
            vk_cycle
                .evaluate_permutation(&equal_values, beta, gamma)
                .unwrap(),
            u256::from(1u8)
        );
        assert!(vk_cycle
            .verify_permutation(&equal_values, beta, gamma)
            .is_ok());
    }

    #[test]
    fn permutation_non_bijection_is_rejected() {
        // sigma maps everything to 0 -> not a permutation.
        let vk = VerificationKey::<3, 1, 3, 0, 0, 0> {
            domain_size: 3,
            custom_gates: [],
            num_gates: 0,
            permutation_sigma: [0, 0, 0],
            permutation_cols: 1,
        };
        let values = [u256::from(10u8), u256::from(20u8), u256::from(30u8)];
        // The grand product of a non-permutation is generally != 1.
        assert_ne!(
            vk.evaluate_permutation(&values, u256::from(2u8), u256::from(3u8))
                .unwrap(),
            u256::from(1u8)
        );
        assert_eq!(
            vk.verify_permutation(&values, u256::from(2u8), u256::from(3u8)),
            Err(ZkError::InvalidInput)
        );
    }

    #[test]
    fn full_verify_combines_gates_and_permutation() {
        let t0 = GateTerm::from_factors(u256::from(1u8), &[(0usize, 0i16)]).unwrap();
        let t1 = GateTerm::from_factors(neg_one(), &[(2usize, 0i16)]).unwrap();
        let gate = CustomGate::from_terms(&[t0, t1]).unwrap();

        let vk = VerificationKey::<2, 3, 6, 1, 2, 1> {
            domain_size: 2,
            custom_gates: [gate],
            num_gates: 1,
            permutation_sigma: [0, 1, 2, 3, 4, 5], // identity over 6 cells
            permutation_cols: 3,
        };
        let evals = [
            [u256::from(2u8), u256::from(3u8), u256::from(2u8)], // 2 - 2 = 0
            [u256::from(4u8), u256::from(5u8), u256::from(4u8)], // 4 - 4 = 0
        ];
        assert!(vk.verify(&evals, u256::from(7u8), u256::from(11u8)).is_ok());
    }

    // ------------------------------------------------------------------------
    // Phase 3: recursion / accumulation state.
    // ------------------------------------------------------------------------

    #[test]
    fn accumulator_folds_commitments_and_values() {
        let mut acc = Accumulator::new();
        assert_eq!(
            acc.commitment(),
            G1Affine {
                x: u256::from(0u8),
                y: u256::from(0u8)
            }
        );

        let p = G1Affine {
            x: u256::from(1u8),
            y: u256::from(2u8),
        };
        // Folding the same point twice must equal p + p.
        let expected = p.add(&p);
        acc.fold_commitment(&p);
        acc.fold_commitment(&p);
        assert_eq!(acc.commitment(), expected);
        assert_eq!(acc.count, 2);

        // Scalar folding.
        acc.fold_value(u256::from(5u8));
        acc.fold_value(u256::from(9u8));
        assert_eq!(acc.value(), Bn254::add(u256::from(5u8), u256::from(9u8)));
    }

    #[test]
    fn accumulator_default_is_identity() {
        let acc = Accumulator::default();
        assert_eq!(
            acc.commitment(),
            G1Affine {
                x: u256::from(0u8),
                y: u256::from(0u8)
            }
        );
        assert_eq!(acc.value(), u256::from(0u8));
    }

    // ========================================================================
    // Issue #431: Halo2Params struct tests
    // ========================================================================

    /// Returns the BN254 G1 generator (1, 2) as a non-identity commitment.
    fn g1_generator() -> G1Affine {
        G1Affine {
            x: u256::from(1u8),
            y: u256::from(2u8),
        }
    }

    /// Returns a placeholder non-identity G2 point distinct from the G2 generator.
    fn g2_tau() -> Halo2G2Affine {
        // A fake [τ]₂ that is clearly not the same as the generator.
        Halo2G2Affine {
            x: (u256::from(3u8), u256::from(4u8)),
            y: (u256::from(5u8), u256::from(6u8)),
        }
    }

    fn g2_generator() -> Halo2G2Affine {
        Halo2G2Affine {
            x: (u256::from(1u8), u256::from(2u8)),
            y: (u256::from(3u8), u256::from(4u8)),
        }
    }

    // --- Halo2G2Affine ---

    #[test]
    fn g2_affine_round_trip_serialization() {
        let pt = g2_tau();
        let bytes = pt.to_bytes();
        let recovered = Halo2G2Affine::from_bytes(&bytes).unwrap();
        assert_eq!(pt, recovered);
    }

    #[test]
    fn g2_affine_from_bytes_rejects_wrong_length() {
        let result = Halo2G2Affine::from_bytes(&[0u8; 64]);
        assert_eq!(result, Err(ZkError::DeserializationError));
    }

    #[test]
    fn g2_affine_identity_is_detectable() {
        assert!(Halo2G2Affine::IDENTITY.is_identity());
        assert!(!g2_generator().is_identity());
    }

    // --- Halo2CommitmentSetup ---

    #[test]
    fn commitment_setup_valid_passes() {
        let setup = Halo2CommitmentSetup {
            g: g1_generator(),
            h: g2_generator(),
            s_g2: g2_tau(),
        };
        assert!(setup.validate().is_ok());
    }

    #[test]
    fn commitment_setup_identity_g_is_rejected() {
        let setup = Halo2CommitmentSetup {
            g: G1Affine {
                x: u256::from(0u8),
                y: u256::from(0u8),
            },
            h: g2_generator(),
            s_g2: g2_tau(),
        };
        assert_eq!(setup.validate(), Err(ZkError::InvalidInput));
    }

    #[test]
    fn commitment_setup_degenerate_tau_is_rejected() {
        // h == s_g2 implies τ = 1, which is a degenerate ceremony.
        let pt = g2_generator();
        let setup = Halo2CommitmentSetup {
            g: g1_generator(),
            h: pt,
            s_g2: pt, // same as h → rejected
        };
        assert_eq!(setup.validate(), Err(ZkError::InvalidInput));
    }

    // --- Halo2Domain ---

    #[test]
    fn domain_k4_valid() {
        // ω for k=4 (n=16) — use a small non-zero field element as placeholder.
        let domain = Halo2Domain {
            k: 4,
            n: 16,
            omega: u256::from(42u8),
        };
        assert!(domain.validate().is_ok());
    }

    #[test]
    fn domain_mismatched_n_is_rejected() {
        let domain = Halo2Domain {
            k: 4,
            n: 8,
            omega: u256::from(42u8),
        };
        assert_eq!(domain.validate(), Err(ZkError::InvalidInput));
    }

    #[test]
    fn domain_k_too_large_is_rejected() {
        let domain = Halo2Domain {
            k: 29,
            n: 1 << 29,
            omega: u256::from(1u8),
        };
        assert_eq!(domain.validate(), Err(ZkError::InvalidInput));
    }

    #[test]
    fn domain_omega_zero_is_rejected() {
        let domain = Halo2Domain {
            k: 2,
            n: 4,
            omega: u256::from(0u8),
        };
        assert_eq!(domain.validate(), Err(ZkError::InvalidFieldElement));
    }

    #[test]
    fn domain_omega_above_modulus_is_rejected() {
        let domain = Halo2Domain {
            k: 2,
            n: 4,
            omega: Bn254::FR_MODULUS,
        };
        assert_eq!(domain.validate(), Err(ZkError::InvalidFieldElement));
    }

    #[test]
    fn vanishing_polynomial_at_n_is_zero() {
        // For any ωⁿ = 1 (honest omega), ω itself satisfies Z_H(ω) != 0.
        // But Z_H(1) = 1ⁿ − 1 = 0 for n >= 1.
        let domain = Halo2Domain {
            k: 4,
            n: 16,
            omega: u256::from(7u8),
        };
        let result = domain.evaluate_vanishing(u256::from(1u8));
        // 1^16 - 1 = 0
        assert_eq!(result, u256::from(0u8));
    }

    #[test]
    fn vanishing_polynomial_at_two_is_nonzero_for_k1() {
        // k=1, n=2: Z_H(2) = 2^2 - 1 = 3.
        let domain = Halo2Domain {
            k: 1,
            n: 2,
            omega: u256::from(3u8),
        };
        let result = domain.evaluate_vanishing(u256::from(2u8));
        assert_eq!(result, u256::from(3u8));
    }

    #[test]
    fn quotient_parts_are_combined_with_zeta_to_domain_size() {
        let domain = Halo2Domain {
            k: 1,
            n: 2,
            omega: u256::from(3u8),
        };
        let first = [u256::from(1u8), u256::from(2u8)];
        let second = [u256::from(3u8), u256::from(4u8)];

        // (1 + 2·5) + 5²·(3 + 4·5) = 586.
        assert_eq!(
            domain.evaluate_quotient_parts(&[&first, &second], u256::from(5u8)),
            Ok(u256::from(586u16)),
        );
    }

    #[test]
    fn quotient_part_larger_than_domain_is_rejected() {
        let domain = Halo2Domain {
            k: 1,
            n: 2,
            omega: u256::from(3u8),
        };
        let oversized = [u256::from(1u8), u256::from(2u8), u256::from(3u8)];

        assert_eq!(
            domain.evaluate_quotient_parts(&[&oversized], u256::from(5u8)),
            Err(ZkError::InvalidInput),
        );
    }

    // --- Halo2Params ---

    fn make_valid_params() -> Halo2Params<2, 1, 2> {
        let nz = G1Affine {
            x: u256::from(1u8),
            y: u256::from(2u8),
        };
        Halo2Params::<2, 1, 2> {
            setup: Halo2CommitmentSetup {
                g: g1_generator(),
                h: g2_generator(),
                s_g2: g2_tau(),
            },
            domain: Halo2Domain {
                k: 3,
                n: 8,
                omega: u256::from(5u8),
            },
            fixed_commitments: [nz, nz],
            selector_commitments: [nz],
            permutation_commitments: [nz, nz],
        }
    }

    #[test]
    fn halo2_params_valid_key_passes() {
        assert!(make_valid_params().validate().is_ok());
        assert!(make_valid_params().is_ready());
    }

    #[test]
    fn halo2_params_zero_fixed_commitment_is_rejected() {
        let mut params = make_valid_params();
        params.fixed_commitments[1] = G1Affine {
            x: u256::from(0u8),
            y: u256::from(0u8),
        };
        assert_eq!(params.validate(), Err(ZkError::InvalidInput));
    }

    #[test]
    fn halo2_params_zero_permutation_commitment_is_rejected() {
        let mut params = make_valid_params();
        params.permutation_commitments[0] = G1Affine {
            x: u256::from(0u8),
            y: u256::from(0u8),
        };
        assert_eq!(params.validate(), Err(ZkError::InvalidInput));
    }

    #[test]
    fn halo2_params_bad_domain_propagates_error() {
        let mut params = make_valid_params();
        params.domain.k = 29; // too large
        assert_eq!(params.validate(), Err(ZkError::InvalidInput));
    }

    #[test]
    fn halo2_params_zero_fixed_zero_selector_zero_permutation_is_valid() {
        // FC=0, SC=0, PC=0 — an empty key is trivially valid (no columns to check).
        let params = Halo2Params::<0, 0, 0> {
            setup: Halo2CommitmentSetup {
                g: g1_generator(),
                h: g2_generator(),
                s_g2: g2_tau(),
            },
            domain: Halo2Domain {
                k: 2,
                n: 4,
                omega: u256::from(9u8),
            },
            fixed_commitments: [],
            selector_commitments: [],
            permutation_commitments: [],
        };
        assert!(params.validate().is_ok());
    }

    // --- Halo2Opening ---

    fn non_zero_g1() -> G1Affine {
        G1Affine {
            x: u256::from(10u8),
            y: u256::from(20u8),
        }
    }

    #[test]
    fn opening_valid_passes() {
        let opening = Halo2Opening {
            commitment: non_zero_g1(),
            point: u256::from(7u8),
            value: u256::from(13u8),
            proof: non_zero_g1(),
        };
        assert!(opening.validate().is_ok());
    }

    #[test]
    fn opening_point_above_modulus_is_rejected() {
        let opening = Halo2Opening {
            commitment: non_zero_g1(),
            point: Bn254::FR_MODULUS,
            value: u256::from(0u8),
            proof: non_zero_g1(),
        };
        assert_eq!(opening.validate(), Err(ZkError::InvalidFieldElement));
    }

    #[test]
    fn opening_value_above_modulus_is_rejected() {
        let opening = Halo2Opening {
            commitment: non_zero_g1(),
            point: u256::from(1u8),
            value: Bn254::FR_MODULUS,
            proof: non_zero_g1(),
        };
        assert_eq!(opening.validate(), Err(ZkError::InvalidFieldElement));
    }

    #[test]
    fn opening_identity_commitment_is_rejected() {
        let opening = Halo2Opening {
            commitment: G1Affine {
                x: u256::from(0u8),
                y: u256::from(0u8),
            },
            point: u256::from(1u8),
            value: u256::from(1u8),
            proof: non_zero_g1(),
        };
        assert_eq!(opening.validate(), Err(ZkError::InvalidInput));
    }

    #[test]
    fn opening_identity_proof_is_rejected() {
        let opening = Halo2Opening {
            commitment: non_zero_g1(),
            point: u256::from(1u8),
            value: u256::from(1u8),
            proof: G1Affine {
                x: u256::from(0u8),
                y: u256::from(0u8),
            },
        };
        assert_eq!(opening.validate(), Err(ZkError::InvalidInput));
    }
}
