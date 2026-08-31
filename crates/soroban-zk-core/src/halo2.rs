//! Halo2-style verifier primitives for PLONKish arithmetization.
//!
//! These are the foundational, `no_std`-compatible building blocks required to
//! verify Halo2-style proofs on Soroban:
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
        for (i, &vi) in values.iter().enumerate() {
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
        let t0 = GateTerm::from_factors(u256::from(1u8), &[(0usize, 0i16)]).unwrap();
        let t1 = GateTerm::from_factors(u256::from(1u8), &[(1usize, 0i16)]).unwrap();
        let t2 = GateTerm::from_factors(neg_one(), &[(2usize, 0i16)]).unwrap();
        let gate = CustomGate::from_terms(&[t0, t1, t2]).unwrap();

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
}
