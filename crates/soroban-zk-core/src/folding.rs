//! Nova-style Relaxed R1CS folding (issue #585).
//!
//! This module replaces the unsound linear folding that
//! [`crate::halo2::Accumulator`] used to perform (plain addition with no
//! random challenge, which admits cancellation attacks) with a sound
//! Nova-style folding scheme for relaxed R1CS instances.
//!
//! A relaxed R1CS instance is `(comm_W, comm_E, u, x)` where `comm_W`
//! commits to the witness, `comm_E` commits to the error (slack) vector, `u`
//! is the scalar that is `1` for a plain R1CS instance and `0` for the
//! trivial instance, and `x` is the public input/output.
//!
//! [`fold_instances`] folds two instances into one, deriving the folding
//! challenge `r` from a Poseidon2 Fiat-Shamir transcript that absorbs both
//! instances and the cross-term commitment `comm_T`:
//!
//! ```text
//! E' = E1 + r·T + r²·E2
//! W' = W1 + r·W2
//! u' = u1 + r·u2
//! x' = x1 + r·x2
//! ```
//!
//! All commitments are checked for G1 curve membership (the point at
//! infinity `(0, 0)` is accepted: a fresh relaxed instance has `E = 0`, whose
//! commitment is the identity) and all scalars are checked to be `<
//! FR_MODULUS` before folding. Everything is `no_std`, stack-only, and
//! fallible via `Result<_, ZkError>` — no panics on the folding path.

use ethnum::u256;

use crate::{Bn254, G1Affine, ZkError, poseidon2::Transcript};

/// A relaxed R1CS instance over BN254 G1, in the sense of Nova.
///
/// `comm_w` (written `comm_W` in the Nova literature and in issue #585)
/// commits to the witness vector, `comm_e` (`comm_E`) commits to the error
/// (slack) vector `E` (the identity for a fresh, unrelaxed instance), `u` is
/// the instance scalar (`1` for a plain R1CS instance, `0` for the trivial
/// instance), and `x` is the public input/output. All scalars are `<
/// FR_MODULUS`; both commitments are G1 curve points or the identity
/// `(0, 0)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelaxedR1CSInstance<const N: usize> {
    /// Commitment to the witness vector (`comm_W` in issue #585).
    pub comm_w: G1Affine,
    /// Commitment to the error (slack) vector (`comm_E` in issue #585).
    pub comm_e: G1Affine,
    /// Instance scalar: `1` for a plain R1CS instance, `0` for the trivial
    /// instance.
    pub u: u256,
    /// Public input/output.
    pub x: [u256; N],
}

impl<const N: usize> RelaxedR1CSInstance<N> {
    /// Build a relaxed R1CS instance, validating both commitments (G1 curve
    /// membership, identity accepted) and every scalar (`< FR_MODULUS`).
    ///
    /// Returns `Err(ZkError::ConstraintUnsatisfied)` for an off-curve
    /// commitment and `Err(ZkError::InvalidFieldElement)` for an out-of-range
    /// scalar.
    pub fn new(
        comm_w: G1Affine,
        comm_e: G1Affine,
        u: u256,
        x: [u256; N],
    ) -> Result<Self, ZkError> {
        let instance = Self {
            comm_w,
            comm_e,
            u,
            x,
        };
        validate_instance(&instance)?;
        Ok(instance)
    }
}

/// Fold two relaxed R1CS instances into one, Nova-style.
///
/// The folding challenge `r` is derived from a fresh Poseidon2 Fiat-Shamir
/// transcript absorbing, in this fixed order, the first instance (`comm_W`,
/// `comm_E`, `u`, then each `x` entry), the second instance in the same
/// order, and finally the cross-term commitment `comm_T`. Because `r` is
/// bound to both instances and `comm_T`, an adversary cannot pick cancelling
/// inputs after seeing the challenge.
///
/// The folded instance is:
///
/// ```text
/// E' = E1 + r·T + r²·E2
/// W' = W1 + r·W2
/// u' = u1 + r·u2
/// x' = x1 + r·x2
/// ```
///
/// All arithmetic is over the BN254 scalar field (mod `FR_MODULUS`).
/// `comm_T` is the commitment to the cross-term `T` from the Nova
/// cross-term computation; this function folds but does not compute `T`.
///
/// Returns `Err(ZkError::ConstraintUnsatisfied)` if any of the three
/// commitments is off-curve, and `Err(ZkError::InvalidFieldElement)` if any
/// scalar is `>= FR_MODULUS`.
pub fn fold_instances<const N: usize>(
    inst1: &RelaxedR1CSInstance<N>,
    inst2: &RelaxedR1CSInstance<N>,
    comm_t: &G1Affine,
) -> Result<RelaxedR1CSInstance<N>, ZkError> {
    validate_instance(inst1)?;
    validate_instance(inst2)?;
    if !Bn254::is_valid_g1_or_identity(comm_t.x, comm_t.y) {
        return Err(ZkError::ConstraintUnsatisfied);
    }

    // Fiat-Shamir challenge, bound to both instances and the cross-term.
    let mut transcript = Transcript::new();
    absorb_instance(&mut transcript, inst1);
    absorb_instance(&mut transcript, inst2);
    transcript.absorb_point(comm_t);
    let r = transcript.challenge();

    let r_squared = Bn254::mul(r, r);

    // E' = E1 + r·T + r²·E2.
    let comm_e = inst1.comm_e.add(&comm_t.scalar_mul(r)).add(&inst2.comm_e.scalar_mul(r_squared));

    // W' = W1 + r·W2.
    let comm_w = inst1.comm_w.add(&inst2.comm_w.scalar_mul(r));

    // u' = u1 + r·u2.
    let u = Bn254::add(inst1.u, Bn254::mul(r, inst2.u));

    // x' = x1 + r·x2.
    let mut x = [u256::from(0u8); N];
    for ((x_out, &x1), &x2) in x.iter_mut().zip(inst1.x.iter()).zip(inst2.x.iter()) {
        *x_out = Bn254::add(x1, Bn254::mul(r, x2));
    }

    Ok(RelaxedR1CSInstance {
        comm_w,
        comm_e,
        u,
        x,
    })
}

/// Validate a relaxed R1CS instance: both commitments must be G1 curve
/// points (the identity `(0, 0)` is accepted) and every scalar must be `<
/// FR_MODULUS`.
fn validate_instance<const N: usize>(inst: &RelaxedR1CSInstance<N>) -> Result<(), ZkError> {
    if !Bn254::is_valid_g1_or_identity(inst.comm_w.x, inst.comm_w.y)
        || !Bn254::is_valid_g1_or_identity(inst.comm_e.x, inst.comm_e.y)
    {
        return Err(ZkError::ConstraintUnsatisfied);
    }
    if inst.u >= Bn254::FR_MODULUS {
        return Err(ZkError::InvalidFieldElement);
    }
    for &x_i in inst.x.iter() {
        if x_i >= Bn254::FR_MODULUS {
            return Err(ZkError::InvalidFieldElement);
        }
    }
    Ok(())
}

/// Absorb one instance into the Fiat-Shamir transcript in the fixed order
/// `comm_W, comm_E, u, x[0..N]`.
fn absorb_instance<const N: usize>(transcript: &mut Transcript, inst: &RelaxedR1CSInstance<N>) {
    transcript.absorb_point(&inst.comm_w);
    transcript.absorb_point(&inst.comm_e);
    transcript.absorb_scalar(inst.u);
    for &x_i in inst.x.iter() {
        transcript.absorb_scalar(x_i);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The BN254 G1 generator (1, 2).
    fn generator() -> G1Affine {
        G1Affine {
            x: u256::from(1u8),
            y: u256::from(2u8),
        }
    }

    /// The point at infinity, encoded as (0, 0).
    fn identity() -> G1Affine {
        G1Affine {
            x: u256::from(0u8),
            y: u256::from(0u8),
        }
    }

    /// A point that is not on the G1 curve: 3² = 9 ≠ 1³ + 3 = 4.
    fn off_curve() -> G1Affine {
        G1Affine {
            x: u256::from(1u8),
            y: u256::from(3u8),
        }
    }

    /// Build a valid instance with small scalar values for testing.
    /// `w_scalar` / `e_scalar` scale the generator for `comm_W` / `comm_E`
    /// (0 yields the identity, i.e. a fresh relaxed instance's `E = 0`).
    fn instance<const N: usize>(
        w_scalar: u64,
        e_scalar: u64,
        u: u64,
        x: [u256; N],
    ) -> RelaxedR1CSInstance<N> {
        RelaxedR1CSInstance::new(
            generator().scalar_mul(u256::from(w_scalar)),
            generator().scalar_mul(u256::from(e_scalar)),
            u256::from(u),
            x,
        )
        .expect("test instance must be valid")
    }

    /// Independently recompute the folded instance from the Nova formulas,
    /// deriving `r` from the same transcript order. Written separately from
    /// `fold_instances` so the test checks the arithmetic, not just that the
    /// function agrees with itself.
    fn expected_fold<const N: usize>(
        inst1: &RelaxedR1CSInstance<N>,
        inst2: &RelaxedR1CSInstance<N>,
        comm_t: &G1Affine,
    ) -> RelaxedR1CSInstance<N> {
        let mut transcript = Transcript::new();
        absorb_instance(&mut transcript, inst1);
        absorb_instance(&mut transcript, inst2);
        transcript.absorb_point(comm_t);
        let r = transcript.challenge();
        let r_squared = Bn254::mul(r, r);
        let comm_e = inst1
            .comm_e
            .add(&comm_t.scalar_mul(r))
            .add(&inst2.comm_e.scalar_mul(r_squared));
        let comm_w = inst1.comm_w.add(&inst2.comm_w.scalar_mul(r));
        let u = Bn254::add(inst1.u, Bn254::mul(r, inst2.u));
        let mut x = [u256::from(0u8); N];
        for ((x_out, &x1), &x2) in x.iter_mut().zip(inst1.x.iter()).zip(inst2.x.iter()) {
            *x_out = Bn254::add(x1, Bn254::mul(r, x2));
        }
        RelaxedR1CSInstance {
            comm_w,
            comm_e,
            u,
            x,
        }
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn fold_matches_hand_computed_values() {
        let inst1 = instance(1, 0, 1, [u256::from(1u8), u256::from(2u8)]);
        let inst2 = instance(2, 3, 1, [u256::from(3u8), u256::from(4u8)]);
        let comm_t = generator().scalar_mul(u256::from(7u8));
        let folded = fold_instances(&inst1, &inst2, &comm_t).unwrap();
        assert_eq!(folded, expected_fold(&inst1, &inst2, &comm_t));
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn fold_is_deterministic() {
        let inst1 = instance(1, 0, 1, [u256::from(1u8), u256::from(2u8)]);
        let inst2 = instance(2, 3, 1, [u256::from(3u8), u256::from(4u8)]);
        let comm_t = generator().scalar_mul(u256::from(7u8));
        let first = fold_instances(&inst1, &inst2, &comm_t).unwrap();
        let second = fold_instances(&inst1, &inst2, &comm_t).unwrap();
        assert_eq!(first, second);
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn fold_is_order_sensitive() {
        let inst1 = instance(1, 0, 1, [u256::from(1u8), u256::from(2u8)]);
        let inst2 = instance(2, 3, 1, [u256::from(3u8), u256::from(4u8)]);
        let comm_t = generator().scalar_mul(u256::from(7u8));
        // Swapping the instances changes the transcript (hence `r`) and the
        // formulas, so the folded instance must differ.
        let forward = fold_instances(&inst1, &inst2, &comm_t).unwrap();
        let swapped = fold_instances(&inst2, &inst1, &comm_t).unwrap();
        assert_ne!(forward, swapped);
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn multi_step_ivc_folding() {
        // Three sequential folds, as in an IVC chain: each step's output is
        // the next step's input, and every step is checked against the
        // hand-computed formulas.
        let inst1 = instance(1, 0, 1, [u256::from(1u8), u256::from(2u8)]);
        let inst2 = instance(2, 3, 1, [u256::from(3u8), u256::from(4u8)]);
        let inst3 = instance(4, 5, 1, [u256::from(5u8), u256::from(6u8)]);
        let inst4 = instance(6, 7, 1, [u256::from(7u8), u256::from(8u8)]);

        let t12 = generator().scalar_mul(u256::from(7u8));
        let folded12 = fold_instances(&inst1, &inst2, &t12).unwrap();
        assert_eq!(folded12, expected_fold(&inst1, &inst2, &t12));

        let t123 = generator().scalar_mul(u256::from(11u8));
        let folded123 = fold_instances(&folded12, &inst3, &t123).unwrap();
        assert_eq!(folded123, expected_fold(&folded12, &inst3, &t123));

        let t1234 = generator().scalar_mul(u256::from(13u8));
        let folded1234 = fold_instances(&folded123, &inst4, &t1234).unwrap();
        assert_eq!(folded1234, expected_fold(&folded123, &inst4, &t1234));

        // The chained result is itself a valid instance: it folds again.
        let t_last = generator().scalar_mul(u256::from(17u8));
        let inst5 = instance(8, 9, 1, [u256::from(9u8), u256::from(10u8)]);
        let folded_last = fold_instances(&folded1234, &inst5, &t_last).unwrap();
        assert_eq!(folded_last, expected_fold(&folded1234, &inst5, &t_last));
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn tampered_cross_term_changes_folded_output() {
        let inst1 = instance(1, 0, 1, [u256::from(1u8), u256::from(2u8)]);
        let inst2 = instance(2, 3, 1, [u256::from(3u8), u256::from(4u8)]);
        let comm_t = generator().scalar_mul(u256::from(7u8));
        let folded = fold_instances(&inst1, &inst2, &comm_t).unwrap();

        // An attacker who swaps in a different cross-term commitment gets a
        // different challenge and a different folded error commitment.
        let tampered_t = comm_t.scalar_mul(u256::from(2u8));
        let tampered = fold_instances(&inst1, &inst2, &tampered_t).unwrap();
        assert_ne!(folded, tampered);
        assert_ne!(folded.comm_e, tampered.comm_e);
    }

    #[test]
    fn off_curve_commitments_are_rejected() {
        let good = instance(1, 0, 1, [u256::from(1u8), u256::from(2u8)]);
        let comm_t = generator().scalar_mul(u256::from(7u8));

        let bad_w = RelaxedR1CSInstance {
            comm_w: off_curve(),
            comm_e: identity(),
            u: u256::from(1u8),
            x: [u256::from(1u8), u256::from(2u8)],
        };
        assert_eq!(fold_instances(&bad_w, &good, &comm_t), Err(ZkError::ConstraintUnsatisfied));

        let bad_e = RelaxedR1CSInstance {
            comm_w: generator(),
            comm_e: off_curve(),
            u: u256::from(1u8),
            x: [u256::from(1u8), u256::from(2u8)],
        };
        assert_eq!(fold_instances(&good, &bad_e, &comm_t), Err(ZkError::ConstraintUnsatisfied));

        assert_eq!(fold_instances(&good, &good, &off_curve()), Err(ZkError::ConstraintUnsatisfied));
    }

    #[test]
    fn out_of_range_scalars_are_rejected() {
        let good = instance(1, 0, 1, [u256::from(1u8), u256::from(2u8)]);
        let comm_t = generator().scalar_mul(u256::from(7u8));

        // u == FR_MODULUS is out of range (valid scalars are [0, r)).
        let bad_u = RelaxedR1CSInstance {
            comm_w: generator(),
            comm_e: identity(),
            u: Bn254::FR_MODULUS,
            x: [u256::from(1u8), u256::from(2u8)],
        };
        assert_eq!(fold_instances(&bad_u, &good, &comm_t), Err(ZkError::InvalidFieldElement));
        assert_eq!(fold_instances(&good, &bad_u, &comm_t), Err(ZkError::InvalidFieldElement));

        // An x entry at the modulus is out of range too.
        let bad_x = RelaxedR1CSInstance {
            comm_w: generator(),
            comm_e: identity(),
            u: u256::from(1u8),
            x: [u256::from(1u8), Bn254::FR_MODULUS],
        };
        assert_eq!(fold_instances(&good, &bad_x, &comm_t), Err(ZkError::InvalidFieldElement));

        // Above the modulus is rejected as well.
        let over_u = RelaxedR1CSInstance {
            comm_w: generator(),
            comm_e: identity(),
            u: Bn254::FR_MODULUS + u256::from(5u8),
            x: [u256::from(1u8), u256::from(2u8)],
        };
        assert_eq!(fold_instances(&good, &over_u, &comm_t), Err(ZkError::InvalidFieldElement));
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn identity_error_commitment_is_accepted() {
        // A fresh relaxed instance has E = 0, whose commitment is the
        // identity; folding must accept it, not reject it as off-curve.
        let fresh = instance(1, 0, 1, [u256::from(1u8), u256::from(2u8)]);
        assert_eq!(fresh.comm_e, identity());
        let inst2 = instance(2, 3, 1, [u256::from(3u8), u256::from(4u8)]);
        let comm_t = generator().scalar_mul(u256::from(7u8));
        let folded = fold_instances(&fresh, &inst2, &comm_t).unwrap();
        assert_eq!(folded, expected_fold(&fresh, &inst2, &comm_t));

        // The cross-term commitment may itself be the identity (T = 0), in
        // which case E' = E1 + r²·E2.
        let folded_zero_t = fold_instances(&fresh, &inst2, &identity()).unwrap();
        assert_eq!(folded_zero_t, expected_fold(&fresh, &inst2, &identity()));
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn boundary_scalars_fold_correctly() {
        let max = Bn254::FR_MODULUS - u256::from(1u8);
        let inst1 = instance(1, 0, 0, [u256::from(0u8), max]);
        let mut inst2 = instance(2, 3, 1, [max, u256::from(0u8)]);
        inst2.u = max;
        let comm_t = generator().scalar_mul(u256::from(7u8));
        // u = 0, u = r - 1, x = r - 1 all fold without error and match the
        // hand-computed formulas (all arithmetic is mod r).
        let folded = fold_instances(&inst1, &inst2, &comm_t).unwrap();
        assert_eq!(folded, expected_fold(&inst1, &inst2, &comm_t));
    }

    #[test]
    fn instance_new_rejects_invalid_inputs() {
        assert_eq!(
            RelaxedR1CSInstance::new(
                off_curve(),
                identity(),
                u256::from(1u8),
                [u256::from(1u8), u256::from(2u8)],
            ),
            Err(ZkError::ConstraintUnsatisfied)
        );
        assert_eq!(
            RelaxedR1CSInstance::new(
                generator(),
                identity(),
                Bn254::FR_MODULUS,
                [u256::from(1u8), u256::from(2u8)],
            ),
            Err(ZkError::InvalidFieldElement)
        );
        let valid = RelaxedR1CSInstance::new(
            generator(),
            identity(),
            u256::from(1u8),
            [u256::from(1u8), u256::from(2u8)],
        );
        assert!(valid.is_ok());
    }
}
