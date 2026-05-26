//! Groth16 verification pipeline for BN254.
//!
//! Implements the full verifier as described in Groth (2016):
//! "On the Size of Pairing-based Non-interactive Arguments".
//!
//! The pairing check is delegated to the Soroban CAP-0075 host function
//! via the `PairingCheck` trait, keeping this module `no_std` and
//! host-agnostic.

use crate::{Bn254, G1Affine, G1Projective, ZkError};
use ethnum::u256;

// ── Data Structures ───────────────────────────────────────────────────────────

/// A Groth16 proof consisting of three G1/G2 points.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct Groth16Proof {
    /// π_A ∈ G1
    pub a: G1Affine,
    /// π_B ∈ G2 (represented as two Fq2 coordinates)
    pub b_x: (u256, u256),
    pub b_y: (u256, u256),
    /// π_C ∈ G1
    pub c: G1Affine,
}

/// A Groth16 verification key.
#[derive(Debug, Clone)]
pub struct VerifyingKey {
    /// α ∈ G1
    pub alpha_g1: G1Affine,
    /// β ∈ G2
    pub beta_g2_x: (u256, u256),
    pub beta_g2_y: (u256, u256),
    /// γ ∈ G2
    pub gamma_g2_x: (u256, u256),
    pub gamma_g2_y: (u256, u256),
    /// δ ∈ G2
    pub delta_g2_x: (u256, u256),
    pub delta_g2_y: (u256, u256),
    /// IC[0..n] ∈ G1 — public input commitments
    pub ic: [G1Affine; MAX_PUBLIC_INPUTS],
    pub ic_len: usize,
}

/// Maximum number of public inputs supported without heap allocation.
pub const MAX_PUBLIC_INPUTS: usize = 16;

// ── Public Input Aggregation ──────────────────────────────────────────────────

/// Aggregate public inputs into a single G1 point.
///
/// Computes: `vk_x = IC[0] + Σᵢ public_inputs[i] · IC[i+1]`
///
/// This is the "public input accumulator" used in the Groth16 verification
/// equation.
pub fn aggregate_public_inputs(
    vk: &VerifyingKey,
    public_inputs: &[u256],
) -> Result<G1Affine, ZkError> {
    if public_inputs.len() + 1 > vk.ic_len {
        return Err(ZkError::InvalidInput);
    }

    // Validate all public inputs are in Fr
    for &pi in public_inputs {
        if !Bn254::is_valid_scalar(pi) {
            return Err(ZkError::InvalidFieldElement);
        }
    }

    // Start with IC[0]
    let mut acc = G1Projective::from(vk.ic[0]);

    // Add IC[i+1] * public_inputs[i] for each input
    for (i, &scalar) in public_inputs.iter().enumerate() {
        let term = Bn254::g1_scalar_mul(G1Projective::from(vk.ic[i + 1]), scalar);
        acc = acc.add(&term);
    }

    Ok(acc.to_affine())
}

// ── Verification Equation ─────────────────────────────────────────────────────

/// Trait for performing the BN254 pairing check.
///
/// Implemented by `zk-soroban` using the CAP-0075 host call.
/// A software fallback can be provided for off-chain testing.
pub trait PairingCheck {
    /// Returns `true` iff `e(a1,b1) · e(a2,b2) · e(a3,b3) · e(a4,b4) == 1`.
    fn check_4(
        &self,
        a1: G1Affine,
        b1_x: (u256, u256),
        b1_y: (u256, u256),
        a2: G1Affine,
        b2_x: (u256, u256),
        b2_y: (u256, u256),
        a3: G1Affine,
        b3_x: (u256, u256),
        b3_y: (u256, u256),
        a4: G1Affine,
        b4_x: (u256, u256),
        b4_y: (u256, u256),
    ) -> Result<bool, ZkError>;
}

/// Verify a Groth16 proof.
///
/// Checks the pairing equation:
/// ```text
/// e(A, B) = e(α, β) · e(vk_x, γ) · e(C, δ)
/// ```
///
/// Rearranged for the multi-pairing API:
/// ```text
/// e(A, B) · e(-α, β) · e(-vk_x, γ) · e(-C, δ) = 1
/// ```
pub fn verify<P: PairingCheck>(
    pairing: &P,
    vk: &VerifyingKey,
    proof: &Groth16Proof,
    public_inputs: &[u256],
) -> Result<bool, ZkError> {
    // 1. Aggregate public inputs → vk_x
    let vk_x = aggregate_public_inputs(vk, public_inputs)?;

    // 2. Negate A (negate y coordinate mod q)
    let neg_a = negate_g1(proof.a);

    // 3. Pairing check:
    //    e(-A, B) · e(α, β) · e(vk_x, γ) · e(C, δ) = 1
    pairing.check_4(
        neg_a,
        proof.b_x,
        proof.b_y,
        vk.alpha_g1,
        vk.beta_g2_x,
        vk.beta_g2_y,
        vk_x,
        vk.gamma_g2_x,
        vk.gamma_g2_y,
        proof.c,
        vk.delta_g2_x,
        vk.delta_g2_y,
    )
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Negate a G1 affine point: `(x, -y mod q)`.
#[inline(always)]
pub fn negate_g1(p: G1Affine) -> G1Affine {
    let zero = u256::from_words(0, 0);
    G1Affine {
        x: p.x,
        y: if p.y == zero {
            zero
        } else {
            Bn254::sub_fq(Bn254::FQ_MODULUS, p.y)
        },
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn fr(v: u128) -> u256 {
        u256::from_words(0, v)
    }

    fn g1(x: u128, y: u128) -> G1Affine {
        G1Affine {
            x: fr(x),
            y: fr(y),
        }
    }

    #[test]
    fn negate_g1_zero_y() {
        let p = g1(5, 0);
        let neg = negate_g1(p);
        assert_eq!(neg.y, fr(0));
    }

    #[test]
    fn negate_g1_nonzero_y() {
        let p = g1(1, 2);
        let neg = negate_g1(p);
        // neg.y + p.y should equal FQ_MODULUS
        let sum = Bn254::add_fq(p.y, neg.y);
        assert_eq!(sum, fr(0)); // wraps to 0 mod q
    }

    #[test]
    fn aggregate_empty_public_inputs() {
        let ic0 = g1(1, 2);
        let mut vk = VerifyingKey {
            alpha_g1: g1(0, 0),
            beta_g2_x: (fr(0), fr(0)),
            beta_g2_y: (fr(0), fr(0)),
            gamma_g2_x: (fr(0), fr(0)),
            gamma_g2_y: (fr(0), fr(0)),
            delta_g2_x: (fr(0), fr(0)),
            delta_g2_y: (fr(0), fr(0)),
            ic: [g1(0, 0); MAX_PUBLIC_INPUTS],
            ic_len: 1,
        };
        vk.ic[0] = ic0;

        let result = aggregate_public_inputs(&vk, &[]).unwrap();
        assert_eq!(result, ic0);
    }

    #[test]
    fn aggregate_rejects_too_many_inputs() {
        let vk = VerifyingKey {
            alpha_g1: g1(0, 0),
            beta_g2_x: (fr(0), fr(0)),
            beta_g2_y: (fr(0), fr(0)),
            gamma_g2_x: (fr(0), fr(0)),
            gamma_g2_y: (fr(0), fr(0)),
            delta_g2_x: (fr(0), fr(0)),
            delta_g2_y: (fr(0), fr(0)),
            ic: [g1(0, 0); MAX_PUBLIC_INPUTS],
            ic_len: 1, // only IC[0], no room for public inputs
        };
        // Providing 1 public input requires ic_len >= 2
        let result = aggregate_public_inputs(&vk, &[fr(1)]);
        assert_eq!(result, Err(ZkError::InvalidInput));
    }

    #[test]
    fn aggregate_rejects_invalid_scalar() {
        let mut vk = VerifyingKey {
            alpha_g1: g1(0, 0),
            beta_g2_x: (fr(0), fr(0)),
            beta_g2_y: (fr(0), fr(0)),
            gamma_g2_x: (fr(0), fr(0)),
            gamma_g2_y: (fr(0), fr(0)),
            delta_g2_x: (fr(0), fr(0)),
            delta_g2_y: (fr(0), fr(0)),
            ic: [g1(0, 0); MAX_PUBLIC_INPUTS],
            ic_len: 2,
        };
        vk.ic[0] = g1(1, 2);
        vk.ic[1] = g1(1, 2);

        // FR_MODULUS itself is invalid
        let result = aggregate_public_inputs(&vk, &[Bn254::FR_MODULUS]);
        assert_eq!(result, Err(ZkError::InvalidFieldElement));
    }
}
