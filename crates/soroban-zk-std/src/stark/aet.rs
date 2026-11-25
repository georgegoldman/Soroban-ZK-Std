//! Algebraic Execution Trace (AET) parameters & boundary/transition checks
//! (Issue #366, Phase 1).
//!
//! The verifier never holds the full trace in memory — it only ever sees the
//! rows **revealed** by Merkle queries. So the checks here operate on those
//! revealed slices (`&[Felt]`), keeping the hot path allocation-free.

use core::ops::Mul;
use soroban_sdk::{Bytes, BytesN, Env, Vec};

use crate::stark::field::Felt;
use crate::stark::merkle;
use soroban_zk_core::ZkError;

/// Coset offset of the trace evaluation domain.
///
/// The trace domain is `{ TRACE_COSET_OFFSET · ω_N^j }` for a `2^N`-th root of
/// unity `ω_N`. It must differ from the FRI/LDE coset (which is offset by a
/// power of two) so that the constraint vanishing polynomial
/// `Z(x) = x^N − TRACE_COSET_OFFSET^N` never vanishes on the FRI domain — a
/// zero there would make the composition polynomial undefined.
pub const TRACE_COSET_OFFSET: u64 = 5;

/// Maximum number of columns per trace row that [`row_leaf`] can hash.
pub const MAX_ROW_COLUMNS: usize = 64;

/// The `index`-th point of the trace evaluation domain of `2^log` rows.
#[inline]
pub fn trace_domain_point(log: u32, index: u64) -> Felt {
    Felt::new(TRACE_COSET_OFFSET).mul(Felt::layer_root(log).pow(index))
}

/// Structured parameters describing an execution trace.
///
/// * `log_trace_length` — the trace has `2^log_trace_length` rows (the FRI
///   domain log-size for the trace commitment).
/// * `trace_width` — number of columns (registers) per row.
pub struct AetConfig {
    pub trace_width: u32,
    pub log_trace_length: u32,
}

impl AetConfig {
    /// Construct, rejecting degenerate sizes.
    pub fn new(log_trace_length: u32, trace_width: u32) -> Result<Self, ZkError> {
        if log_trace_length == 0
            || log_trace_length > 32
            || trace_width == 0
            || trace_width as usize > MAX_ROW_COLUMNS
        {
            return Err(ZkError::InvalidInput);
        }
        Ok(Self {
            trace_width,
            log_trace_length,
        })
    }

    /// Number of rows in the trace.
    pub fn trace_length(&self) -> u64 {
        1u64 << self.log_trace_length
    }

    /// The `index`-th coset domain point for this trace's evaluation domain.
    pub fn domain_point(&self, index: u64) -> Felt {
        trace_domain_point(self.log_trace_length, index)
    }
}

/// A boundary constraint: column `column` of row `step` must equal `value`.
#[derive(Clone, Copy)]
pub struct BoundaryConstraint {
    pub step: u32,
    pub column: u32,
    pub value: Felt,
}

impl BoundaryConstraint {
    /// Check the constraint against a *revealed* value at the claimed cell.
    pub fn verify(&self, revealed: &Felt) -> Result<(), ZkError> {
        if revealed == &self.value {
            Ok(())
        } else {
            Err(ZkError::BoundaryConstraintFailed)
        }
    }
}

/// Verify a batch of boundary constraints against revealed values.
pub fn verify_boundary_constraints(checks: &[(BoundaryConstraint, Felt)]) -> Result<(), ZkError> {
    for (c, revealed) in checks {
        c.verify(revealed)?;
    }
    Ok(())
}

/// Verify a transition (AIR) constraint between two revealed consecutive rows.
///
/// `f(cur, next)` must evaluate to `0` for the constraint to hold; it is supplied
/// by the caller so arbitrary AIR transition polynomials can be checked without
/// this crate hard-coding any specific STARK.
pub fn verify_transition<F>(cur: &[Felt], next: &[Felt], f: F) -> Result<(), ZkError>
where
    F: Fn(&[Felt], &[Felt]) -> Felt,
{
    if f(cur, next).is_zero() {
        Ok(())
    } else {
        Err(ZkError::TransitionConstraintFailed)
    }
}

/// Merkle leaf for one trace row: SHA-256 over the concatenated 8-byte encodings
/// of its columns.
///
/// Rows with no columns, or with more than [`MAX_ROW_COLUMNS`] columns, are
/// rejected instead of overflowing the fixed scratch buffer.
pub fn row_leaf(env: &Env, row: &[Felt]) -> Result<BytesN<32>, ZkError> {
    if row.is_empty() || row.len() > MAX_ROW_COLUMNS {
        return Err(ZkError::InvalidInput);
    }
    let mut buf = [0u8; 8 * MAX_ROW_COLUMNS];
    let mut n = 0usize;
    for f in row {
        let b = f.to_bytes();
        buf[n..n + 8].copy_from_slice(&b);
        n += 8;
    }
    Ok(merkle::hash(env, &Bytes::from_slice(env, &buf[..n])))
}

/// Commit to a trace by Merkle-rooting its row leaves. `rows` is a slice of
/// column-slices (one per row). Prover/verifier-shared structure.
pub fn commit_trace(env: &Env, rows: &[&[Felt]]) -> Result<BytesN<32>, ZkError> {
    if rows.is_empty() {
        return Err(ZkError::InvalidInput);
    }
    let mut leaves: Vec<BytesN<32>> = Vec::new(env);
    for r in rows {
        leaves.push_back(row_leaf(env, r)?);
    }
    Ok(merkle::merkle_root(env, &leaves))
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use core::ops::{Add, Sub};

    #[test]
    fn boundary_check_accepts_and_rejects() {
        let c = BoundaryConstraint {
            step: 0,
            column: 1,
            value: Felt::new(42),
        };
        assert!(c.verify(&Felt::new(42)).is_ok());
        assert_eq!(
            c.verify(&Felt::new(43)),
            Err(ZkError::BoundaryConstraintFailed)
        );
    }

    #[test]
    fn transition_check_rejects_wrong_rows() {
        // Constraint: next[0] == cur[0] + 1 (a simple counter trace).
        let check = |cur: &[Felt], next: &[Felt]| next[0].sub(cur[0].add(Felt::ONE));
        let good_cur = [Felt::new(5)];
        let good_next = [Felt::new(6)];
        assert!(verify_transition(&good_cur, &good_next, check).is_ok());

        let bad_next = [Felt::new(7)];
        assert_eq!(
            verify_transition(&good_cur, &bad_next, check),
            Err(ZkError::TransitionConstraintFailed)
        );
    }

    #[test]
    fn row_leaf_rejects_degenerate_widths() {
        let env = soroban_sdk::Env::default();
        env.cost_estimate().budget().reset_unlimited();
        assert_eq!(row_leaf(&env, &[]), Err(ZkError::InvalidInput));
        let wide = [Felt::ZERO; MAX_ROW_COLUMNS + 1];
        assert_eq!(row_leaf(&env, &wide), Err(ZkError::InvalidInput));
        assert!(row_leaf(&env, &[Felt::ZERO]).is_ok());
    }

    #[test]
    fn trace_commitment_and_boundary_tie_together() {
        let env = soroban_sdk::Env::default();
        env.cost_estimate().budget().reset_unlimited();
        // Build a tiny counter trace: row i has column 0 = i (over 4 rows).
        let rows: std::vec::Vec<std::vec::Vec<Felt>> =
            (0..4u64).map(|i| std::vec![Felt::new(i)]).collect();
        let row_refs: std::vec::Vec<&[Felt]> = rows.iter().map(|r| r.as_slice()).collect();
        let root = commit_trace(&env, &row_refs).expect("commit");

        // Reveal row 2 and check its boundary constraint via the Merkle path.
        let leaf = row_leaf(&env, &rows[2]).expect("leaf");
        let leaves: Vec<BytesN<32>> = {
            let mut v = Vec::new(&env);
            for r in rows.iter() {
                v.push_back(row_leaf(&env, r).expect("leaf"));
            }
            v
        };
        let path = merkle::open(&env, &leaves, 2);
        assert!(path.verify(&env, &leaf, &root));

        let bc = BoundaryConstraint {
            step: 2,
            column: 0,
            value: Felt::new(2),
        };
        assert!(bc.verify(&Felt::new(2)).is_ok());
    }

    #[test]
    fn trace_domain_never_meets_the_fri_coset() {
        // The composition divides by Z(x) = x^N - TRACE_COSET_OFFSET^N on the FRI
        // coset; if any coset point were a root of Z the verifier could not
        // evaluate the composition there.
        let log_n = 6u32;
        let log_m = log_n + 2;
        let n = 1u64 << log_n;
        let c_n = Felt::new(TRACE_COSET_OFFSET).pow(n);
        for i in 0..(1u64 << log_m) {
            let z = Felt::domain_point(log_m, i);
            assert!(
                !z.pow(n).sub(c_n).is_zero(),
                "Z vanishes at coset point {i}"
            );
        }
    }
}
