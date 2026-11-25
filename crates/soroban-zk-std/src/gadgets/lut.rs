//! Functional Lookup Tables (LUTs) — Issue #367, Phase 3.
//!
//! A LUT is a *public* pre-computed table of `(inputs…, output)` rows. Gadgets
//! can prove that a claimed `(inputs, output)` tuple is present in the table
//! without re-evaluating the (possibly expensive) function it encodes — this is
//! the gas-saving primitive called out in the issue's technical constraints.
//!
//! Soundness: the table is a fixed circuit constant, so a prover cannot forge a
//! row that is not present. [`Lut::lookup`] returns the canonical output and
//! [`Lut::assert_lookup`] rejects any claimed output that does not match a real
//! table row.

use soroban_sdk::{Env, Vec, U256};
use soroban_zk_core::ZkError;

/// A static lookup table.
///
/// Each row is `[in_0, in_1, …, in_{width-1}, output]` (so `width + 1` columns).
/// The table may be kept sorted by its input columns to enable binary-search
/// lookups; [`Lut::sort`] pre-sorts and sets the `sorted` flag.
pub struct Lut {
    /// Number of input columns (`width`).
    width: u32,
    /// Rows, each `width + 1` columns.
    table: Vec<Vec<U256>>,
    /// Whether `table` is sorted by input columns (enables binary search).
    sorted: bool,
}

impl Lut {
    /// Build a LUT from rows. Every row must have exactly `width + 1` columns.
    pub fn new(width: u32, rows: Vec<Vec<U256>>) -> Result<Self, ZkError> {
        if width == 0 {
            return Err(ZkError::InvalidInput);
        }
        for i in 0..rows.len() {
            if rows.get(i).unwrap().len() != width + 1 {
                return Err(ZkError::InvalidInput);
            }
        }
        Ok(Self {
            width,
            table: rows,
            sorted: false,
        })
    }

    /// Number of input columns.
    pub fn width(&self) -> u32 {
        self.width
    }

    /// Number of rows.
    pub fn len(&self) -> u32 {
        self.table.len()
    }

    pub fn is_empty(&self) -> bool {
        self.table.is_empty()
    }

    /// Sort rows lexicographically by their input columns and mark the table as
    /// sorted, enabling O(log n) lookups.
    pub fn sort(&mut self) {
        let n = self.table.len();
        for i in 1..n {
            let mut j = i;
            while j > 0 {
                let a = self.table.get(j - 1).unwrap();
                let b = self.table.get(j).unwrap();
                if Self::row_lt(&b, &a) {
                    self.table.set(j - 1, b);
                    self.table.set(j, a);
                    j -= 1;
                } else {
                    break;
                }
            }
        }
        self.sorted = true;
    }

    /// Return the row at `index` (input columns + output).
    pub fn row(&self, index: u32) -> Vec<U256> {
        self.table.get(index).unwrap()
    }

    fn input_eq(row: &Vec<U256>, inputs: &[U256]) -> bool {
        let n = inputs.len() as u32;
        for i in 0..n {
            if row.get(i).unwrap() != inputs[i as usize] {
                return false;
            }
        }
        true
    }

    fn row_lt(a: &Vec<U256>, b: &Vec<U256>) -> bool {
        let w = a.len().min(b.len());
        for i in 0..w {
            let av = a.get(i).unwrap();
            let bv = b.get(i).unwrap();
            if av < bv {
                return true;
            } else if av > bv {
                return false;
            }
        }
        false
    }

    fn cmp_input(row: &Vec<U256>, inputs: &[U256]) -> core::cmp::Ordering {
        let n = inputs.len() as u32;
        for i in 0..n {
            let rv = row.get(i).unwrap();
            let iv = inputs[i as usize].clone();
            if rv < iv {
                return core::cmp::Ordering::Less;
            } else if rv > iv {
                return core::cmp::Ordering::Greater;
            }
        }
        core::cmp::Ordering::Equal
    }

    /// Look up the output for `inputs`, returning it if a matching row exists.
    /// Proves (against the public table) that `inputs` is present.
    pub fn lookup(&self, inputs: &[U256]) -> Result<U256, ZkError> {
        if inputs.len() as u32 != self.width {
            return Err(ZkError::InvalidInput);
        }
        if self.sorted {
            if let Some(out) = self.lookup_sorted(inputs) {
                return Ok(out);
            }
            return Err(ZkError::ConstraintUnsatisfied);
        }
        for idx in 0..self.table.len() {
            let row = self.table.get(idx).unwrap();
            if Self::input_eq(&row, inputs) {
                return Ok(row.get(self.width).unwrap());
            }
        }
        Err(ZkError::ConstraintUnsatisfied)
    }

    fn lookup_sorted(&self, inputs: &[U256]) -> Option<U256> {
        let mut lo: u32 = 0;
        let mut hi = self.table.len();
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            let row = self.table.get(mid).unwrap();
            match Self::cmp_input(&row, inputs) {
                core::cmp::Ordering::Less => lo = mid + 1,
                core::cmp::Ordering::Greater => hi = mid,
                core::cmp::Ordering::Equal => return Some(row.get(self.width).unwrap()),
            }
        }
        None
    }

    /// Look up `inputs` and constrain that the result equals `claimed_output`.
    /// A prover supplying a wrong output is rejected.
    pub fn assert_lookup(&self, inputs: &[U256], claimed_output: &U256) -> Result<(), ZkError> {
        let out = self.lookup(inputs)?;
        if &out == claimed_output {
            Ok(())
        } else {
            Err(ZkError::ConstraintUnsatisfied)
        }
    }

    /// Build a 1-to-1 range-check LUT: every value in `[0, max]` maps to `1`.
    /// Looking up a value in this table proves it is in range.
    pub fn range_lut(env: &Env, max: U256) -> Result<Self, ZkError> {
        let mut rows = Vec::new(env);
        let mut cur = U256::from_u128(env, 0);
        let one = U256::from_u128(env, 1);
        loop {
            let mut row = Vec::new(env);
            row.push_back(cur.clone());
            row.push_back(one.clone());
            rows.push_back(row);
            if cur == max {
                break;
            }
            cur = cur.add(&one);
        }
        Self::new(1, rows)
    }

    /// Build a 2-input boolean gate LUT for AND / OR / XOR over a single bit.
    /// `op` is one of [`GateOp::And`] / [`GateOp::Or`] / [`GateOp::Xor`]. The
    /// table maps `(a, b) -> out`.
    pub fn binary_gate_lut(env: &Env, op: GateOp) -> Result<Self, ZkError> {
        let truth = op.truth_table();
        let mut rows = Vec::new(env);
        for (a, b, out) in truth {
            let mut row = Vec::new(env);
            row.push_back(U256::from_u128(env, a as u128));
            row.push_back(U256::from_u128(env, b as u128));
            row.push_back(U256::from_u128(env, out as u128));
            rows.push_back(row);
        }
        Self::new(2, rows)
    }
}

/// Which boolean gate a [`Lut::binary_gate_lut`] encodes.
#[derive(Clone, Copy)]
pub enum GateOp {
    And,
    Or,
    Xor,
}

impl GateOp {
    fn truth_table(self) -> [(u8, u8, u8); 4] {
        match self {
            GateOp::And => [(0, 0, 0), (0, 1, 0), (1, 0, 0), (1, 1, 1)],
            GateOp::Or => [(0, 0, 0), (0, 1, 1), (1, 0, 1), (1, 1, 1)],
            GateOp::Xor => [(0, 0, 0), (0, 1, 1), (1, 0, 1), (1, 1, 0)],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::Env;

    fn env() -> Env {
        let e = Env::default();
        e.cost_estimate().budget().reset_unlimited();
        e
    }

    #[test]
    fn lookup_finds_row_and_rejects_missing() {
        let env = env();
        let mut rows = Vec::new(&env);
        for x in 0u128..8 {
            let mut row = Vec::new(&env);
            row.push_back(U256::from_u128(&env, x));
            row.push_back(U256::from_u128(&env, x * x));
            rows.push_back(row);
        }
        let lut = Lut::new(1, rows).unwrap();
        assert_eq!(
            lut.lookup(&[U256::from_u128(&env, 3)]).unwrap(),
            U256::from_u128(&env, 9)
        );
        assert_eq!(
            lut.lookup(&[U256::from_u128(&env, 100)]),
            Err(ZkError::ConstraintUnsatisfied)
        );
    }

    #[test]
    fn sorted_lookup_matches_linear() {
        let env = env();
        let mut rows = Vec::new(&env);
        for x in 0u128..64 {
            let mut row = Vec::new(&env);
            row.push_back(U256::from_u128(&env, x));
            row.push_back(U256::from_u128(&env, x + 1));
            rows.push_back(row);
        }
        let mut lut = Lut::new(1, rows).unwrap();
        lut.sort();
        assert_eq!(
            lut.lookup(&[U256::from_u128(&env, 0)]).unwrap(),
            U256::from_u128(&env, 1)
        );
        assert_eq!(
            lut.lookup(&[U256::from_u128(&env, 63)]).unwrap(),
            U256::from_u128(&env, 64)
        );
        assert_eq!(
            lut.lookup(&[U256::from_u128(&env, 200)]),
            Err(ZkError::ConstraintUnsatisfied)
        );
    }

    #[test]
    fn assert_lookup_rejects_wrong_output() {
        let env = env();
        let mut rows = Vec::new(&env);
        let mut row = Vec::new(&env);
        row.push_back(U256::from_u128(&env, 5));
        row.push_back(U256::from_u128(&env, 25));
        rows.push_back(row);
        let lut = Lut::new(1, rows).unwrap();
        assert!(lut
            .assert_lookup(&[U256::from_u128(&env, 5)], &U256::from_u128(&env, 25))
            .is_ok());
        assert_eq!(
            lut.assert_lookup(&[U256::from_u128(&env, 5)], &U256::from_u128(&env, 26)),
            Err(ZkError::ConstraintUnsatisfied)
        );
    }

    #[test]
    fn range_lut_proves_membership() {
        let env = env();
        let lut = Lut::range_lut(&env, U256::from_u128(&env, 15)).unwrap();
        assert!(lut
            .assert_lookup(&[U256::from_u128(&env, 0)], &U256::from_u128(&env, 1))
            .is_ok());
        assert!(lut
            .assert_lookup(&[U256::from_u128(&env, 15)], &U256::from_u128(&env, 1))
            .is_ok());
        assert_eq!(
            lut.assert_lookup(&[U256::from_u128(&env, 16)], &U256::from_u128(&env, 1)),
            Err(ZkError::ConstraintUnsatisfied)
        );
    }

    #[test]
    fn binary_gate_lut_matches_reference() {
        let env = env();
        let and = Lut::binary_gate_lut(&env, GateOp::And).unwrap();
        assert_eq!(
            and.lookup(&[U256::from_u128(&env, 1), U256::from_u128(&env, 1)])
                .unwrap(),
            U256::from_u128(&env, 1)
        );
        assert_eq!(
            and.lookup(&[U256::from_u128(&env, 1), U256::from_u128(&env, 0)])
                .unwrap(),
            U256::from_u128(&env, 0)
        );
        let xor = Lut::binary_gate_lut(&env, GateOp::Xor).unwrap();
        assert_eq!(
            xor.lookup(&[U256::from_u128(&env, 1), U256::from_u128(&env, 1)])
                .unwrap(),
            U256::from_u128(&env, 0)
        );
    }
}
