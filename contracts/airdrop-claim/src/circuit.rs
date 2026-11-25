//! Test-only reference implementation of the airdrop circuit (arkworks R1CS).
//!
//! The contract never runs this code: it only checks a Groth16 proof against
//! the circuit's verifying key. The tests use it to produce **real** proofs for
//! the exact public-input layout the contract expects, so the happy path and
//! every negative path go through the genuine pairing check.
//!
//! Hash: Poseidon2 over BN254 (t = 3, d = 5, R_F = 8, R_P = 56), driven as the
//! same capacity-zero, rate-2 sponge as `soroban_zk_std::poseidon2::hash_to_field`,
//! with the round constants read from `soroban_zk_std::cache::round_constants`.
//! `reference_poseidon2_matches_library` in `test.rs` pins the native
//! implementation below to the on-chain host permutation.
//!
//! Statement (public inputs, in order):
//!
//! ```text
//! [0] merkle_root  = MerkleRoot_Poseidon2(leaf, path)        leaf = H(secret)
//! [1] nullifier    = H(secret, NULLIFIER_DOMAIN)
//! [2] recipient    = recipient_to_field(recipient)   (bound via recipient² = sq)
//! ```
//!
//! where `H(..)` is the Poseidon2 sponge hash and each Merkle node is
//! `H(left, right)`.

use ark_bn254::Fr;
use ark_ff::{AdditiveGroup, Field};
use ark_relations::gr1cs::{
    ConstraintSynthesizer, ConstraintSystemRef, LinearCombination, SynthesisError, Variable,
};

/// Depth of the eligibility tree used by the tests (16 leaves).
pub const DEPTH: usize = 4;

/// Domain-separation constant hashed with the secret to derive the nullifier.
pub const NULLIFIER_DOMAIN: u64 = 1;

const FULL_HALF: usize = 4;
const PARTIAL: usize = 56;
const ROUNDS: usize = 2 * FULL_HALF + PARTIAL;

/// Poseidon2 BN254 t = 3 parameters.
#[derive(Clone)]
pub struct Poseidon2Params {
    pub rc: [[Fr; 3]; ROUNDS],
    pub diag: [Fr; 3],
}

// ── Native Poseidon2 ─────────────────────────────────────────────────────────

fn sbox(x: Fr) -> Fr {
    let x2 = x.square();
    x2.square() * x
}

fn external(s: &mut [Fr; 3]) {
    let sum = s[0] + s[1] + s[2];
    for v in s.iter_mut() {
        *v += sum;
    }
}

fn internal(s: &mut [Fr; 3], diag: &[Fr; 3]) {
    let sum = s[0] + s[1] + s[2];
    for (v, d) in s.iter_mut().zip(diag.iter()) {
        *v = *v * d + sum;
    }
}

impl Poseidon2Params {
    pub fn permute(&self, s: &mut [Fr; 3]) {
        external(s);
        for r in 0..ROUNDS {
            if !(FULL_HALF..FULL_HALF + PARTIAL).contains(&r) {
                for i in 0..3 {
                    s[i] = sbox(s[i] + self.rc[r][i]);
                }
                external(s);
            } else {
                s[0] = sbox(s[0] + self.rc[r][0]);
                internal(s, &self.diag);
            }
        }
    }

    /// Capacity-zero, rate-2 sponge hash (absorb all, permute on every full
    /// block, then one final permutation and output `state[0]`).
    pub fn hash(&self, inputs: &[Fr]) -> Fr {
        let mut s = [Fr::ZERO; 3];
        let mut idx = 0;
        for x in inputs {
            s[idx] += x;
            idx += 1;
            if idx == 2 {
                self.permute(&mut s);
                idx = 0;
            }
        }
        self.permute(&mut s);
        s[0]
    }
}

// ── R1CS gadget ──────────────────────────────────────────────────────────────

/// A circuit wire: a linear combination together with its assigned value.
#[derive(Clone)]
struct Wire {
    lc: LinearCombination<Fr>,
    val: Fr,
}

impl Wire {
    fn var(v: Variable, val: Fr) -> Self {
        Self {
            lc: LinearCombination::from(v),
            val,
        }
    }

    fn constant(c: Fr) -> Self {
        Self {
            lc: LinearCombination::from((c, Variable::One)),
            val: c,
        }
    }

    fn zero() -> Self {
        Self {
            lc: LinearCombination::zero(),
            val: Fr::ZERO,
        }
    }

    fn add(&self, o: &Wire) -> Wire {
        Wire {
            lc: &self.lc + &o.lc,
            val: self.val + o.val,
        }
    }

    fn sub(&self, o: &Wire) -> Wire {
        Wire {
            lc: &self.lc - &o.lc,
            val: self.val - o.val,
        }
    }

    fn scale(&self, c: Fr) -> Wire {
        Wire {
            lc: &self.lc * c,
            val: self.val * c,
        }
    }
}

fn witness(cs: &ConstraintSystemRef<Fr>, val: Fr) -> Result<Wire, SynthesisError> {
    let v = cs.new_witness_variable(|| Ok(val))?;
    Ok(Wire::var(v, val))
}

/// `out = a * b`, one constraint.
fn mul(cs: &ConstraintSystemRef<Fr>, a: &Wire, b: &Wire) -> Result<Wire, SynthesisError> {
    let out = witness(cs, a.val * b.val)?;
    cs.enforce_r1cs_constraint(|| a.lc.clone(), || b.lc.clone(), || out.lc.clone())?;
    Ok(out)
}

fn sbox_gadget(cs: &ConstraintSystemRef<Fr>, x: &Wire) -> Result<Wire, SynthesisError> {
    let x2 = mul(cs, x, x)?;
    let x4 = mul(cs, &x2, &x2)?;
    mul(cs, &x4, x)
}

fn external_gadget(s: &mut [Wire; 3]) {
    let sum = s[0].add(&s[1]).add(&s[2]);
    for w in s.iter_mut() {
        *w = w.add(&sum);
    }
}

fn internal_gadget(s: &mut [Wire; 3], diag: &[Fr; 3]) {
    let sum = s[0].add(&s[1]).add(&s[2]);
    for (w, d) in s.iter_mut().zip(diag.iter()) {
        *w = w.scale(*d).add(&sum);
    }
}

fn permute_gadget(
    cs: &ConstraintSystemRef<Fr>,
    p: &Poseidon2Params,
    s: &mut [Wire; 3],
) -> Result<(), SynthesisError> {
    external_gadget(s);
    for r in 0..ROUNDS {
        if !(FULL_HALF..FULL_HALF + PARTIAL).contains(&r) {
            for i in 0..3 {
                let x = s[i].add(&Wire::constant(p.rc[r][i]));
                s[i] = sbox_gadget(cs, &x)?;
            }
            external_gadget(s);
        } else {
            let x = s[0].add(&Wire::constant(p.rc[r][0]));
            s[0] = sbox_gadget(cs, &x)?;
            internal_gadget(s, &p.diag);
        }
    }
    Ok(())
}

fn hash_gadget(
    cs: &ConstraintSystemRef<Fr>,
    p: &Poseidon2Params,
    inputs: &[Wire],
) -> Result<Wire, SynthesisError> {
    let mut s = [Wire::zero(), Wire::zero(), Wire::zero()];
    let mut idx = 0;
    for x in inputs {
        s[idx] = s[idx].add(x);
        idx += 1;
        if idx == 2 {
            permute_gadget(cs, p, &mut s)?;
            idx = 0;
        }
    }
    permute_gadget(cs, p, &mut s)?;
    Ok(s[0].clone())
}

fn enforce_equal(cs: &ConstraintSystemRef<Fr>, a: &Wire, b: &Wire) -> Result<(), SynthesisError> {
    cs.enforce_r1cs_constraint(
        || a.lc.clone(),
        || LinearCombination::from(Variable::One),
        || b.lc.clone(),
    )
}

/// The airdrop circuit: Poseidon2 Merkle membership + nullifier + recipient binding.
#[derive(Clone)]
pub struct AirdropCircuit {
    pub params: Poseidon2Params,
    // public
    pub merkle_root: Fr,
    pub nullifier: Fr,
    pub recipient: Fr,
    // private
    pub secret: Fr,
    pub siblings: [Fr; DEPTH],
    /// `true` when the current node is the right child at that level.
    pub path_bits: [bool; DEPTH],
}

impl ConstraintSynthesizer<Fr> for AirdropCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        // Public inputs, in the order the contract passes them to the verifier.
        let root_in = Wire::var(
            cs.new_input_variable(|| Ok(self.merkle_root))?,
            self.merkle_root,
        );
        let null_in = Wire::var(
            cs.new_input_variable(|| Ok(self.nullifier))?,
            self.nullifier,
        );
        let recip_in = Wire::var(
            cs.new_input_variable(|| Ok(self.recipient))?,
            self.recipient,
        );

        let secret = witness(&cs, self.secret)?;

        // leaf = H(secret); walk the path up to the root.
        let mut cur = hash_gadget(&cs, &self.params, core::slice::from_ref(&secret))?;
        for level in 0..DEPTH {
            let sib = witness(&cs, self.siblings[level])?;
            let bit_val = if self.path_bits[level] {
                Fr::ONE
            } else {
                Fr::ZERO
            };
            let bit = witness(&cs, bit_val)?;
            // bit ∈ {0, 1}
            let one_minus_bit = Wire::constant(Fr::ONE).sub(&bit);
            cs.enforce_r1cs_constraint(
                || bit.lc.clone(),
                || one_minus_bit.lc.clone(),
                LinearCombination::zero,
            )?;
            // swap = bit * (sib - cur); left = cur + swap; right = sib - swap
            let swap = mul(&cs, &bit, &sib.sub(&cur))?;
            let left = cur.add(&swap);
            let right = sib.sub(&swap);
            cur = hash_gadget(&cs, &self.params, &[left, right])?;
        }
        enforce_equal(&cs, &cur, &root_in)?;

        // nullifier = H(secret, NULLIFIER_DOMAIN)
        let domain = Wire::constant(Fr::from(NULLIFIER_DOMAIN));
        let nullifier = hash_gadget(&cs, &self.params, &[secret, domain])?;
        enforce_equal(&cs, &nullifier, &null_in)?;

        // Bind the recipient with a non-trivial constraint (Tornado-style).
        mul(&cs, &recip_in, &recip_in)?;
        Ok(())
    }
}
