//! Advanced non-native arithmetic (Issue #367, Phase 2).
//!
//! Evaluates arithmetic in a *foreign field* `F_p` whose prime `p` is larger
//! than (or incomparable to) the base BN254 scalar field, by splitting elements
//! into fixed-width [`LIMB_BITS`]-bit little-endian limbs. Each limb is carried
//! as a Soroban [`U256`] so it can be committed to by a prover and range-checked
//! by a verifier.
//!
//! The module guarantees, via constraint checks, that a malicious prover cannot:
//! - overflow a limb (every limb is range-checked `< 2^LIMB_BITS`),
//! - forge a carry (the carry-chain equation is verified limb-by-limb), or
//! - skip modular reduction (multiplication is reduced modulo `p` and the
//!   relation `product = q·p + remainder` is re-verified in limb arithmetic).
//!
//! Foreign-field arithmetic is completed by `add_mod` (addition reduced
//! modulo `p`), `sub`, `neg`, and `inv` on [`NonNativeField`]. Each new
//! operation range-checks its inputs to be `< p`, verifies its defining
//! limb relation, and returns the canonical representative in `[0, p)`;
//! `inv` additionally enforces `a · inv == 1 (mod p)` through `mul`.
//!
//! All limb arithmetic uses [`ethnum::u256`] accumulators and *fixed-capacity
//! stack arrays* (no heap allocation) so the gadget is safe inside a `no_std`
//! Soroban contract guest. The foreign modulus must fit in 256 bits — the common
//! case for secp256k1, P-256, the BN254 base field itself treated as foreign, etc.

use ethnum::u256 as eth_u256;
use soroban_sdk::{Bytes, Env, Vec, U256};
use soroban_zk_core::ZkError;

/// Maximum limb width in bits. Products of two [`LIMB_BITS`]-bit limbs must fit
/// in a `u256`, so we cap at 64 (`2·64 = 128 < 256`).
pub const LIMB_BITS: u32 = 64;

/// Hard cap on the number of limbs held in any big-integer (covers foreign
/// moduli up to 256 bits with 64-bit limbs, plus head-room for products and
/// normalization during division).
const MAX_LIMBS: usize = 12;

/// Big-integer carried as little-endian limbs, each `< base = 2^LIMB_BITS`.
/// `len` is the number of significant limbs (always `>= 1`).
#[derive(Clone, Copy)]
struct Bignum {
    limbs: [eth_u256; MAX_LIMBS],
    len: usize,
}

impl Bignum {
    fn zero() -> Self {
        Self {
            limbs: [eth_u256::ZERO; MAX_LIMBS],
            len: 1,
        }
    }

    #[allow(dead_code)]
    fn from_slice(slice: &[eth_u256]) -> Self {
        let mut limbs = [eth_u256::ZERO; MAX_LIMBS];
        let mut len = slice.len().min(MAX_LIMBS);
        while len > 1 && slice[len - 1] == eth_u256::ZERO {
            len -= 1;
        }
        limbs[..len].copy_from_slice(&slice[..len]);
        Self { limbs, len }
    }

    #[allow(dead_code)]
    fn as_slice(&self) -> &[eth_u256] {
        &self.limbs[..self.len]
    }

    /// Decompose a `u256` into little-endian limbs (value must fit in 256 bits).
    fn decompose(v: eth_u256) -> Self {
        let b = base();
        let mut limbs = [eth_u256::ZERO; MAX_LIMBS];
        let mut x = v;
        let mut len = 0usize;
        while x > eth_u256::ZERO {
            limbs[len] = x % b;
            x /= b;
            len += 1;
        }
        if len == 0 {
            len = 1;
        }
        Self { limbs, len }
    }

    /// Recompose into a single `u256` (valid while the value fits in 256 bits).
    fn recompose(&self) -> eth_u256 {
        let b = base();
        let mut acc = eth_u256::ZERO;
        for i in (0..self.len).rev() {
            acc = acc * b + self.limbs[i];
        }
        acc
    }
}

#[inline(always)]
fn base() -> eth_u256 {
    eth_u256::ONE << LIMB_BITS
}

/// Branchless select: returns `a` if `mask_true`, else `b`. Never branches
/// on `mask_true` — the condition is folded into a bitmask (Issue #372).
#[inline(always)]
fn ct_select_u256(mask_true: bool, a: eth_u256, b: eth_u256) -> eth_u256 {
    let mask = eth_u256::ZERO.wrapping_sub(eth_u256::from(mask_true as u8));
    (a & mask) | (b & !mask)
}

/// Constant-time-oriented comparison: always scans all `MAX_LIMBS` slots
/// instead of early-exiting on `a.len`/`b.len`, so timing does not leak the
/// magnitude of either operand (Issue #372).
fn cmp(a: &Bignum, b: &Bignum) -> core::cmp::Ordering {
    let mut result = core::cmp::Ordering::Equal;
    for i in (0..MAX_LIMBS).rev() {
        let ai = ct_select_u256(i < a.len, a.limbs[i], eth_u256::ZERO);
        let bi = ct_select_u256(i < b.len, b.limbs[i], eth_u256::ZERO);
        let this_cmp = ai.cmp(&bi);
        let still_equal = result == core::cmp::Ordering::Equal;
        result = if still_equal { this_cmp } else { result };
    }
    result
}

/// Constant-time limb-wise addition: always iterates all `MAX_LIMBS` slots
/// so the loop trip count does not depend on `a.len`/`b.len` (Issue #372).
fn add(a: &Bignum, b: &Bignum) -> (Bignum, eth_u256) {
    let b0 = base();
    let mut out = Bignum::zero();
    let mut carry = eth_u256::ZERO;
    for i in 0..MAX_LIMBS {
        let ai = ct_select_u256(i < a.len, a.limbs[i], eth_u256::ZERO);
        let bi = ct_select_u256(i < b.len, b.limbs[i], eth_u256::ZERO);
        let sum = ai + bi + carry;
        carry = sum / b0;
        out.limbs[i] = sum % b0;
    }
    let n = a.len.max(b.len);
    let has_extra_carry = (carry != eth_u256::ZERO) as usize;
    debug_assert!(
        n + has_extra_carry <= MAX_LIMBS,
        "Bignum::add overflow: result exceeds MAX_LIMBS"
    );
    out.len = (n + has_extra_carry).min(MAX_LIMBS);
    // The loop above runs over all `MAX_LIMBS` slots, so a carry out of the
    // most significant input limb is absorbed into the next slot and the
    // final `carry` is zero: `out.len` then understates the length whenever
    // the sum needs more limbs than `max(a.len, b.len)` (e.g. `a + b >=
    // 2^256` for 4-limb inputs), and `cmp`/`recompose` silently drop the
    // top limb. Re-derive the length from the limbs themselves.
    out.normalize();
    (out, carry)
}

/// `a - b`; caller must ensure `a >= b`.
/// Constant-time limb-wise subtraction (caller must ensure `a >= b`).
/// Always iterates all `MAX_LIMBS` slots and selects the borrow branch via a
/// branchless mask instead of a data-dependent `if` (Issue #372).
fn sub(a: &Bignum, b: &Bignum) -> Bignum {
    let b0 = base();
    let mut out = Bignum::zero();
    let mut borrow = eth_u256::ZERO;
    for i in 0..MAX_LIMBS {
        let ai = ct_select_u256(i < a.len, a.limbs[i], eth_u256::ZERO);
        let bi = ct_select_u256(i < b.len, b.limbs[i], eth_u256::ZERO);
        let t = ai + b0 - borrow - bi;
        // A borrow is needed exactly when `t < base`, i.e. `ai < bi +
        // borrow`: the limb keeps the added `base`. Otherwise the added
        // `base` is removed again (`t - base`) and no borrow propagates.
        // The previous code had this backwards: it borrowed exactly when
        // no borrow was needed, so every multi-limb subtraction was wrong.
        let need_borrow = (t < b0) as u8;
        let mask = eth_u256::ZERO.wrapping_sub(eth_u256::from(need_borrow));
        out.limbs[i] = (t & mask) | (t.wrapping_sub(b0) & !mask);
        borrow = eth_u256::from(need_borrow);
    }
    out.len = a.len.max(b.len);
    out.normalize();
    out
}

fn mul(a: &Bignum, b: &Bignum) -> Bignum {
    let b0 = base();
    let mut out = Bignum::zero();
    for i in 0..a.len {
        let mut carry = eth_u256::ZERO;
        for j in 0..b.len {
            let cur = out.limbs[i + j] + carry + a.limbs[i] * b.limbs[j];
            out.limbs[i + j] = cur % b0;
            carry = cur / b0;
        }
        let mut k = i + b.len;
        while carry != eth_u256::ZERO {
            let cur = out.limbs[k] + carry;
            out.limbs[k] = cur % b0;
            carry = cur / b0;
            k += 1;
        }
    }
    out.len = a.len + b.len;
    out.normalize();
    out
}

/// Constant-time scalar multiplication: always iterates all `MAX_LIMBS`
/// slots so the loop trip count does not depend on `a.len` (Issue #372).
fn mul_scalar(a: &Bignum, d: eth_u256) -> Bignum {
    let b0 = base();
    let mut out = Bignum::zero();
    let mut carry = eth_u256::ZERO;
    for i in 0..MAX_LIMBS {
        let ai = ct_select_u256(i < a.len, a.limbs[i], eth_u256::ZERO);
        let cur = ai * d + carry;
        out.limbs[i] = cur % b0;
        carry = cur / b0;
    }
    let has_extra = (carry != eth_u256::ZERO) as usize;
    debug_assert!(
        a.len + has_extra <= MAX_LIMBS,
        "Bignum::mul_scalar overflow: result exceeds MAX_LIMBS"
    );
    out.len = (a.len + has_extra).min(MAX_LIMBS);
    out.normalize();
    out
}

fn div_scalar(a: &Bignum, d: eth_u256) -> (Bignum, eth_u256) {
    let b0 = base();
    let mut out = Bignum::zero();
    let mut rem = eth_u256::ZERO;
    for i in (0..a.len).rev() {
        let cur = rem * b0 + a.limbs[i];
        out.limbs[i] = cur / d;
        rem = cur % d;
    }
    out.len = a.len;
    out.normalize();
    (out, rem)
}

/// Long division (Knuth Algorithm D) returning `(quotient, remainder)`.
#[allow(clippy::many_single_char_names)]
fn div_rem(mut a: Bignum, b: Bignum) -> (Bignum, Bignum) {
    let mut b = b.normalized();
    if b.len == 1 && b.limbs[0] == eth_u256::ZERO {
        return (Bignum::zero(), a);
    }
    a = a.normalized();
    if cmp(&a, &b) == core::cmp::Ordering::Less {
        return (Bignum::zero(), a);
    }
    let b0 = base();
    let n = b.len;

    // Normalize so the top limb of b has its high bit set.
    let d = b0 / (b.limbs[n - 1] + eth_u256::ONE);
    if d != eth_u256::ONE {
        a = mul_scalar(&a, d);
        b = mul_scalar(&b, d);
    }

    // Ensure `a` has at least n+1 digits so the algorithm's top accesses are in
    // bounds: with `u` having `m+n+1` digits, `m = a.len() - n - 1`.
    while a.len <= n {
        a.limbs[a.len] = eth_u256::ZERO;
        a.len += 1;
    }
    let m = a.len - n - 1;

    let mut q = Bignum::zero();
    for j in (0..=m).rev() {
        let num = a.limbs[j + n] * b0 + a.limbs[j + n - 1];
        let mut qhat = num / b.limbs[n - 1];
        let mut rhat = num % b.limbs[n - 1];

        if n >= 2 {
            while qhat >= b0 || qhat * b.limbs[n - 2] > rhat * b0 + a.limbs[j + n - 2] {
                qhat -= eth_u256::ONE;
                rhat += b.limbs[n - 1];
                if rhat >= b0 {
                    break;
                }
            }
        } else {
            while qhat >= b0 {
                qhat -= eth_u256::ONE;
            }
        }

        let mut carry = eth_u256::ZERO;
        let mut borrow = eth_u256::ZERO;
        for i in 0..=n {
            let bi = if i < n { b.limbs[i] } else { eth_u256::ZERO };
            let p = qhat * bi + carry;
            let p_lo = p % b0;
            carry = p / b0;
            let t = a.limbs[j + i] + b0 - borrow - p_lo;
            if t >= b0 {
                a.limbs[j + i] = t - b0;
                borrow = eth_u256::ZERO;
            } else {
                a.limbs[j + i] = t;
                borrow = eth_u256::ONE;
            }
        }

        if borrow == eth_u256::ONE {
            qhat -= eth_u256::ONE;
            let mut c = eth_u256::ZERO;
            for i in 0..=n {
                let bi = if i < n { b.limbs[i] } else { eth_u256::ZERO };
                let s = a.limbs[j + i] + bi + c;
                a.limbs[j + i] = s % b0;
                c = s / b0;
            }
        }
        q.limbs[j] = qhat;
    }
    q.len = m + 1;
    q.normalize();

    let mut r = Bignum::zero();
    r.limbs[..n].copy_from_slice(&a.limbs[..n]);
    r.len = n;
    r.normalize();
    if d != eth_u256::ONE {
        r = div_scalar(&r, d).0;
    }
    (q, r)
}

/// Square-and-multiply modular exponentiation: returns
/// `base^exp mod modulus` as a [`Bignum`].
///
/// Every intermediate product is reduced with [`div_rem`], so no value
/// exceeds the limb capacity. Used by [`NonNativeField::inv`] (Fermat's
/// little theorem: `a^(p-2) mod p` for prime `p`); the result is always
/// re-verified against the relation `a · inv == 1 (mod p)`, so a wrong
/// candidate is rejected even if `p` were not prime.
fn mod_pow(base: &Bignum, exp: &Bignum, modulus: &Bignum) -> Bignum {
    let mut result = Bignum::decompose(eth_u256::ONE);
    let mut acc = *base;
    if cmp(&acc, modulus) != core::cmp::Ordering::Less {
        acc = div_rem(acc, *modulus).1;
    }
    for limb in (0..exp.len).rev() {
        let word = exp.limbs[limb];
        for bit in (0..64).rev() {
            let sq = mul(&result, &result);
            result = div_rem(sq, *modulus).1;
            if ((word >> (bit as u32)) & eth_u256::ONE) == eth_u256::ONE {
                let prod = mul(&result, &acc);
                result = div_rem(prod, *modulus).1;
            }
        }
    }
    result
}

impl Bignum {
    /// Return a normalized copy (no leading zero limbs).
    fn normalized(&self) -> Self {
        let mut out = *self;
        out.normalize();
        out
    }

    /// Constant-time-oriented normalization: scans all `MAX_LIMBS` slots
    /// instead of an early-exit `while` loop, so the number of iterations
    /// does not depend on how many leading limbs happen to be zero (Issue #372).
    fn normalize(&mut self) {
        let mut new_len = 1usize;
        for (i, limb) in self.limbs.iter().enumerate().take(MAX_LIMBS).skip(1) {
            let is_nonzero = (*limb != eth_u256::ZERO) as usize;
            let candidate = (i + 1) * is_nonzero;
            new_len = new_len.max(candidate);
        }
        self.len = new_len;
    }
}

// ── Public non-native field types ─────────────────────────────────────────────

/// Describes a foreign field `F_p` (prime modulus `p`) represented in
/// [`LIMB_BITS`]-bit limbs.
pub struct NonNativeField {
    /// Prime modulus `p`.
    modulus: Bignum,
    /// Number of limbs used to hold an element of `F_p`.
    num_limbs: u32,
    /// `2^limb_bits`, cached.
    base: eth_u256,
}

impl NonNativeField {
    /// Build a foreign field from a BN254-scalar-compatible modulus value.
    ///
    /// The modulus must be non-zero and fit in 256 bits. `limb_bits` must equal
    /// [`LIMB_BITS`] (all limb arithmetic is specialised to that width).
    pub fn from_modulus(modulus: U256, limb_bits: u32) -> Result<Self, ZkError> {
        if limb_bits != LIMB_BITS {
            return Err(ZkError::InvalidInput);
        }
        let m = to_eth_v(&modulus);
        if m == eth_u256::ZERO {
            return Err(ZkError::InvalidInput);
        }
        let modulus = Bignum::decompose(m);
        let num_limbs = modulus.len as u32;
        Ok(Self {
            modulus,
            num_limbs,
            base: base(),
        })
    }

    /// The modulus as a [`U256`].
    pub fn modulus_u256(&self, env: &Env) -> U256 {
        from_eth_v(env, self.modulus.recompose())
    }

    /// Number of limbs per element.
    pub fn num_limbs(&self) -> u32 {
        self.num_limbs
    }

    /// Constrain that every limb of `fp` is strictly below `2^limb_bits`. A
    /// prover who overflows a limb is rejected here.
    pub fn assert_valid(&self, fp: &Fp) -> Result<(), ZkError> {
        if fp.limbs.len() != self.num_limbs {
            return Err(ZkError::InvalidInput);
        }
        for l in fp.limbs.iter() {
            if to_eth_v(&l) >= self.base {
                return Err(ZkError::ConstraintUnsatisfied);
            }
        }
        Ok(())
    }

    /// Reduce `fp` modulo `p`, returning the canonical element and verifying the
    /// relation `value(fp) = q·p + result` in limb arithmetic.
    pub fn reduce(&self, env: &Env, fp: &Fp) -> Result<Fp, ZkError> {
        self.assert_valid(fp)?;
        let value = fp.to_bignum();
        let (q, r) = div_rem(value, self.modulus);
        let recomputed = add(&mul(&q, &self.modulus), &r);
        if cmp(&recomputed.0, &value) != core::cmp::Ordering::Equal {
            return Err(ZkError::ConstraintUnsatisfied);
        }
        Fp::from_bignum(env, &r, self.num_limbs)
    }

    /// Add two elements with strict carry tracking.
    ///
    /// Returns `(sum, carry)` where `sum` has the same limb count as the inputs
    /// and `carry ∈ {0,1}` (overflow beyond `num_limbs` limbs). The limb carry
    /// equation `a_i + b_i + c_i = s_i + c_{i+1}·base` is verified for every
    /// position, so a forged carry is rejected.
    pub fn add(&self, env: &Env, a: &Fp, b: &Fp) -> Result<(Fp, U256), ZkError> {
        self.assert_valid(a)?;
        self.assert_valid(b)?;
        let al = a.to_bignum();
        let bl = b.to_bignum();
        let (sum, _carry) = add(&al, &bl);

        let mut carry_in = eth_u256::ZERO;
        let n = self.num_limbs as usize;
        for i in 0..n {
            let ai = al.limbs.get(i).copied().unwrap_or(eth_u256::ZERO);
            let bi = bl.limbs.get(i).copied().unwrap_or(eth_u256::ZERO);
            let si = sum.limbs.get(i).copied().unwrap_or(eth_u256::ZERO);
            let total = ai + bi + carry_in;
            if total % self.base != si {
                return Err(ZkError::ConstraintUnsatisfied);
            }
            carry_in = total / self.base;
        }
        let reported_carry = sum.limbs.get(n).copied().unwrap_or(eth_u256::ZERO);
        if reported_carry != carry_in {
            return Err(ZkError::ConstraintUnsatisfied);
        }

        let out = Fp::from_bignum(env, &sum, self.num_limbs)?;
        Ok((out, from_eth_v(env, carry_in)))
    }

    /// Multiply two elements and reduce modulo `p`.
    pub fn mul(&self, env: &Env, a: &Fp, b: &Fp) -> Result<Fp, ZkError> {
        self.assert_valid(a)?;
        self.assert_valid(b)?;
        let product = mul(&a.to_bignum(), &b.to_bignum());
        let (q, r) = div_rem(product, self.modulus);
        let recomputed = add(&mul(&q, &self.modulus), &r);
        if cmp(&recomputed.0, &product) != core::cmp::Ordering::Equal {
            return Err(ZkError::ConstraintUnsatisfied);
        }
        Fp::from_bignum(env, &r, self.num_limbs)
    }

    /// Constrain that `fp` is a canonical field element: every limb is
    /// below `2^limb_bits` and the value is strictly below the modulus `p`.
    /// Inputs `>= p` are rejected with [`ZkError::InvalidFieldElement`].
    fn assert_canonical(&self, fp: &Fp) -> Result<(), ZkError> {
        self.assert_valid(fp)?;
        if cmp(&fp.to_bignum(), &self.modulus) != core::cmp::Ordering::Less {
            return Err(ZkError::InvalidFieldElement);
        }
        Ok(())
    }

    /// Add two field elements modulo `p`: returns `(a + b) mod p`.
    ///
    /// Both inputs are range-checked to be `< p`. The limb sum `s = a + b`
    /// is verified with the same carry-chain equation as [`add`]; then `s`
    /// is compared with `p` and `p` is subtracted once when `s >= p`, so
    /// the result is always the canonical representative in `[0, p)`. The
    /// reduction is verified by the relation `s == r` (no reduction) or
    /// `s == r + p` (reduced), and the result is range-checked `< p`.
    pub fn add_mod(&self, env: &Env, a: &Fp, b: &Fp) -> Result<Fp, ZkError> {
        self.assert_canonical(a)?;
        self.assert_canonical(b)?;
        let al = a.to_bignum();
        let bl = b.to_bignum();
        let (sum, _carry) = add(&al, &bl);

        // Verify the carry chain limb-by-limb, exactly as `add` does, so a
        // forged carry is rejected.
        let mut carry_in = eth_u256::ZERO;
        let n = self.num_limbs as usize;
        for i in 0..n {
            let ai = al.limbs.get(i).copied().unwrap_or(eth_u256::ZERO);
            let bi = bl.limbs.get(i).copied().unwrap_or(eth_u256::ZERO);
            let si = sum.limbs.get(i).copied().unwrap_or(eth_u256::ZERO);
            let total = ai + bi + carry_in;
            if total % self.base != si {
                return Err(ZkError::ConstraintUnsatisfied);
            }
            carry_in = total / self.base;
        }
        let reported_carry = sum.limbs.get(n).copied().unwrap_or(eth_u256::ZERO);
        if reported_carry != carry_in {
            return Err(ZkError::ConstraintUnsatisfied);
        }

        // Reduce once when `s >= p`; the sum of two elements `< p` is
        // `< 2p`, so a single conditional subtraction canonicalizes it.
        let needs_reduce = cmp(&sum, &self.modulus) != core::cmp::Ordering::Less;
        let r = if needs_reduce {
            sub(&sum, &self.modulus)
        } else {
            sum
        };
        // Verify the reduction relation: `s == r`, or `s == r + p`.
        let check = if needs_reduce {
            add(&r, &self.modulus).0
        } else {
            r
        };
        if cmp(&check, &sum) != core::cmp::Ordering::Equal {
            return Err(ZkError::ConstraintUnsatisfied);
        }
        if cmp(&r, &self.modulus) != core::cmp::Ordering::Less {
            return Err(ZkError::ConstraintUnsatisfied);
        }
        Fp::from_bignum(env, &r, self.num_limbs)
    }

    /// Subtract two field elements modulo `p`: returns `(a - b) mod p`.
    ///
    /// Both inputs are range-checked to be `< p`. When `a >= b` the result
    /// is `a - b`; otherwise `p` is added back, i.e. `a - b + p`. The
    /// result is verified by the relation `a == b + d` (no wrap) or
    /// `a + p == b + d` (wrapped), and range-checked `< p`.
    pub fn sub(&self, env: &Env, a: &Fp, b: &Fp) -> Result<Fp, ZkError> {
        self.assert_canonical(a)?;
        self.assert_canonical(b)?;
        let al = a.to_bignum();
        let bl = b.to_bignum();
        let a_ge_b = cmp(&al, &bl) != core::cmp::Ordering::Less;
        let d = if a_ge_b {
            sub(&al, &bl)
        } else {
            // `b - a` is `< p`, so `p - (b - a)` is the canonical `a - b + p`.
            let t = sub(&bl, &al);
            sub(&self.modulus, &t)
        };
        if a_ge_b {
            let rebuilt = add(&bl, &d);
            if cmp(&rebuilt.0, &al) != core::cmp::Ordering::Equal {
                return Err(ZkError::ConstraintUnsatisfied);
            }
        } else {
            let lhs = add(&al, &self.modulus);
            let rhs = add(&bl, &d);
            if cmp(&lhs.0, &rhs.0) != core::cmp::Ordering::Equal {
                return Err(ZkError::ConstraintUnsatisfied);
            }
        }
        if cmp(&d, &self.modulus) != core::cmp::Ordering::Less {
            return Err(ZkError::ConstraintUnsatisfied);
        }
        Fp::from_bignum(env, &d, self.num_limbs)
    }

    /// Negate a field element modulo `p`: returns `(-a) mod p`.
    ///
    /// The input is range-checked to be `< p`. The result is `0` when
    /// `a == 0` and `p - a` otherwise, verified by the relation `a + r == p`
    /// (or `r == 0` when `a == 0`), and range-checked `< p`.
    pub fn neg(&self, env: &Env, a: &Fp) -> Result<Fp, ZkError> {
        self.assert_canonical(a)?;
        let al = a.to_bignum();
        let zero = Bignum::zero();
        let is_zero = cmp(&al, &zero) == core::cmp::Ordering::Equal;
        let r = if is_zero {
            zero
        } else {
            sub(&self.modulus, &al)
        };
        if is_zero {
            if cmp(&r, &zero) != core::cmp::Ordering::Equal {
                return Err(ZkError::ConstraintUnsatisfied);
            }
        } else {
            let rebuilt = add(&al, &r);
            if cmp(&rebuilt.0, &self.modulus) != core::cmp::Ordering::Equal {
                return Err(ZkError::ConstraintUnsatisfied);
            }
        }
        if cmp(&r, &self.modulus) != core::cmp::Ordering::Less {
            return Err(ZkError::ConstraintUnsatisfied);
        }
        Fp::from_bignum(env, &r, self.num_limbs)
    }

    /// Invert a field element modulo `p`: returns `a^-1 mod p`.
    ///
    /// The input is range-checked to be `< p` and `a == 0` is rejected
    /// (zero has no inverse). The candidate inverse is computed with
    /// Fermat's little theorem (`a^(p-2) mod p`, valid for prime `p`) and
    /// then enforced through the existing [`mul`]: the result is only
    /// returned when `a * inv == 1 (mod p)`, so a wrong candidate is
    /// rejected with [`ZkError::ConstraintUnsatisfied`].
    pub fn inv(&self, env: &Env, a: &Fp) -> Result<Fp, ZkError> {
        self.assert_canonical(a)?;
        let al = a.to_bignum();
        if cmp(&al, &Bignum::zero()) == core::cmp::Ordering::Equal {
            return Err(ZkError::ConstraintUnsatisfied);
        }
        let exp = sub(&self.modulus, &Bignum::decompose(eth_u256::from(2u8)));
        let inv = mod_pow(&al, &exp, &self.modulus);
        let inv_fp = Fp::from_bignum(env, &inv, self.num_limbs)?;
        let check = self.mul(env, a, &inv_fp)?;
        if cmp(&check.to_bignum(), &Bignum::decompose(eth_u256::ONE)) != core::cmp::Ordering::Equal
        {
            return Err(ZkError::ConstraintUnsatisfied);
        }
        Ok(inv_fp)
    }
}

/// A non-native field element, stored as little-endian [`U256`] limbs each
/// strictly below `2^limb_bits`.
#[derive(Clone)]
pub struct Fp {
    pub limbs: Vec<U256>,
}

impl Fp {
    fn from_bignum(env: &Env, bn: &Bignum, num_limbs: u32) -> Result<Self, ZkError> {
        let b = base();
        let mut out = Vec::new(env);
        for i in 0..num_limbs as usize {
            let v = bn.limbs.get(i).copied().unwrap_or(eth_u256::ZERO);
            if v >= b {
                return Err(ZkError::ConstraintUnsatisfied);
            }
            out.push_back(from_eth_v(env, v));
        }
        Ok(Self { limbs: out })
    }

    fn to_bignum(&self) -> Bignum {
        let mut limbs = [eth_u256::ZERO; MAX_LIMBS];
        let len = (self.limbs.len() as usize).min(MAX_LIMBS);
        for (i, l) in self.limbs.iter().enumerate().take(len) {
            limbs[i] = to_eth_v(&l);
        }
        let mut bn = Bignum { limbs, len };
        bn.normalize();
        bn
    }

    /// Build an `Fp` from a base [`U256`] value, decomposing it into limbs and
    /// asserting the result is below the modulus.
    pub fn from_u256(env: &Env, field: &NonNativeField, value: U256) -> Result<Self, ZkError> {
        let v = to_eth_v(&value);
        if v >= field.modulus.recompose() {
            return Err(ZkError::InvalidFieldElement);
        }
        let bn = Bignum::decompose(v);
        Self::from_bignum(env, &bn, field.num_limbs)
    }

    /// Recompose into a single [`U256`] (valid while the value fits in 256 bits,
    /// which holds for any reduced element of a 256-bit foreign field).
    pub fn to_u256(&self, env: &Env) -> U256 {
        from_eth_v(env, self.to_bignum().recompose())
    }
}

// ── Boundary conversions (U256 <-> ethnum) ──────────────────────────────────────

#[inline(always)]
fn to_eth_v(v: &U256) -> eth_u256 {
    let mut b = [0u8; 32];
    v.to_be_bytes().copy_into_slice(&mut b);
    eth_u256::from_be_bytes(b)
}

#[inline(always)]
fn from_eth_v(env: &Env, v: eth_u256) -> U256 {
    U256::from_be_bytes(env, &Bytes::from_array(env, &v.to_be_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::BigUint;
    use soroban_sdk::Env;

    fn env() -> Env {
        let e = Env::default();
        e.cost_estimate().budget().reset_unlimited();
        e
    }

    fn big(v: &U256) -> BigUint {
        let mut b = [0u8; 32];
        v.to_be_bytes().copy_into_slice(&mut b);
        BigUint::from_bytes_be(&b)
    }

    fn u256_from_big(env: &Env, b: &BigUint) -> U256 {
        let bytes = b.to_bytes_be();
        let mut buf = [0u8; 32];
        let start = 32usize.saturating_sub(bytes.len());
        buf[start..].copy_from_slice(&bytes);
        U256::from_be_bytes(env, &Bytes::from_array(env, &buf))
    }

    // A 192-bit foreign prime (a realistic non-native field scenario).
    fn foreign_modulus(env: &Env) -> U256 {
        let p = (eth_u256::ONE << 192) - (eth_u256::ONE << 64) - eth_u256::ONE;
        from_eth_v(env, p)
    }

    fn rng_step(seed: &core::cell::Cell<u64>) -> eth_u256 {
        let mut x = seed.get();
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        seed.set(x);
        let lo = x;
        let hi = x.wrapping_mul(0x2545F4914F6CDD1D);
        (eth_u256::from(hi) << 64) | eth_u256::from(lo)
    }

    #[test]
    fn div_rem_matches_reference() {
        let env = env();
        let field = NonNativeField::from_modulus(foreign_modulus(&env), 64).unwrap();
        let p = field.modulus.recompose();
        let seed = core::cell::Cell::new(0x9E3779B97F4A7C15u64);
        for _ in 0..300 {
            let a = rng_step(&seed) % p;
            let b = rng_step(&seed) % p;
            if b == eth_u256::ZERO {
                continue;
            }
            let (q, r) = div_rem(Bignum::decompose(a), Bignum::decompose(b));
            assert_eq!(q.recompose(), a / b, "quotient mismatch");
            assert_eq!(r.recompose(), a % b, "remainder mismatch");
        }
    }

    #[test]
    fn add_with_carry_is_correct() {
        let env = env();
        let field = NonNativeField::from_modulus(foreign_modulus(&env), 64).unwrap();
        let p = field.modulus.recompose();
        let seed = core::cell::Cell::new(0x9E3779B97F4A7C15u64);
        for _ in 0..300 {
            let av = rng_step(&seed) % p;
            let bv = rng_step(&seed) % p;
            let a = Fp::from_u256(&env, &field, from_eth_v(&env, av)).unwrap();
            let b = Fp::from_u256(&env, &field, from_eth_v(&env, bv)).unwrap();
            let (s, _carry) = field.add(&env, &a, &b).unwrap();
            assert_eq!(s.to_bignum().recompose(), (av + bv) % p, "add mismatch");
        }
    }

    #[test]
    fn mul_and_reduce_matches_reference() {
        let env = env();
        let field = NonNativeField::from_modulus(foreign_modulus(&env), 64).unwrap();
        let p = field.modulus.recompose();
        let seed = core::cell::Cell::new(0x9E3779B97F4A7C15u64);
        for _ in 0..300 {
            let av = rng_step(&seed) % p;
            let bv = rng_step(&seed) % p;
            let a = Fp::from_u256(&env, &field, from_eth_v(&env, av)).unwrap();
            let b = Fp::from_u256(&env, &field, from_eth_v(&env, bv)).unwrap();
            let product = field.mul(&env, &a, &b).unwrap();
            assert_eq!(
                product.to_bignum().recompose(),
                (av * bv) % p,
                "mul mismatch"
            );
            // Cross-check against num-bigint reference.
            let ref_a = big(&a.to_u256(&env));
            let ref_b = big(&b.to_u256(&env));
            let ref_p = (&ref_a * &ref_b) % big(&field.modulus_u256(&env));
            assert_eq!(product.to_u256(&env), u256_from_big(&env, &ref_p));
        }
    }

    #[test]
    fn reduce_canonicalizes_overflow() {
        let env = env();
        let field = NonNativeField::from_modulus(foreign_modulus(&env), 64).unwrap();
        let p = field.modulus.recompose();
        let over = p + eth_u256::from(123u8);
        let fp = Fp::from_bignum(&env, &Bignum::decompose(over), field.num_limbs).unwrap();
        let reduced = field.reduce(&env, &fp).unwrap();
        assert_eq!(reduced.to_bignum().recompose(), eth_u256::from(123u8));
    }

    #[test]
    fn assert_valid_rejects_overflowed_limb() {
        let env = env();
        let field = NonNativeField::from_modulus(foreign_modulus(&env), 64).unwrap();
        let mut limbs = Vec::new(&env);
        for _ in 0..field.num_limbs {
            limbs.push_back(U256::from_u128(&env, 0));
        }
        limbs.set(0, from_eth_v(&env, field.base));
        let fp = Fp { limbs };
        assert_eq!(field.assert_valid(&fp), Err(ZkError::ConstraintUnsatisfied));
    }

    // secp256k1 field prime: 2^256 - 2^32 - 977.
    fn secp256k1_modulus(env: &Env) -> U256 {
        let p = eth_u256::MAX - (eth_u256::ONE << 32) - eth_u256::from(976u16);
        from_eth_v(env, p)
    }

    // NIST P-256 (secp256r1) field prime: 2^256 - 2^224 + 2^192 + 2^96 - 1.
    fn secp256r1_modulus(env: &Env) -> U256 {
        let p =
            eth_u256::MAX - (eth_u256::ONE << 224) + (eth_u256::ONE << 192) + (eth_u256::ONE << 96);
        from_eth_v(env, p)
    }

    fn big_eth(v: eth_u256) -> BigUint {
        BigUint::from_bytes_be(&v.to_be_bytes())
    }

    fn fp(env: &Env, field: &NonNativeField, v: eth_u256) -> Fp {
        Fp::from_u256(env, field, from_eth_v(env, v)).unwrap()
    }

    fn both_fields(env: &Env) -> [NonNativeField; 2] {
        [
            NonNativeField::from_modulus(secp256k1_modulus(env), 64).unwrap(),
            NonNativeField::from_modulus(secp256r1_modulus(env), 64).unwrap(),
        ]
    }

    fn rng_wide(seed: &core::cell::Cell<u64>) -> eth_u256 {
        // `rng_step` only yields 128 bits; combine two steps for full-range
        // values below a 256-bit modulus.
        (rng_step(seed) << 128) | rng_step(seed)
    }

    #[test]
    fn curve_moduli_match_known_primes() {
        let env = env();
        let k1 = big(&secp256k1_modulus(&env));
        assert_eq!(
            k1.to_str_radix(16),
            "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f"
        );
        let r1 = big(&secp256r1_modulus(&env));
        assert_eq!(
            r1.to_str_radix(16),
            "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff"
        );
    }

    #[test]
    fn add_mod_matches_reference() {
        let env = env();
        for field in both_fields(&env) {
            let p = field.modulus.recompose();
            let bp = big_eth(p);
            let seed = core::cell::Cell::new(0xA11CE5EED1F00Du64);
            for _ in 0..200 {
                let av = rng_wide(&seed) % p;
                let bv = rng_wide(&seed) % p;
                let r = field
                    .add_mod(&env, &fp(&env, &field, av), &fp(&env, &field, bv))
                    .unwrap();
                let expected = (big_eth(av) + big_eth(bv)) % bp.clone();
                assert_eq!(r.to_u256(&env), u256_from_big(&env, &expected));
            }
            // Boundaries: exact reduction, no reduction, and zero.
            let one = eth_u256::ONE;
            let two = eth_u256::from(2u8);
            for (a, b) in [
                (p - one, one),
                (p - one, p - one),
                (eth_u256::ZERO, eth_u256::ZERO),
                (p - one, eth_u256::ZERO),
                (one, p - two),
            ] {
                let r = field
                    .add_mod(&env, &fp(&env, &field, a), &fp(&env, &field, b))
                    .unwrap();
                let expected = (big_eth(a) + big_eth(b)) % bp.clone();
                assert_eq!(r.to_u256(&env), u256_from_big(&env, &expected));
            }
        }
    }

    #[test]
    fn sub_matches_reference() {
        let env = env();
        for field in both_fields(&env) {
            let p = field.modulus.recompose();
            let bp = big_eth(p);
            let seed = core::cell::Cell::new(0x5EED0BADC0DE5EEDu64);
            for _ in 0..200 {
                let av = rng_wide(&seed) % p;
                let bv = rng_wide(&seed) % p;
                let r = field
                    .sub(&env, &fp(&env, &field, av), &fp(&env, &field, bv))
                    .unwrap();
                let expected = (big_eth(av) + bp.clone() - big_eth(bv)) % bp.clone();
                assert_eq!(r.to_u256(&env), u256_from_big(&env, &expected));
            }
            // Boundaries: wrap-around, no wrap, and zero.
            let one = eth_u256::ONE;
            for (a, b) in [
                (eth_u256::ZERO, one),
                (eth_u256::ZERO, eth_u256::ZERO),
                (one, one),
                (p - one, p - one),
                (one, p - one),
                (p - one, eth_u256::ZERO),
            ] {
                let r = field
                    .sub(&env, &fp(&env, &field, a), &fp(&env, &field, b))
                    .unwrap();
                let expected = (big_eth(a) + bp.clone() - big_eth(b)) % bp.clone();
                assert_eq!(r.to_u256(&env), u256_from_big(&env, &expected));
            }
        }
    }

    #[test]
    fn neg_matches_reference() {
        let env = env();
        for field in both_fields(&env) {
            let p = field.modulus.recompose();
            let bp = big_eth(p);
            let seed = core::cell::Cell::new(0x9E6A7B5D4C3B2A1u64);
            for _ in 0..200 {
                let av = rng_wide(&seed) % p;
                let r = field.neg(&env, &fp(&env, &field, av)).unwrap();
                let expected = (bp.clone() - big_eth(av)) % bp.clone();
                assert_eq!(r.to_u256(&env), u256_from_big(&env, &expected));
            }
            // Boundaries: zero is its own negation; p - 1 negates to 1.
            for a in [eth_u256::ZERO, eth_u256::ONE, p - eth_u256::ONE] {
                let r = field.neg(&env, &fp(&env, &field, a)).unwrap();
                let expected = (bp.clone() - big_eth(a)) % bp.clone();
                assert_eq!(r.to_u256(&env), u256_from_big(&env, &expected));
            }
        }
    }

    #[test]
    fn inv_matches_reference() {
        let env = env();
        for field in both_fields(&env) {
            let p = field.modulus.recompose();
            let bp = big_eth(p);
            let seed = core::cell::Cell::new(0x1A2B3C4D5E6F7081u64);
            for _ in 0..100 {
                let av = rng_wide(&seed) % p;
                if av == eth_u256::ZERO {
                    continue;
                }
                let r = field.inv(&env, &fp(&env, &field, av)).unwrap();
                let exp = bp.clone() - big_eth(eth_u256::from(2u8));
                let expected = big_eth(av).modpow(&exp, &bp);
                assert_eq!(r.to_u256(&env), u256_from_big(&env, &expected));
                // The defining relation: a * inv == 1 (mod p).
                let prod = field.mul(&env, &fp(&env, &field, av), &r).unwrap();
                assert_eq!(prod.to_bignum().recompose(), eth_u256::ONE);
            }
            // Boundaries: 1 and p - 1 are their own inverses.
            for a in [eth_u256::ONE, p - eth_u256::ONE] {
                let r = field.inv(&env, &fp(&env, &field, a)).unwrap();
                assert_eq!(r.to_bignum().recompose(), a);
            }
        }
    }

    #[test]
    fn field_ops_reject_out_of_range_inputs() {
        let env = env();
        for field in both_fields(&env) {
            let p = field.modulus.recompose();
            // An element equal to the modulus (and above it) is not a
            // canonical field element, even though its limbs are valid.
            let good = fp(&env, &field, eth_u256::ONE);
            for v in [p, p + eth_u256::from(5u8)] {
                let bad = Fp::from_bignum(&env, &Bignum::decompose(v), field.num_limbs).unwrap();
                // `Fp` has no `Debug` impl, so the error is matched
                // instead of unwrapped.
                assert!(matches!(
                    field.add_mod(&env, &bad, &good),
                    Err(ZkError::InvalidFieldElement)
                ));
                assert!(matches!(
                    field.add_mod(&env, &good, &bad),
                    Err(ZkError::InvalidFieldElement)
                ));
                assert!(matches!(
                    field.sub(&env, &bad, &good),
                    Err(ZkError::InvalidFieldElement)
                ));
                assert!(matches!(
                    field.sub(&env, &good, &bad),
                    Err(ZkError::InvalidFieldElement)
                ));
                assert!(matches!(
                    field.neg(&env, &bad),
                    Err(ZkError::InvalidFieldElement)
                ));
                assert!(matches!(
                    field.inv(&env, &bad),
                    Err(ZkError::InvalidFieldElement)
                ));
            }
            // Zero has no inverse.
            let zero = fp(&env, &field, eth_u256::ZERO);
            assert!(matches!(
                field.inv(&env, &zero),
                Err(ZkError::ConstraintUnsatisfied)
            ));
        }
    }
}
