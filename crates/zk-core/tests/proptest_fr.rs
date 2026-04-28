//! Property-based fuzz tests for BN254 scalar field (Fr) arithmetic.
//!
//! These tests verify the nine fundamental algebraic properties that must hold
//! for any correct finite-field implementation. Unlike known-answer tests (KATs),
//! proptest generates thousands of random inputs and checks each invariant, catching
//! edge-case bugs that no human would think to write manually.
//!
//! ## Properties under test
//!
//! | Property              | Expression                        |
//! |-----------------------|-----------------------------------|
//! | Additive identity     | `a + 0 == a`                      |
//! | Additive inverse      | `a + (-a) == 0`                   |
//! | Commutativity (add)   | `a + b == b + a`                  |
//! | Associativity (add)   | `(a+b)+c == a+(b+c)`              |
//! | Multiplicative identity | `a * 1 == a`                    |
//! | Multiplicative inverse | `a * a⁻¹ == 1` (a ≠ 0)          |
//! | Commutativity (mul)   | `a * b == b * a`                  |
//! | Distributivity        | `(a+b)*c == a*c + b*c`            |
//! | Fermat's little theorem | `a^(r-1) == 1` (a ≠ 0)         |
//!
//! All properties are verified for **1 000+ random inputs** (proptest default).
//!
//! ## Input strategy
//!
//! Raw bytes `any::<[u8; 32]>()` are interpreted as a big-endian `u256` and
//! reduced modulo `r` using `% BASE_MODULUS`, producing a uniformly-distributed
//! valid Fr element. This avoids the rejection-sampling cost of a `filter` and
//! keeps the runner fast.

use ethnum::u256;
use proptest::prelude::*;
use zk_core::Bn254;

// ── helpers ──────────────────────────────────────────────────────────────────

/// Reduce a raw 32-byte big-endian buffer to a valid Fr element.
/// Returns 0 if the buffer is all-zeros (which maps to additive identity).
#[inline]
fn bytes_to_fr(raw: [u8; 32]) -> u256 {
    let n = u256::from_be_bytes(raw);
    // Reduce modulo r.  Cheap single-division path; no rejection needed.
    if n == u256::ZERO {
        u256::ZERO
    } else {
        n % Bn254::BASE_MODULUS
    }
}

/// Additive negation in Fr:  -a = (r - a) mod r.
#[inline]
fn fr_neg(a: u256) -> u256 {
    if a == u256::ZERO {
        u256::ZERO
    } else {
        Bn254::BASE_MODULUS - a
    }
}

// ── proptest strategy ────────────────────────────────────────────────────────

/// Strategy that yields valid (reduced) Fr elements.
fn fr_element() -> impl Strategy<Value = u256> {
    any::<[u8; 32]>().prop_map(bytes_to_fr)
}

/// Strategy that yields a valid **non-zero** Fr element.
fn fr_nonzero() -> impl Strategy<Value = u256> {
    fr_element().prop_filter("must be non-zero", |&x| x != u256::ZERO)
}

// ── 1. Additive identity: a + 0 == a ─────────────────────────────────────────
proptest! {
    #![proptest_config(ProptestConfig::with_cases(1_000))]

    #[test]
    fn prop_additive_identity(a in fr_element()) {
        let result = Bn254::add(a, u256::ZERO);
        prop_assert_eq!(result, a,
            "additive identity failed: ({} + 0) = {} ≠ {}", a, result, a);
    }
}

// ── 2. Additive inverse: a + (-a) == 0 ───────────────────────────────────────
proptest! {
    #![proptest_config(ProptestConfig::with_cases(1_000))]

    #[test]
    fn prop_additive_inverse(a in fr_element()) {
        let neg_a = fr_neg(a);
        let result = Bn254::add(a, neg_a);
        prop_assert_eq!(result, u256::ZERO,
            "additive inverse failed: {} + (-{}) = {} ≠ 0", a, a, result);
    }
}

// ── 3. Commutativity of addition: a + b == b + a ─────────────────────────────
proptest! {
    #![proptest_config(ProptestConfig::with_cases(1_000))]

    #[test]
    fn prop_add_commutativity(a in fr_element(), b in fr_element()) {
        let lhs = Bn254::add(a, b);
        let rhs = Bn254::add(b, a);
        prop_assert_eq!(lhs, rhs,
            "add commutativity failed: {} + {} = {} but {} + {} = {}",
            a, b, lhs, b, a, rhs);
    }
}

// ── 4. Associativity of addition: (a+b)+c == a+(b+c) ─────────────────────────
proptest! {
    #![proptest_config(ProptestConfig::with_cases(1_000))]

    #[test]
    fn prop_add_associativity(
        a in fr_element(),
        b in fr_element(),
        c in fr_element(),
    ) {
        let lhs = Bn254::add(Bn254::add(a, b), c);
        let rhs = Bn254::add(a, Bn254::add(b, c));
        prop_assert_eq!(lhs, rhs,
            "add associativity failed: ({}+{})+{} = {} but {}+({}+{}) = {}",
            a, b, c, lhs, a, b, c, rhs);
    }
}

// ── 5. Multiplicative identity: a * 1 == a ───────────────────────────────────
proptest! {
    #![proptest_config(ProptestConfig::with_cases(1_000))]

    #[test]
    fn prop_multiplicative_identity(a in fr_element()) {
        let result = Bn254::mul(a, u256::ONE);
        prop_assert_eq!(result, a,
            "multiplicative identity failed: ({} * 1) = {} ≠ {}", a, result, a);
    }
}

// ── 6. Multiplicative inverse: a * a⁻¹ == 1 (a ≠ 0) ─────────────────────────
proptest! {
    #![proptest_config(ProptestConfig::with_cases(1_000))]

    #[test]
    fn prop_multiplicative_inverse(a in fr_nonzero()) {
        let a_inv = Bn254::invert(a);
        // The inverse of a non-zero element must itself be non-zero.
        prop_assert_ne!(a_inv, u256::ZERO,
            "invert({}) returned 0", a);
        let result = Bn254::mul(a, a_inv);
        prop_assert_eq!(result, u256::ONE,
            "multiplicative inverse failed: {} * inv({}) = {} ≠ 1", a, a, result);
    }
}

// ── 7. Commutativity of multiplication: a * b == b * a ───────────────────────
proptest! {
    #![proptest_config(ProptestConfig::with_cases(1_000))]

    #[test]
    fn prop_mul_commutativity(a in fr_element(), b in fr_element()) {
        let lhs = Bn254::mul(a, b);
        let rhs = Bn254::mul(b, a);
        prop_assert_eq!(lhs, rhs,
            "mul commutativity failed: {} * {} = {} but {} * {} = {}",
            a, b, lhs, b, a, rhs);
    }
}

// ── 8. Distributivity: (a+b)*c == a*c + b*c ──────────────────────────────────
proptest! {
    #![proptest_config(ProptestConfig::with_cases(1_000))]

    #[test]
    fn prop_distributivity(
        a in fr_element(),
        b in fr_element(),
        c in fr_element(),
    ) {
        let lhs = Bn254::mul(Bn254::add(a, b), c);
        let rhs = Bn254::add(Bn254::mul(a, c), Bn254::mul(b, c));
        prop_assert_eq!(lhs, rhs,
            "distributivity failed: ({a}+{b})*{c} = {lhs} but {a}*{c}+{b}*{c} = {rhs}");
    }
}

// ── 9. Fermat's little theorem: a^(r-1) == 1 (a ≠ 0) ────────────────────────
//
// Fermat's little theorem for prime fields states that for any a ≠ 0:
//   a^(p-1) ≡ 1 (mod p)
//
// This property simultaneously validates `pow` and confirms that r is prime —
// a composite modulus would produce counter-examples with high probability.
proptest! {
    #![proptest_config(ProptestConfig::with_cases(1_000))]

    #[test]
    fn prop_fermats_little_theorem(a in fr_nonzero()) {
        let exponent = Bn254::BASE_MODULUS - u256::ONE;
        let result = Bn254::pow(a, exponent);
        prop_assert_eq!(result, u256::ONE,
            "Fermat's little theorem failed: {}^(r-1) = {} ≠ 1", a, result);
    }
}

// ── Bonus: invert(0) == 0 (implementation-defined convention) ────────────────
#[test]
fn invert_zero_returns_zero() {
    assert_eq!(
        Bn254::invert(u256::ZERO),
        u256::ZERO,
        "invert(0) must return 0 by convention"
    );
}

// ── Smoke test: field constants are well-formed ───────────────────────────────
#[test]
fn bn254_constants_are_valid() {
    // BASE_MODULUS (r) must be > 1
    assert!(
        Bn254::BASE_MODULUS > u256::ONE,
        "BASE_MODULUS must be > 1"
    );
    // FQ_MODULUS (p) must be > 1
    assert!(
        Bn254::FQ_MODULUS > u256::ONE,
        "FQ_MODULUS must be > 1"
    );
    // r ≠ p for BN254
    assert_ne!(
        Bn254::BASE_MODULUS,
        Bn254::FQ_MODULUS,
        "BASE_MODULUS (r) and FQ_MODULUS (p) must be distinct for BN254"
    );
}
