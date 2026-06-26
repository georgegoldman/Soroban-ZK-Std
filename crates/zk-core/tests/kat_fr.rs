use ethnum::u256;
use zk_core::Bn254;

const R_MINUS_1: u256 = u256::from_words(
    0x30644e72e131a029b85045b68181585d_u128,
    0x2833e84879b9709143e1f593f0000000_u128,
);

const R_MINUS_2: u256 = u256::from_words(
    0x30644e72e131a029b85045b68181585d_u128,
    0x2833e84879b9709143e1f593efffffff_u128,
);

const R_MINUS_5: u256 = u256::from_words(
    0x30644e72e131a029b85045b68181585d_u128,
    0x2833e84879b9709143e1f593effffffc_u128,
);

/// Known-Answer Tests for Addition.
/// Reference vectors are sourced from the `arkworks` (specifically `ark-bn254` crate)
/// PrimeField implementation of Fr arithmetic.
#[test]
fn test_kat_addition() {
    let cases = [
        (u256::from(0u8), u256::from(0u8), u256::from(0u8)),
        (u256::from(1u8), u256::from(2u8), u256::from(3u8)),
        (R_MINUS_1, u256::from(1u8), u256::from(0u8)),
        (R_MINUS_2, u256::from(2u8), u256::from(0u8)),
        (R_MINUS_5, u256::from(6u8), u256::from(1u8)),
        (
            u256::from(0x1234567890abcdef_u64),
            u256::from(0xabcdef1234567890_u64),
            u256::from(0xbe02458ac502467f_u128),
        ),
    ];

    for &(a, b, expected) in &cases {
        assert_eq!(Bn254::add(a, b), expected);
    }
}

/// Known-Answer Tests for Subtraction.
/// Reference vectors are sourced from the `arkworks` (specifically `ark-bn254` crate)
/// PrimeField implementation of Fr arithmetic.
#[test]
fn test_kat_subtraction() {
    let cases = [
        (u256::from(0u8), u256::from(0u8), u256::from(0u8)),
        (u256::from(3u8), u256::from(2u8), u256::from(1u8)),
        (u256::from(0u8), u256::from(1u8), R_MINUS_1),
        (u256::from(1u8), u256::from(2u8), R_MINUS_1),
        (
            u256::from(0xabcdef1234567890_u64),
            u256::from(0x1234567890abcdef_u64),
            u256::from(0x99999899a3aaaaa1_u64),
        ),
    ];

    for &(a, b, expected) in &cases {
        assert_eq!(Bn254::sub(a, b), expected);
    }
}

/// Known-Answer Tests for Multiplication.
/// Reference vectors are sourced from the `arkworks` (specifically `ark-bn254` crate)
/// PrimeField implementation of Fr arithmetic.
#[test]
fn test_kat_multiplication() {
    let cases = [
        (u256::from(0u8), u256::from(0u8), u256::from(0u8)),
        (
            u256::from(1u8),
            u256::from(0x12345u32),
            u256::from(0x12345u32),
        ),
        (u256::from(2u8), u256::from(3u8), u256::from(6u8)),
        (R_MINUS_1, R_MINUS_1, u256::from(1u8)),
        (
            u256::from(0x1234567890abcdef_u64),
            u256::from(0xabcdef1234567890_u64),
            u256::from(0xc379aabef5007656e9642fba375de70_u128),
        ),
    ];

    for &(a, b, expected) in &cases {
        assert_eq!(Bn254::mul(a, b), expected);
    }
}

/// Known-Answer Tests for Negation.
/// Reference vectors are sourced from the `arkworks` (specifically `ark-bn254` crate)
/// PrimeField implementation of Fr arithmetic.
#[test]
fn test_kat_negation() {
    let cases = [
        (u256::from(0u8), u256::from(0u8)),
        (u256::from(1u8), R_MINUS_1),
        (R_MINUS_1, u256::from(1u8)),
        (
            u256::from(0x1234567890abcdef_u64),
            u256::from_words(
                0x30644e72e131a029b85045b68181585d_u128,
                0x2833e84879b9709131ad9f1b5f543212_u128,
            ),
        ),
        (
            u256::from_words(
                0x30644e72e131a029b85045b68181585d_u128,
                0x2833e84879b9709143e1f593f0000000_u128,
            ),
            u256::from(1u8),
        ),
    ];

    for &(a, expected) in &cases {
        let neg_a = Bn254::sub(u256::from(0u8), a);
        assert_eq!(neg_a, expected);
    }
}

/// Known-Answer Tests for Inversion.
/// Reference vectors are sourced from the `arkworks` (specifically `ark-bn254` crate)
/// PrimeField implementation of Fr arithmetic.
#[test]
fn test_kat_inversion() {
    let cases = [
        (u256::from(1u8), u256::from(1u8)),
        (
            u256::from(2u8),
            u256::from_words(
                0x183227397098d014dc2822db40c0ac2e_u128,
                0x9419f4243cdcb848a1f0fac9f8000001_u128,
            ),
        ),
        (R_MINUS_1, R_MINUS_1),
        (
            u256::from(0x1234567890abcdef_u64),
            u256::from_words(
                0x10923cb71bd18e57fcf2078c4fc44604_u128,
                0x39172fe785f45ea4c6c58a411c2216bb_u128,
            ),
        ),
        (
            u256::from_words(
                0x30644e72e131a029b85045b68181585d_u128,
                0x2833e84879b9709143e1f593f0000000_u128,
            ),
            u256::from_words(
                0x30644e72e131a029b85045b68181585d_u128,
                0x2833e84879b9709143e1f593f0000000_u128,
            ),
        ),
    ];

    for &(a, expected) in &cases {
        assert_eq!(Bn254::invert(a), expected);
    }
}

/// Known-Answer Tests for Exponentiation/Power.
/// Reference vectors are sourced from the `arkworks` (specifically `ark-bn254` crate)
/// PrimeField implementation of Fr arithmetic.
#[test]
fn test_kat_power() {
    let cases = [
        (u256::from(2u8), u256::from(0u8), u256::from(1u8)),
        (u256::from(2u8), u256::from(1u8), u256::from(2u8)),
        (u256::from(2u8), u256::from(2u8), u256::from(4u8)),
        (u256::from(3u8), R_MINUS_1, u256::from(1u8)),
        (
            u256::from(0x1234567890abcdef_u64),
            R_MINUS_1,
            u256::from(1u8),
        ),
        (
            u256::from(0x1234567890abcdef_u64),
            u256::from(5u8),
            u256::from_words(
                0xc299233369ef3d359511e7b3472fa1c_u128,
                0x5c045ac448ea825ea568e518b5dd5e30_u128,
            ),
        ),
    ];

    for &(a, exp, expected) in &cases {
        assert_eq!(Bn254::pow(a, exp), expected);
    }
}

/// Fermat's Little Theorem Check: a^(r - 1) == 1 (mod r) for non-zero `a`.
/// Reference properties verified against standard BN254 scalar field parameters.
#[test]
fn test_kat_fermats_little_theorem() {
    let values = [
        u256::from(2u8),
        u256::from(3u8),
        u256::from(5u8),
        u256::from(0x1234567890abcdef_u64),
        R_MINUS_2,
    ];

    for &a in &values {
        assert_eq!(Bn254::pow(a, R_MINUS_1), u256::from(1u8));
    }
}

/// Multiplicative Inverse Check: a * invert(a) == 1 (mod r) for non-zero `a`.
/// Sourced with same values used in inversion tests.
#[test]
fn test_kat_multiplicative_inverse_consistency() {
    let values = [
        u256::from(1u8),
        u256::from(2u8),
        R_MINUS_1,
        u256::from(0x1234567890abcdef_u64),
        u256::from_words(
            0x30644e72e131a029b85045b68181585d_u128,
            0x2833e84879b9709143e1f593f0000000_u128,
        ),
    ];

    for &a in &values {
        let inv_a = Bn254::invert(a);
        assert_eq!(Bn254::mul(a, inv_a), u256::from(1u8));
    }
}
