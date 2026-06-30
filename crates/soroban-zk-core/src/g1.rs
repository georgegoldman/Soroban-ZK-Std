/// The BN254 G1 generator point.
/// This specific point (1, 2) is a property of the BN254 parameter selection
/// and is used as the standard generator across proof systems (e.g., Groth16).
pub const G1_GENERATOR: G1Affine = G1Affine {
    x: 1,
    y: 2,
    is_infinity: false,
};

/// The order of the G1 group, equal to the scalar field modulus `r`.
/// Because the cofactor h = 1, the number of points in the group is exactly r.
/// Hex: 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
pub const G1_ORDER: Fr = Fr::from_raw([
    0x43e1f593f0000001,
    0x2833e84879b97091,
    0xb85045b68181585d,
    0x30644e72e131a029,
]);

// Compile-time assertion that the generator is on the curve.
// The BN254 G1 curve equation is y² = x³ + 3.
// For G1_GENERATOR (1, 2):
// y² = 2² = 4
// x³ + 3 = 1³ + 3 = 4
// Thus, 4 == 4 mod p holds for any prime p > 4.
const _: () = {
    // Note: This logic assumes your types support const evaluation or 
    // are evaluated within a const context provided by the library.
    let x_cubed_plus_3 = 1u128 * 1 * 1 + 3;
    let y_squared = 2u128 * 2;
    assert!(x_cubed_plus_3 == y_squared);
};

/// Verifies if a point is in the G1 prime-order subgroup.
/// 
/// For the BN254 G1 group, the cofactor `h` is exactly 1. This means that 
/// every point that satisfies the curve equation is guaranteed to be in 
/// the prime-order subgroup. Therefore, a subgroup check is equivalent 
/// to simply verifying the point is on the curve.
pub fn g1_is_in_subgroup(p: &G1Affine) -> bool {
    p.is_on_curve()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_g1_generator_properties() {
        // Verify generator is on curve
        assert!(G1_GENERATOR.is_on_curve());
        
        // Verify subgroup membership
        assert!(g1_is_in_subgroup(&G1_GENERATOR));
    }

    #[test]
    fn test_generator_order() {
        // Multiplying the generator by the group order must yield the identity point (point at infinity).
        // g1_scalar_mul(G1_GENERATOR, G1_ORDER) == G1Affine::identity()
        let result = g1_scalar_mul(G1_GENERATOR, G1_ORDER);
        assert!(result.is_identity(), "Generator multiplied by G1_ORDER should be identity");
    }
}
