//! Dev utility: prints the BN254 G2 generator coordinates as hex.
//!
//! The values are the Fq² components (c0 = real, c1 = imaginary) of the X and Y
//! coordinates, used to derive the hardcoded G2 test vectors in `pairing.rs`.
//!
//! Run with: `cargo run -p zk-soroban --example gen_vectors`

fn main() {
    use ark_bn254::G2Affine;
    use ark_ec::AffineRepr; // for the curve generator
    use ark_ff::PrimeField; // for into_bigint()
    use num_bigint::BigUint; // for hex-formatting field elements

    let g2 = G2Affine::generator();

    // Arkworks G2 elements store each coordinate as an Fq² value with c0/c1 parts.
    let x_c0: BigUint = g2.x.c0.into_bigint().into();
    let x_c1: BigUint = g2.x.c1.into_bigint().into();
    let y_c0: BigUint = g2.y.c0.into_bigint().into();
    let y_c1: BigUint = g2.y.c1.into_bigint().into();

    println!("G2 X c0 (Real): {:x}", x_c0);
    println!("G2 X c1 (Imag): {:x}", x_c1);
    println!("G2 Y c0 (Real): {:x}", y_c0);
    println!("G2 Y c1 (Imag): {:x}", y_c1);
}
