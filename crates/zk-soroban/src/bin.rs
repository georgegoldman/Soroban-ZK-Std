fn main() {
    use ark_ec::AffineRepr;
    use ark_bn254::G2Affine;
    use num_bigint::BigUint;

    let g2 = G2Affine::generator();
    let x_c0: BigUint = g2.x.c0.into();
    let x_c1: BigUint = g2.x.c1.into();
    let y_c0: BigUint = g2.y.c0.into();
    let y_c1: BigUint = g2.y.c1.into();

    println!("G2 X c0 (Real): {:x}", x_c0);
    println!("G2 X c1 (Imag): {:x}", x_c1);
    println!("G2 Y c0 (Real): {:x}", y_c0);
    println!("G2 Y c1 (Imag): {:x}", y_c1);
}
