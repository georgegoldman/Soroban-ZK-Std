#[cfg(feature = "std")]
fn main() {
    use num_bigint::BigUint;
    use soroban_zk_std::G2Affine;

    let g2 = G2Affine::generator();

    let x_c0 = BigUint::from_bytes_be(&g2.x.0.to_be_bytes());
    let x_c1 = BigUint::from_bytes_be(&g2.x.1.to_be_bytes());
    let y_c0 = BigUint::from_bytes_be(&g2.y.0.to_be_bytes());
    let y_c1 = BigUint::from_bytes_be(&g2.y.1.to_be_bytes());

    println!("G2 X c0 (Real): {:x}", x_c0);
    println!("G2 X c1 (Imag): {:x}", x_c1);
    println!("G2 Y c0 (Real): {:x}", y_c0);
    println!("G2 Y c1 (Imag): {:x}", y_c1);
}

// no_std builds (e.g. kani's --all-targets instrumentation) compile this
// target as a no-op; running the vector generator requires `std`.
#[cfg(not(feature = "std"))]
fn main() {}
