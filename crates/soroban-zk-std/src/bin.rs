use soroban_zk_std::G2Affine;

fn main() {
    let g2 = G2Affine::generator();

    println!("G2 X c0 (Real): {:x}", g2.x.0);
    println!("G2 X c1 (Imag): {:x}", g2.x.1);
    println!("G2 Y c0 (Real): {:x}", g2.y.0);
    println!("G2 Y c1 (Imag): {:x}", g2.y.1);
}
