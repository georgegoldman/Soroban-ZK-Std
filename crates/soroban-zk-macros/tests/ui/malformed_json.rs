// Truncated JSON must be a compile error.
use soroban_zk_std::{snarkjs_vk, Groth16VerifyingKey};

const VK: Groth16VerifyingKey<'static> = snarkjs_vk!(r#"{ "protocol": "groth16", "vk_alpha_1": ["1", "2", "1" "#);

fn main() {
    let _ = VK;
}
