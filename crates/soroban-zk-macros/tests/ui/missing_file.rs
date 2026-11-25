// A path that does not exist (relative to CARGO_MANIFEST_DIR) is a compile error.
use soroban_zk_std::{include_snarkjs_vk, Groth16VerifyingKey};

const VK: Groth16VerifyingKey<'static> = include_snarkjs_vk!("does/not/exist.json");

fn main() {
    let _ = VK;
}
