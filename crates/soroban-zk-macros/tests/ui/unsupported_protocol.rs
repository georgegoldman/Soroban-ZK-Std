// Only Groth16 is supported by #[zk_verifier].
use soroban_zk_std::zk_verifier;

pub struct Verifier;

#[zk_verifier(protocol = "plonk", vk = VK)]
impl Verifier {}

fn main() {}
