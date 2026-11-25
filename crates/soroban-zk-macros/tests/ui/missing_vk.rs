// #[zk_verifier] needs a verifying key.
use soroban_zk_std::zk_verifier;

pub struct Verifier;

#[zk_verifier(protocol = "groth16", anti_replay = true)]
impl Verifier {}

fn main() {}
