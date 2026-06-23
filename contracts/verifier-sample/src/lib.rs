#![no_std]
use soroban_sdk::{contract, contractimpl, Env, U256};
use zk_soroban::ZkEnv;

#[contract]
pub struct Verifier;

#[contractimpl]
impl Verifier {
    pub fn check(env: Env, input: U256) -> bool {
        env.validate_bn254_scalar(input).is_ok()
    }
}

mod test;
