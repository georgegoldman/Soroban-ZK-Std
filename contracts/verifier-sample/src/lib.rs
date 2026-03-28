#![no_std]
use soroban_sdk::{contract, contractimpl, Env, U256};
use zk_soroban::{Transcript, ZkEnv};

#[contract]
pub struct Verifier;

#[contractimpl]
impl Verifier {
    pub fn check(env: Env, input: U256) -> bool {
        env.is_bn254_scalar(input)
    }

    pub fn challenge(env: Env, input_a: U256, input_b: U256) -> U256 {
        let mut transcript = Transcript::new(&env);
        if transcript.absorb(input_a).is_err() {
            return U256::from_u32(&env, 0);
        }
        if transcript.absorb(input_b).is_err() {
            return U256::from_u32(&env, 0);
        }

        match transcript.squeeze_challenge() {
            Ok(challenge) => challenge,
            Err(_) => U256::from_u32(&env, 0),
        }
    }
}

mod test;
