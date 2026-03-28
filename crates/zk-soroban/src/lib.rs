#![no_std]
use ethnum::u256 as eth_u256;
use soroban_sdk::{Env, U256};
use zk_core::Bn254;

pub mod error;
pub mod transcript;

pub use error::ZkError;
pub use transcript::Transcript;

/// Validates a Soroban U256 as a BN254 scalar.
/// This prevents "out of bounds" field element errors in ZK verifiers.
pub fn validate_soroban_scalar(_env: &Env, val: U256) -> bool {
    let mut bytes = [0u8; 32];
    val.to_be_bytes().copy_into_slice(&mut bytes);

    // Convert Big-Endian bytes to ethnum u256
    let internal_val = eth_u256::from_be_bytes(bytes);

    Bn254::is_valid_scalar(internal_val)
}

/// Helper trait to add this functionality directly to the Env
pub trait ZkEnv {
    fn is_bn254_scalar(&self, val: U256) -> bool;
}

impl ZkEnv for Env {
    fn is_bn254_scalar(&self, val: U256) -> bool {
        validate_soroban_scalar(self, val)
    }
}

use soroban_sdk::{contract, contractimpl};

#[contract]
pub struct ZkContract;

#[contractimpl]
impl ZkContract {
    /// Benchmark function to ensure CI measures REAL library footprint.
    pub fn validate_scalar(env: Env, val: U256) -> bool {
        // This forces the compiler to include the ethnum and zk-core logic
        env.is_bn254_scalar(val)
    }
}
