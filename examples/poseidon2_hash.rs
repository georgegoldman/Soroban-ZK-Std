// SPDX-License-Identifier: Apache-2.0
//! Run with `cargo run --example poseidon2_hash`.

use soroban_sdk::{vec, Env, U256};
use soroban_zk_core::ZkError;
use soroban_zk_std::gadgets::hash::poseidon::{poseidon_hash, poseidon_hash_chunked};

fn main() -> Result<(), ZkError> {
    let env = Env::default();
    let inputs = [U256::from_u128(&env, 1), U256::from_u128(&env, 2)];
    let chunk = vec![&env, inputs[0].clone(), inputs[1].clone()];

    // The BN254 sponge absorbs up to two elements per chunk.
    let digest = poseidon_hash_chunked(&env, &[chunk])?;
    if digest != poseidon_hash(&env, &inputs) {
        return Err(ZkError::InvalidInput);
    }

    print!("Poseidon2 digest: 0x");
    for byte in digest.to_be_bytes().iter() {
        print!("{byte:02x}");
    }
    println!();
    Ok(())
}

#[test]
fn hashes_a_soroban_vector() -> Result<(), ZkError> {
    main()
}
