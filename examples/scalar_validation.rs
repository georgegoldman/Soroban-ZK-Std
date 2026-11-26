// SPDX-License-Identifier: Apache-2.0
//! Run with `cargo run --example scalar_validation`.

use ethnum::u256;
use soroban_sdk::{Bytes, Env, U256};
use soroban_zk_core::{Bn254, ZkError};
use soroban_zk_std::HostConvert;

fn main() -> Result<(), ZkError> {
    let env = Env::default();
    let one = u256::from(1u8);
    let modulus = Bn254::FR_MODULUS;

    // Valid BN254 scalars are in [0, r), where r is the scalar field modulus.
    for value in [u256::from(0u8), u256::from(42u8), modulus - one] {
        let host_value = U256::from_be_bytes(&env, &Bytes::from_array(&env, &value.to_be_bytes()));
        let scalar = env.fr_from_u256(host_value)?;
        println!("Accepted scalar: {}", scalar.inner());
    }

    for value in [modulus, modulus + one] {
        let host_value = U256::from_be_bytes(&env, &Bytes::from_array(&env, &value.to_be_bytes()));
        match env.fr_from_u256(host_value) {
            Err(ZkError::InvalidFieldElement) => println!("Rejected scalar: {value}"),
            Err(error) => return Err(error),
            Ok(_) => return Err(ZkError::InvalidInput),
        }
    }
    Ok(())
}

#[test]
fn accepts_canonical_scalars_and_rejects_field_boundaries() -> Result<(), ZkError> {
    main()
}
