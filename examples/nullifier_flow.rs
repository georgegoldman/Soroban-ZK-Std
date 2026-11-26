// SPDX-License-Identifier: Apache-2.0
//! Run with `cargo run --example nullifier_flow`.

use soroban_sdk::{vec, Bytes, Env, U256};
use soroban_zk_std::{
    nullifier::{inputs_to_bytes, NullifierSet, NullifierStore},
    ZkContract, ZkContractError,
};

fn main() -> Result<(), ZkContractError> {
    let env = Env::default();
    let contract = env.register(ZkContract, ());

    env.as_contract(&contract, || {
        let store = NullifierStore::new(&env);
        // Placeholder bytes show the storage API. Verify a real proof before marking it spent.
        let proof = Bytes::from_array(&env, &[1, 2, 3, 4]);
        let inputs = inputs_to_bytes(&env, &vec![&env, U256::from_u128(&env, 42)]);
        let nullifier = NullifierStore::derive_nullifier(&env, &proof, &inputs);
        println!("Derived nullifier: {:02x?}", nullifier.to_array());

        if store.is_spent(&env, &proof, &inputs) {
            return Err(ZkContractError::ReplayDetected);
        }
        store.mark_spent(&env, &proof, &inputs)?;
        if !store.is_spent(&env, &proof, &inputs) {
            return Err(ZkContractError::StorageError);
        }

        match store.mark_spent(&env, &proof, &inputs) {
            Err(ZkContractError::ReplayDetected) => {
                println!("First use recorded, replay rejected.");
                Ok(())
            }
            Err(error) => Err(error),
            Ok(()) => Err(ZkContractError::StorageError),
        }
    })
}

#[test]
fn records_first_use_and_rejects_replay() -> Result<(), ZkContractError> {
    main()
}
