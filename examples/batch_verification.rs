// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 Soroban Contributors

use soroban_sdk:{contractimport, vec, Env, Address, BytesN;
use soroban_zks::kzg::{KzgProof, KzgProofBatch, ExtendedKzgVerifier};

fn main() {
    let env = Env::default();
    let verifier = ExtendedKzgVerifier;

    // Generate batch of proofs (in real usage, these would come from prover)
    let proofs = vec![&env, KzgProof::default(&env); 10];
    let inputs = vec![&env, BytesN::from_array(&env, &[0u8; 32]); 10];
    let batch = KzgProofBatch::new(&env, proofs, inputs);

    // Single batch verification call
    match verifier.verify_batch(&env, &batch) {
        Ok(_) => println("Batch verification successful"),
        Err(e) => eprintln("Verification failed: {:?}", e),
    }
}
