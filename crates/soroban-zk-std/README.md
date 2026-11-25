# Soroban-ZK-Std

**A High-Performance Cryptographic Standard Library for Stellar Protocol 25 ZK-Primitives.**

This SDK provides a ready-to-use toolkit for Stellar smart contract developers to verify zero-knowledge proofs (such as Groth16) on-chain using Soroban. It bridges the gap between the low-level Protocol 25 BN254 host functions and the high-level needs of modern privacy applications.

## Installation

Add the library to your Soroban smart contract's `Cargo.toml`:

```toml
[dependencies]
soroban-zk-std = "0.1.3"
```

## Quick Start: Verifying a Groth16 Proof

This library provides a highly optimized, single-call 4-pairing check for Groth16 verifiers using the native `bn254_multi_pairing_check` host function.

Here is a simple example of how to verify a Groth16 proof inside your contract:

```rust
#![no_std]
use soroban_sdk::{contract, contractimpl, Bytes, Env};
use soroban_zk_std::groth16::{groth16_verify, Groth16Proof, Groth16VerifyingKey};
use ethnum::u256;

#[contract]
pub struct ZKVerifierContract;

#[contractimpl]
impl ZKVerifierContract {
    pub fn verify_proof(env: Env, proof_bytes: Bytes, public_input_bytes: Bytes) -> bool {
        // 1. Deserialize the Groth16 Proof (A, B, C points)
        let mut proof_buf = [0u8; 256];
        proof_bytes.copy_into_slice(&mut proof_buf);
        let proof = Groth16Proof::from_bytes(&proof_buf).expect("Invalid proof format");

        // 2. Load your circuit's Verifying Key
        let vk = get_verifying_key(); // Fetch from storage or hardcode

        // 3. Parse public inputs
        let mut pi_buf = [0u8; 32];
        public_input_bytes.copy_into_slice(&mut pi_buf);
        let public_input = u256::from_be_bytes(pi_buf);

        // 4. Verify the Zero Knowledge Proof!
        groth16_verify(&env, &vk, &proof, &[public_input]).unwrap_or(false)
    }
}
```

## Zero-Boilerplate Verifiers with Macros

With the default `macros` feature, a SnarkJS verifying key can be embedded and
validated at compile time, and a complete verifier contract generated:

```rust
#![no_std]
use soroban_sdk::contract;
use soroban_zk_std::{include_snarkjs_vk, zk_verifier, Groth16VerifyingKey};

// Path is relative to this crate's Cargo.toml. Every G1/G2 point is checked
// to be on BN254 and in the prime-order subgroup; a bad key is a compile error.
const MY_VK: Groth16VerifyingKey<'static> =
    include_snarkjs_vk!("circuits/verification_key.json");

#[contract]
pub struct MyVerifier;

// Replaces `#[contractimpl]`. Generates
//   verify_proof(env, proof: BytesN<256>, public_inputs: Vec<U256>)
//       -> Result<bool, ZkContractError>
//   is_proof_spent(env, proof, public_inputs) -> bool   (anti_replay only)
// Each call publishes a `ZkVerificationEvent` (see EVENTS.md).
#[zk_verifier(protocol = "groth16", vk = MY_VK, anti_replay = true)]
impl MyVerifier {}
```

`snarkjs_vk!(r#"{...}"#)` does the same from an inline JSON string. SnarkJS
stores G2 coordinates as `[c0, c1]`, matching `G2Affine`'s `(c0, c1)` tuples;
the EIP-197 `c1 || c0` wire order is only applied when the point is encoded,
so pass the JSON exactly as `snarkjs zkey export verificationkey` writes it.

## Use Case Guide: Compliant Private USDC (Shielded Asset)

One of the most powerful use cases for this SDK is building a **Compliant Private Stablecoin** on Stellar. 
In this model, users can transfer USDC privately using Zero-Knowledge Proofs, but the transaction amount is encrypted using the regulator's public key (ElGamal). This ensures absolute privacy for the user on the public ledger, while maintaining a backdoor for regulatory compliance.

Here is a full template demonstrating how `soroban-zk-std` powers the on-chain verification:

```rust
#![no_std]

use soroban_sdk::{contract, contractimpl, Address, Bytes, Env};
use soroban_zk_core::{ElGamalCiphertext, G1Affine};
use soroban_zk_std::groth16::{groth16_verify, Groth16Proof, Groth16VerifyingKey};
use soroban_zk_std::pairing::G2Affine;
use ethnum::u256;

#[contract]
pub struct CompliantShieldedUSDC;

#[contractimpl]
impl CompliantShieldedUSDC {
    /// Transfers a shielded amount between two users, while providing a ciphertext to the regulator.
    /// The ZK Proof guarantees:
    /// 1. Sender has sufficient balance.
    /// 2. Sender balance, Receiver balance, and Regulator ciphertexts all encrypt the SAME amount.
    /// 3. Values are in range (no negative amounts).
    pub fn transfer_shielded(
        env: Env,
        sender: Address,
        receiver: Address,
        proof_bytes: Bytes,
        public_inputs_bytes: Bytes,
    ) {
        sender.require_auth();

        // 1. Deserialize the Groth16 Proof (A, B, C points)
        let mut proof_buf = [0u8; 256];
        proof_bytes.copy_into_slice(&mut proof_buf);
        let proof = Groth16Proof::from_bytes(&proof_buf).expect("Invalid proof format");

        // 2. Load the Verifying Key (Typically stored in contract state)
        let vk = get_verifying_key();

        // 3. Parse public inputs (e.g. public keys, updated state roots)
        let mut pi_buf = [0u8; 32];
        public_inputs_bytes.copy_into_slice(&mut pi_buf);
        let public_input = u256::from_be_bytes(pi_buf);

        // 4. VERIFY THE ZERO KNOWLEDGE PROOF!
        // This utilizes Soroban-ZK-Std's Protocol 25 optimized multi-pairing checks under the hood!
        let is_valid = groth16_verify(&env, &vk, &proof, &[public_input])
            .expect("Verification failed due to malformed points");
        
        if !is_valid {
            panic!("ZK Proof is invalid! Transfer rejected.");
        }

        // 5. ZK Proof passed! Update the encrypted balances via Homomorphic Addition
        // ... (Update State) ...
        
        env.events().publish((sender, receiver), "Shielded Transfer Verified");
    }
}

fn get_verifying_key<'a>() -> Groth16VerifyingKey<'a> {
    // Return your circuit's actual curve points here
    Groth16VerifyingKey {
        alpha_g1: G1Affine { x: u256::from(0u8), y: u256::from(0u8) },
        beta_g2: G2Affine { x: (u256::from(0u8), u256::from(0u8)), y: (u256::from(0u8), u256::from(0u8)) },
        gamma_g2: G2Affine { x: (u256::from(0u8), u256::from(0u8)), y: (u256::from(0u8), u256::from(0u8)) },
        delta_g2: G2Affine { x: (u256::from(0u8), u256::from(0u8)), y: (u256::from(0u8), u256::from(0u8)) },
        ic: &[],
    }
}
```

## Other Supported Use Cases

This library is foundational infrastructure. Beyond compliant stablecoins, you can use it to build:
- **Trustless Governance**: ZK-Voting where users prove they hold a governance token without revealing their address or vote choice.
- **Configurable Privacy**: Integration with Association Set Providers (ASPs) for KYC-gated private pools.
- **Off-Chain Computation Verification**: Running complex logic off-chain (like a rollup or game state) and verifying the state transition on Soroban for minimal gas.

## Features

- **Host-Guest Mapping**: Seamlessly converts between Soroban's `U256` and the internal BN254 field representations.
- **Gas Efficient**: Wraps native Stellar Protocol 25 primitives to keep instruction counts incredibly low.
- **Constant Time**: Ensures cryptographic operations are side-channel resistant.
- **No-Std**: Fully compatible with the `#![no_std]` environment required by Soroban.

## Learn More

For complete documentation, contributing guidelines, and more examples, please visit the [Main Repository on GitHub](https://github.com/georgegoldman/Soroban-ZK-Std).
