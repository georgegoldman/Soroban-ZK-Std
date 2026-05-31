# Getting Started Guide

> **Step-by-step instructions for integrating Soroban-ZK-Std into a new Soroban smart contract.**

## Overview

This guide walks you through adding zero-knowledge proof capabilities to your Soroban contract using the `Soroban-ZK-Std` library. By the end, you will have a working contract that can verify Groth16 proofs, hash with Poseidon2, and perform BN254 pairing checks — all within Soroban's WASM and instruction budget limits.

---

## Prerequisites

Before starting, ensure you have the following installed:

| Tool | Version | Installation Command |
|------|---------|---------------------|
| **Rust** | nightly (recommended) or stable | `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \| sh` |
| **WebAssembly target** | — | `rustup target add wasm32-unknown-unknown` |
| **Soroban CLI** | latest | `cargo install --locked soroban-cli` |
| **Make** | system | `apt install build-essential` (Linux) or `xcode-select --install` (macOS) |

> **Verify your installation:**
> ```bash
> rustc --version
> cargo --version
> soroban --version
> ```

---

## Step 1: Create a New Soroban Contract

If you don't already have a contract, create one using the Soroban CLI:

```bash
soroban contract init my-zk-contract
cd my-zk-contract
```

This generates a basic Soroban contract scaffold with a `Cargo.toml`, `src/lib.rs`, and a test file.

---

## Step 2: Add Soroban-ZK-Std as a Dependency

Edit your `Cargo.toml` to add the `zk-soroban` crate:

```toml
[dependencies]
soroban-sdk = "25.0.0"
zk-soroban = { git = "https://github.com/georgegoldman/Soroban-ZK-Std" }

# You may also need these for field arithmetic:
ethnum = "1.3"
```

> **Note:** The exact Soroban SDK version should match the protocol version your contract targets. Check the [Soroban documentation](https://developers.stellar.org/docs/soroban) for the latest compatibility matrix.


## Step 3: Import the Library in Your Contract

In your `src/lib.rs`, import the types and functions you need:

```rust
#![no_std]
use soroban_sdk::{contract, contractimpl, Env, Vec};
use zk_core::{G1Affine, Bn254};
use zk_soroban::pairing::{G2Affine, pairing_check};
use zk_soroban::poseidon2::Poseidon2;
use zk_soroban::ZkError;
```

---

## Step 4: Use Pairing Checks (Groth16 Verification)

Here is a minimal contract that exposes a Groth16 proof verification endpoint:

```rust
#[contract]
pub struct ZKVerifier;

#[contractimpl]
impl ZKVerifier {
    /// Verifies a Groth16 proof given the verification key and public inputs.
    ///
    /// # Parameters
    /// - `proof_a`, `proof_b`, `proof_c`: The three proof points
    /// - `vk_alpha_g1`, `vk_beta_g2`, `vk_gamma_g2`, `vk_delta_g2`: Verification key points
    /// - `public_inputs`: Serialized public inputs
    ///
    /// # Returns
    /// `true` if the proof is valid, `false` otherwise.
    pub fn verify(
        env: Env,
        proof_a_bytes: Vec<u8>,
        proof_b_bytes: Vec<u8>,
        proof_c_bytes: Vec<u8>,
        vk_alpha_g1_bytes: Vec<u8>,
        vk_beta_g2_bytes: Vec<u8>,
        vk_gamma_g2_bytes: Vec<u8>,
        vk_delta_g2_bytes: Vec<u8>,
        public_inputs: Vec<u8>,
    ) -> bool {
        // Deserialize points from bytes
        // Note: In a real contract, you would implement from_bytes
        // for each type. See the zk-soroban crate for helpers.

        // Build the pairing check pairs
        let pairs = [
            (
                deserialize_g1(&proof_a_bytes),
                deserialize_g2(&proof_b_bytes),
            ),
            (
                negate_g1(deserialize_g1(&public_inputs)),
                deserialize_g2(&vk_gamma_g2_bytes),
            ),
            (
                negate_g1(deserialize_g1(&proof_c_bytes)),
                deserialize_g2(&vk_delta_g2_bytes),
            ),
            (
                negate_g1(deserialize_g1(&vk_alpha_g1_bytes)),
                deserialize_g2(&vk_beta_g2_bytes),
            ),
        ];

        pairing_check(&env, &pairs).unwrap_or(false)
    }
}
```

> **Key insight:** The pairing check evaluates `e(A₁, B₁) · e(A₂, B₂) · ... · e(Aₙ, Bₙ) == 1`. Negating certain G1 points achieves the standard Groth16 verification equation.


## Step 5: Use Poseidon2 Hashing

To hash values in your contract using the native Poseidon2 host function:

```rust
#[contractimpl]
impl ZKVerifier {
    /// Hashes two field elements using Poseidon2.
    pub fn hash_two_values(env: Env, left: u256, right: u256) -> u256 {
        Poseidon2::hash_two(&env, left, right)
    }

    /// Computes a Merkle root from leaves using Poseidon2 as the hash function.
    pub fn compute_merkle_root(env: Env, leaves: Vec<u256>) -> u256 {
        // Build the Merkle tree bottom-up using Poseidon2 hashing
        let mut current_level: Vec<u256> = leaves;

        while current_level.len() > 1 {
            let mut next_level: Vec<u256> = Vec::new(&env);
            for chunk in current_level.chunks(2) {
                let left = chunk[0];
                let right = if chunk.len() > 1 { chunk[1] } else { left };
                let hash = Poseidon2::hash_two(&env, left, right);
                next_level.push_back(hash);
            }
            current_level = next_level;
        }

        current_level.get(0).unwrap_or(u256::from(0u8))
    }
}
```

---

## Step 6: Build and Test

### Build the WASM Contract

```bash
cargo build --target wasm32-unknown-unknown --release
```

### Check WASM Size

```bash
twiggy top target/wasm32-unknown-unknown/release/my_zk_contract.wasm
```

Your contract should be well under Soroban's **64KB** limit. If it exceeds this, check for accidental `std` dependencies.

### Run Tests

```bash
cargo test
```


## Step 7: Deploy and Invoke

### Deploy to a Local Test Network

```bash
soroban contract deploy \
    --wasm target/wasm32-unknown-unknown/release/my_zk_contract.wasm \
    --source <your-identity> \
    --network local
```

### Invoke the Contract

```bash
soroban contract invoke \
    --id <contract-id> \
    --source <your-identity> \
    --network local \
    -- \
    verify \
    --proof_a_bytes <hex-encoded-proof-a> \
    --proof_b_bytes <hex-encoded-proof-b> \
    --proof_c_bytes <hex-encoded-proof-c> \
    --vk_alpha_g1_bytes <hex-encoded-vk-alpha> \
    --vk_beta_g2_bytes <hex-encoded-vk-beta> \
    --vk_gamma_g2_bytes <hex-encoded-vk-gamma> \
    --vk_delta_g2_bytes <hex-encoded-vk-delta> \
    --public_inputs <hex-encoded-public-inputs>
```

---

## Complete Example Contract

Here is a complete, minimal contract that uses Soroban-ZK-Std:

```rust
#![no_std]
use soroban_sdk::{contract, contractimpl, Env};
use ethnum::u256;
use zk_core::G1Affine;
use zk_soroban::pairing::{G2Affine, pairing_check};
use zk_soroban::poseidon2::Poseidon2;
use zk_soroban::ZkError;

#[contract]
pub struct MinimalZK;

#[contractimpl]
impl MinimalZK {
    /// Returns the Poseidon2 hash of two u256 values.
    pub fn hash(env: Env, a: u256, b: u256) -> u256 {
        Poseidon2::hash_two(&env, a, b)
    }

    /// Returns the result of a BN254 pairing check `e(G1, G2)`.
    /// This is a minimal sanity check for contract integration testing.
    pub fn check_pairing(env: Env) -> bool {
        let g1 = G1Affine {
            x: u256::from(1u8),
            y: u256::from(2u8),
        };
        let g2 = G2Affine {
            x: (
                u256::from_str_radix("1800deef121f1e764ff97665de1f4e53e2d8f75cfb208be8a76c26f20b32c0b9", 16).unwrap(),
                u256::from_str_radix("1800deef121f1e764ff97665de1f4e53e2d8f75cfb208be8a76c26f20b32c0b9", 16).unwrap(),
            ),
            y: (
                u256::from_str_radix("198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2", 16).unwrap(),
                u256::from_str_radix("1800deef121f1e764ff97665de1f4e53e2d8f75cfb208be8a76c26f20b32c0b9", 16).unwrap(),
            ),
        };
        let pairs = [(g1, g2)];
        pairing_check(&env, &pairs).unwrap_or(false)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use soroban_sdk::Env;

    #[test]
    fn test_hash() {
        let env = Env::default();
        let contract_id = env.register_contract(None, MinimalZK);
        let client = MinimalZKClient::new(&env, &contract_id);
        let result = client.hash(&u256::from(1u8), &u256::from(2u8));
        assert!(result != u256::from(0u8));
    }
}
```

---

## Troubleshooting

| Problem | Likely Cause | Solution |
|---------|-------------|----------|
| **WASM binary too large (>64KB)** | Accidental `std` dependency | Ensure all dependencies are `no_std`-compatible. Check with `cargo tree` for `std` features. |
| **Instruction budget exceeded** | Too many pairing pairs | Keep the number of `(G1, G2)` pairs in a single `pairing_check` call under 10 for typical budgets. |
| **Compilation error: `use of undeclared crate or module`** | Missing dependency | Double-check your `Cargo.toml` includes `zk-soroban` and `zk-core`. |
| **`pairing_check` returns `InvalidInput`** | Empty pairs slice | Ensure your pairs array has at least one `(G1, G2)` tuple. |

---

## Next Steps

- **Explore the [API Reference](./cap0075-integration-guide.md)** for advanced usage of pairing checks, Poseidon2, and scalar field conversion.
- **Learn about [Polynomial Operations](./polynomial-operations.md)** for building custom ZK circuits.
- **Review the [ASP Integration Guide](./ASP_Integration.md)** to understand how to configure compliance workflows with Association Set Providers.
- **Check the [Shielded Asset Template](../contracts/shielded-asset-template/)** for a complete private token implementation.
