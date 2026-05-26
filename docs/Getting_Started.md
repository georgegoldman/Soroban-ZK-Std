# Getting Started with Soroban-ZK-Std

## Installation

Add to your contract's `Cargo.toml`:

```toml
[dependencies]
zk-soroban = { git = "https://github.com/georgegoldman/Soroban-ZK-Std" }
zk-core    = { git = "https://github.com/georgegoldman/Soroban-ZK-Std" }
```

## Prerequisites

```bash
rustup target add wasm32-unknown-unknown
cargo install --locked soroban-cli
```

## Validate a BN254 Scalar

```rust
use soroban_sdk::{contract, contractimpl, Env, U256};
use zk_soroban::ZkEnv;

#[contract]
pub struct MyContract;

#[contractimpl]
impl MyContract {
    pub fn check_scalar(env: Env, val: U256) -> bool {
        env.is_bn254_scalar(val)
    }
}
```

## Hash with Poseidon2

```rust
use zk_soroban::poseidon2::hash_to_field;
use soroban_sdk::{Env, U256};

pub fn compute_hash(env: &Env, a: U256, b: U256) -> U256 {
    hash_to_field(env, &[a, b])
}
```

## Verify a Groth16 Proof

```rust
use zk_soroban::groth16::verify_groth16;
use zk_core::groth16::{Groth16Proof, VerifyingKey};
use soroban_sdk::Env;

pub fn verify(env: &Env, vk: &VerifyingKey, proof: &Groth16Proof, inputs: &[u256]) -> bool {
    verify_groth16(env, vk, proof, inputs).unwrap_or(false)
}
```

## Verify a Merkle Path

```rust
use zk_soroban::merkle::verify_merkle_path;
use soroban_sdk::{Env, U256};

pub fn check_membership(env: &Env, root: &U256, leaf: &U256, index: u64, path: &[U256]) -> bool {
    verify_merkle_path(env, root, leaf, index, path).unwrap_or(false)
}
```

## Build for WASM

```bash
make build-wasm
# Check size:
twiggy top target/wasm32-unknown-unknown/release/zk_soroban.wasm
```

## Run Tests

```bash
cargo test -p zk-core
cargo test -p zk-soroban
```

## Architecture

| Crate | Purpose |
|-------|---------|
| `zk-core` | Pure math: Fr/Fq/Fq2, G1, polynomials, Groth16 verifier logic |
| `zk-soroban` | Soroban integration: pairing, Poseidon2, Merkle, auth guards |
| `contracts/verifier-sample` | Example contract + integration tests |
