# Cross-Contract Verification Guide

> **Issue #214** — How to securely call the `Soroban-ZK-Std` verifier from an external dApp contract.

This guide shows you how a separate Soroban dApp contract can invoke the ZK verifier as a cross-contract call, including how to validate inputs before delegating to it and how to interpret the result safely.

---

## Overview

In a typical deployment, the verifier lives in its own contract (e.g., `verifier-sample`) and dApp contracts call it rather than re-embedding verification logic. This separation:

- Keeps each contract under the 64 KB WASM limit
- Lets the verifier be upgraded independently
- Provides a single audited verification path shared by multiple dApps

---

## Step 1: Understand the Verifier Interface

The `verifier-sample` contract exposes a single public entry point:

```rust
// contracts/verifier-sample/src/lib.rs
#[contractimpl]
impl Verifier {
    pub fn check(env: Env, input: U256) -> bool {
        env.is_bn254_scalar(input)
    }
}
```

`check` returns `true` if the supplied `U256` value is a valid BN254 scalar field element (i.e., strictly less than the field modulus `r`). It never panics — malformed inputs return `false`.

---

## Step 2: Add the Verifier as a Dependency

Deploy the verifier contract to your target network first, then record its contract ID. In your dApp contract's crate, import the Soroban SDK client utilities:

```toml
# Cargo.toml
[dependencies]
soroban-sdk = "25.0.0"
```

There is no separate Rust crate to add; you reference the deployed contract by its on-chain ID at runtime.

---

## Step 3: Declare the Client in Your dApp Contract

Generate a thin Rust client for the verifier's interface using `soroban_sdk::contractclient`:

```rust
#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env, U256};

// Declare the remote verifier interface.
// This must match the function signatures of the deployed verifier contract.
mod verifier_contract {
    soroban_sdk::contractimport!(
        file = "path/to/verifier_sample.wasm"
        // Or reference by interface type if the WASM is not available at compile time.
    );
}
```

Alternatively, if you do not have the WASM at compile time, declare the interface manually:

```rust
mod verifier_contract {
    use soroban_sdk::{contractclient, Env, U256};

    #[contractclient(name = "VerifierClient")]
    pub trait VerifierInterface {
        fn check(env: Env, input: U256) -> bool;
    }
}

use verifier_contract::VerifierClient;
```

---

## Step 4: Call the Verifier from Your Contract

Store the verifier's `Address` in your contract's storage or accept it as a parameter. Then call `check` before processing any proof-dependent logic:

```rust
#[contracttype]
pub enum DataKey {
    VerifierAddress,
}

#[contract]
pub struct DApp;

#[contractimpl]
impl DApp {
    /// Initializes the dApp with the address of the deployed verifier contract.
    pub fn initialize(env: Env, verifier: Address) {
        env.storage().instance().set(&DataKey::VerifierAddress, &verifier);
    }

    /// Example: accept a public input, validate it via the verifier, then proceed.
    pub fn submit_proof(env: Env, public_input: U256) -> Result<(), u32> {
        let verifier_addr: Address = env
            .storage()
            .instance()
            .get(&DataKey::VerifierAddress)
            .unwrap_or_else(|| panic!("verifier not set"));

        let verifier = VerifierClient::new(&env, &verifier_addr);

        // Validate the scalar field element before any further computation.
        if !verifier.check(&public_input) {
            return Err(1u32); // ERR_INVALID_SCALAR
        }

        // Safe to proceed — `public_input` is a valid BN254 scalar.
        // ... your proof-processing logic here ...

        Ok(())
    }
}
```

---

## Step 5: Security Considerations

### Always validate inputs before use

Never assume a `U256` received from an untrusted caller is within the field. Passing an out-of-range value directly to a pairing or hash function can cause unexpected behavior. The `check` call is your gate.

```rust
// WRONG — passes raw caller-supplied input directly to pairing
pairing_check(&env, &[(g1_from_u256(raw_input), g2)]);

// CORRECT — validate first, then use
if !verifier.check(&raw_input) { return Err(ERR_INVALID); }
pairing_check(&env, &[(g1_from_u256(raw_input), g2)]);
```

### Pin the verifier address at initialization

Accept the verifier address only at contract initialization and store it in instance storage. Never take the verifier address as a per-call parameter from untrusted callers, as this would allow them to substitute a malicious contract.

```rust
// WRONG — caller controls which verifier is used
pub fn submit(env: Env, verifier: Address, input: U256) { ... }

// CORRECT — verifier is set once by the admin at initialization
pub fn submit(env: Env, input: U256) { /* reads verifier from storage */ }
```

### Treat `false` as rejection, never as a soft warning

`check` returning `false` means the input is cryptographically invalid. Any subsequent computation that depends on this input must be aborted immediately — do not log-and-continue.

### Cross-contract call costs

Each cross-contract call incurs additional instruction overhead beyond the verifier's own computation. For `check` (a scalar comparison, < 1,000 instructions), this overhead is negligible. For heavier verifier functions such as a full Groth16 check (~167 M instructions), plan your total budget accordingly using the figures in [GAS.md](../GAS.md).

---

## Full Example

```rust
#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env, U256};

mod verifier_contract {
    use soroban_sdk::{contractclient, Env, U256};

    #[contractclient(name = "VerifierClient")]
    pub trait VerifierInterface {
        fn check(env: Env, input: U256) -> bool;
    }
}

use verifier_contract::VerifierClient;

#[contracttype]
pub enum DataKey {
    Verifier,
}

#[contract]
pub struct PrivateVote;

#[contractimpl]
impl PrivateVote {
    pub fn initialize(env: Env, verifier: Address) {
        env.storage().instance().set(&DataKey::Verifier, &verifier);
    }

    /// Casts a vote backed by a ZK proof. The nullifier must be a valid BN254 scalar.
    pub fn cast_vote(env: Env, nullifier: U256, choice: u32) -> bool {
        let verifier_addr: Address = env
            .storage()
            .instance()
            .get(&DataKey::Verifier)
            .expect("verifier not initialized");

        let verifier = VerifierClient::new(&env, &verifier_addr);

        if !verifier.check(&nullifier) {
            // Reject: nullifier is not a valid field element.
            return false;
        }

        // Nullifier is valid; record the vote.
        // (Nullifier uniqueness check and actual vote tallying omitted for brevity.)
        let _ = choice;
        true
    }
}
```

---

## Next Steps

- [Getting Started Guide](./getting-started-guide.md) — set up a contract from scratch
- [GAS.md](../GAS.md) — instruction cost reference for budget planning
- [ASP Integration Guide](./ASP_Integration.md) — compliance workflow with cross-contract verifiers
