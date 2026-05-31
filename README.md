# Soroban-ZK-Std
**A High-Performance Cryptographic Standard Library for Stellar Protocol 25 ZK-Primitives.**

## The Unsolved Problem in Stellar ZK
While Protocol 25 ("X-Ray") introduced native host functions for BN254 pairing checks and Poseidon hashing, a massive **Developer Experience (DX)** gap remains. To build a private stablecoin or compliant RWA protocol on Stellar today, developers face three "Hard Stops":

1. **Host-Guest Mapping**: Manually handling the conversion between Soroban’s host-managed U256 and internal 256-bit field representations is error-prone.

2. **Resource Exhaustion**: Standard Rust ZK libraries are too heavy for Soroban’s 64KB WASM limit.

3. **Gas Inefficiency**: Software-only math often exceeds the 400M instruction limit.

**Soroban-ZK-Std** is the solution—a modular, no_std Rust SDK designed to make Stellar the premier home for configurable, compliance-forward privacy.


## Mathematical Specification
- **Curve**: BN254 (alt_bn128) optimized for the native bn254_multi_pairing_check host function.
- **Field Modulus ($r$)**: 21888242871839275222246405745257275088548364400416034343698204186575808495617
- **Primitives**: Constant-time modular addition, custom Schoolbook Multiplication with 512-bit reduction, and Fermat-based inversion.

## Performance Benchmarks (March 2026)
- **47% Faster Hashing**: Directly utilizes the poseidon2_permutation host function via CAP-0075.
- **Minimal Footprint**: Uses ethnum for assembly-optimized arithmetic, reducing WASM binary size by ~22KB—saving 30% of your total contract space.
- **Instruction Efficiency**: Optimized field arithmetic allows for complex verifiers to run well within the 400M instruction budget.

## Public Good Impact & Use Cases
This is foundational infrastructure for the Stellar ecosystem. It empowers developers to build:
- **Shielded RWA Transfers**: Private tokenized assets that maintain regulatory visibility via ElGamal Viewing Keys (see our [Shielded Asset Template](./contracts/shielded-asset-template)).
- **Configurable Privacy**: Integration with [Association Set Providers (ASPs)](./docs/ASP_Integration.md) for compliance.
- **Trustless Governance**: ZK-Voting and anonymous contribution tracking for Stellar-native DAOs.

## Installation
Add this to your `Cargo.toml`:
```toml
[dependencies]
zk-soroban = { git = "[https://github.com/georgegoldman/Soroban-ZK-Std](https://github.com/georgegoldman/Soroban-ZK-Std)" }
```

## 🛠️ Contributing to Soroban-ZK-Std
Soroban-ZK-Std is a high-performance, no_std cryptographic library optimized specifically for the Stellar network. Because we operate within the strict limits of the Soroban Virtual Machine, our contribution standards are higher than standard Rust projects.

💬 Community
Join our Telegram group to collaborate with other contributors and get real-time support: https://t.me/+beBHvsplOPVmYmM0

### 🚀 Getting Started
1. **Prerequisites**

You must have the following installed:
- **Rust (Nightly/Stable):** `rustup target add wasm32-unknown-unknown`

- **Soroban CLI:** `cargo install --locked soroban-cli`

- **Twiggy & Bloat:** (For size auditing) `cargo install twiggy cargo-bloat`

2. Local Environment Setup

Clone the repo and run the master check to ensure your environment is compatible:
```bash
git clone https://github.com/georgegoldman/Soroban-ZK-Std.git
cd Soroban-ZK-Std
make all
```

### 🏗️ Project Architecture
To keep the library modular, we split the code into three distinct areas:

| Component         | Path                          | Purpose                                                                 |
|------------------|-------------------------------|-------------------------------------------------------------------------|
| zk-core          | crates/zk-core/               | Pure Math. Elliptic curve logic, Field arithmetic, and U256 mappings. No Soroban dependencies here. |
| zk-soroban       | crates/zk-soroban/            | Stellar Integration. Traits that extend the Soroban Env, host-function mappings, and XDR conversion. |
| verifier-sample  | contracts/verifier-sample/    | Integration Tests. A sample contract used to verify WASM size and gas costs. |

**Rule:** 

If you are adding a new mathematical primitive (e.g., a new Curve), it goes in `zk-core`. If you are adding a tool for developers to use in their contracts, it goes in `zk-soroban`.

### 📥 How to Add Your Code

1. **Claim an Issue**
Check the [Issues](https://www.google.com/search?q=https://github.com/georgegoldman/Soroban-ZK-Std/issues) tab for "Good First Issues" or "Stellar Wave Bounties." Comment on the issue to be assigned.

2. **Implementation Rules**

- **No Standard Library:** We are strictly `#![no_std]`. Do not use `std::`. Use `core::` or `alloc::` (if absolutely necessary).

- **No Panics:** Avoid `unwrap()` and `expect()`. Use `Result<T, ZkError>` to allow contracts to handle errors gracefully.

- **Constant Time:** All cryptographic operations (add, mul, inv) **must** be constant-time to prevent side-channel attacks.

3. **Testing**

Add unit tests in the same file as your code using a `mod test` block. Ensure they run with:

```bash 
cargo test -p <your-crate-name>
```

## 🚦 The "Green Light" Checklist
Before submitting a Pull Request (PR), you **must** run the local bouncer:

1. **Linting:** make `clippy` (Must have 0 warnings).
2. Formatting: `make fmt` (Standardizes style).
3. Size Check: `make build-wasm`
  - Check the size with twiggy top `target/wasm32-unknown-unknown/release/zk_soroban.wasm`.
  - **If your code increases the size by > 5KB, your PR will require an optimization review.**


## 📝 Pull Request Template
When you open a PR, please use the provided template. Briefly explain the **Mathematical Logic** behind your changes and provide the **Instruction Cost** (gas) if applicable.
