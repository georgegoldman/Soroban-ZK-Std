# soroban-zk-core

**Pure `#![no_std]` cryptographic primitives for the Soroban ZK Standard.**

`soroban-zk-core` provides zero-dependency (no `soroban-sdk` required) mathematical building blocks for zero-knowledge proofs on Stellar Protocol 25 (BN254 / `alt_bn128`). It is designed for minimal WASM footprint, constant-time field operations, and zero-panic error handling (`Result<T, ZkError>`).

## Features

- **BN254 Field & Curve Arithmetic**: Constant-time `Fq` / `Fr` operations, G1 affine/projective arithmetic, and subgroup validation.
- **ZK-Friendly Hashes**: Poseidon2, Rescue-Prime, and `no_std` SHA-256 padding and word-packing utilities.
- **Bulletproofs**: Range-proof verification (and optional prover behind the `prover` feature) with Wasm-specialized MSM kernels (`wasm-msm`, `wasm-prover`).
- **ElGamal Encryption**: Homomorphic EC-ElGamal over BN254 G1 for shielded balances and regulatory viewing keys.
- **Memory Hygiene**: Volatile-zeroing RAII guards (`zeroize::SensitiveBuffer`) for wiping temporary secrets.

## Installation

Add `soroban-zk-core` to your `Cargo.toml`:

```toml
[dependencies]
soroban-zk-core = "0.1.0"
```

For full Soroban smart-contract integration (Groth16 verification, host-function bindings, and `#[zk_verifier]` macros), use [`soroban-zk-std`](https://crates.io/crates/soroban-zk-std).

## Cargo Features

| Feature       | Default | Description                                                                 |
|---------------|---------|-----------------------------------------------------------------------------|
| `prover`      | No      | Enables the Bulletproofs range-proof prover. Omit for verifier-only WASM.   |
| `wasm-msm`    | No      | Enables WebAssembly-specialized MSM / vector-matrix multiplication kernels. |
| `wasm-prover` | No      | Convenience feature enabling both `prover` and `wasm-msm`.                  |

## License

Licensed under the [Apache-2.0](https://www.apache.org/licenses/LICENSE-2.0) license.
