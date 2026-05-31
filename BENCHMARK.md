# Soroban-ZK-Std Gas Benchmarks

This suite measures the CPU instruction cost of fundamental zero-knowledge cryptographic primitives within the Soroban WASM environment. 

Soroban enforces a strict computational budget of **400,000,000 instructions** per transaction. Our goal is to ensure that a complete Groth16 verification, including hashing and scalar multiplications, leaves ample room for standard application logic.

## Environment details
* **Soroban Simulator Version:** [Insert Version, e.g., v20.x.x]
* **Stellar Protocol:** 25
* **Target:** `wasm32-unknown-unknown`

## Results Overview

| Operation             | Inputs | Instruction Cost | % of 400M Budget | Naive Baseline Cost | Improvement      |
| :--------             | :----- | :--------------- | :--------------- | :------------------ | :----------      |
| `Fr::add`             | ------ | [0,000]          | ~0.0%            | -                   | -                |
| `Fr::mul`             | -      | [0,000]          | ~0.0%            | -                   | -                |
| `Fr::invert`          | -      | [0,000] | ~0.0%  | -                | -                   |                  |
| `g1_scalar_mul`       | 1      | [00,000,000]     | X.X%             | [00,000,000]        | **XX% Faster**   | 
| `g1_msm`              | n=2    | [00,000,000]     | X.X%             | -                   | -                |
| `g1_msm`              | n=4    | [00,000,000]     | X.X%             | -                   | -                |
| `g1_msm`              | n=8    | [00,000,000]     | X.X%             | -                   | -                |
| `poseidon2_hash`      | 1      | [0,000,000]      | X.X%             | [0,000,000]         | **47% Faster**   | 
| `poseidon2_hash`      | 2      | [0,000,000]      | X.X%             | -                   | -                |
| `poseidon2_hash`      | 4      | [0,000,000]      | X.X%             | -                   | -                |
| **`groth16_verify`**  | 1      | **[000,000,000]**| **XX.X%**        | -                   | -                |

## Reproducibility 
To run these benchmarks locally and verify the instruction consumption against the Soroban budget API, run:

```bash
make bench
# or
cargo test --benches -- --nocapture