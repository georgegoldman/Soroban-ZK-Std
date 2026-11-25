# Soroban-ZK-Std Benchmarks

Measured CPU instructions, RAM bytes, and WASM sizes for the library's
primitives. Every figure here was produced on **2026-11-25** at commit
**`578490f`**. Nothing is estimated.

> Budget planning tables live in [GAS.md](./GAS.md). The per-row reference
> with sample counts is
> [`benchmark_gas_tables.mdx`](./frontend/content/docs/getting-started/benchmark_gas_tables.mdx).

## Environment

| Property | Value |
|---|---|
| `soroban-sdk` | 27.0.6 (testutils), `soroban-env-host` 27.0.1 |
| Ledger protocol reported by the test `Env` | 27 |
| Rust | 1.100.0, target `wasm32v1-none` |
| Profile | workspace `release` (`opt-level = "z"`, `lto = true`, `codegen-units = 1`) |
| Per-transaction CPU limit | 400,000,000 instructions |

## Two kinds of measurement

1. **WASM-metered (authoritative here).** The library calls are compiled into
   a `wasm32v1-none` contract and invoked through the metered Soroban host.
   This charges every guest WASM instruction plus every host function, which
   is what a deployed contract pays. Per-op cost is
   `cost(iters = K) - cost(iters = 0)` divided by `K`, so setup and VM
   instantiation cancel out. Reported values are the maximum across samples.
2. **Host-only (`cargo test -p soroban-zk-std --bench instruction_cost`).**
   The bench runs the library natively inside the test `Env`, so only host
   work (pairing and Poseidon2 host functions, storage, host objects) is
   charged. Pure-Rust arithmetic shows as **0**. Use these numbers for
   regression tracking of host-bound paths only.

The criterion benches in `crates/soroban-zk-core/benches` (`g1_ops`,
`montgomery_ops`, `bulletproofs_vs_groth16`) report wall-clock time, not
Soroban instructions:

```bash
cargo bench -p soroban-zk-core --bench montgomery_ops
cargo bench -p soroban-zk-core --bench g1_ops
```

## WASM-metered CPU instructions

| Primitive | CPU instructions | Fits 400M? |
|---|---:|:---:|
| `FqAdd` | 1,632 | yes |
| `Fq2Add` | 3,508 | yes |
| `FqMul` | 260,159 | yes |
| `Poseidon2` permutation (host fn) | 715,030 | yes |
| Transcript `squeeze_challenge` | 719,258 | yes |
| `Fq2Sqr` | 783,507 | yes |
| `Fq2Mul` | 787,732 | yes |
| `NullifierStore::is_spent` | 1,711,372 | yes |
| `NullifierStore::mark_spent` (new nullifier) | 1,819,060 | yes |
| `G1Double` | 2,608,919 | yes |
| `poseidon2::hash_to_field_cached`, 2 inputs, warm | 3,182,286 | yes |
| `G1Add` | 4,179,102 | yes |
| `poseidon2::hash_to_field`, 2 inputs | 4,652,644 | yes |
| Pairing check, 2 pairs, raw host fn | 14,953,893 | yes |
| `FqInv` | 95,441,120 | yes |
| `G1Projective::to_affine` | 96,481,144 | yes |
| `G1ScalarMul`, 254-bit scalar | 1,715,027,632 | no |
| `rescue_prime_hash_cached`, 2 inputs, warm | 3,769,292,006 | no |
| `rescue_prime_hash`, 2 inputs | 4,668,882,971 | no |
| `G2` subgroup check | 5,176,751,412 | no |
| `pairing_check` (library wrapper), 2 pairs | 13,805,580,873 | no |
| PLONK-KZG verify, 1 proof | 26,225,699,205 | no |
| Halo2 IPA verifier reduction, n = 2^10 | 38,120,963,668 | no |
| Shielded transfer (`transfer_shielded`, real proof) | 38,044,242,475 | no |
| PLONK-KZG batch verify, 5 proofs | 72,429,735,050 | no |
| `kzg_commit`, n = 2^10 | 218,267,778,548 | no |
| PLONK-KZG batch verify, 20 proofs | 232,150,455,680 | no |
| `kzg_commit`, n = 2^14 | traps (`MemoryOutOfBounds`) | no |

### RAM (host memory bytes charged)

Guest WASM arithmetic charges no host memory. Host-backed calls do:

| Primitive | Memory bytes |
|---|---:|
| Pairing check, 2 pairs | 101,220 |
| `poseidon2::hash_to_field`, 2 inputs | 82,808 |
| `poseidon2::hash_to_field_cached`, 2 inputs, warm | 90,928 |
| `NullifierStore::mark_spent` | 26,432 |
| Poseidon2 permutation | 13,048 |
| Shielded transfer, whole invocation | 1,514,867 |

## Host-only bench output (`instruction_cost`)

| Bench | CPU instructions |
|---|---:|
| `pairing_check`, 1 / 2 / 4 / 8 pairs | 10,050,230 / 14,833,973 / 24,401,471 / 43,536,514 |
| `plonk_kzg_verify_single`, `_batch_5`, `_batch_20` | 14,833,973 each (one aggregated pairing) |
| `poseidon2_hash2`: uncached / cached cold / cached warm | 1,740,033 / 1,772,524 / 1,467,344 |
| `rescue_prime_hash2`: uncached / cached warm | 4,225 / 63,762 |
| `halo2_perm_key_cache` 16x4: write / read | 21,098 / 18,968 |
| `nullifier`: mark_spent / is_spent / replay rejected | 58,088 / 41,346 / 41,346 |
| `vk_save` (1024 IC points) | 10,289,806 |

The gap between the two tables (Rescue-Prime 4,225 host-only against 4.67
billion WASM-metered) is the guest arithmetic the host-only bench cannot
see.

## WASM sizes

`cargo build --release --target wasm32v1-none -p <crate>`, built one package
at a time so features are not unified across the workspace:

| Contract | Bytes | Under 64 KB? |
|---|---:|:---:|
| `verifier-sample` (CI size gate) | 9,911 | yes |
| `shielded-asset-template` | 113,528 | no |
| `airdrop-claim` | 114,951 | no |

## What the numbers say

- Host functions are cheap. A raw 2-pair BN254 pairing is about 15M
  instructions and a Poseidon2 permutation about 0.7M.
- Software BN254 arithmetic in the guest is the bottleneck. `FqMul` uses the
  shift-and-add path at about 260K instructions, so one G1 addition costs
  about 4.2M and a 254-bit scalar multiplication about 1.7B.
- `pairing_check` validates every G2 point with a software subgroup check
  (about 5.2B each) before the host call. That validation, not the pairing,
  puts every verifier in this repo over the 400M limit.
- Rescue-Prime has no host function and costs about 4.7B per 2-input hash.
