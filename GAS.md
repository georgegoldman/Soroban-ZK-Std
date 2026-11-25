# Gas & Instruction Budget Reference

Use this page to check whether a proof workflow fits in one Soroban
transaction before writing contract code. All figures were measured on
**2026-11-25** at commit **`578490f`** by running the library inside a
compiled `wasm32v1-none` contract on the metered Soroban host
(`soroban-sdk` 27.0.6, `soroban-env-host` 27.0.1, ledger protocol 27). The
method is in [BENCHMARK.md](./BENCHMARK.md).

> **Limit:** 400,000,000 CPU instructions per transaction.
> `simulateTransaction` on a live network adds a 20% CPU margin, so treat
> anything above about 330M here as not fitting.

## Quick reference

| Operation | CPU instructions | % of 400M | RAM bytes | WASM |
|---|---:|---:|---:|---|
| `FqAdd` | 1,632 | < 0.01% | 0 | guest |
| `FqMul` | 260,159 | 0.07% | 0 | guest |
| `FqInv` | 95,441,120 | 23.9% | 0 | guest |
| `Fq2Add` | 3,508 | < 0.01% | 0 | guest |
| `Fq2Mul` | 787,732 | 0.20% | 0 | guest |
| `Fq2Sqr` | 783,507 | 0.20% | 0 | guest |
| `G1Add` | 4,179,102 | 1.04% | 0 | guest |
| `G1Double` | 2,608,919 | 0.65% | 0 | guest |
| `G1` to affine | 96,481,144 | 24.1% | 0 | guest |
| `G1ScalarMul`, 254-bit | 1,715,027,632 | 429% | 0 | guest |
| `G2` subgroup check | 5,176,751,412 | 1,294% | 0 | guest |
| Poseidon2 permutation | 715,030 | 0.18% | 13,048 | host fn |
| `hash_to_field`, 2 inputs | 4,652,644 | 1.16% | 82,808 | host fn |
| `hash_to_field_cached`, 2 inputs, warm | 3,182,286 | 0.80% | 90,928 | host fn |
| Transcript squeeze | 719,258 | 0.18% | 13,200 | host fn |
| `rescue_prime_hash`, 2 inputs | 4,668,882,971 | 1,167% | 560 | guest |
| `rescue_prime_hash_cached`, 2 inputs, warm | 3,769,292,006 | 942% | 9,356 | guest |
| `NullifierStore::mark_spent` | 1,819,060 | 0.45% | 26,432 | storage |
| `NullifierStore::is_spent` | 1,711,372 | 0.43% | 119 | storage |
| Pairing, 2 pairs, raw host fn | 14,953,893 | 3.74% | 101,220 | host fn |
| `pairing_check` wrapper, 2 pairs | 13,805,580,873 | 3,451% | 101,220 | guest + host |

## Full verifiers

| Verifier | CPU instructions | % of 400M | Fee (stroops) |
|---|---:|---:|---:|
| PLONK-KZG, 1 proof | 26,225,699,205 | 6,556% | 18,330,744 |
| PLONK-KZG batch, 5 proofs | 72,429,735,050 | 18,107% | not measured |
| PLONK-KZG batch, 20 proofs | 232,150,455,680 | 58,038% | not measured |
| Halo2 IPA reduction, n = 2^10 | 38,120,963,668 | 9,530% | not measured |
| Shielded transfer (real snarkjs proof) | 38,044,242,475 | 9,511% | 28,831,863 |

Fees come from `env.cost_estimate().fee()` with the test environment's
default fee settings and resource limits turned off. No verifier above fits
in a transaction today, so the fees describe a transaction the network would
reject.

## Commitments

| Operation | CPU instructions |
|---|---:|
| `kzg_commit`, n = 2^10 | 218,267,778,548 |
| `kzg_commit`, n = 2^14 | traps with `MemoryOutOfBounds` |

## Planning rules

- **Stay on host functions.** The raw CAP-0075 pairing (about 15M for 2
  pairs, plus about 4.8M per extra pair) and Poseidon2 are the only primitives
  cheap enough to compose.
- **Avoid software subgroup checks on-chain.** `pairing_check` runs them on
  every G2 input. Trusted constants (a stored verifying key) can go straight
  to `host::pairing_check_host`.
- **Avoid guest scalar multiplication.** One 254-bit `G1ScalarMul` is over
  four times the limit. Use the `bn254_g1_mul` / `bn254_g1_add` host
  functions for public-input accumulation.
- **Prefer Poseidon2 over Rescue-Prime on-chain.** Rescue-Prime has no host
  function.
- **Use cached Poseidon2 constants** for repeated hashing: about 32% cheaper
  per warm 2-input hash.

## Reproducing

```bash
# Host-only regression benches (pure-Rust work reports 0):
cargo test -p soroban-zk-std --bench instruction_cost -- --nocapture

# Wall-clock criterion benches:
cargo bench -p soroban-zk-core --bench montgomery_ops
```

For WASM-metered numbers, compile the call into a `wasm32v1-none` contract,
register it with `env.register(wasm_bytes, ())`, call
`env.cost_estimate().budget().reset_unlimited()` before each invocation,
and read `cpu_instruction_cost()` and `memory_bytes_cost()` afterward.

## Future work

- Montgomery multiplication for `Fq` (today only `Fr` uses it), which every
  curve operation inherits.
- Endomorphism-based G2 subgroup check, or skipping it for trusted points.
- Pippenger/Strauss MSM backed by host functions instead of guest
  arithmetic.
- `kzg_commit` that does not take its polynomial by value, so n = 2^14 fits
  in contract memory.
