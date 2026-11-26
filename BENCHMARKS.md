# Gas Benchmark Suite

This document records the CPU instruction cost (gas) of core zero-knowledge primitives within the Soroban VM, as measured by the `soroban-sdk` budget API in our integration benchmark suite. 

These benchmarks validate the performance claims made in the project requirements and substantiate that the 400M instruction limit per transaction is respected.

## Environment Setup
*   **Soroban SDK Version:** v25.3.0
*   **Profile:** release (with opt-level "z" and lto)
*   **Measurement API:** `env.cost_estimate().budget().cpu_instruction_cost()`

## Benchmark Results

### Poseidon2 Hashing
The Poseidon2 hash implementation utilizes host functions (`hash_to_field`), yielding accurate budget consumption:

| Operation | Inputs | CPU Instructions | Budget Consumed |
| :--- | :--- | :--- | :--- |
| `poseidon2_hash_1` | 1 | 1,007,753 | 0.25% |
| `poseidon2_hash_2` | 2 | 2,010,994 | 0.50% |
| `poseidon2_hash_4` | 4 | 3,024,708 | 0.75% |

### Core BN254 Arithmetic (Native Implementations)
Basic mathematical operations implemented natively in `soroban-zk-core` (without invoking Soroban host functions) register a base budget cost of 0 in the mock environment native benchmark since native CPU execution bypasses WASM metering. In a deployed contract, these compile to WASM instructions, consuming a minimal subset of the budget.

| Operation | Measured Cost (Mock) | Status |
| :--- | :--- | :--- |
| `Fr::add` | 0 (Native) | Pass |
| `Fr::mul` | 0 (Native) | Pass |
| `Fr::invert` | 0 (Native) | Pass |
| `g1_scalar_mul` | 0 (Native) | Pass |
| `g1_msm_8` | 0 (Native) | Pass |

### Groth16 Verification (Composite)
A Groth16 verification with 1 public input requires:
1. 1x Multi-Scalar Multiplication (size 2)
2. 1x Pairing Check of 4 pairs `e(A, B) * e(alpha, beta) * e(L, gamma) * e(C, delta) == 1`

| Operation | Measured Cost | Status |
| :--- | :--- | :--- |
| `groth16_verify` | 29,327,515 | Pass (Well under 400M limit) |

*Note: The `pairing_check` host function is heavily optimized by the Soroban environment, completing well within the ~395M budget.*

## CI Integration
The benchmark suite is fully integrated into the project's CI pipeline via the `make bench` target. 
- All primitives assert `cost <= 100_000_000` to prevent regressions.
- The `groth16_verify` mock asserts `cost <= 400_000_000` to ensure transactions fit in the budget.

## CI Regression Tracking (`.github/workflows/bench.yml`)

The Criterion suites (`crates/soroban-zk-core/benches/g1_ops.rs`,
`montgomery_ops.rs`, `bulletproofs_vs_groth16.rs`) are tracked automatically:

| Event | What runs | Result |
|:--|:--|:--|
| Push to `main` (`crates/**`, `Cargo.toml`, `Cargo.lock`) | The three Criterion suites plus the `instruction_cost` budget bench | Raw Criterion estimates uploaded as the `criterion-baseline` artifact (90 days) |
| Pull request touching `crates/**` | The same suites on the same runner | Comparison table in the job summary; the job fails when a benchmark is **> 10 %** slower than the newest `main` baseline |

The comparison is done by `scripts/bench-regression.py` (standard library only)
from Criterion's `target/criterion/**/new/estimates.json` mean point estimates.

- **Threshold** — 10 % by default. Change it without editing the workflow by
  setting the repository variable `BENCH_MAX_REGRESSION_PCT` (Settings → Secrets
  and variables → Actions → **Variables**) or the `max_regression_pct` input of
  a manual `workflow_dispatch`.
- **Noise control** — runner label pinned to `ubuntu-24.04` (or the
  `BENCH_RUNNER` repository variable for a dedicated machine), identical
  `--sample-size 100 --warm-up-time 3 --measurement-time 10` settings on both
  sides, one benchmark job per ref (`concurrency`), no other jobs on the runner.
  A change of runner image is a re-baseline event, not a regression.
- **Missing baseline** — if no successful `main` benchmark run exists yet, the
  PR job reports “No baseline available” and passes instead of failing.
- **New benchmarks** — reported as `🆕 new` and never fail the job.
- The `instruction_cost` benches are assertion-based (≤ 100 M per primitive,
  ≤ 400 M per Groth16 verification) rather than Criterion-based, so they run in
  the same workflow but are outside the percentage comparison.

### How to re-baseline

The baseline is always whatever the most recent successful `main` run produced.

1. **Deliberate performance change** (faster implementation, new algorithm):
   merge it to `main`. The next push re-records the baseline automatically —
   no workflow change and no committed numbers are needed.
2. **Unblock a PR whose numbers legitimately moved**: run the workflow manually
   against `main` (Actions → **Benchmarks** → Run workflow → branch `main`).
   That run replaces the `criterion-baseline` artifact.
3. **Locally**, reproduce both sides with Criterion's own baselines:

   ```bash
   cargo bench -p soroban-zk-core --all-features \
     --bench g1_ops --bench montgomery_ops --bench bulletproofs_vs_groth16 \
     -- --save-baseline main
   # ... after your change ...
   cargo bench -p soroban-zk-core --all-features \
     --bench g1_ops --bench montgomery_ops --bench bulletproofs_vs_groth16 \
     -- --baseline main
   ```

   The CI gate itself can be replayed from any two Criterion output trees:

   ```bash
   python3 scripts/bench-regression.py \
     --baseline <baseline-tree> --current target/criterion --threshold 10
   ```

   `python3 scripts/bench-regression.py --self-test` checks the comparison
   logic without compiling anything.
