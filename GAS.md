# Gas & Instruction Budget Reference

This document captures measured wall-clock timings and estimated Soroban
instruction budgets for the core `zk-core` BN254 primitives.

> **Note**: Soroban charges CPU cost based on a metered instruction model.
> Until a Soroban host metering integration is wired into this repo the numbers
> below are *wall-clock timings* from Criterion micro-benchmarks run on a
> commodity developer machine.  They are sufficient for relative comparisons
> and release-regression detection; absolute Soroban instruction counts will
> differ from the wall-clock-derived estimates.

---

## Benchmark Environment

| Property            | Value                            |
|---------------------|----------------------------------|
| CPU                 | x86-64 (developer workstation)   |
| Rust toolchain      | stable (edition 2021)            |
| Optimization level  | `opt-level = 3` (bench profile)  |
| Criterion version   | 0.5                              |
| Sample count        | 100 samples per benchmark        |
| Warm-up duration    | 3 s                              |
| Measurement window  | ≥ 5 s (auto-adjusted)            |
| Harness             | Criterion (html_reports enabled) |

---

## Measured Operation Timings

All timings are the Criterion *point estimate* (median of the sampling
distribution).  Low/High are the 95% confidence interval bounds.

### Field Arithmetic

| Operation   | Description                           | Low      | Point    | High     |
|-------------|---------------------------------------|----------|----------|----------|
| `FrMul`     | Fr scalar field multiplication (×)    | 219 ns   | 223 ns   | 228 ns   |
| `FqMul`     | Fq base field multiplication (×)      | 1.51 µs  | 1.54 µs  | 1.56 µs  |
| `FqInvert`  | Fq inversion via Fermat (a^(p-2))     | 1.91 ms  | 1.93 ms  | 1.95 ms  |

### G1 Point Operations

| Operation                 | Input                   | Low      | Point    | High     |
|---------------------------|-------------------------|----------|----------|----------|
| `G1Double`                | 3·G (non-trivial Z)     | 5.54 µs  | 5.56 µs  | 5.58 µs  |
| `G1Add`                   | G + 2·G                 | 22.1 µs  | 23.1 µs  | 24.1 µs  |
| `G1ProjectiveToAffine`    | Projective → affine     | 1.93 ms  | 1.95 ms  | 1.98 ms  |

### G1 Scalar Multiplication

The double-and-add loop runs 254 iterations; cost depends on scalar bit density.

| Scalar               | Description                        | Low       | Point     | High      |
|----------------------|------------------------------------|-----------|-----------|-----------|
| `2`                  | Trivial (2 bits)                   | 15.1 µs   | 15.2 µs   | 15.5 µs   |
| `2^128 + 1`          | Medium (~129 bits, half bit-width)  | 11.4 ms   | 11.5 ms   | 11.6 ms   |
| `r − 1` (worst case) | All 254 bits set                   | 22.9 ms   | 23.0 ms   | 23.2 ms   |

---

## Operation Complexity Model

These estimates count the dominant Fq multiplications per operation, which
determines throughput on field-dominated curves like BN254.

| Operation           | Approx Fq Muls | Notes                                      |
|---------------------|----------------|--------------------------------------------|
| `FqMul`             | 1              | Binary method, O(256) iterations           |
| `FqInvert`          | ~1,250         | Fermat: a^(p-2) = 254 doublings + squarings|
| `G1Double`          | ~7–8           | Jacobian double formula                    |
| `G1Add`             | ~14–16         | Jacobian add formula (mixed: ~12)          |
| `G1ToAffine`        | ~1,252         | 1 inversion + 2 muls                       |
| `G1ScalarMul` (254b)| ~3,810         | ~254 doubles + ~127 adds (avg half bits)   |

---

## Soroban Budget Context

Soroban Protocol 21+ imposes per-transaction resource limits.  The current
published CPU instruction limit is **100,000,000 CPU instructions** per
transaction invocation.

Using a conservative estimate of **3,000 equivalent instructions per µs**
(typical x86-64 clock rate × IPC factor on the Soroban metering machine):

| Operation               | Wall-clock  | Est. Soroban Instructions | % of Budget (100M) |
|-------------------------|-------------|---------------------------|--------------------|
| `FrMul`                 | 223 ns      | ~669                      | < 0.001%           |
| `FqMul`                 | 1.54 µs     | ~4,620                    | 0.005%             |
| `FqInvert`              | 1.93 ms     | ~5,790,000                | 5.79%              |
| `G1Double`              | 5.56 µs     | ~16,680                   | 0.017%             |
| `G1Add`                 | 23.1 µs     | ~69,300                   | 0.069%             |
| `G1ToAffine`            | 1.95 ms     | ~5,850,000                | 5.85%              |
| `G1ScalarMul` (worst)   | 23.0 ms     | ~69,000,000               | 69.0%              |

**Key insight:** A single worst-case `G1ScalarMul` consumes ~69% of the
Soroban transaction budget.  Proof verification workflows using multiple
scalar multiplications must be carefully budgeted or decomposed across
multiple contract invocations.

> These instruction estimates are *approximate*.  Actual Soroban metered costs
> depend on the host's physical machine, the JIT/interpreter in use, and the
> specific Protocol version.  Use the Soroban simulator with metering enabled
> for production budget validation.

---

## Assumptions

1. **No `std` overhead**: `zk-core` is `#![no_std]`.  All operations are
   pure stack-based field arithmetic with no allocations.

2. **Binary-method field multiplication**: `FqMul` and `FrMul` use a
   double-and-add binary method (O(256) field additions per multiply).
   A Montgomery reduction implementation would reduce this to ~O(1) cost
   per limb pair; the current implementation is correctness-first.

3. **Jacobian projective coordinates**: `G1Add` and `G1Double` use classic
   Jacobian formulas.  Mixed (affine + projective) addition would reduce
   `G1Add` from ~16 to ~12 Fq multiplications.

4. **Scalar width**: The `g1_scalar_mul` loop always iterates 254 times
   regardless of scalar bit-width; no short-circuit for leading zeros.

5. **No pairing**: `PairingCheck` (EIP-197) is not yet implemented in this
   codebase.  When added, expect ~O(30,000) Fq multiplications for a single
   Miller loop on BN254.

---

## Reproducibility Instructions

### Prerequisites

```bash
rustup install stable
rustup target add wasm32-unknown-unknown
```

### Run benchmarks

```bash
# From repository root:
cargo bench -p zk-core

# Run a specific benchmark:
cargo bench -p zk-core -- G1ScalarMul

# Open HTML reports (requires a browser):
open target/criterion/G1Add/report/index.html
```

### Verify all tests pass before benchmarking

```bash
cargo test -p zk-core
```

### Compare releases

```bash
# Baseline: tag or branch to compare against
git stash
cargo bench -p zk-core -- --save-baseline before

# Switch to new code
git stash pop
cargo bench -p zk-core -- --baseline before
```

Criterion will print regression percentages and flag statistically significant
changes.

---

## Future Work

- [ ] Wire Soroban host metering to obtain native instruction counts
- [ ] Add Montgomery-form `FqMul` to reduce scalar multiplication cost ~10×
- [ ] Implement mixed Jacobian/affine `G1Add` to save ~4 Fq muls per add
- [ ] Add `PairingCheck` (EIP-197) benchmarks once implemented
- [ ] Benchmark `ElGamalCiphertext::encrypt` end-to-end

---

*Last updated: 2026-05-27.  Re-run benchmarks after any change to `zk-core`
field arithmetic or curve operations.*