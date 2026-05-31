# WASM Footprint Audit

This document records the findings, techniques applied, and binary size results
from the WASM bloat audit conducted for issue #4.

---

## Baseline vs. Post-Audit Sizes

Measurements taken with `cargo build --target wasm32-unknown-unknown --release`.

| Contract                   | Baseline  | Post-Audit | Delta  |
|----------------------------|-----------|------------|--------|
| `shielded-asset-template`  | 2,153 B   | 2,153 B    | 0 B    |
| `verifier-sample`          | 2,093 B   | 2,093 B    | 0 B    |

**Both artifacts are well under the 12 KB core math module target.**

The sizes remain identical because the baseline profile was already fully
optimized (LTO, `opt-level = "z"`, dead-code-elimination).  The structural
dead code removed from `zk-core` was already eliminated by the linker before
this audit; removing it at the source level cleans the API surface without
altering binary output.

---

## Dependency Audit

### `zk-core` dependency tree

```
zk-core v0.1.0
└── ethnum v1.5.3  (default-features = false)
```

**Finding**: Zero transitive dependencies beyond `ethnum`.  No `std` is
pulled in.  `ethnum` is already gated with `default-features = false`,
disabling the optional `serde` and LLVM intrinsics features.

### `zk-soroban` dependency tree

```
zk-soroban v0.1.0
├── soroban-sdk v25.3.0   (features = ["hazmat-crypto"])
├── ethnum v1.5.3
└── zk-core v0.1.0
```

`soroban-sdk` is the dominant dependency.  It is a required Soroban host
interface library and cannot be trimmed without changing the contract model.

---

## Release Profile (already optimal)

Confirmed in `Cargo.toml` workspace profile:

```toml
[profile.release]
opt-level = "z"          # Optimize for binary size
overflow-checks = true   # Keep arithmetic safety
debug = 0                # No debug symbols in binary
strip = "symbols"        # Strip symbol table
debug-assertions = false # No assertion code in release
panic = "abort"          # Eliminates unwinding infrastructure (~5-15 KB saved)
codegen-units = 1        # Single CGU enables full LTO
lto = true               # Link-time dead-code elimination
```

All standard WASM size optimization flags are active.

---

## Dead Code Removed

### `G1Jacobian` struct (removed)

The library defined `G1Jacobian` but never implemented any arithmetic on it.
All projective arithmetic uses `G1Projective` (same coordinate system).
`G1Jacobian` was unreachable code with no constructors, no impl blocks, and
no usages in the codebase.

**Action**: Removed the struct entirely.

### `SCALAR_ORDER` constant (removed)

`SCALAR_ORDER` was bit-for-bit identical to `FR_MODULUS` and `BASE_MODULUS`.
Three constants with the same value introduce maintenance risk (future
divergence). The canonical name `FR_MODULUS` is used throughout the code.

**Action**: Removed `SCALAR_ORDER`; callers should use `FR_MODULUS`.

### `G1_B` usage in `is_valid_g1` (fixed)

The `is_valid_g1` function hard-coded the constant `3u8` despite the library
defining `G1_B = 3` for exactly this purpose.  Inconsistency between the
named constant and the literal could cause silent mismatch if the constant
were ever updated.

**Action**: `is_valid_g1` now uses `Self::G1_B` instead of the literal.

---

## Techniques Evaluated

| Technique                  | Status    | Notes                                              |
|----------------------------|-----------|----------------------------------------------------|
| `panic = "abort"`          | ✅ Applied | Workspace profile; eliminates unwinding tables      |
| `opt-level = "z"`          | ✅ Applied | Workspace profile; size over speed                  |
| `lto = true`               | ✅ Applied | Workspace profile; cross-crate dead code removal    |
| `strip = "symbols"`        | ✅ Applied | Workspace profile; removes symbol table             |
| `codegen-units = 1`        | ✅ Applied | Workspace profile; maximizes LTO effectiveness      |
| `no_std`                   | ✅ Applied | `zk-core` and `zk-soroban` are `#![no_std]`        |
| `ethnum` default-features  | ✅ Applied | `serde` and intrinsics features disabled            |
| Struct dead code           | ✅ Removed | `G1Jacobian` struct removed                        |
| Duplicate constants        | ✅ Removed | `SCALAR_ORDER` alias removed                       |
| Format/Debug in release    | N/A       | `Debug` derives exist but are LTO-eliminated        |
| `wasm-opt` post-processing | Not yet   | Binaryen `wasm-opt -Oz` could shave further bytes   |
| Custom allocator           | N/A       | No heap allocations in `zk-core`                   |
| `serde` dependencies       | N/A       | Not pulled in                                       |

---

## Security / Correctness Considerations

- No `unsafe` code introduced.
- Removed code was provably unreachable (no usages, no external references).
- All existing tests pass after changes.
- `overflow-checks = true` preserved; arithmetic safety is not compromised.
- `G1_B` refactor is a pure rename — compiled output is identical.

---

## How to Reproduce

```bash
# Install target
rustup target add wasm32-unknown-unknown

# Build and measure (from repo root)
make wasm-size

# Or manually:
cargo build --target wasm32-unknown-unknown --release
find target/wasm32-unknown-unknown/release -maxdepth 1 -name '*.wasm' \
  -exec wc -c {} \;
```

---

## Future Opportunities

- **`wasm-opt`**: Run Binaryen's `wasm-opt -Oz` as a post-build step; can
  typically reduce WASM by 10–20% on top of LLVM's output.
- **Montgomery arithmetic**: Replacing the binary-method `FqMul` with a
  Montgomery reduction would reduce instruction count ~10×, keeping size
  roughly the same.
- **Mixed Jacobian/affine `G1Add`**: Reduces Fq multiplications from ~16 to
  ~12 per addition; marginal size impact but significant throughput gain.
- **CI size gate**: Add a GitHub Actions step that fails if any WASM artifact
  exceeds a configured threshold (e.g., 50 KB).

---

*Last updated: 2026-05-27.*