# Upgrading from v1 to v2

> **A migration guide template for developers transitioning Soroban-ZK-Std from version 1.x to 2.x.**

## Overview

This guide describes the high-level changes, compatibility expectations, and migration steps for projects upgrading from `Soroban-ZK-Std` v1 to v2.

Use this document to identify breaking changes, update dependency versions, and confirm the correct contract and test updates required by the new major release.

---

## Scope

This migration guide covers:

- dependency version updates for `zk-soroban`, `zk-core`, and related crates
- API and module path changes
- contract initialization and runtime behavior changes
- recommended verification and regression testing before deployment

It does not replace the release notes for v2; instead, it provides a structured checklist and practical examples to make migration easier.

---

## What changed in v2

### Breaking changes

- `v2` introduces one or more breaking API changes. Document each relevant change here.
- If any public API was renamed, moved, or removed, list the old and new identifiers.
- If the dependency tree now requires a different Soroban SDK or protocol version, note that here.

### New behavior

- Describe new default behavior introduced in v2.
- Highlight changes to proof verification, pairing host interactions, or serialization semantics.

### Removed or deprecated features

- List any v1 features that were removed in v2.
- If a v1 API is still available but deprecated, explain the replacement.

---

## Compatibility checklist

1. Confirm the target Soroban protocol and SDK versions required by `v2`.
2. Update `Cargo.toml` dependencies:
   - `zk-soroban = "^2.0.0"`
   - `zk-core = "^2.0.0"` (or the matching v2 compatible version)
3. Audit all import paths and API usage from v1.
4. Update any contract storage layout or initialization logic affected by v2.
5. Re-run existing unit tests and integration tests.
6. Deploy to a testnet or local Soroban network before production migration.

---

## API migration map

| v1 API | v2 API | Notes |
|--------|--------|-------|
| `zk_soroban::old_module::OldType` | `zk_soroban::new_module::NewType` | Example placeholder |
| `old_function_name(...)` | `new_function_name(...)` | If signature changed, document the new call shape |
| `OldVerifier` | `NewVerifier` | Note any changes in constructor or return type |

> Replace the placeholder rows above with the actual v1→v2 mappings for your library.

---

## Example migration steps

### 1. Update dependency versions

```toml
[dependencies]
soroban-sdk = "25.0.0"
zk-soroban = "^2.0.0"
zk-core = "^2.0.0"
```

### 2. Update imports

```rust
// v1
use zk_soroban::old_module::OldType;

// v2
use zk_soroban::new_module::NewType;
```

### 3. Update contract code

```rust
// v1
let result = old_function_name(arg1, arg2);

// v2
let result = new_function_name(arg1, arg2, config);
```

### 4. Verify serialization and proof paths

- Confirm that any proof or verification key serialization formats remain compatible.
- If the v2 release changed the expected byte order for G1/G2 points or public input layouts, update the helper functions accordingly.

---

## Testing and validation

- Run the existing test suite and ensure all v1 behavior still works after migration.
- Add regression tests for any changed edge cases.
- Validate proof verification on both local and testnet deployments.
- If the library exposes benchmark or gas estimation helpers, run them to compare v1 and v2 costs.

---

## Rollback strategy

If issues are discovered after deploying v2:

- Preserve the v1 dependency versions and pin the crate versions in `Cargo.toml`.
- Revert to the last known working commit for the contract code.
- Compare the failing v2 behavior against the preserved v1 test cases.

---

## Notes for maintainers

- Keep this migration guide updated with concrete example mappings as the v2 release evolves.
- Add links to the official v2 release notes and changelog once available.
- If a specific v2 submodule or feature requires a separate migration path, create a dedicated section for it.
