## Description

## Linked Issue
Fixes #

## Mathematical/Cryptographic Impact

## Pre-flight Checklist
Run each command locally and check it off before opening this PR. PRs with unchecked items will not be reviewed.

- [ ] Ran `cargo fmt --all -- --check` (no formatting differences)
- [ ] Ran `cargo clippy --all-targets --all-features -- -D warnings` (0 warnings)
- [ ] Ran `cargo test --release` (all tests pass)
- [ ] Ran `make build-wasm` (contracts compile for `wasm32v1-none`)
- [ ] Checked WASM binary size with `make wasm-size` (increase ≤ 5KB, or optimization justification provided below)

## PR Checklist
- [ ] My code strictly adheres to `no_std` (no standard library imports).
- [ ] I have added tests that prove my fix is effective or that my feature works.
- [ ] I have not introduced any `.unwrap()` or `panic!()` calls (using `Result<T, ZkError>` instead).
- [ ] My changes do not push the core WASM binary over the 64KB limit.
