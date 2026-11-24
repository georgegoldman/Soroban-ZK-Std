## Description
<!-- What does this PR change and why? Keep it focused: one issue per PR. -->

## Linked Issue
<!-- Required. Use a closing keyword, e.g. "Fixes #123". -->
Fixes #

## Mathematical/Cryptographic Impact
<!-- Soundness, constant-time, curve/field/subgroup assumptions. Write "None" if not applicable. -->

## Pre-flight Checklist
Run each command locally and check it off **after** it passes. PRs with unchecked items are not reviewed.
Rust 1.100.0 is pinned by `rust-toolchain.toml`; do not override it.

- [ ] PR title follows `type(scope): summary` (e.g. `fix(core): reject zero scalar`)
- [ ] Ran `make ci-rust` (security scan, fmt, clippy `-D warnings`, `cargo test --release`, WASM ≤ 64 KB)
- [ ] Ran `make guard` (title / issue link / file rules)
- [ ] `verifier-sample` WASM growth ≤ 5 KB (or justification given below)
- [ ] If I touched `unsafe`, `zeroize`, padding or field math: ran `cargo +nightly miri test -p soroban-zk-core --lib`

## PR Checklist
- [ ] My code strictly adheres to `no_std` (no `std::` in library code).
- [ ] I added tests that prove my fix works or that my feature works.
- [ ] I did not introduce `.unwrap()`, `.expect()` or `panic!()` in library code (using `Result<T, ZkError>`).
- [ ] Heavy elliptic-curve tests are marked `#[cfg_attr(miri, ignore)]`.
- [ ] No binaries, generated files, secrets, or new files in the repository root.
- [ ] No unrelated changes (formatting, dependency bumps, other issues).
