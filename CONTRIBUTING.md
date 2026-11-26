# Contributing to Soroban-ZK-Std

Thank you for helping build zero-knowledge tooling for Stellar! Soroban has strict
limits (64 KB contracts, tight CPU/memory budgets), so our bar is higher than a
typical Rust project. This guide tells you exactly what to do so your PR is
reviewed quickly.

💬 **Community / questions:** <https://t.me/SorobanZKStd>
🔒 **Found a vulnerability?** Do **not** open a public issue. See [SECURITY.md](SECURITY.md).

---

## TL;DR

```bash
git clone https://github.com/<you>/Soroban-ZK-Std.git && cd Soroban-ZK-Std
make hooks        # once: installs a pre-push rustfmt check
make ci-rust      # must pass before you open a PR (same checks as CI)
make guard        # checks your title/files/diff/formatting against our PR rules
```

1. Comment on an issue to get it assigned. One issue per PR.
2. Branch from an up-to-date `main`.
3. Make `make ci-rust` pass.
4. Open the PR with a title like `fix(core): short summary` and `Fixes #123` in the description.

---

## 1. Setup

| Tool | Version | Notes |
| :--- | :--- | :--- |
| Rust | **1.100.0 (pinned)** | `rust-toolchain.toml` makes `rustup` install the exact compiler CI uses, with `clippy`, `rustfmt` and the `wasm32v1-none` target. Do not override it. |
| Nightly + Miri | optional | `rustup +nightly component add miri rust-src` to run `cargo +nightly miri test -p soroban-zk-core --lib`. |
| Stellar CLI | optional | Only needed for deploying/inspecting contracts. |

> Different compiler versions produce different Clippy lints. "It passes on my machine"
> with another Rust version is the most common reason a PR fails CI.

## 2. The one command: `make ci-rust`

This is exactly what CI runs on every PR:

| Step | Command | What it protects |
| :--- | :--- | :--- |
| Security scan | `python3 scripts/check-malware.py` | Supply-chain / hidden payload detection |
| Format | `cargo fmt --all -- --check` | No style noise in diffs |
| Lint | `cargo clippy --all-targets --all-features -- -D warnings` | Zero warnings |
| Tests | `cargo test --release` | Correctness |
| WASM size | `make wasm-size-check` | `verifier-sample` must stay **≤ 64 KB** |

> Run `make hooks` once to install a local `pre-push` formatting check. If CI fails at
> **Format Gate** or **Code Quality & Tests**, run `cargo fmt --all` first—unformatted code
> skips Clippy and tests.

CI additionally runs **Miri** (memory safety, `soroban-zk-core`), **Kani** (formal proofs), the
**Halo2 primitives** tests and `cargo-deny` (dependency audit). If your change touches
`unsafe`, `zeroize`, padding or field math, run Miri locally.

The Rust coverage workflow measures `soroban-zk-core` with `cargo-llvm-cov` and
enforces a 40% line-coverage floor. Its LCOV and HTML reports are uploaded as
workflow artifacts, and the per-file report appears in the job summary. Run
`make coverage` locally after installing `cargo-llvm-cov`. Raise
`COVERAGE_MIN_LINES` in the Makefile and the matching workflow threshold when
coverage improves; do not lower the threshold to accommodate uncovered code.

Independent BN254/Poseidon2 known-answer vectors are generated with
`python3 scripts/reference/generate_vectors.py`; run `make reference-vectors`
to verify that the committed `tests/vectors/reference_vectors.json` has not
drifted. The Python generator uses only the standard library and the fixed
Poseidon2 parameters in `scripts/reference/poseidon2_parameters.json`.

## 3. Project rules

- **`#![no_std]`.** No `std::` in library code. Use `core::` / `alloc::` only when unavoidable.
- **No panics in library code.** Avoid `.unwrap()`, `.expect()` and `panic!()`; return
  `Result<T, ZkError>`. (Fine inside tests.)
- **Constant time.** Operations on secret data (add, mul, inversion, comparisons) must not branch on secrets.
- **WASM budget.** Your change must not push `verifier-sample` past 64 KB. A growth of more
  than 5 KB needs an optimisation justification in the PR.
- **`contract` feature.** `soroban_zk_std::ZkContract` is behind the default-on `contract`
  feature. Contracts that only use the library should depend on `soroban-zk-std` with
  `default-features = false`; enable `features = ["contract"]` if you need `ZkContract`.
- **Heavy tests and Miri.** Tests that do elliptic-curve scalar multiplication, proving or MSMs
  are ~10,000× slower under Miri. Mark them `#[cfg_attr(miri, ignore)]`.
- **Tests are required** for every fix/feature. Put unit tests next to the code in a `mod tests` block.
- **Keep PRs focused.** No drive-by reformatting, no unrelated dependency bumps, no unrelated files.
- **Where code goes.** Pure math → `crates/soroban-zk-core`. Soroban integration (host functions,
  storage, events) → `crates/soroban-zk-std`. Sample/production contracts → `contracts/`.
  Docs → `docs/` (`.mdx`) and `specs/` (`.md`). Do not add new files to the repository root.
- **Rebuilding the demo** (`hackathon-demo/`) is not accepted; it was removed on purpose.

## 4. Branches, commits and PR titles

- Branch names: `fix/123-short-description`, `feat/…`, `test/…`, `docs/…`.
- **PR title format** (enforced by CI): `type(scope): summary`
  - types: `feat fix test docs perf refactor chore ci build style revert`
  - example: `fix(bulletproofs): reject zero-length IPA input`
- **Link the issue** in the description: `Fixes #123` / `Closes #123`.
- Tick every box in the PR template **after actually running the command**. PRs with unchecked
  boxes are not reviewed.

## 5. What the Contributor Guard checks

The **Contributor Guard** workflow (`.github/workflows/contributor-guard.yml`) runs
`scripts/contributor-guard.py`. Run it locally with `make guard` (also runs `cargo fmt --all -- --check`).

| Check | Result |
| :--- | :--- |
| PR title follows `type(scope): summary` | ❌ blocks |
| Description links an issue (`Fixes #N`) | ❌ blocks |
| No unchecked `- [ ]` items | ❌ blocks |
| No binaries / archives / fonts / files over 500 KB | ❌ blocks |
| No new files in the repository root (maintainers exempt), no `hackathon-demo/` | ❌ blocks |
| Maintainer-only files untouched (`.github/workflows`, `scripts/`, `Makefile`, `deny.toml`, `rust-toolchain.toml`, `SECURITY.md`) | ❌ blocks (maintainers exempt) |
| `Cargo.lock` changed without `Cargo.toml` | ❌ blocks |
| New `unwrap`/`expect`/`panic!`/`std::` in library code | ⚠️ warning |
| New heavy test missing `#[cfg_attr(miri, ignore)]` | ⚠️ warning |

## 6. Security gate

We have been targeted by malicious pull requests ("PolinRider"-style droppers). Therefore:

- A PR that adds JS/config files such as `init`, `api.js`, `postcss.config*`, `.vscode/tasks.json`,
  font files, install-time scripts in `package.json`, or code hidden behind long runs of
  whitespace / obfuscated identifiers (`_0x…`) is **closed immediately** and may be reported.
- The `Security & Malware Scan` check must pass.
- **Never run scripts, `npm install`, or `git checkout` of untrusted branches** on your machine
  before reading the diff on GitHub. If your own machine or token may be compromised, rotate your credentials.

## 7. Review and merge

- Maintainers review in the order the CI is green; failing CI = not reviewed.
- Address review comments with new commits; do not force-push over reviewed history without saying so.
- Maintainers merge only when **all** checks are green.

---

## Documentation Policy

### General Documentation

All documentation files in `docs/` (and subdirectories, **except** `specs/`) **must** use the `.mdx` extension.

- Supports embedded React components
- Required for the documentation viewer / Next.js frontend
- Must include YAML frontmatter with at minimum `title` and `description` fields

**Examples:**

```
✅ docs/tutorials/getting-started.mdx
✅ docs/guides/installation.mdx
✅ docs/math/rescue.mdx

❌ docs/tutorials/getting-started.md
❌ docs/guides/setup.md
```

### Algorithm Specifications

Files in `specs/` **may** remain `.md`.

- Intended for mathematical proofs and formal algorithm specifications
- Plain Markdown keeps the content portable and diff-friendly (preserves math/algo purity)
- React components are not required here

**Examples:**

```
✅ specs/pairing-proof.md
✅ specs/poseidon2-spec.md
```

### Frontmatter Requirements

Every `.mdx` file in `docs/` must open with a YAML frontmatter block:

```yaml
---
title: "Human-readable page title"
description: "One-sentence summary shown in search results and link previews"
protocol: "25"
cap: "CAP-0075"
---
```

The `protocol` and `cap` fields are strongly recommended for all ZK-related docs.

### Validation

Before opening a PR that touches docs, run:

```bash
bash scripts/check-doc-extensions.sh
```

This script traverses `docs/`, skips `specs/`, and exits non-zero if any forbidden `.md` file is found. CI runs the same check on every pull request.

---

## Pull Request Checklist (summary)

- [ ] `make ci-rust` passes
- [ ] `make guard` passes
- [ ] Title is `type(scope): summary` and the description has `Fixes #N`
- [ ] Tests added; no `.unwrap()`/`panic!()` in library code; heavy tests gated for Miri
- [ ] WASM size within budget
- [ ] Docs use `.mdx` (outside `specs/`) with frontmatter; internal links use `.mdx` paths
- [ ] No unrelated changes, binaries or new root-level files
