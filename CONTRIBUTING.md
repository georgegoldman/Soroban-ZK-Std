# Contributing to Soroban-ZK-Std

Thank you for helping build zero-knowledge tooling for Stellar! Soroban has strict
limits (64 KB contracts, tight CPU/memory budgets), so our bar is higher than a
typical Rust project. This guide tells you exactly what to do so your PR is
reviewed quickly.

💬 **Community / questions:** <https://t.me/SorobanZKStd> — see [SUPPORT.md](docs/SUPPORT.mdx) for GitHub Discussions and issues.
🤝 **Community standards:** [CODE_OF_CONDUCT.md](docs/CODE_OF_CONDUCT.mdx).
🔒 **Found a vulnerability?** Do **not** open a public issue. See [SECURITY.md](SECURITY.md).
⚖️ **License:** [Apache-2.0](docs/LICENSE.txt).

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
- **SPDX headers.** New Rust source files must start with
  `// SPDX-License-Identifier: Apache-2.0`. The project is licensed under
  [Apache-2.0](docs/LICENSE.txt); each crate ships a `LICENSE` symlink to
  `docs/LICENSE.txt` so `cargo package --list` includes it.

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

## 8. Coverage-guided fuzzing (`cargo-fuzz`)

`cargo test` uses bounded `proptest` suites. The `fuzz/` crate adds
coverage-guided libFuzzer targets for the byte-parsing surface that untrusted
proofs and verifying keys reach first:

| Target | Surface |
| :--- | :--- |
| `groth16_proof_bytes` | `Groth16Proof::from_bytes` (256-byte `A \|\| B \|\| C`) |
| `groth16_vk_bytes` | `vk_from_bytes` (chunked serialized verifying key) |
| `plonk_proof_bytes` | Fixed PLONK proof layout (9 G1 + 8 Fr) |
| `bulletproof_bytes` | Fixed Bulletproof layout (17 G1 + 5 Fr) |
| `xdr_decode` | XDR-style G1/G2/Fr record walker |

Each target asserts the decoder never panics and returns a clean
`Err(ZkError::DeserializationError)` on malformed input. Seed corpora built from
the repository's test vectors live in `fuzz/corpus/<target>/`.

### Running a target

The fuzz crate is excluded from the root workspace so normal CI never builds
libFuzzer. Use a nightly toolchain:

```bash
rustup toolchain install nightly
cargo install cargo-fuzz --locked
cd fuzz
cargo fuzz run groth16_proof_bytes corpus/groth16_proof_bytes
```

Run for a bounded time (a 60-second smoke run per target):

```bash
cargo fuzz run groth16_proof_bytes corpus/groth16_proof_bytes -- -max_total_time=60
```

A scheduled CI smoke run needs a workflow under `.github/workflows/`, which is
maintainer-only under the contributor guard. Ask a maintainer to add one; until
then, run the bounded command locally before opening the PR.

### Crash triage

1. **Preserve the artifact.** A crashing input is written to
   `fuzz/artifacts/<target>/crash-<sha1>`. Keep it before rerunning.
2. **Reproduce.** From `fuzz/`, run the target with the artifact:
   ```bash
   cargo fuzz run <target> artifacts/<target>/crash-<sha1>
   ```
   Set `RUST_BACKTRACE=1` to get a backtrace.
3. **Minimize.** Shrink the input with `cargo fuzz tmin`:
   ```bash
   cargo fuzz tmin <target> artifacts/<target>/crash-<sha1>
   ```
4. **Decide whether it is a real bug.** A panic, abort, host trap, unbounded
   allocation, or a `Ok` result for malformed input is a bug. Fix the parser or
   verifier rather than catching the panic.
5. **Add a regression test.** Convert the minimized input into an ordinary unit
   or integration test asserting the clean `Err`/rejection. Fuzzing is how the
   case was found; the regression test is what keeps it fixed.
6. **Add the artifact to the seed corpus.** Copy the minimized artifact into
   `fuzz/corpus/<target>/` (give it a descriptive name) so the next run starts
   from the bug's neighborhood. Do not delete the artifact and do not add it to
   `.gitignore`.
7. **Open a normal PR.** Use the `type(scope): summary` title, link the issue or
   advisory, and mention which target found the crash. If the bug is a security
   vulnerability, follow [SECURITY.md](SECURITY.md) and coordinate privately
   before publishing the minimized input.

> **Do not ignore a fuzz crash** by adding `-ignore_crashes`, raising limits, or
> deleting the artifact. A crash in parsing is a potential denial of service or
> soundness bug.

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
✅ docs/LICENSE.txt (canonical license text, not rendered as a page)

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
- [ ] Fuzz corpus/crash artifacts added with a regression test when a parser changed
- [ ] New Rust files carry `// SPDX-License-Identifier: Apache-2.0`
- [ ] WASM size within budget
- [ ] Docs use `.mdx` (outside `specs/`) with frontmatter; internal links use `.mdx` paths
- [ ] No unrelated changes, binaries or new root-level files
