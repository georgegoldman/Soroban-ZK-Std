# Soroban Project

## Project Structure

This repository uses the recommended structure for a Soroban project:

```text
.
├── contracts
│   └── hello_world
│       ├── src
│       │   ├── lib.rs
│       │   └── test.rs
│       └── Cargo.toml
├── Cargo.toml
└── README.md
```

- New Soroban contracts can be put in `contracts`, each in their own directory. There is already a `hello_world` contract in there to get you started.
- If you initialized this project with any other example contracts via `--with-example`, those contracts will be in the `contracts` directory as well.
- Contracts should have their own `Cargo.toml` files that rely on the top-level `Cargo.toml` workspace for their dependencies.
- Frontend libraries can be added to the top-level directory as well. If you initialized this project with a frontend template via `--frontend-template` you will have those files already included.

## Testnet deploy & smoke test

`scripts/deploy_testnet.sh` deploys this contract to Stellar **testnet** and
checks it on the real network host. That catches problems the local
`soroban-sdk` test environment cannot, such as budget limits, XDR encoding and
protocol-version mismatches.

### What the script does

1. Generates a throwaway identity in a temporary `stellar` config directory
   and funds it with Friendbot. The key is deleted when the script exits, and
   no repository secrets are used.
2. Builds the contract with `stellar contract build --package verifier-sample`.
3. Deploys the WASM to testnet.
4. Calls `check(input: U256) -> bool` with the same vectors as `src/test.rs`,
   submitting each call as a real transaction (`--send=yes`):

   | Case | `input` | Expected |
   | --- | --- | --- |
   | known-good: small scalar | `42` | `true` |
   | known-good: zero scalar | `0` | `true` |
   | known-bad: BN254 modulus `r` | `21888…5617` | `false` |
   | known-bad: `U256::MAX` | `2^256 - 1` | `false` |

This contract has no verification key and no `verify_proof` entrypoint yet; it
only exposes `check`, so the smoke test exercises `check`. When a VK setter
and `verify_proof` land, add their cases to the `CASES` list in the script.

### Prerequisites

- Rust with the `wasm32v1-none` target (the pinned `rust-toolchain.toml`
  installs it automatically through `rustup`).
- [`stellar-cli`](https://github.com/stellar/stellar-cli) (tested with
  `30.0.1`) on `PATH`, or set `STELLAR_BIN=/path/to/stellar`.
- Network access to `https://friendbot.stellar.org` and the testnet RPC.

### Running it

```bash
# From the repository root
scripts/deploy_testnet.sh               # build, deploy, smoke-test
scripts/deploy_testnet.sh --dry-run     # print every command, send nothing
scripts/deploy_testnet.sh --wasm target/wasm32v1-none/release/verifier_sample.wasm
scripts/deploy_testnet.sh --help
```

In CI, run the **Testnet Smoke (verifier-sample)** workflow from the Actions
tab (`workflow_dispatch` only). It runs behind the same malware gate as the
main CI, uses a read-only token (`permissions: contents: read`), installs a
pinned, sha256-verified `stellar-cli` binary, shellchecks and dry-runs the
script, then runs it.

### Reading the output

Progress lines start with `==>` (stderr), along with the CLI's transaction
links on `stellar.expert`. Each check prints one line on stdout:

```text
PASS  known-good: 42 (small scalar)            got true
PASS  known-good: 0 (zero scalar)              got true
PASS  known-bad: r (BN254 modulus itself)      got false
PASS  known-bad: U256::MAX                     got false
----------------------------------------------------------------
network:  testnet
contract: CBQA…QG3S
result:   PASS (4/4 checks passed)
```

- `PASS`: the contract returned the expected value.
- `FAIL … expected X, got Y`: the contract returned the wrong value.
- `FAIL … invoke errored`: the call itself failed on the host (for example a
  budget or XDR error); the CLI error is printed just above it.

Exit codes: `0` all checks passed, `1` at least one check failed, `2` usage
or missing prerequisite. A failing CLI step (Friendbot, build, or deploy)
stops the script with that command's own non-zero exit code. A Friendbot or RPC outage shows up as a failed
first step, not as a contract failure; re-run later.
