# verifier-sample

Minimal Soroban contract that exercises the `soroban-zk-std` library from
on-chain code. It exists to prove that the library builds, links and runs
inside a real contract binary, and it is the artifact the CI size gate
(`make wasm-size-check`) measures against the 64 KB contract limit.

## What it does

`Verifier::check(input)` delegates to `soroban-zk-std`'s `ZkEnv` helper and
returns whether `input` is a canonical BN254 scalar — the validation every ZK
verifier must perform before touching a proof or public input.

## Layout

```text
contracts/verifier-sample
├── Cargo.toml   # depends on soroban-zk-std with default-features = false
├── Makefile     # build / test / 64 KB size gate, mirrors the root Makefile
└── src
    ├── lib.rs   # the contract entry point
    └── test.rs  # host-side tests
```

## Build and test

Soroban Protocol 25 builds for the `wasm32v1-none` target:

```bash
rustup target add wasm32v1-none   # once
make build                        # cargo build --target wasm32v1-none --release
make wasm-size-check              # fails if the artifact exceeds 64 KB
make test
```

The artifact is written to `target/wasm32v1-none/release/verifier_sample.wasm`.

## Using the library in your own contract

Depend on the library with the default features disabled (the `contract`
feature exports `ZkContract` and pulls in the whole proof-system stack), and
enable only what you need:

```toml
[dependencies]
soroban-zk-std = { version = "0.1.4", default-features = false }
soroban-sdk = { version = "27.0.2", default-features = false }
```
