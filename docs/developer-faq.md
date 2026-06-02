# Developer FAQ

> **Issue #218** — Frequently asked questions about setup, gas limits, and Rust `no_std` constraints in `Soroban-ZK-Std`.

---

## Setup

### Q: What is the minimum toolchain I need to build and test the library?

You need:

| Tool | Version | Install |
|------|---------|---------|
| Rust | stable or nightly | `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \| sh` |
| WASM target | — | `rustup target add wasm32-unknown-unknown` |
| Soroban CLI | latest | `cargo install --locked soroban-cli` |

Optional but recommended for size auditing:

```bash
cargo install twiggy cargo-bloat
```

Run the full environment check after installing:

```bash
git clone https://github.com/georgegoldman/Soroban-ZK-Std.git
cd Soroban-ZK-Std
make all
```

---

### Q: The build fails with `error[E0463]: can't find crate for 'std'` when targeting WASM. What's wrong?

One of your dependencies or your own code is pulling in the Rust standard library, which is unavailable in the `wasm32-unknown-unknown` target.

**Check your own code:** every file in `zk-core` and `zk-soroban` must begin with `#![no_std]`. If this attribute is missing, the compiler assumes `std`.

**Find the offending dependency:**

```bash
cargo tree -p your-crate --target wasm32-unknown-unknown | grep " std "
```

Look for crates that do not declare `default-features = false`. Many Rust crates gate their `std` usage behind a feature flag:

```toml
# Cargo.toml — disable std for all no_std-compatible crates
some-crate = { version = "1.0", default-features = false }
```

---

### Q: `make all` fails on macOS with `make: command not found`.

Install the Xcode command-line tools, which include GNU Make:

```bash
xcode-select --install
```

---

### Q: How do I run only the unit tests without building the WASM binary?

```bash
cargo test -p zk-core
cargo test -p zk-soroban
```

To run a specific test by name:

```bash
cargo test -p zk-core -- field_add_identity --nocapture
```

---

### Q: I get `error: linker 'cc' not found` on a fresh Linux machine.

Install the C build toolchain:

```bash
# Debian / Ubuntu
apt install build-essential

# Fedora / RHEL
dnf groupinstall "Development Tools"
```

---

## Gas Limits

### Q: What are Soroban's instruction budget limits?

Under Protocol 25:

| Limit | Value |
|-------|-------|
| CPU instructions per transaction (standard) | 100,000,000 |
| Composite budget (covers native host functions like pairing) | 400,000,000 |

Pairing-based operations such as `bn254_pairing_check` consume from the composite budget, not the standard CPU budget.

---

### Q: How many instructions does a full Groth16 verification use?

For a proof with one public input:

| Component | Instructions |
|-----------|-------------|
| MSM(2) public-input accumulator (WASM guest) | ~138,140,000 |
| 4-pair `bn254_pairing_check` (host function) | ~29,327,515 |
| **Total estimate** | **~167,467,515** |
| % of 400 M composite budget | ~41.9% |

This leaves roughly 232 M instructions for application logic. See [GAS.md](../GAS.md) for the complete reference.

---

### Q: Can I run two Groth16 verifications in a single transaction?

Yes, two verifications together cost approximately 335 M instructions, which is within the 400 M composite budget. Three verifications (~502 M) exceed it and must be split across multiple transactions.

---

### Q: `G1::scalar_mul` exceeds the instruction limit. How do I fix it?

A worst-case 254-bit scalar multiplication costs ~69 M instructions alone. If you are running multiple scalar multiplications per transaction, you will exceed the 100 M standard budget.

Options:
1. Use the 400 M **composite** budget path by pairing with `bn254_pairing_check`.
2. Break the work across multiple transactions with intermediate state stored on-chain.
3. Reduce the scalar bit-width — shorter scalars cost proportionally less.
4. Wait for Pippenger/Strauss MSM (tracked in [GAS.md Future Work](../GAS.md#future-work)).

---

### Q: How do I measure the actual instruction cost of my contract function?

Use the Soroban budget API inside a test:

```rust
#[test]
fn measure_my_function() {
    let env = Env::default();
    env.budget().reset_default();

    // ... call your contract function ...

    let cpu_used = env.budget().cpu_instruction_cost();
    println!("CPU instructions: {}", cpu_used);
    assert!(cpu_used < 100_000_000, "exceeds 100M budget");
}
```

Run with `--nocapture` to see the printed value:

```bash
cargo test -p zk-soroban -- measure_my_function --nocapture
```

---

### Q: Twiggy shows my WASM is larger than 64 KB. What should I cut?

The most common causes:

| Cause | Fix |
|-------|-----|
| Accidental `std` dependency | Add `default-features = false` to offending crate in `Cargo.toml` |
| Debug symbols in release build | Ensure `[profile.release]` sets `debug = false` and `lto = true` |
| Generic monomorphisation | Reduce generic type parameters; prefer concrete types in contract code |
| Multiple copies of `ethnum` | Pin to a single version in the workspace `Cargo.toml` |

Use `cargo bloat` to rank the largest contributors:

```bash
cargo bloat --target wasm32-unknown-unknown --release -p your-contract --crates
```

---

## Rust `no_std` Constraints

### Q: Why does this library require `#![no_std]`?

Soroban contracts compile to WASM and run inside the Soroban Virtual Machine, which does not provide a host operating system. The Rust standard library (`std`) depends on OS primitives such as file I/O, threads, and a heap allocator. Without these, `std` cannot link, so the WASM binary must be built without it.

`zk-core` contains only pure field arithmetic, which needs nothing from `std`. `zk-soroban` depends on the Soroban SDK, which provides its own `no_std`-compatible allocator when needed.

---

### Q: I need a `Vec` or `String`. Can I use them in a `no_std` environment?

Yes, but you must use them from the correct source:

- For types used inside a Soroban contract, use `soroban_sdk::Vec`, `soroban_sdk::Bytes`, and `soroban_sdk::String`.
- For types used inside `zk-core` (no Soroban dependency), you may use `alloc::vec::Vec` and `alloc::string::String` by enabling the `alloc` crate. Add `extern crate alloc;` at the top of your file and enable the allocator in your Soroban contract crate (the SDK provides one).

Avoid using these unnecessarily — heap allocation increases WASM binary size and instruction costs.

---

### Q: How do I handle errors without `std::error::Error`?

Return `Result<T, ZkError>` from any function that can fail. `ZkError` is a simple `Copy` enum defined in `zk-core`:

```rust
pub enum ZkError {
    InvalidFieldElement,
    InvalidInput,
}
```

Add new variants to this enum for new error conditions. Do not use `unwrap()` or `expect()` in library code — if a value cannot be unwrapped without panicking, return an `Err` instead.

---

### Q: Can I use `println!` or `dbg!` for debugging?

Not inside `no_std` code targeting WASM, because these macros call `std::io`. For debugging during development, use Soroban's logging mechanism:

```rust
soroban_sdk::log!(&env, "value: {}", some_value);
```

This writes to the Soroban test environment's log, visible when running tests with `--nocapture`.

---

### Q: My dependency uses `std` and I cannot change it. What are my options?

1. **Check for a `no_std` feature flag** — many crates expose one: `features = ["no_std"]` or `default-features = false`.
2. **Find a `no_std` alternative** — `ethnum` (used here) replaces big-integer types from `std`-dependent crates like `num-bigint`.
3. **Vendor and strip** — fork the dependency, add `#![no_std]` at the top, and remove the `std`-dependent parts. This is a maintenance burden; prefer finding an alternative.
4. **Move the dependency to a separate off-chain binary** — if the dependency is only needed for proof generation (which runs off-chain), it does not need to compile to WASM at all.

---

### Q: I added a new mathematical primitive. Where does it go?

Follow the project's architecture rule:

| What you are adding | Where it goes |
|--------------------|---------------|
| A new curve, field, or hash primitive | `crates/zk-core/` — no Soroban imports allowed here |
| A developer tool for use inside contracts | `crates/zk-soroban/` — may use `soroban_sdk` |
| An integration test or sample contract | `contracts/` |

Before submitting a pull request, verify that your code compiles to WASM without growing the binary by more than 5 KB:

```bash
make build-wasm
twiggy top target/wasm32-unknown-unknown/release/zk_soroban.wasm
```

---

## Next Steps

- [Getting Started Guide](./getting-started-guide.md) — full setup walkthrough
- [GAS.md](../GAS.md) — instruction cost reference
- [Cross-Contract Verification Guide](./cross-contract-verification.md) — calling the verifier from another contract
- [Constant-Time Implementation Notes](./constant-time-notes.md) — timing side-channel prevention
