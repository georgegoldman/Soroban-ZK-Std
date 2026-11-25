# soroban-zk-cli

Host-side developer CLI for `soroban-zk-std`. It builds two binaries:

- `soroban-zk`
- `cargo-soroban-zk`, so that `cargo soroban-zk <command>` works once it is on your `PATH`

```sh
cargo install --path crates/soroban-zk-cli
```

Only BN254 Groth16 artifacts are supported. BLS12-381 and Noir are reported as unsupported.

## `import-vk`

```sh
soroban-zk import-vk --input verification_key.json --format snarkjs --out src/vk_generated.rs
soroban-zk import-vk --input vk.json --format gnark --name MY_VK
```

This writes `no_std`, allocation-free constants: `<NAME>_IC: [G1Affine; N]`, `<NAME>_NUM_PUBLIC_INPUTS`, and `<NAME>: Groth16VerifyingKey<'static>`. All of them are built with `ethnum::u256::from_words`. Include the file with `mod vk { include!("vk_generated.rs"); }` and pass `&vk::VERIFYING_KEY` to `groth16_verify`. The generated file depends on the `ethnum`, `soroban-zk-core` and `soroban-zk-std` crates.

Every coordinate is checked before anything is written:

- it is canonical (`< p`)
- the point is on the curve
- G2 points are in the prime-order subgroup
- `nPublic` (if present) matches `IC.len() - 1`

### Supported input formats

- **snarkjs**: the output of `snarkjs zkey export verificationkey`. It has `vk_alpha_1`, `vk_beta_2`, `vk_gamma_2`, `vk_delta_2` and `IC`.
- **gnark**: the `encoding/json` form of `groth16/bn254.VerifyingKey`:
  - `{"G1": {"Alpha", "Beta", "Delta", "K": [..]}, "G2": {"Beta", "Gamma", "Delta"}}`
  - G1 points are `{"X", "Y"}`, and G2 points are `{"X": {"A0", "A1"}, "Y": {..}}`.
  - Coordinates may be decimal strings, `0x` hex strings or JSON integers.
  - `K` is the IC vector.
  - Keys with non-empty `CommitmentKeys` (gnark's Pedersen commitment extension) are rejected, because `groth16_verify` does not support them.

### G2 coordinate order

SnarkJS stores an Fq2 element as `[c0, c1]` (real, imaginary), and gnark stores it as `{A0: c0, A1: c1}`. Both map unchanged onto the `(c0, c1)` tuple of `soroban_zk_std::G2Affine`. The EIP-197 byte order (`c1 || c0`) is applied only when bytes are produced.

This was checked against the shielded-asset-template SnarkJS key and proof in `tests/fixtures`. The `[c0, c1]` reading is on the curve and verifies. The swapped reading is not on the curve, and the CLI reports it with a hint that the values look swapped.

## `encode-proof`

```sh
soroban-zk encode-proof --proof proof.json --public public.json --output hex|json|stellar-cli
```

This produces the exact 256-byte buffer that `Groth16Proof::from_bytes` reads: `A (64) || B (128, x.c1 || x.c0 || y.c1 || y.c0) || C (64)`, all big-endian. Public inputs become 32-byte big-endian scalars, and any value `>= r` is rejected.

`--output stellar-cli` prints flags you can paste into `stellar contract invoke`. By default they match `shielded-asset-template`'s `transfer_shielded(.., proof_bytes: Bytes, public_inputs_bytes: Bytes)`:

```sh
stellar contract invoke --id <C...> -- transfer_shielded --sender <G...> --receiver <G...> \
  $(soroban-zk encode-proof --proof proof.json --public public.json --output stellar-cli)
```

Use `--proof-arg` and `--public-arg` to match other contracts' parameter names.

## `inspect`

```sh
soroban-zk inspect verification_key.json   # or proof.json, public.json, gnark vk, hex proof
```

This detects the file type and checks every point and scalar offline. It prints one `ok` or `FAIL` line per item.

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Success |
| `1` | Invalid artifact or I/O error |
| `2` | Usage error |

The CLI never panics on bad input.
