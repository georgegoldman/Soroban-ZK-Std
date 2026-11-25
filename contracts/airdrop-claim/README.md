# Anonymous Airdrop Claim

An example Soroban contract for a **private airdrop**: an eligible user proves,
with a Groth16 proof over BN254, that they own one leaf of a Poseidon2 Merkle
tree, without revealing which one. Each leaf can claim exactly once, and the
proof is bound to the recipient address, so a claim cannot be front-run.

It is built only from `soroban-zk-std` primitives:

| Concern | Library piece |
| :--- | :--- |
| Proof check | `groth16_verify` + `Groth16Proof::from_bytes` |
| Verifying-key storage | `vk_from_bytes` / `save_vk` / `load_vk` (chunked, persistent) |
| Double-claim protection | `nullifier::NullifierStore` (`is_spent` / `mark_spent`) |
| Hash used by the circuit | Poseidon2 (BN254, t = 3), same sponge as `poseidon2::hash_to_field` |

## Architecture

```text
┌──────────────────────────────────────────────────────────┐
│  OFF-CHAIN: prover (Circom / Noir / arkworks)            │
│  • private: secret, Merkle path (siblings + bits)        │
│  • prove:   leaf = H(secret) is in the tree with `root`  │
│  • prove:   nullifier = H(secret, 1)                     │
│  • bind:    recipient field element                      │
│  • output:  256-byte Groth16 proof + nullifier           │
└──────────────────────────────────────────────────────────┘
                           │  claim(proof, nullifier, recipient)
                           ▼
┌──────────────────────────────────────────────────────────┐
│  ON-CHAIN: AirdropClaim (Soroban)                        │
│  • rebuild public inputs [root, nullifier, recipient]    │
│  • NullifierStore: reject a spent nullifier              │
│  • groth16_verify against the stored VK                  │
│  • NullifierStore: record the nullifier, emit `claimed`  │
└──────────────────────────────────────────────────────────┘
```

## Entry points

| Function | Description |
| :--- | :--- |
| `init(admin, merkle_root, verifying_key)` | One-shot setup. `admin` must sign. `merkle_root` must be a canonical BN254 scalar. `verifying_key` is the circuit VK serialized with `soroban_zk_std::vk_to_bytes` and must have exactly 4 IC points (3 public inputs), i.e. 708 bytes. |
| `claim(proof, nullifier, recipient)` | Verifies the proof for `[merkle_root, nullifier, recipient_field(recipient)]`, rejects a reused nullifier, records it, emits `claimed`. Anyone (the user or a relayer) may submit; `recipient` does not need to sign because the proof is bound to it. |
| `is_claimed(nullifier)` | `true` once the nullifier has been spent. |
| `merkle_root()` / `admin()` | Getters (`NotInitialized` before `init`). |
| `recipient_field(recipient)` | The exact field element the prover must use for `recipient`. |

This example stops at "the claim is valid and recorded". A real airdrop adds the
payout after the nullifier is recorded, for example a
`token::Client::transfer(&contract, &recipient, &amount)`.

## Circuit public-input layout

The contract calls the verifier with exactly three public inputs, in this order
(each a big-endian BN254 scalar, `< r`):

| Index | Name | Value | Constraint in the circuit |
| :---: | :--- | :--- | :--- |
| 0 | `merkle_root` | Read from contract storage (set at `init`) | Root of the Poseidon2 Merkle path from `leaf = H(secret)` |
| 1 | `nullifier` | `claim` argument | `nullifier == H(secret, 1)` |
| 2 | `recipient` | `SHA-256(XDR(ScVal::Address(recipient)))` with byte 0 set to `0x00` | `recipient · recipient == sq` (binds the input; Tornado-style) |

So the VK has `IC[0..4]`: `IC[0]` is the constant term and `IC[1..=3]` match the
rows above.

`H(..)` is the Poseidon2 sponge used by `soroban_zk_std::poseidon2::hash_to_field`:
BN254, t = 3, d = 5, 8 full + 56 partial rounds, rate 2, capacity-zero
initialisation, round constants from `poseidon2_instance_bn254` (RC3). Each
Merkle node is `H(left, right)`; at each level a path bit says whether the
current node is the right child.

Clearing the top byte of the recipient digest keeps it below 2^248 < r, so the
value is always canonical. Provers can get it on-chain with `recipient_field` or
recompute it off-chain from the address XDR.

### Why the nullifier is keyed on its value only

`NullifierStore` records `SHA-256(proof_bytes || inputs_bytes)`. The contract
calls it with empty `proof_bytes` and the 32-byte nullifier as `inputs_bytes`,
so the spent marker depends on the nullifier alone. Keying on the proof bytes
would be unsafe here: Groth16 proofs can be re-randomised, so the same leaf
could otherwise claim again with a fresh-looking proof.

## Errors

All entry points return `Result<_, AirdropError>`; no path panics on caller data.

| Code | Variant | When |
| :---: | :--- | :--- |
| 1 | `AlreadyInitialized` | `init` called twice |
| 2 | `NotInitialized` | `claim` or a getter before `init` |
| 3 | `InvalidVerifyingKey` | VK bytes are not a 3-input VK or contain invalid points |
| 4 | `MalformedProof` | Proof is not 256 bytes or its points are invalid |
| 5 | `InvalidProof` | Pairing check failed (wrong root, nullifier or recipient) |
| 6 | `AlreadyClaimed` | Nullifier already spent |
| 7 | `InvalidFieldElement` | Root or nullifier is `>= r` |
| 8 | `VerifierFailure` | Host or VK-storage failure |

## Tests

```bash
cargo test --release -p airdrop-claim
```

The tests use **real Groth16 proofs**. `src/circuit.rs` (test-only) implements
the circuit above in arkworks R1CS. Each test builds a 16-leaf Poseidon2 tree,
runs a deterministic (`seed = 684`) circuit-specific setup, proves a claim for
leaf 5, and passes the VK and proof to the contract in the same byte formats a
deployment would use. Nothing in the contract is mocked or skipped.
`reference_poseidon2_matches_library` pins the test hash to the on-chain
`poseidon2::hash_to_field`, so the tree the tests build is the tree a real
deployment would commit to.

| Test | Case |
| :--- | :--- |
| `valid_claim_succeeds_and_marks_nullifier` | Happy path, nullifier recorded, one event |
| `double_claim_is_rejected` | Second claim with the same nullifier → `AlreadyClaimed` |
| `claim_against_wrong_root_is_rejected` | Contract initialised with another root → `InvalidProof` |
| `claim_with_mismatched_recipient_is_rejected` | Front-runner swaps recipient → `InvalidProof`, nullifier not burned |
| `claim_with_mismatched_nullifier_is_rejected` | Different nullifier → `InvalidProof` |
| `claim_on_uninitialised_contract_fails` | `claim` / getters before `init` → `NotInitialized` |
| `malformed_proof_is_rejected` | 255 / 257 / 0 bytes and off-curve points → `MalformedProof` |
| `non_canonical_nullifier_is_rejected` | Nullifier `= r` and `nullifier + r` → `InvalidFieldElement` |
| `init_twice_is_rejected` | → `AlreadyInitialized` |
| `init_rejects_bad_verifying_key` | Truncated, 2-input, lying IC count, off-curve point → `InvalidVerifyingKey` |
| `init_rejects_non_canonical_root` | Root `= r` → `InvalidFieldElement` |
| `init_requires_admin_auth` | No admin signature → call aborts, nothing stored |
| `recipient_field_is_canonical_and_matches_helper` | Recipient encoding is `< r` and address-specific |
| `reference_poseidon2_matches_library` | Test Poseidon2 = library `hash_to_field` |
| `reference_circuit_is_satisfied_and_rejects_wrong_root` | Reference R1CS is satisfied, and unsatisfied for a wrong root |

## Build and WASM size

```bash
cargo build --target wasm32v1-none --release -p airdrop-claim
ls -l target/wasm32v1-none/release/airdrop_claim.wasm
```

The contract depends on `soroban-zk-std` with `default-features = false`
(workspace default), so the reference `ZkContract` entry points are not linked in.

**Known limitation:** the release WASM is currently about **113 KiB** (115,855
bytes with the pinned 1.100.0 toolchain), above the 64 KiB Soroban limit. Almost
all of it comes from the library verifier, not from this contract.
`groth16_verify` → `pairing_check` → `validate_pairs` re-checks every G1/G2 point
in software (`soroban_zk_core::Bn254::is_valid_g1_subgroup` /
`is_in_correct_subgroup`, which pull in `mul_fq`, `invert_fq` and 256-bit
`divmod`), and `vk_from_bytes` / `Groth16Proof::from_bytes` do the same. For
comparison, `shielded-asset-template`, which calls the same `groth16_verify`,
builds to 112,660 bytes; this contract adds about 3 KiB on top. To get under
64 KiB, the verifier needs a lighter path that leaves point validation to the
CAP-0074 host functions instead of re-doing it in software. That is a library
change outside the scope of this example.
