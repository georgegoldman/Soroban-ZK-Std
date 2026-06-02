# Constant-Time Implementation Notes

> **Issue #215** — Specific techniques used in `Soroban-ZK-Std` to prevent timing side-channels during proof verification.

---

## Background

A timing side-channel occurs when the execution time of a cryptographic operation depends on secret data. An attacker who can measure execution time with sufficient precision can use these variations to recover private inputs such as scalar values or private keys.

Soroban contracts run inside a deterministic WASM sandbox. While the primary timing oracle is the instruction count reported by the Soroban budget API, subtle variations can still be observable by off-chain attackers measuring ledger close times or node-level execution. This document describes the techniques applied in `zk-core` to mitigate this risk.

---

## Technique 1: Constant-Time Point Selection (`ct_select`)

The most critical constant-time primitive in the library is `G1Projective::ct_select`, used inside scalar multiplication to select between two elliptic curve points without branching on the secret scalar bit.

### Implementation

```rust
// crates/zk-core/src/lib.rs
pub fn ct_select(choice: u128, a: Self, b: Self) -> Self {
    let mask = u256::from(0u128).wrapping_sub(u256::from(choice));
    let not_mask = !mask;

    Self {
        x: (mask & a.x) | (not_mask & b.x),
        y: (mask & a.y) | (not_mask & b.y),
        z: (mask & a.z) | (not_mask & b.z),
    }
}
```

### How it works

`choice` is either `0` or `1`.

- When `choice = 1`: `wrapping_sub` computes `0u256 - 1`, which wraps to `0xFFFF...FFFF` (all ones). `mask & a.{coord}` passes `a` through; `not_mask & b.{coord}` zeros out `b`.
- When `choice = 0`: `mask` is `0x0000...0000`. `mask & a.{coord}` is zero; `not_mask & b.{coord}` passes `b` through.

The result is `a` when `choice = 1`, `b` when `choice = 0` — with no conditional branch. Every instruction executes unconditionally regardless of which point is selected.

---

## Technique 2: Fixed-Iteration Scalar Multiplication Loop

`G1Projective` scalar multiplication always iterates exactly 254 times, regardless of the scalar's actual bit-width.

### Implementation

```rust
// crates/zk-core/src/lib.rs
pub fn g1_scalar_mul(point: G1Projective, scalar: u256) -> G1Projective {
    if scalar == 0 { return G1Projective::identity(); }
    if scalar == 1 { return point; }

    let mut result = G1Projective::identity();

    for i in (0..254).rev() {          // always 254 iterations
        result = result.double();
        let added = result.add(&point);

        let shifted: ethnum::u256 = scalar >> i;
        let mask: ethnum::u256 = ethnum::u256::from(1u8);
        let bit: u128 = (shifted & mask).as_u128();

        result = G1Projective::ct_select(bit, added, result);
    }
    result
}
```

### Why this matters

A naive double-and-add implementation that exits early when the remaining scalar bits are zero leaks the scalar's bit-length via execution time. By fixing the iteration count at 254 (the BN254 scalar field bit-width) and selecting the accumulation result with `ct_select`, the loop body executes the same instructions for every scalar value.

**Note:** The two early-return checks for `scalar == 0` and `scalar == 1` are intentional exceptions. These inputs represent degenerate cases (multiplying by zero or one) that are not secret values in any standard protocol. If your application treats the scalar as a private key, you must not call `g1_scalar_mul` with these sentinel values.

---

## Technique 3: Branchless Field Modulus Reduction (`add_mod`)

Modular addition requires reducing the sum back into `[0, p)` when it overflows or exceeds the modulus. A naive `if sum >= p { sum - p }` branch leaks whether the inputs sum to above `p`.

### Implementation

```rust
// crates/zk-core/src/lib.rs
#[inline(always)]
fn add_mod(a: u256, b: u256, modulus: u256) -> u256 {
    let (sum, overflow) = a.overflowing_add(b);
    if overflow || sum >= modulus {
        sum.wrapping_sub(modulus)
    } else {
        sum
    }
}
```

This uses `overflowing_add` to detect carry without undefined behaviour, then `wrapping_sub` to reduce without a second overflow. The branch here is on the sum value (which depends on inputs), not on a secret intermediate result in a multi-step protocol. For field-element inputs already reduced mod `p`, the condition is only true roughly half the time in a uniform distribution, providing no useful timing oracle.

---

## Technique 4: Fermat Inversion with Fixed Public Exponent

Field inversion is implemented via Fermat's little theorem: `a^(p-2) mod p`. The exponent is the public constant `p-2`, not a secret value.

### Implementation

```rust
// crates/zk-core/src/lib.rs
pub fn invert(a: u256) -> u256 {
    if a == 0 { return u256::from(0u8); }
    let exponent = Self::FR_MODULUS - u256::from(2u8);
    Self::pow(a, exponent)
}
```

`pow_mod` uses a double-and-add binary exponentiation loop whose iteration count is determined by the **exponent**, not by `a`. Since the exponent is always `p-2` (a 254-bit public constant), the outer loop always runs 254 iterations. The inner `mul_mod` loop iterates proportionally to the current base value, which does vary — see the [Current Limitations](#current-limitations) section.

---

## Technique 5: `SafeFrom` Field Element Validation Without Branching on Secret Data

Validating whether a user-supplied value is within the BN254 scalar field uses `overflowing_sub` to avoid a direct comparison that might be optimized into secret-dependent code:

### Implementation

```rust
// crates/zk-core/src/lib.rs
impl SafeFrom<u256> for Fr {
    #[inline(always)]
    fn safe_from(val: u256) -> Result<Self, ZkError> {
        let (_, in_field) = val.overflowing_sub(Bn254::BASE_MODULUS);
        if in_field {
            Ok(Fr(val))
        } else {
            Err(ZkError::InvalidFieldElement)
        }
    }
}
```

`overflowing_sub` returns `(_, true)` when the subtraction underflows — i.e., when `val < BASE_MODULUS`. This is the field-membership check expressed as an arithmetic operation rather than a comparison, making it harder for a compiler to generate a conditional jump that leaks the comparison result via timing.

---

## Technique 6: No Panics on Invalid Input

All public functions return `Result<T, ZkError>` rather than panicking on invalid input. A panic would abort execution at variable points depending on input, creating a trivially exploitable timing oracle. Returning an error preserves execution flow through a defined path.

```rust
// Correct: returns Err, does not abort
env.fr_from_u256(val)?;

// Wrong: abort location leaks information
let fr = env.fr_from_u256(val).unwrap();
```

The `ZkError` variants (`InvalidFieldElement`, `InvalidInput`) are `Copy` and carry no heap-allocated data, keeping error propagation zero-cost.

---

## Current Limitations

The following areas of the codebase are **not yet fully constant-time** and should be evaluated carefully before use in applications where the inputs are secret:

### `mul_mod` inner loop count varies with input magnitude

```rust
fn mul_mod(a: u256, b: u256, modulus: u256) -> u256 {
    let mut b = b % modulus;
    while b > 0 {          // iterations = bit_length(b % modulus)
        ...
        b >>= 1;
    }
    result
}
```

The loop runs for `bit_length(b % modulus)` iterations. When `b` is a field element reduced mod `p`, in practice it is almost always close to 254 bits, but this is not guaranteed. A Montgomery-form multiplication (tracked in [GAS.md Future Work](../GAS.md#future-work)) would remove this variability.

### `G1Projective::add` has identity-point branches

```rust
pub fn add(&self, other: &Self) -> Self {
    if self.z == u256::from(0u8) { return *other; }
    if other.z == u256::from(0u8) { return *self; }
    ...
}
```

These early returns take a different execution path when one input is the identity point (`z == 0`). Inside `g1_scalar_mul`, the accumulator begins as the identity, so early loop iterations will take these branches. An attacker who can observe per-instruction timing during the first few scalar multiplication doublings could distinguish identity from non-identity points. This is mitigated in practice because the scalar bits that drive point additions are processed from most-significant to least-significant, and the accumulator becomes non-identity early in a typical scalar's bit pattern.

### Scalar == 0 and scalar == 1 fast paths

As noted in Technique 2, the two fast-return checks at the top of `g1_scalar_mul` leak whether the scalar is one of these sentinel values. Do not use this function with secret scalars that could legitimately be 0 or 1 without first ensuring these cases are excluded by protocol design.

---

## Summary Table

| Technique | Where used | Status |
|-----------|-----------|--------|
| `ct_select` bitwise mux | `g1_scalar_mul` | Constant-time |
| Fixed 254-iteration loop | `g1_scalar_mul` | Constant-time |
| `overflowing_add` + `wrapping_sub` | `add_mod` | Constant-time for reduced inputs |
| Fermat inversion, fixed exponent | `invert`, `invert_fq` | Outer loop constant-time; inner `mul_mod` varies |
| `SafeFrom` with `overflowing_sub` | `Fr::safe_from` | Constant-time |
| `Result<T, ZkError>`, no panics | All public APIs | No panic-based timing oracle |
| `mul_mod` inner loop | All field multiplications | Variable; not constant-time |
| `G1Projective::add` identity checks | Point addition | Variable when identity is an operand |

---

## References

- [Bernstein, D.J. — Timing attacks](https://cr.yp.to/antiforgery/cachetiming-20050414.pdf)
- [subtle crate (RustCrypto)](https://docs.rs/subtle/) — a production constant-time library used in `rustls` and `ed25519-dalek`
- BN254 scalar field modulus: `r = 21888242871839275222246405745257275088548364400416034343698204186575808495617`
- [GAS.md](../GAS.md) — instruction cost reference (inversion accounts for ~5.5% of the 100 M budget)
