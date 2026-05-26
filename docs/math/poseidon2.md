# Poseidon2 Sponge Construction (BN254, t=3)

## Parameters

| Parameter | Value |
|-----------|-------|
| Field     | BN254 Fr |
| t (state width) | 3 |
| d (S-box degree) | 5 |
| R_F (full rounds) | 8 |
| R_P (partial rounds) | 56 |
| Rate | 2 |
| Capacity | 1 |

## Permutation Structure

### Full Round

Applied to all `t` state elements:

```
1. AddRoundConstants: sᵢ ← sᵢ + rcᵢ
2. S-box:            sᵢ ← sᵢ⁵  (for all i)
3. MDS Matrix:       s  ← M · s
```

### Partial Round

Applied to only the first element:

```
1. AddRoundConstants: s₀ ← s₀ + rc₀  (others unchanged)
2. S-box:            s₀ ← s₀⁵
3. MDS Matrix:       s  ← M · s
```

### Round Schedule

```
4 full rounds → 56 partial rounds → 4 full rounds
```

## MDS Matrix (t=3, BN254)

Internal matrix diagonal `(M_I - I)` = `[1, 1, 2]`.

The full matrix multiplication is:

```
s'₀ = 2·s₀ + s₁ + s₂
s'₁ = s₀ + 2·s₁ + s₂
s'₂ = s₀ + s₁ + 3·s₂
```

## Sponge API

```
init:    state ← [0, 0, 0]
absorb:  state[rate_idx] ← state[rate_idx] + input (mod r)
         if rate_idx == rate: permute(); rate_idx = 0
squeeze: permute(); return state[0]
```

## CAP-0075 Host Call

The permutation is executed as a single Soroban host call:

```rust
env.crypto_hazmat().poseidon2_permutation(
    &state, "BN254", t=3, d=5, rounds_f=8, rounds_p=56, &mat_diag, &round_constants
)
```

This eliminates all guest-side loop overhead.
