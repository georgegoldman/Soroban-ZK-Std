# FRI Proximity Testing — Reed-Solomon Proximity

## Purpose

FRI (Fast Reed-Solomon IOP of Proximity) proves that a committed function is
close to a low-degree polynomial, forming the core of STARK proof systems.

## Setup

- Domain `D` of size `N = 2^k`
- Target degree bound `d < N`
- Blowup factor `ρ = d/N` (rate)
- Number of rounds: `r = log₂(N/d)`

## Commit Phase

### Round 0

Prover commits to `f₀: D₀ → Fr` (the original polynomial evaluations).

### Round i → i+1

Verifier sends challenge `αᵢ ← Fr`.

Prover folds:
```
f_{i+1}(x²) = (f_i(x) + f_i(-x)) / 2 + αᵢ · (f_i(x) - f_i(-x)) / (2x)
```

Domain halves: `D_{i+1} = { x² : x ∈ D_i }`.

After `r` rounds, `f_r` is a constant polynomial.

## Query Phase

Verifier picks random `s ∈ D₀` and checks consistency across all rounds:

```
For each round i:
    Query f_i(s_i) and f_i(-s_i)
    Verify: f_{i+1}(s_i²) = fold(f_i(s_i), f_i(-s_i), αᵢ, s_i)
    s_{i+1} ← s_i²
```

Each query requires a Merkle authentication path per round.

## Deep FRI

For STARK integration, the prover also commits to the composition polynomial:

```
DEEP_i(x) = (f(x) - f(z)) / (x - z)
```

evaluated at the out-of-domain point `z`, ensuring the polynomial matches
the claimed evaluation.

## Security

- `λ`-bit security requires `λ / log₂(1/ρ)` queries.
- Each query opens `r` Merkle paths.
- Total proof size: `O(λ · log²(N))` field elements.
