# KZG Polynomial Commitment

## Setup (Structured Reference String)

Trusted setup produces:
```
SRS = { [τ⁰]₁, [τ¹]₁, ..., [τᵈ]₁, [τ]₂ }
```
where `τ` is a secret scalar and `[x]₁ = x·G1`, `[x]₂ = x·G2`.

## Commitment

For polynomial `f(X) = Σᵢ fᵢ·Xⁱ` of degree `d`:

```
C = Σᵢ fᵢ · [τⁱ]₁   (multi-scalar multiplication)
  = [f(τ)]₁
```

## Opening Proof

To prove `f(z) = y`:

Compute quotient polynomial:
```
q(X) = (f(X) - y) / (X - z)
```

Proof:
```
π = [q(τ)]₁ = Σᵢ qᵢ · [τⁱ]₁
```

## Verification

Check via pairing:
```
e(C - [y]₁, [1]₂) = e(π, [τ]₂ - [z]₂)
```

Equivalently (for pairing check API):
```
e(C - [y]₁, [1]₂) · e(-π, [τ - z]₂) = 1
```

## Batch Verification

For `m` openings `(Cᵢ, zᵢ, yᵢ, πᵢ)` with random `r ← Fiat-Shamir`:

```
F = Σᵢ rⁱ · Cᵢ
E = Σᵢ rⁱ · yᵢ · [1]₁
W = Σᵢ rⁱ · πᵢ

e(F - E + Σᵢ rⁱ·zᵢ·πᵢ, [1]₂) = e(W, [τ]₂)
```

This reduces `m` pairings to 2 pairings.
