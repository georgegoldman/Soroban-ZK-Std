# Lagrange Interpolation over Fr

## Problem

Given `n` distinct evaluation points `(x₀,y₀), ..., (xₙ₋₁,yₙ₋₁)` in Fr,
find the unique polynomial `f` of degree < n such that `f(xᵢ) = yᵢ`.

## Formula

```
f(X) = Σᵢ yᵢ · Lᵢ(X)

Lᵢ(X) = Π_{j≠i} (X - xⱼ) / (xᵢ - xⱼ)
```

## Algorithm

```
for i in 0..n:
    basis ← 1
    denom ← 1
    for j in 0..n, j ≠ i:
        basis ← basis · (X - xⱼ)     // polynomial multiplication
        denom ← denom · (xᵢ - xⱼ)   // scalar multiplication in Fr

    f ← f + yᵢ · basis · denom⁻¹
```

## Evaluation at a Point (Barycentric Form)

To evaluate `f(z)` without constructing the full polynomial:

```
w[i] = 1 / Π_{j≠i} (xᵢ - xⱼ)   // barycentric weights (pre-computable)

f(z) = (Σᵢ w[i]·yᵢ/(z-xᵢ)) / (Σᵢ w[i]/(z-xᵢ))
```

This reduces evaluation to O(n) operations after O(n²) pre-computation.

## Vanishing Polynomial

The polynomial that is zero at all `xᵢ`:

```
Z(X) = Π_{i=0}^{n-1} (X - xᵢ)
```

Used in PLONK to express that gate constraints hold on the evaluation domain.
