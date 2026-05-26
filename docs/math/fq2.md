# Fq2 Arithmetic — Degree-2 Extension Field

## Definition

```
Fq2 = Fq[u] / (u² + 1)
```

Elements are pairs `(a0, a1)` representing `a0 + a1·u` where `u² = -1`.

## Addition

```
(a0 + a1·u) + (b0 + b1·u) = (a0 + b0) + (a1 + b1)·u
```

Component-wise addition mod q.

## Subtraction

```
(a0 + a1·u) - (b0 + b1·u) = (a0 - b0) + (a1 - b1)·u
```

## Multiplication (Karatsuba)

Let `c = a · b`:

```
v0 = a0 · b0
v1 = a1 · b1

c0 = v0 - v1          (since u² = -1, so a1·b1·u² = -a1·b1)
c1 = (a0 + a1)(b0 + b1) - v0 - v1
```

Cost: 3 Fq multiplications, 5 Fq additions.

## Squaring

```
v0 = a0 · a1

c0 = (a0 - a1)(a0 + a1)   = a0² - a1²
c1 = 2 · v0               = 2·a0·a1
```

Cost: 2 Fq multiplications, 3 Fq additions.

## Inversion

```
norm = a0² + a1²          (since N(a) = a · conj(a) = a0² + a1²)
inv_norm = norm⁻¹  (Fq inversion)

a⁻¹ = (a0 · inv_norm, -(a1 · inv_norm))
```

## Conjugate / Frobenius

```
conj(a0 + a1·u) = a0 - a1·u
```

The Frobenius endomorphism on Fq2 is the conjugate map.
