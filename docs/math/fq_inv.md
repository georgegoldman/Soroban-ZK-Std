# Fq Modular Inversion — Binary Extended Euclidean Algorithm

## Field

BN254 base field modulus:

```
q = 21888242871839275222246405745257275088696311157297823662689037894645226208583
  = 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47
```

## Algorithm: Binary Extended GCD

Given `a ∈ Fq`, compute `a⁻¹ mod q` such that `a · a⁻¹ ≡ 1 (mod q)`.

### Inputs
- `a`: field element, `0 < a < q`
- `q`: the prime modulus

### Output
- `a⁻¹ mod q`, or `0` if `a = 0`

### Steps

```
u ← a
v ← q
x1 ← 1
x2 ← 0

while u ≠ 1 and v ≠ 1:
    while u is even:
        u ← u / 2
        if x1 is even: x1 ← x1 / 2
        else:          x1 ← (x1 + q) / 2

    while v is even:
        v ← v / 2
        if x2 is even: x2 ← x2 / 2
        else:          x2 ← (x2 + q) / 2

    if u ≥ v:
        u  ← u - v
        x1 ← x1 - x2  (mod q)
    else:
        v  ← v - u
        x2 ← x2 - x1  (mod q)

if u = 1: return x1 mod q
else:     return x2 mod q
```

### Constant-Time Note
The binary GCD loop is inherently variable-time (branch on even/odd). For
constant-time inversion use Fermat's little theorem: `a^(q-2) mod q`. The
binary GCD is provided here as a reference for the mathematical structure;
the Rust implementation uses the Fermat path for side-channel safety.
