# Non-Native Field Addition — Carry-Tracking Mathematics

## Problem

Add two elements `a, b` of a foreign field `Fp` (e.g. secp256k1 prime)
inside a circuit defined over BN254 Fr.

Since `p > r` in general, we cannot represent `a, b` as single Fr elements.

## Limb Representation

Decompose each element into `k` limbs of `L` bits:

```
a = a₀ + a₁·2^L + a₂·2^(2L) + ... + a_{k-1}·2^((k-1)L)
```

For 256-bit foreign fields with L=88: k=3 limbs.

## Addition Algorithm

```
c₀ = a₀ + b₀
c₁ = a₁ + b₁
c₂ = a₂ + b₂

// Carry propagation
carry₀ = c₀ >> L
c₀     = c₀ & (2^L - 1)

carry₁ = (c₁ + carry₀) >> L
c₁     = (c₁ + carry₀) & (2^L - 1)

c₂     = c₂ + carry₁
```

## Modular Reduction

If `c ≥ p`, subtract `p`:

```
borrow₀ = p₀ > c₀ ? 1 : 0
d₀ = c₀ - p₀ + borrow₀ · 2^L

borrow₁ = (p₁ + borrow₀) > c₁ ? 1 : 0
d₁ = c₁ - p₁ - borrow₀ + borrow₁ · 2^L

d₂ = c₂ - p₂ - borrow₁
```

## Constraint Count

Each limb addition requires:
- 1 range check on the output limb (L bits)
- 1 range check on the carry (1 bit)

Total: `2k` range checks per addition.
