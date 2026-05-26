# Montgomery Reduction — Constant-Time Modular Arithmetic

## Purpose

Montgomery form avoids expensive division in modular multiplication by
replacing `mod q` with cheaper bit-shifts and additions.

## Parameters

For modulus `q` and `R = 2^256`:

```
R_inv = R⁻¹ mod q
q_inv = -q⁻¹ mod R   (so that q · q_inv ≡ -1 mod R)
```

### BN254 Fq Constants

```
q     = 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47
R     = 2^256
R²    = R · R mod q   (Montgomery constant for converting into Montgomery form)
q_inv = q⁻¹ mod 2^64  (low 64-bit word of -q⁻¹ mod R)
```

## Montgomery Multiplication: MonPro(a, b)

Inputs: `ã = a·R mod q`, `b̃ = b·R mod q`
Output: `ã·b̃·R⁻¹ mod q = (a·b)·R mod q`

```
t ← ã · b̃                  (512-bit product)
m ← (t mod R) · q_inv mod R  (low word correction factor)
u ← (t + m · q) / R          (exact division, shift right by 256 bits)
if u ≥ q: return u - q
else:     return u
```

## Converting To/From Montgomery Form

```
to_mont(a)   = MonPro(a, R²)   → a·R mod q
from_mont(ã) = MonPro(ã, 1)    → a mod q
```

## Montgomery Addition

Addition does not require Montgomery form — it is the same as standard
modular addition:

```
add_mont(ã, b̃) = ã + b̃  (then subtract q if ≥ q)
```

## Constant-Time Guarantee

The final conditional subtraction `if u ≥ q` must be implemented using
branchless arithmetic (bitmasking) to prevent timing side-channels.
