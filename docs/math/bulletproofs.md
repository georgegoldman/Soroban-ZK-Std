# Bulletproofs Range Validation — 64-bit Integer Range Proofs

## Statement

Prove that a committed value `v` satisfies `0 ≤ v < 2^64` without revealing `v`.

## Commitment

```
V = v·G + γ·H    (Pedersen commitment, G and H are independent generators)
```

## Bit Decomposition

Express `v` in binary: `v = Σᵢ aᵢ · 2ⁱ` for `i = 0..63`.

Commit to the bit vector:
```
A  = Σᵢ aᵢ·Gᵢ + α·H
S  = Σᵢ sᵢ·Gᵢ + ρ·H    (blinding vector)
```

## Inner Product Argument

The range proof reduces to proving knowledge of vectors `l, r` such that:

```
<l, r> = t
P = l·G + r·H
```

The inner product argument recursively halves the vector length:

```
Round k:
    L_k = <l_lo, G_hi> + <r_hi, H_lo> + t_L·Q
    R_k = <l_hi, G_lo> + <r_lo, H_hi> + t_R·Q

    x_k ← Hash(L_k, R_k)   // Fiat-Shamir challenge

    l' = l_lo + x_k · l_hi
    r' = r_hi + x_k⁻¹ · r_lo
    G' = G_lo + x_k⁻¹ · G_hi
    H' = H_hi + x_k · H_lo
```

After `log₂(64) = 6` rounds, the verifier checks a single inner product.

## Verification Cost

- `2·log₂(n)` group exponentiations for the recursive checks
- 1 multi-scalar multiplication for the final check
- Total: ~128 group operations for 64-bit range proofs

## Batch Verification

For `m` range proofs, use random linear combination:

```
Σᵢ xᵢ · (proof_i check equation) = 0
```

This reduces `m` verifications to a single multi-scalar multiplication.
