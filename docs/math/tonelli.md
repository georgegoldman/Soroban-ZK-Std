# Tonelli-Shanks Square Root in Fr

See `crates/zk-core/src/BN254_Square_Root_Algorithm.md` for the full
mathematical derivation. This file summarises the implementation contract.

## Quick Reference

| Field | Modulus | S  | Q (odd part) | Non-residue z |
|-------|---------|-----|--------------|---------------|
| Fr    | r       | 28  | (r-1)/2²⁸   | 5             |
| Fq    | q       | 1   | (q-1)/2      | 2             |

## Algorithm (Fr)

```
sqrt_fr(a):
    if a == 0: return 0
    if pow(a, (r-1)/2) ≠ 1: return None   // not a QR

    M ← 28
    c ← pow(5, Q_r)          // pre-computable
    t ← pow(a, Q_r)
    R ← pow(a, (Q_r+1)/2)

    loop:
        if t == 1: return R
        find smallest i > 0 s.t. t^(2^i) == 1
        b ← pow(c, 2^(M-i-1))
        M ← i
        c ← b²
        t ← t · b²
        R ← R · b
```

## Fq Special Case (S=1)

Since `S_q = 1`, the algorithm simplifies to:

```
sqrt_fq(a):
    if a == 0: return 0
    if pow(a, (q-1)/2) ≠ 1: return None
    // S=1 means q ≡ 3 (mod 4) is FALSE — use one Tonelli step
    // Actually q ≡ 3 (mod 4): sqrt = a^((q+1)/4)
    return pow(a, (q+1)/4)
```

Note: `q ≡ 3 (mod 4)` so the simple formula applies for Fq.
