# Tonelli–Shanks Algorithm Specification for BN254

## Context: Modular Square Roots in \(F_r\) and \(F_q\)

---

## 1. Field Parameters

The BN254 curve involves two primary fields:

- **Scalar Field (\(F_r\))**

  $$
  r = 21888242871839275222246405745257275088548364400416034343698204186575808495617
  $$

- **Base Field (\(F_q\))**

  $$
  q = 21888242871839275222246405745257275088696311157297823662689037894645226208583
  $$

Both \(r\) and \(q\) satisfy:

$$
p \equiv 1 \pmod{4}
$$

This necessitates the use of the **Tonelli–Shanks** algorithm rather than the simpler:

$$
a^{(p+1)/4}
$$

method used when:

$$
p \equiv 3 \pmod{4}
$$

---

# 2. Pre-computed Constants (Tonelli–Shanks Setup)

To implement the algorithm, decompose:

$$
p - 1 = Q \cdot 2^S
$$

where \(Q\) is odd.

---

## Scalar Field (\(F_r\))

### \(r - 1\)

$$
21888242871839275222246405745257275088548364400416034343698204186575808495616
$$

### \(S_r\)

Number of trailing zeros in binary:

$$
S_r = 28
$$

### \(Q_r = \frac{r - 1}{2^{28}}\)

```text
0x069c133e06a8a35d79044247a1928014582f094f9e61257497d34199
```

### \(z_r\)

Quadratic non-residue in \(F_r\):

$$
z_r = 5
$$

This is the smallest positive integer such that:

$$
\left(\frac{z}{r}\right) = -1
$$

---

## Base Field (\(F_q\))

### \(q - 1\)

$$
21888242871839275222246405745257275088696311157297823662689037894645226208582
$$

### \(S_q\)

$$
S_q = 1
$$

### \(Q_q = \frac{q - 1}{2^1}\)

```text
0x183227397098d014dc2822db40c0ac2ecbc0b548b438e5469e10460b6c3e7ea3
```

### \(z_q\)

Quadratic non-residue in \(F_q\):

$$
z_q = 2
$$

This is the smallest positive integer such that:

$$
\left(\frac{z}{q}\right) = -1
$$

---

# 3. The Algorithm: `sqrt(a, p)`

## Input

- \(a \in F_p\)
- Prime \(p\)
- Pre-computed values \(Q, S, z\)

## Output

A value \(x\) such that:

$$
x^2 \equiv a \pmod{p}
$$

or `None` if no square root exists.

---

## Step 1: Handle Trivial Cases

1. If:

   $$
   a = 0
   $$

   return:

   ```text
   0
   ```

2. Compute Euler’s Criterion:

   $$
   a^{(p-1)/2} \pmod{p}
   $$

   If the result is:

   $$
   p - 1
   $$

   return:

   ```text
   None
   ```

   since \(a\) is a quadratic non-residue.

---

## Step 2: Initialize

Set:

$$
M = S
$$

$$
c = z^Q \pmod{p}
$$

$$
t = a^Q \pmod{p}
$$

$$
R = a^{(Q+1)/2} \pmod{p}
$$

---

## Step 3: Iterate

While:

$$
t \neq 0
\quad \text{and} \quad
t \neq 1
$$

perform the following:

### 1. Find the smallest integer \(i\)

Find the smallest:

$$
0 < i < M
$$

such that:

$$
t^{2^i} \equiv 1 \pmod{p}
$$

#### Logic

Repeatedly square \(t\) until it becomes \(1\).

---

### 2. Compute \(b\)

$$
b = c^{2^{M-i-1}} \pmod{p}
$$

---

### 3. Update Variables

$$
M = i
$$

$$
c = b^2 \pmod{p}
$$

$$
t = t \cdot b^2 \pmod{p}
$$

$$
R = R \cdot b \pmod{p}
$$

---

## Step 4: Termination

Return:

$$
R
$$

where:

- \(R\) is one square root
- The second root is:

$$
-R \equiv p - R
$$

---

# 4. Integration Logic for Protocol Engineer

## G1 Point Decompression

Given:

- \(x\)
- `sign_bit`

perform:

### 1. Compute \(y^2\)

$$
y_{\text{squared}} = x^3 + 3 \pmod{q}
$$

---

### 2. Compute Square Root

$$
y = \text{sqrt\_fq}(y_{\text{squared}})
$$

---

### 3. Validate

If the result is `None`, the point is invalid.

---

### 4. Normalize Sign

If:

$$
y \bmod 2 \neq \text{sign\_bit}
$$

then set:

$$
y = q - y
$$

---

### 5. Return Point

$$
(x, y)
$$

---

# 5. Implementation Notes

## Modular Exponentiation

Use:

- Fixed-window exponentiation, or
- Montgomery ladder

for efficient and constant-time modular arithmetic.

> Note: The Tonelli–Shanks loop itself is naturally variable-time because the number of iterations depends on the input value.

---

## Quadratic Residue Check

The Euler’s Criterion step:

$$
a^{(p-1)/2}
$$

is mandatory to avoid infinite loops on non-residues.

---

## Pre-computation Optimization

The value:

$$
z^Q \pmod{p}
$$

can also be pre-computed to save one exponentiation during runtime.
