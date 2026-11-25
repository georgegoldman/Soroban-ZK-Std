# BN254 Square Root Algorithm Specification

## Context: Modular Square Roots in \(\mathbb{F}_r\) and \(\mathbb{F}_q\)

---

## 1. Field Parameters

The BN254 curve involves two primary fields:

- **Scalar Field (\(\mathbb{F}_r\))** — the order of the prime subgroup:

  $$
  r = 21888242871839275222246405745257275088548364400416034343698204186575808495617
  $$

  ```text
  0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
  ```

- **Base Field (\(\mathbb{F}_q\))** — the field for curve coordinates:

  $$
  q = 21888242871839275222246405745257275088696311157297823662689037894645226208583
  $$

  ```text
  0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47
  ```

These are distinct moduli with different square-root algorithms:

- \(q \equiv 3 \pmod 4\). For a quadratic residue \(a \in \mathbb{F}_q\),
  compute the root as:

$$
a^{(q+1)/4} \pmod q
$$

- \(r \equiv 1 \pmod 4\), with \(2^{28} \mid (r-1)\). A square root in
  \(\mathbb{F}_r\) therefore uses **Tonelli–Shanks** with 2-adicity \(S_r=28\).

---

# 2. Pre-computed Constants for Tonelli–Shanks in \(\mathbb{F}_r\)

Decompose the scalar-field modulus:

$$
r - 1 = Q_r \cdot 2^{S_r}
$$

where \(Q_r\) is odd.

---

## Scalar Field (\(\mathbb{F}_r\))

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
0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f
```

### \(z_r\)

Quadratic non-residue in \(\mathbb{F}_r\):

$$
z_r = 5
$$

This is the smallest positive integer such that:

$$
\left(\frac{5}{r}\right) = -1
$$

---

# 3. The Algorithm: `sqrt(a, r)`

## Input

- \(a \in \mathbb{F}_r\)
- Scalar-field prime \(r\)
- Pre-computed values \(Q_r, S_r, z_r\)

## Output

A value \(x\) such that:

$$
x^2 \equiv a \pmod{r}
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
   a^{(r-1)/2} \pmod{r}
   $$

   If the result is:

   $$
   r - 1
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
M = S_r
$$

$$
c = z_r^{Q_r} \pmod{r}
$$

$$
t = a^{Q_r} \pmod{r}
$$

$$
R = a^{(Q_r+1)/2} \pmod{r}
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
t^{2^i} \equiv 1 \pmod{r}
$$

#### Logic

Repeatedly square \(t\) until it becomes \(1\).

---

### 2. Compute \(b\)

$$
b = c^{2^{M-i-1}} \pmod{r}
$$

---

### 3. Update Variables

$$
M = i
$$

$$
c = b^2 \pmod{r}
$$

$$
t = t \cdot b^2 \pmod{r}
$$

$$
R = R \cdot b \pmod{r}
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
-R \equiv r - R \pmod{r}
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
y = y_{\text{squared}}^{(q+1)/4} \pmod q
$$

---

### 3. Validate

Verify \(y^2 \equiv y_{\text{squared}} \pmod q\); if not, the point is invalid.

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

The current `Bn254::sqrt_fq` in `lib.rs` computes \(a^{(q+1)/4}\) through
`pow_fq` and the binary `pow_mod` routine. The exponent has 252 bits and 109
set bits, so this implementation performs 252 modular squarings and 109
conditional modular multiplications. These are operation counts for the
current implementation, not a claim about a fixed instruction cost.

The Tonelli–Shanks loop for \(\mathbb{F}_r\) is naturally variable-time because
the number of iterations depends on the input value.

---

## Quadratic Residue Check

The Euler’s Criterion step for \(\mathbb{F}_r\):

$$
a^{(r-1)/2}
$$

is mandatory to avoid infinite loops on non-residues.

---

## Pre-computation Optimization

For \(\mathbb{F}_r\), the value:

$$
z_r^{Q_r} \pmod{r}
$$

can also be pre-computed to save one exponentiation during runtime.
