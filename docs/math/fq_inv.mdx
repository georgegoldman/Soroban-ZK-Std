# Fq Modular Inversion Algorithm

## 1. Introduction

Let $\mathbb{F}_q$ be a finite field of prime order $q$. For any non-zero element $a \in \mathbb{F}_q$, the **modular inverse** $a^{-1}$ is the unique element in $\mathbb{F}_q$ satisfying

$$
a \cdot a^{-1} \equiv 1 \pmod{q}.
$$

Because $q$ is prime, every non-zero element of $\mathbb{F}_q$ is coprime to $q$, and therefore a multiplicative inverse exists and is unique. Computing this inverse efficiently is a fundamental operation in cryptographic arithmetic.

This document specifies the **Binary Extended Euclidean Algorithm (Binary EEA)** for computing $a^{-1} \bmod q$, a division-free, shift-based alternative to the standard extended Euclidean algorithm.

## 2. Finite Field Background

Let $q$ be a prime. The finite field $\mathbb{F}_q$ consists of the set $\{0, 1, \dots, q-1\}$ together with addition and multiplication modulo $q$. The multiplicative group $\mathbb{F}_q^* = \mathbb{F}_q \setminus \{0\}$ is cyclic of order $q-1$.

For $a \in \mathbb{F}_q^*$, the modular inverse $a^{-1}$ is defined by

$$
a \cdot a^{-1} \equiv 1 \pmod{q}.
$$

Existence follows from the fact that $\gcd(a, q) = 1$ whenever $q$ is prime and $a \not\equiv 0 \pmod{q}$.

## 3. Bézout Identity

The extended Euclidean algorithm computes integers $x$ and $y$ satisfying the **Bézout identity**

$$
a \cdot x + q \cdot y = \gcd(a, q).
$$

Since $q$ is prime and $a \not\equiv 0 \pmod{q}$, we have $\gcd(a, q) = 1$, hence

$$
a \cdot x + q \cdot y = 1.
$$

Reducing both sides modulo $q$ gives

$$
a \cdot x \equiv 1 \pmod{q},
$$

so $x \bmod q$ is precisely the modular inverse $a^{-1} \bmod q$.

## 4. Binary Extended Euclidean Algorithm

The standard extended Euclidean algorithm uses integer division (with remainder) to reduce the pair $(a, q)$ to $(g, 0)$. The binary variant replaces the expensive division operations with inexpensive right shifts, exploiting the following observations for odd moduli $q$:

- If both $u$ and $v$ are even, then $\gcd(u, v) = 2 \cdot \gcd(u/2, v/2)$.
- If $u$ is even and $v$ is odd, then $\gcd(u, v) = \gcd(u/2, v)$.
- If both $u$ and $v$ are odd, then $\gcd(u, v) = \gcd(|u - v|/2, \min(u, v))$.

The algorithm maintains Bézout coefficients $(x_1, x_2)$ and $(y_1, y_2)$ such that the invariants

$$
u \equiv a \cdot x_1 + q \cdot y_1 \pmod{2^m}, \qquad
v \equiv a \cdot x_2 + q \cdot y_2 \pmod{2^m}
$$

hold throughout execution for a sufficiently large modulus $2^m$ (typically $m$ is the bit length of $q$). Upon termination, $u = 1$ and the corresponding coefficient $x_1$ yields the inverse.

The gcd is preserved because each transformation corresponds to one of the elementary gcd identities above, and the coefficients track the linear combination that expresses the current values in terms of $a$ and $q$.

## 5. Algorithm Description

The algorithm proceeds as follows:

1. **Initialize** state variables:
   - $u \gets a$, $v \gets q$
   - Bézout coefficients for $u$: $x_1 \gets 1$, $y_1 \gets 0$
   - Bézout coefficients for $v$: $x_2 \gets 0$, $y_2 \gets 1$

2. **Remove common factors of two:** While both $u$ and $v$ are even, divide both by 2.

3. **Reduce $u$:** While $u$ is even, divide $u$ by 2. If the corresponding Bézout coefficients $(x_1, y_1)$ become even, also divide them by 2; otherwise add $q$ to $x_1$ (or subtract $a$ from $y_1$) to make them even before dividing.

4. **Reduce $v$:** While $v$ is even, apply the analogous reduction to $v$ and $(x_2, y_2)$.

5. **Difference step:** When both $u$ and $v$ are odd, set
   $$u \gets |u - v| / 2, \qquad v \gets \min(u, v).$$
   Update the Bézout coefficients accordingly:
   - If $u > v$, subtract the $v$-coefficients from the $u$-coefficients, then divide the result by 2 (with the same parity adjustment as above).
   - Otherwise, subtract the $u$-coefficients from the $v$-coefficients analogously.

6. **Loop:** Repeat steps 3–5 until $v = 0$ or $u = 0$.

7. **Return:** The surviving non-zero value is $\gcd(a, q) = 1$. The associated Bézout coefficient reduced modulo $q$ is $a^{-1}$.

## 6. Pseudocode

```
Input:  a (non-zero integer), q (prime modulus)
Output: a^{-1} mod q

function binary_inverse(a, q):
    u := a
    v := q
    x1 := 1, x2 := 0

    // Remove common factors of 2
    while u is even and v is even:
        u := u >> 1
        v := v >> 1

    // Main loop
    while u != 0 and v != 0:
        while u is even:
            u := u >> 1
            if x1 is even:
                x1 := x1 >> 1
            else:
                x1 := (x1 + q) >> 1

        while v is even:
            v := v >> 1
            if x2 is even:
                x2 := x2 >> 1
            else:
                x2 := (x2 + q) >> 1

        if u >= v:
            u := u - v
            x1 := x1 - x2
        else:
            v := v - u
            x2 := x2 - x1

    // One of u, v is now 0; the other holds gcd
    if u == 1:
        return x1 mod q
    else if v == 1:
        return x2 mod q
    else:
        error("inverse does not exist")
```

## 7. Worked Example

Compute $7^{-1} \bmod 19$.

$$
\begin{array}{c|c|c|c|c}
\text{Step} & u & v & x_1 & x_2 \\ \hline
0 & 7 & 19 & 1 & 0 \\
1 & 7 & 19 & 1 & 0 \\
2 & 7 & 19 & 1 & 0 \\
3 & 7 & 12 & 1 & - \\
 & 7 & 6 & 1 & - \\
 & 7 & 3 & 1 & - \\
 & 7 & 3 & 1 & - \\
4 & 7 & 3 & 1 & - \\
5 & 2 & 3 & -3 & - \\
 & 1 & 3 & -3 & - \\
 & 1 & 3 & -3 & - \\
 & 1 & 3 & -3 & - \\
6 & 1 & 2 & -3 & - \\
\dots
\end{array}
$$

We elaborate the iterations:

1. **Init:** $u = 7$, $v = 19$, $x_1 = 1$, $x_2 = 0$.

2. **$u$ odd, $v$ odd** — skip even-reduction.

3. **$u < v$:** $v \gets v - u = 12$, $x_2 \gets x_2 - x_1 = -1$.

4. **Reduce $v$ (even):**
   - $v = 12 \to 6$, $x_2 = -1$ (odd) $\to x_2 = (-1 + 19)/2 = 9$.
   - $v = 6 \to 3$, $x_2 = 9$ (odd) $\to x_2 = (9 + 19)/2 = 14$.

5. **$u < v$:** $v \gets v - u = 3 - 7 \to$ since $u < v$ doesn't hold here, we actually have $7 > 3$, so $u \gets u - v = 4$, reduce: $u = 4 \to 2$, $x_1 = 1$ (odd) $\to x_1 = (1 + 19)/2 = 10$. Then $u = 2 \to 1$, $x_1 = 10$ (even) $\to x_1 = 5$.

   We reach $u = 1$, $v = 3$. Since $u = 1$, the inverse is $x_1 \bmod 19 = 5$.

   Verification: $7 \times 5 = 35 \equiv 35 - 19 = 16 \equiv 16 - 19 = -3 \equiv 16\ \text{?}$ Let us check carefully:

Actually, recompute more carefully:

| Step | Operation | $u$ | $v$ | $x_1$ | $x_2$ |
|------|-----------|-----|-----|-------|-------|
| 0 | Init | 7 | 19 | 1 | 0 |
| 1 | $v \gets v - u$ ($19 - 7$) | 7 | 12 | 1 | $-1$ |
| 2 | $v$ even: $v \gets v/2$; $x_2$ odd $\to$ $( -1 + 19)/2 = 9$ | 7 | 6 | 1 | 9 |
| 3 | $v$ even: $v \gets v/2$; $x_2$ odd $\to$ $(9 + 19)/2 = 14$ | 7 | 3 | 1 | 14 |
| 4 | $u > v$: $u \gets u - v$ ($7 - 3$) | 4 | 3 | $-13$ | 14 |
| 5 | $u$ even: $u \gets u/2$; $x_1$ odd $\to$ $(-13 + 19)/2 = 3$ | 2 | 3 | 3 | 14 |
| 6 | $u$ even: $u \gets u/2$; $x_1$ odd $\to$ $(3 + 19)/2 = 11$ | 1 | 3 | 11 | 14 |
| 7 | $u = 1$: **terminate** | 1 | 3 | **11** | 14 |

Result: $x_1 = 11$, and $11 \bmod 19 = 11$. Verification: $7 \times 11 = 77 \equiv 77 - 3 \times 19 = 77 - 57 = 20 \equiv 1 \pmod{19}$. Hence $7^{-1} \equiv 11 \pmod{19}$.

## 8. Complexity Analysis

**Time complexity:** The Binary EEA runs in $O(\log q)$ bit operations. Each iteration eliminates at least one factor of two from $u$ or $v$, and the values at most double in bit length. The total number of iterations is $O(\log q)$, with each iteration requiring $O(1)$ word-level shifts and additions.

**Space complexity:** $O(1)$ auxiliary space — only a handful of multi-precision integers are stored.

**Comparison with Fermat's Little Theorem method:**

| Criterion | Binary EEA | Fermat $a^{q-2} \bmod q$ |
|-----------|------------|--------------------------|
| Operations | Shifts, additions, subtractions | Modular multiplications |
| Typical speed | $\approx 2 \log_2 q$ shifts | $\approx 1.5 \log_2 q$ multiplications |
| Constant factors | Very low (word ops) | Higher (multiplication) |
| Suitability | General modulus | Prime modulus only |

While both methods are $O(\log q)$, the Binary EEA typically outperforms exponentiation for general-purpose inversion because shifts and additions are significantly cheaper than modular multiplications on most architectures. The Fermat method is simpler to implement and constant-time if the exponentiation is constant-time, but the Binary EEA can also be made constant-time with careful implementation.

## 9. Cryptographic Relevance

**Elliptic curve cryptography (ECC):** Point addition and scalar multiplication on elliptic curves over $\mathbb{F}_q$ require modular inversion for affine coordinate arithmetic. Every point doubling and point addition in affine coordinates involves a field inversion, making the efficiency of $a^{-1} \bmod q$ critical for performance. Many implementations switch to projective coordinates to defer inversions, but at least one inversion per scalar multiplication remains.

**Zero-knowledge proofs:** Protocols such as Bulletproofs, PLONK, and Halo 2 rely heavily on field arithmetic for polynomial commitment schemes and relation checks. Inversion appears in:
- Lagrange basis evaluation and interpolation.
- Barycentric formula evaluation of polynomials.
- Fiat-Shamir transform components requiring modular division.
- Recursive proof composition where field element inversion occurs in-circuit.

**Optimizations in finite field arithmetic:** The Binary EEA is the foundation for many optimized inversion implementations:
- It can be specialized to constant-time form to prevent side-channel attacks.
- It naturally handles arbitrary moduli, unlike Montgomery inversion which requires precomputed constants.
- The shift-based nature maps efficiently to hardware implementations and SIMD architectures.
- Combined with Montgomery multiplication, it enables efficient inversion in both prime and binary fields.

## 10. Conclusion

Modular inversion in $\mathbb{F}_q$ is a cornerstone operation in cryptographic computation. The Binary Extended Euclidean Algorithm provides an efficient, division-free method for computing $a^{-1} \bmod q$ using only shifts, additions, and subtractions. Its $O(\log q)$ complexity, small constant factors, and suitability for constant-time implementation make it a practical choice across elliptic curve cryptography, zero-knowledge proofs, and general finite field arithmetic. Understanding this algorithm is essential for engineers working with field operations at the cryptographic protocol level.
