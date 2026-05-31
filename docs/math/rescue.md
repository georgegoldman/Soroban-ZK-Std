# Rescue-Prime Hash Function

<div align="center">

## State Permutation and S-Box Inversion Specification

**Soroban-ZK-Std**

</div>

---

# 1. Introduction

Rescue-Prime is an algebraic hash function designed specifically for zero-knowledge proof systems.

Unlike traditional hash functions such as SHA-256, Rescue-Prime is constructed to minimize arithmetic circuit complexity while maintaining strong cryptographic security.

Its design alternates between nonlinear transformations and linear mixing operations, producing a permutation that is efficient to verify inside finite-field constraint systems.

This document specifies the state permutation process and the S-box inversion mechanism used by Rescue-Prime.

---

# 2. State Representation

Rescue-Prime operates on a state consisting of $t$ field elements.

The state is represented as:

$$\mathbf{s} = (s_0, s_1, \ldots, s_{t-1})$$

where $s_i \in \mathbb{F}_p$ and $\mathbb{F}_p$ denotes the underlying finite field.

---

# 3. Permutation Structure

A Rescue-Prime permutation consists of multiple rounds.

Each round applies:

1. Nonlinear S-box layer
2. Linear MDS matrix layer
3. Round constant addition
4. Inverse S-box layer
5. Second MDS matrix layer
6. Additional round constants

This alternating structure ensures both diffusion and nonlinearity.

---

# 4. Round Constants

For each round $r$, predefined constants are added to the state.

Let:

$$\mathbf{c}^{(r)} = (c_0^{(r)}, c_1^{(r)}, \ldots, c_{t-1}^{(r)})$$

Then:

$$\mathbf{s} \leftarrow \mathbf{s} + \mathbf{c}^{(r)}$$

where addition is performed component-wise.

Round constants prevent structural symmetries and strengthen resistance against cryptanalytic attacks.

---

# 5. Forward S-Box

The primary nonlinear operation is exponentiation by a fixed exponent $\alpha$ chosen such that:

$$\gcd(\alpha, p-1) = 1$$

to ensure invertibility.

The forward S-box is defined as:

$$S(x) = x^\alpha$$

and applied independently to every state element:

$$s_i \leftarrow s_i^\alpha$$

for all state coordinates.

---

# 6. MDS Matrix Mixing

After the S-box layer, the state is multiplied by a Maximum Distance Separable (MDS) matrix $M$.

The new state becomes:

$$\mathbf{s}' = M\mathbf{s}$$

This operation ensures that every output coordinate depends on every input coordinate.

---

# 7. Inverse S-Box

A defining feature of Rescue-Prime is the use of an inverse nonlinear layer.

Let $\alpha^{-1}$ be the multiplicative inverse of $\alpha$ modulo $p-1$, such that:

$$\alpha \cdot \alpha^{-1} \equiv 1 \pmod{p-1}$$

The inverse S-box is:

$$S^{-1}(x) = x^{\alpha^{-1}}$$

Applied component-wise:

$$s_i \leftarrow s_i^{\alpha^{-1}}$$

for every state element.

---

# 8. Why Inversion Works

By Fermat's Little Theorem:

$$x^{p-1} = 1$$

for all nonzero $x \in \mathbb{F}_p$.

Since $\alpha \cdot \alpha^{-1} \equiv 1 \pmod{p-1}$, we obtain:

$$\left(x^\alpha\right)^{\alpha^{-1}} = x$$

Thus the inverse S-box exactly reverses the forward S-box.

---

# 9. Complete Round Definition

One Rescue-Prime round may be expressed as:

$$\mathbf{s} \rightarrow S(\mathbf{s}) \rightarrow M\mathbf{s} \rightarrow \mathbf{s} + \mathbf{c}_1 \rightarrow S^{-1}(\mathbf{s}) \rightarrow M\mathbf{s} \rightarrow \mathbf{s} + \mathbf{c}_2$$

where:

* $S$ is the forward S-box,
* $S^{-1}$ is the inverse S-box,
* $M$ is the MDS matrix.

---

# 10. Security Intuition

The forward S-box introduces nonlinearity.

The MDS layer spreads information across the entire state.

The inverse S-box introduces additional nonlinearity while preserving efficient algebraic representation.

The alternating structure provides strong diffusion while maintaining low constraint complexity in zero-knowledge circuits.

---

# 11. Efficiency in ZK Systems

Rescue-Prime was designed specifically for arithmetic circuits.

Its operations consist primarily of:

* field additions,
* field multiplications,
* exponentiation by fixed exponents,
* matrix multiplication.

These operations translate efficiently into Rank-1 Constraint Systems (R1CS), PLONK-style circuits, and Halo2 circuits.

---

# 12. Relevance to Soroban-ZK-Std

Rescue-Prime provides a ZK-friendly alternative to conventional cryptographic hash functions.

Applications include:

* Merkle trees,
* commitment schemes,
* nullifier generation,
* private state transitions,
* recursive proof systems.

Its algebraic structure makes it particularly suitable for constrained execution environments and proof-generation pipelines.

---

# 13. Security Considerations

Implementations must ensure:

* constant-time field arithmetic,
* correct exponentiation routines,
* valid MDS matrices,
* deterministic round constant generation.

Incorrect parameter selection may weaken diffusion or introduce structural vulnerabilities.

---

# 14. Summary

Rescue-Prime is a permutation-based hash function optimized for zero-knowledge systems.

Its security derives from alternating:

* forward S-box transformations,
* MDS mixing,
* inverse S-box transformations,
* round constant injections.

The use of both exponentiation and inverse exponentiation distinguishes Rescue-Prime from many other ZK-friendly hash functions and enables efficient implementation within finite-field arithmetic circuits.

---