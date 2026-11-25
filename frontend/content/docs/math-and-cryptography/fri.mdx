---
title: "FRI Proximity Testing"
description: "Mathematical specification for Reed-Solomon proximity testing in Soroban-ZK-Std"
protocol: "25"
cap: "CAP-0075"
---

# FRI Proximity Testing

## Mathematical Specification for Reed-Solomon Proximity Testing

**Soroban-ZK-Std**

---

# 1. Introduction

Fast Reed-Solomon Interactive Oracle Proofs of Proximity (FRI) provide an efficient method for proving that a function is close to a low-degree polynomial.

FRI is a fundamental component of modern STARK proof systems and enables scalable verification of polynomial constraints without requiring the verifier to inspect the entire evaluation domain.

The protocol repeatedly reduces the size of an evaluation domain while preserving information about polynomial degree. Through successive folding operations and randomized sampling, a verifier obtains high confidence that a submitted codeword is close to a valid Reed-Solomon codeword.

This document specifies the mathematical structure of the FRI proximity testing procedure.

---

# 2. Reed-Solomon Codes

Let:

$$\mathbb{F}$$

denote a finite field.

Let:

$$D = [x_0,x_1,\ldots,x_{N-1}]$$

be an evaluation domain.

Given a polynomial:

$$f(X)$$

with degree:

$$\deg(f) < d$$

the corresponding Reed-Solomon codeword is:

$$(f(x_0),f(x_1),\ldots,f(x_{N-1}))$$

A codeword is considered valid if it corresponds to evaluations of a sufficiently low-degree polynomial.

---

# 3. Goal of Proximity Testing

The prover submits evaluations:

$$v = (v_0,v_1,\ldots,v_{N-1})$$

and claims that:

$$v_i = f(x_i)$$

for some polynomial satisfying:

$$\deg(f) < d$$

The verifier's goal is not necessarily to reconstruct the polynomial, but rather to determine whether the submitted evaluations are sufficiently close to a valid Reed-Solomon codeword.

---

# 4. Evaluation Domains

FRI operates over multiplicative subgroups.

Let:

$$D_0$$

be the initial evaluation domain.

Typically:

$$|D_0| = 2^m$$

for some integer:

$$m$$

allowing repeated domain halving during the protocol.

---

# 5. Folding Principle

The central optimization in FRI is the folding operation.

Suppose:

$$f_i(X)$$

is the polynomial represented during round:

$$i$$

The verifier samples a random challenge:

$$\beta_i$$

from the field.

The next polynomial is constructed by combining neighboring evaluations:

$$f_{i+1}(X) = \frac{f_i(X)+f_i(-X)}{2} + \beta_i \cdot \frac{f_i(X)-f_i(-X)}{2X}$$

This operation approximately halves the degree.

---

# 6. Degree Reduction

If:

$$\deg(f_i)=d_i$$

then after folding:

$$\deg(f_{i+1}) \approx \left\lfloor \frac{d_i}{2} \right\rfloor$$

Thus repeated folding rapidly reduces polynomial complexity.

---

# 7. Domain Reduction

Each folding round also reduces the evaluation domain.

Given:

$$D_i$$

the next domain becomes:

$$D_{i+1} = [x^2 \mid x \in D_i]$$

Since opposite points:

$$x \quad\text{and}\quad -x$$

map to the same square, the domain size is halved.

Therefore:

$$|D_{i+1}| =\frac{|D_i|}{2}$$

---

# 8. Recursive Proximity Loop

The FRI protocol repeatedly performs:

1. Challenge generation
2. Folding
3. Domain reduction
4. Commitment generation

For round:

$$i$$

the procedure is:

$$(D_i,f_i) \rightarrow (D_{i+1},f_{i+1})$$

until the polynomial degree becomes sufficiently small.

---

# 9. Terminal Polynomial

After enough folding rounds, the remaining polynomial:

$$f_t$$

has very small degree.

The prover reveals its coefficients directly.

The verifier can then explicitly evaluate:

$$f_t$$

and compare against the final committed evaluations.

---

# 10. Consistency Queries

To verify correctness, the verifier samples random positions from the original domain.

For a queried point:

$$x$$

the prover supplies:

* evaluation at (x),
* evaluation at (-x),
* Merkle authentication paths.

The verifier checks that these values satisfy the folding equation used to derive the next round.

---

# 11. Merkle Commitments

Each round's evaluation table is committed using a Merkle tree.

Let:

$$R_i$$

denote the root corresponding to round:

$$i$$

The verifier uses authentication paths to ensure queried values originate from the committed codeword.

---

# 12. Soundness Intuition

If the original evaluations are far from any low-degree polynomial, the folding relations will eventually become inconsistent.

Random verifier challenges:

$$\beta_i$$

prevent the prover from predicting which algebraic relationships will be checked.

Consequently, an invalid codeword passes verification only with negligible probability.

---

# 13. Why Folding Works

The folding operation separates:

* even polynomial components,
* odd polynomial components.

Any polynomial:

$$f(X)$$

can be written as:

$$f(X) = f_{\text{even}}(X^2) + Xf_{\text{odd}}(X^2)$$

FRI combines these components into a single lower-degree polynomial while preserving enough information to verify correctness.

---

# 14. Security Considerations

The security of FRI depends on:

* low-degree testing soundness,
* random verifier challenges,
* collision-resistant Merkle commitments,
* correct domain construction.

Implementations must ensure deterministic folding operations and consistent challenge generation.

---

# 15. Relevance to STARK Systems

FRI serves as the primary low-degree testing mechanism in many STARK constructions.

Its advantages include:

* logarithmic verifier complexity,
* efficient proof generation,
* scalability to large evaluation domains,
* transparency without trusted setup.

These properties make FRI one of the most important building blocks in modern proof systems.

---

# 16. Summary

FRI proximity testing provides an efficient method for verifying that a collection of evaluations is close to a Reed-Solomon codeword.

The protocol repeatedly folds evaluation tables, reduces polynomial degree, and shrinks the evaluation domain while preserving algebraic consistency.

Through randomized consistency checks and recursive domain reduction, FRI achieves scalable low-degree testing suitable for large-scale zero-knowledge proof systems.