# Non-Native Field Addition with Carry Tracking

<div align="center">

## Mathematical Specification for Foreign-Field Addition in ZK Circuits

**Soroban-ZK-Std**

</div>

---

# 1. Introduction

In zero-knowledge systems, it is often necessary to perform arithmetic over a field that differs from the proving system's native field. Such arithmetic is referred to as **non-native field arithmetic** or **foreign-field arithmetic**.

Because the target field modulus may exceed the size of a single native field element, foreign-field elements must be represented as a sequence of smaller components called **limbs**.

This document specifies the mathematical constraints and carry-tracking rules required to safely perform non-native field addition inside a constraint system.

---

# 2. Limb Representation

Let:

* $p$ denote the modulus of the foreign field
* $B$ denote the limb base
* $n$ denote the number of limbs

A foreign-field element $A$ is represented as:

$$A = \sum_{i=0}^{n-1} a_i B^i$$

where each limb satisfies:

$$0 \le a_i < B$$

Similarly, another element $C$ is represented as:

$$C = \sum_{i=0}^{n-1} c_i B^i$$

---

# 3. Goal of Addition

Given two foreign-field elements:

$$A = (a_0, a_1, \dots, a_{n-1})$$

$$C = (c_0, c_1, \dots, c_{n-1})$$

we wish to compute:

$$R = A + C$$

while ensuring that:

1. limb bounds remain valid,
2. carries are propagated correctly,
3. reconstruction equals canonical integer addition.

---

# 4. Carry-Tracking Addition

Addition is performed independently on each limb.

For each limb index $i$, define:

$$s_i = a_i + c_i + k_i$$

where:

* $s_i$ is the intermediate sum,
* $k_i$ is the incoming carry.

The sum is decomposed into:

$$s_i = r_i + k_{i+1}B$$

where:

* $r_i$ is the resulting limb,
* $k_{i+1}$ is the outgoing carry.

Thus:

$$r_i = s_i \bmod B$$

$$k_{i+1} = \left\lfloor \frac{s_i}{B} \right\rfloor$$

---

# 5. Constraint Formulation

Inside a zero-knowledge circuit, the carry relation is enforced algebraically.

For each limb:

$$a_i + c_i + k_i - r_i = k_{i+1}B$$

This constraint guarantees:

* correctness of carry propagation,
* correctness of limb decomposition,
* consistency with integer addition.

---

# 6. Reconstruction Correctness

The reconstructed result is:

$$R = \sum_{i=0}^{n-1} r_i B^i$$

Substituting the carry equation:

$$a_i + c_i + k_i = r_i + k_{i+1}B$$

and summing across all limbs yields:

$$A + C = R + k_n B^n$$

where $k_n$ is the final carry.

This demonstrates that the limb decomposition preserves standard integer addition.

---

# 7. Carry Bounds

To maintain soundness, carry values must remain bounded.

Assuming:

$$0 \le a_i < B$$

$$0 \le c_i < B$$

$$0 \le k_i \le 1$$

then:

$$s_i < 2B + 1$$

which implies:

$$k_{i+1} \in \{0, 1\}$$

for sufficiently chosen limb bases.

This boundedness property is essential for preventing invalid witness assignments.

---

# 8. Why Carry Tracking Matters

Without explicit carry constraints, a prover could assign arbitrary limb values that satisfy local equations while failing to correspond to valid integer arithmetic.

Carry tracking ensures:

* arithmetic consistency,
* canonical decomposition,
* sound witness generation,
* deterministic reconstruction.

These guarantees are foundational for secure non-native arithmetic inside recursive proof systems and elliptic-curve operations.

---

# 9. Intuition

Non-native addition behaves identically to ordinary positional addition.

For example, in base 10:

$$789 + 456$$

produces carries during each digit addition:

$$9 + 6 = 15$$

Write:

* $5$ as the current digit,
* carry $1$ into the next position.

Non-native field arithmetic applies the same principle using large cryptographic bases such as:

$$B = 2^{16}, \quad 2^{32}, \quad 2^{64}$$

instead of decimal digits.

---

# 10. Security Considerations

All limb operations and carry propagation rules must be implemented in constant time.

Failure to enforce bounded carries or canonical decomposition may permit:

* invalid witness constructions,
* malformed field representations,
* soundness violations in recursive systems.

For this reason, every limb decomposition constraint must be enforced explicitly inside the circuit.

---

# 11. Summary

This specification defines a carry-tracked decomposition method for performing non-native field addition within zero-knowledge circuits.

The construction guarantees:

* correctness of reconstruction,
* bounded carry propagation,
* compatibility with limb-based representations,
* algebraic enforceability inside constraint systems.

These properties make the method suitable for efficient foreign-field arithmetic in constrained proving environments such as Soroban-compatible ZK systems.

---