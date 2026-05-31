export const mockDocs = {
  cryptoMath: `
# Cryptographic Primitives in Soroban-ZK-Std

This standard library provides optimized ZK primitives. Below are the core mathematical operations supported.

## BN254 Field Equations

The scalar field $\\mathbb{F}_r$ and base field $\\mathbb{F}_q$ are used extensively. The pairing is a bilinear map:

$$ e: \\mathbb{G}_1 \\times \\mathbb{G}_2 \\rightarrow \\mathbb{G}_T $$

Where:
- $\\mathbb{G}_1$ is a subgroup of $E(\\mathbb{F}_q): y^2 = x^3 + 3$
- $\\mathbb{G}_2$ is a subgroup of $E'(\\mathbb{F}_{q^2}): y^2 = x^3 + 3 / (i+9)$

### Pairing Equation

The optimal Ate pairing evaluates:

$$ e(P, Q) = f_{r, Q}(P)^{(q^k - 1)/r} $$

## Poseidon Hash Notation

Poseidon is a ZK-friendly hash function based on the Hades design strategy. It operates directly on field elements. The permutation function applies $R_f$ full rounds and $R_p$ partial rounds.

For state vector $S$, the round function is:

$$ S_{i+1} = M \\times \\text{S-Box}(S_i + C_i) $$

Where:
- $C_i$ are the round constants.
- $M$ is the MDS matrix.
- $\\text{S-Box}(x) = x^\\alpha$ (typically $\\alpha = 5$ for BN254).

## Modular Arithmetic & Fermat Inversion

Inversion in the scalar field is computed using Fermat's Little Theorem, which avoids the need for extended Euclidean algorithms inside the SNARK circuit.

For any non-zero element $a \\in \\mathbb{F}_p$, its inverse is:

$$ a^{-1} \\equiv a^{p-2} \\pmod{p} $$

## Code Example

Here is how you might implement a simple pairing check in Rust:

\`\`\`rust
use soroban_zk_std::pairing::{G1Affine, G2Affine, pairing_check};

pub fn verify_pairing(p1: G1Affine, q1: G2Affine, p2: G1Affine, q2: G2Affine) -> bool {
    // Checks if e(p1, q1) == e(p2, q2)
    // Equivalent to e(p1, q1) * e(-p2, q2) == 1
    pairing_check(&[(p1, q1), (-p2, q2)])
}
\`\`\`
  `,
};
