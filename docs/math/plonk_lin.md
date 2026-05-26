# PLONK Linearization Polynomial

## Gate Equation

For a 3-wire arithmetic gate with wire values `(a, b, c)` and selectors
`(q_L, q_R, q_O, q_M, q_C)`:

```
q_L·a + q_R·b + q_O·c + q_M·a·b + q_C = 0
```

## Permutation Argument

The grand product polynomial `Z(X)` encodes the copy constraints. At
evaluation point `ζ`:

```
Z(ζ)·[(a(ζ) + β·ζ + γ)(b(ζ) + β·k₁·ζ + γ)(c(ζ) + β·k₂·ζ + γ)]
  - Z(ζ·ω)·[(a(ζ) + β·σ₁(ζ) + γ)(b(ζ) + β·σ₂(ζ) + γ)(c(ζ) + β·σ₃(ζ) + γ)] = 0
```

where `k₁, k₂` are coset generators and `σ₁, σ₂, σ₃` are permutation polynomials.

## Linearization

To reduce the verifier's work, the prover sends evaluations at `ζ` and the
verifier reconstructs the linearized polynomial `r(X)`:

```
r(X) = q_M(ζ)·a(ζ)·b(ζ)·q_L(X)
     + a(ζ)·q_L(X)
     + b(ζ)·q_R(X)
     + c(ζ)·q_O(X)
     + q_C(X)
     + α·[(a(ζ) + β·ζ + γ)(b(ζ) + β·k₁·ζ + γ)(c(ζ) + β·k₂·ζ + γ)·Z(X)]
     - α·[(a(ζ) + β·σ₁(ζ) + γ)(b(ζ) + β·σ₂(ζ) + γ)·β·Z_ω(ζ)·σ₃(X)]
     + α²·L₁(ζ)·Z(X)
```

## Verification Equation

The verifier checks:

```
r(ζ) + t_lo(ζ)·Z_H(ζ) + t_mid(ζ)·ζⁿ⁺² + t_hi(ζ)·ζ²⁽ⁿ⁺²⁾ = 0
```

where `Z_H(ζ) = ζⁿ - 1` is the vanishing polynomial evaluation.
