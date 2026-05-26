# Fiat-Shamir Transcript — Non-Interactive Challenge Generation

## Purpose

Converts an interactive proof system into a non-interactive one by deriving
verifier challenges deterministically from a hash of the transcript so far.

## State Machine

```
State = { hash_state: Poseidon2State, domain_sep: [u8] }
```

### Initialization

```
transcript.init(domain_separator: &[u8]):
    state ← Poseidon2Sponge::new()
    state.absorb(domain_separator as field elements)
```

### Absorbing a Commitment

```
transcript.absorb(label: &str, point: G1Affine):
    state.absorb([label_as_field_element, point.x, point.y])
```

### Squeezing a Challenge

```
transcript.challenge(label: &str) → Fr:
    state.absorb([label_as_field_element])
    raw ← state.squeeze()
    return raw mod r   // reduce into BN254 scalar field
```

## Security Properties

- **Binding**: The prover cannot change earlier messages after seeing a challenge.
- **Hiding**: Challenges are pseudorandom given the Poseidon2 preimage resistance.
- **Domain Separation**: Each protocol uses a unique domain separator to prevent
  cross-protocol attacks.

## Challenge Sequence for PLONK

```
β  ← transcript.challenge("beta")   // permutation argument
γ  ← transcript.challenge("gamma")  // permutation argument
α  ← transcript.challenge("alpha")  // linearization
ζ  ← transcript.challenge("zeta")   // evaluation point
v  ← transcript.challenge("v")      // opening combination
u  ← transcript.challenge("u")      // batch opening
```

## no_std Implementation Note

The transcript uses only `Poseidon2Sponge` (which delegates to the CAP-0075
host call) and `Fr` arithmetic — no heap allocation required.
