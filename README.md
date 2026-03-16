## The Unsolved Problem in ZK
While Protocol 25 added the mathematical "primitives" (the ability to do pairing checks on the BN254 curve), there is a massive gap in Developer Experience (DX).

Currently, if a developer wants to build a private stablecoin or a "ZK-Login" on Stellar, they have to manually handle:

**Field element conversion**: Moving between internal Rust representations and Soroban’s U256 types.

**Constraint mapping**: Writing manual logic for Poseidon hashing in the host environment.

**Proof abstraction**: There is no standard "Standard Library" for common ZK proofs (like UltraHonk or Groth16) specifically optimized for Soroban’s gas limits.


The Protocol 25 upgrade introduced native host functions for BN254 (bn254_g1_add, bn254_multi_pairing_check) and Poseidon hash permutations. However, there is currently no idiomatic Rust library that abstracts these low-level host calls into a developer-friendly SDK.

**Soroban-ZK-Std** will bridge this gap, providing a "standard library" for developers to build private RWA (Real World Asset) protocols, shielded transfers, and verifiable credentials on Stellar with minimal cryptographic overhead.
