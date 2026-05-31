# ZK Cryptography Glossary

> **A plain-English reference for zero-knowledge cryptography terminology used throughout Soroban-ZK-Std.**

---

## A — Arithmetic Circuit

An **arithmetic circuit** is a computational model where a program is broken down into addition and multiplication gates over a finite field. Think of it as a flowchart where each node is either `+` or `×`, and the wires carry numbers (field elements).

In ZK proving systems, the statement being proved (e.g., "I know a secret preimage of this hash") is first compiled into an arithmetic circuit. The circuit is then translated into a set of polynomial constraints that the prover must satisfy.

> **Analogy:** Like building a circuit board where every component is either an adder or a multiplier, and you want to prove that the whole board computes the right answer without revealing the inputs.

---

## B — BN254 (alt_bn128)

BN254 (also called **alt_bn128**) is an elliptic curve commonly used in zero-knowledge cryptography. Its defining feature is that it supports **bilinear pairings** — a special mathematical operation that is the foundation of efficient ZK proof systems like Groth16.

The "254" refers to the bit length of the prime field. Key properties:
- **Base field modulus (p):** 21888242871839275222246405745257275088696311157297823662689037894645226208583
- **Scalar field modulus (r):** 21888242871839275222246405745257275088548364400416034343698204186575808495617

BN254 is the curve natively supported by Stellar Protocol 25's CAP-0075 host functions.

> **Analogy:** BN254 is like a special type of gear that lets you "pair" two numbers together in a way that enables complex proofs. Stellar picked this particular gear because it's well-studied and efficient.

---

## E — ElGamal Encryption

An **asymmetric (public-key) encryption scheme** built on top of elliptic curve Diffie-Hellman. In Soroban-ZK-Std, ElGamal is used for **Viewing Keys** — allowing regulators to decrypt transaction amounts while keeping them hidden from the public.

The ciphertext consists of two points `(C1, C2)` on the BN254 curve. Given the recipient's public key `P = x·G`:
- `C1 = r·G` (ephemeral public key)
- `C2 = M + r·P` (message blinded by shared secret)

Anyone with the private key `x` can recover `M = C2 - x·C1`.

> **Analogy:** Like a locked box where everyone can see the box (C1) and the locked message (C2), but only the regulator has the key to open it.


### Extension Field

An **extension field** is a larger field built on top of a smaller base field. For BN254:
- **Fq** — the base field (elements are single numbers modulo p)
- **Fq²** — a quadratic extension field (elements are pairs `(c0, c1)` representing `c0 + c1·u`, where `u` is a formal square root of a non-square in Fq)

G2 points live in Fq², meaning their coordinates are pairs of numbers rather than single numbers. This is why G2 serialization (128 bytes) is twice as long as G1 serialization (64 bytes).

> **Analogy:** Like complex numbers extend real numbers by adding `i = √-1`. Fq² extends Fq by adding an element that behaves like a square root of some fixed non-square value.

---

## G — G1 and G2

In pairing-based cryptography, the elliptic curve has two related groups:
- **G1** — Points on the BN254 curve over the base field Fq (64 bytes serialized)
- **G2** — Points on the same curve over the extension field Fq² (128 bytes serialized)

Pairings take one point from G1 and one from G2 and produce an output in a target group GT.

> **Analogy:** Think of G1 and G2 as two different types of keys. A pairing is a special lock that requires one key of each type to work.

### Groth16

**Groth16** is a zero-knowledge proving system that produces very small proofs (only 3 group elements = ~200 bytes) with fast verification (a single multi-pairing check). It requires a **trusted setup** ceremony to generate the proving and verification keys.

Pros:
- Smallest proof size of any general-purpose ZK system
- Fastest verification (constant-time, just a pairing check)
- Well-studied and widely deployed

Cons:
- Requires a trusted setup (ceremony must be completed honestly)
- Circuit-specific setup (new circuit = new ceremony)

> **Analogy:** Groth16 is like a pre-assembled lock that a locksmith (trusted setup) built once. Anyone can quickly check if a key works, but building a new lock requires calling the locksmith again.

---

## K — KZG Polynomial Commitment

**KZG** (Kate-Zaverucha-Goldberg) is a polynomial commitment scheme using bilinear pairings. A prover commits to a polynomial and can later reveal evaluations at specific points along with a proof that the evaluation is correct.

KZG commitments are:
- **Succinct:** The commitment is a single group element, regardless of polynomial degree
- **Transparent with setup:** Requires a structured reference string (SRS) from a trusted setup

> **Analogy:** Like sealing a recipe in an envelope. Later, you can open a tiny window to show just one ingredient, and the seal proves you didn't change the recipe.


## M — Merkle Tree

A **Merkle tree** is a hash-based data structure used for efficient membership proofs. Each leaf is a piece of data, each internal node is the hash of its two children, and the root is a single hash representing the entire tree.

In Soroban-ZK-Std, Merkle trees are used in shielded asset contracts to maintain the set of valid deposits without revealing which specific deposit a user is spending.

> **Analogy:** Like having a list of everyone in a building. The Merkle root is like a fingerprint of the entire list. You can prove you're on the list without saying your name — just by showing your branch of the tree.

---

## N — Nullifier

A **nullifier** is a unique identifier that prevents double-spending in privacy systems. When a user spends a shielded asset, they reveal a nullifier that is cryptographically tied to that specific deposit. The system records the nullifier as "spent" so the same deposit cannot be spent twice.

The nullifier is computationally infeasible to link back to the original deposit without knowing the user's secret key.

> **Analogy:** Like tearing a ticket stub in half when you enter a venue. The torn half proves you used the ticket, but nobody can tell which ticket you originally had.

---

## P — Pairing (Bilinear Pairing)

A **bilinear pairing** is a function `e: G1 × G2 → GT` with the property:

```
e(a·P, b·Q) = e(P, Q)^(a·b)
```

This bilinearity is the secret sauce that powers many ZK systems. It allows a verifier to combine multiple checks into a single equation.

Stellar provides a native `bn254_multi_pairing_check` host function (CAP-0075) that evaluates `e(A₁, B₁) · e(A₂, B₂) · ... · e(Aₙ, Bₙ) == 1` in a single atomic operation — **190× faster** than a software-only implementation.

> **Analogy:** A pairing is like a special handshake between two points. The magic property is that doing the handshake with doubled points is the same as doing the handshake twice — which lets you combine many checks into one.

### PLONK

**PLONK** (Permutations over Lagrange-bases for Oecumenical Non-interactive arguments of Knowledge) is a universal zk-SNARK that does not require a circuit-specific trusted setup. Instead, it uses a single structured reference string (SRS) that works for any circuit up to a certain size.

PLONK is more flexible than Groth16 (universal setup) but produces larger proofs and has slightly slower verification.

> **Analogy:** If Groth16 is a custom-built lock for each door, PLONK is a universal lock that can be programmed to fit any door — you just need a master key (the SRS) created once.


## Q — QAP (Quadratic Arithmetic Program)

A **Quadratic Arithmetic Program** is a way of representing an arithmetic circuit as a set of polynomials. This representation is used by Groth16 and other SNARKs to convert circuit satisfaction into a polynomial divisibility check.

The QAP transforms the statement "this circuit is satisfied" into "these polynomials divide evenly," which can be efficiently verified with a pairing check.

> **Analogy:** Like translating a blueprint into a musical score. The QAP lets the verifier "listen" to one note (the pairing check) and confirm the whole song is correct.

---

## S — SNARK

**SNARK** stands for **Succinct Non-interactive ARgument of Knowledge**:
- **Succinct:** Proofs are small (often a few hundred bytes) and fast to verify
- **Non-interactive:** The prover sends a single message; no back-and-forth required
- **Argument:** Soundness is computational (a computationally bounded prover cannot cheat)
- **Knowledge:** The prover demonstrates knowledge of a secret witness

Groth16 and PLONK are both types of SNARKs.

### SNARK vs. STARK

| Feature | SNARK | STARK |
|---------|-------|-------|
| Proof size | ~200 bytes | ~100 KB |
| Verification | Very fast (pairing check) | Slower |
| Setup | Requires trusted setup (or universal SRS) | Transparent (no setup) |
| Post-quantum | No (uses elliptic curves) | Yes (uses hash functions) |
| Gas cost on Stellar | Low (native pairing) | Higher (software-only hashes) |

> **Analogy:** A SNARK is like a tiny key that opens a lock. A STARK is like a large blueprint that proves the lock was built correctly — no secret key needed, but it's much bigger.

---

## T — Trusted Setup

A **trusted setup** is a ceremony that generates the proving and verification keys for a ZK system. It involves multiple participants who each contribute randomness, and as long as at least one participant is honest and destroys their secret, the setup is secure.

Groth16 requires a circuit-specific trusted setup, while PLONK can use a universal setup that works for any circuit.

> **Analogy:** Like having a group of people each mix a secret ingredient into a master recipe. As long as at least one person doesn't peek, the final recipe is secure.


## V — Viewing Key

A **viewing key** is a cryptographic mechanism that allows selective disclosure of private data. In Soroban-ZK-Std, ElGamal encryption is used to create viewing keys for regulators:

1. The transfer amount is encrypted with the regulator's public key
2. The encrypted value `(C1, C2)` is posted on-chain alongside the ZK proof
3. Only the regulator (holding the private key) can decrypt and audit the amount
4. The public sees only cryptographic noise

This provides **configurable privacy** — transactions are private from the public but transparent to authorized auditors.

> **Analogy:** Like a voting booth where the ballot is sealed in an envelope. Everyone can see that a vote was cast (the proof), only election officials can open the envelope to count it (viewing key), and no one can link the vote to the voter (nullifier).

---

## W — Witness

In ZK terminology, the **witness** is the secret information that the prover wants to prove knowledge of, without revealing it. Examples:
- The private key corresponding to a public key
- The preimage of a hash
- The path in a Merkle tree from a leaf to the root

The witness, together with the public inputs, satisfies the arithmetic circuit constraints.

> **Analogy:** Like knowing the solution to a Sudoku puzzle. The witness is the filled-in grid; the public statement is that the grid is valid. You can prove you have a valid solution without showing any numbers.

---

## Z — ZkError

`ZkError` is the error type used throughout Soroban-ZK-Std. It provides meaningful failure information without panicking:

```rust
pub enum ZkError {
    InvalidInput,   // Bad input data (e.g., empty pairs array)
    DeserializationFailed,  // Could not parse byte data into a curve point
    ArithmeticError,  // Field arithmetic overflow or invalid result
}
```

> **Why no panics?** In Soroban smart contracts, panics waste the user's gas. By returning `Result<T, ZkError>`, developers can handle errors gracefully and refund unused gas when appropriate.


---

## Quick Reference Card

| Term | Definition | Used In |
|------|-----------|---------|
| **Arithmetic Circuit** | Computation model of +/- gates over a field | All ZK systems |
| **BN254** | Elliptic curve with pairings | Pairing checks, Groth16 |
| **ElGamal** | Public-key encryption on elliptic curves | Viewing keys |
| **Extension Field** | Larger field built from a base field (e.g., Fq²) | G2 points |
| **G1/G2** | Two related groups for pairings | Pairing checks |
| **Groth16** | ZK proving system with smallest proofs | Shielded transfers |
| **KZG** | Polynomial commitment using pairings | PLONK, custom circuits |
| **Merkle Tree** | Hash tree for efficient membership proofs | Deposit sets |
| **Nullifier** | Unique identifier preventing double-spending | Shielded transfers |
| **Pairing** | Bilinear map e: G1×G2→GT | All pairing-based ZK |
| **PLONK** | Universal zk-SNARK (no circuit-specific setup) | Alternative to Groth16 |
| **SNARK** | Succinct Non-interactive ARgument of Knowledge | Proof verification |
| **Trusted Setup** | Ceremony generating proving/verification keys | Groth16, KZG |
| **Viewing Key** | Selective disclosure mechanism | Regulatory compliance |
| **Witness** | Secret information the prover knows | All ZK proofs |
| **ZkError** | Library error type for graceful failure | Error handling |
