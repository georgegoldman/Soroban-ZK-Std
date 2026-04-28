# Association Set Providers (ASP) Integration on Stellar

Privacy on public ledgers often introduces a conflict between individual financial confidentiality and regulatory compliance. The concept of **Privacy Pools** and **Association Set Providers (ASPs)** resolves this by allowing users to prove that their funds do not originate from illicit sources without revealing their exact transaction history.

## What is an Association Set Provider?

An ASP is an off-chain entity or smart contract that maintains a dynamic list (an "association set") of compliant or non-compliant actors. 
Instead of revealing their identity, users generate Zero-Knowledge Proofs (ZKPs) demonstrating that their transaction history is part of a "compliant" set (or definitively *not* part of a "sanctioned" set).

## How ASPs Work with Shielded Assets

The `shielded-asset-template` contract in `Soroban-ZK-Std` allows the integration of ASPs through the following mechanism:

### 1. Merkle Trees for State Management
The ASP maintains a Merkle Tree representing the current set of known compliant deposits. The Merkle Root is periodically published to the Soroban smart contract.

### 2. Zero-Knowledge Proof Generation
When a user wishes to transfer a shielded asset, they generate a Groth16 (or Plonk) proof off-chain. This proof cryptographically asserts:
*   "I know the private key for a deposit inside the Merkle Tree with root `R`."
*   "I have not spent this deposit before (via a revealed Nullifier)."
*   "The value I am transferring does not exceed my deposit."

### 3. Viewing Keys for Regulatory Compliance
While the ZKP proves the transaction is valid and compliant, the *amount* transferred remains hidden from the public. To satisfy audit requirements, the `shielded-asset-template` uses an **ElGamal Ciphertext** viewing key system over the BN254 elliptic curve.
*   The transaction amount is encrypted using a regulatory body's Public Key.
*   The regulator (holding the private key) can intercept the Soroban transaction, perform a point decryption, and recover the exact amount transferred.
*   The public observer sees only cryptographic noise (the ElGamal `C1` and `C2` points).

## Stellar Integration Flow

1. **Deposit**: A user deposits standard Stellar assets (e.g., USDC) into the privacy pool. The ASP includes their deposit commitment in the Merkle Tree.
2. **Transfer**: The user generates a ZK proof of membership against the ASP's Merkle Root and encrypts the transfer amount using the ElGamal viewing key.
3. **Verification**: The Soroban smart contract uses `Soroban-ZK-Std` to verify the Groth16 proof and validate the ElGamal ciphertext points.
4. **Audit**: Regulators utilize their private viewing keys to decrypt transaction amounts when required by law, ensuring full transparency without compromising public privacy.
