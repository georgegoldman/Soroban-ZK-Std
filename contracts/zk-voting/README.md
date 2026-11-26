# ZK Voting Reference Contract

This Soroban contract accepts Groth16 ballots for a committed Merkle voter set.
The voting circuit must expose `[proposal_id, merkle_root, nullifier, choice]`
and constrain Merkle membership, nullifier derivation, and a binary choice.
`init` takes the serialized BN254 verifying key for exactly four public inputs.

The admin creates each proposal with a canonical BN254 scalar root and a future
end-ledger bounded by `MAX_PROPOSAL_LEDGERS` (500,000 ledgers). `cast_vote` verifies the proof
before recording a nullifier scoped to that proposal and incrementing the
yes/no tally. Anyone may finalize after the end ledger, which emits the final
tally. The contract does not inspect circuit constraints: install only a VK
from an audited circuit that enforces the stated relation.

See the [integration guide](../../frontend/content/docs/integration-and-verification/zk-voting-guide.mdx)
for public inputs, privacy limits, and the threat model.
