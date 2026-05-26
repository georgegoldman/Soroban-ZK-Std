# Merkle Authentication Paths — STARK Verification

## Tree Structure

A binary Merkle tree of depth `d` over `n = 2^d` leaves.

```
Layer 0 (leaves): H(data_i)
Layer k+1:        H(left_child || right_child)
Root:             single 32-byte hash
```

Hash function: Poseidon2 over BN254 Fr (via CAP-0075 host call).

## Authentication Path

To prove leaf `i` is in the tree with root `R`:

```
path = [sibling_0, sibling_1, ..., sibling_{d-1}]
index_bits = binary representation of i (LSB first)
```

### Verification Algorithm

```
current ← H(leaf_value)

for k in 0..d:
    bit ← index_bits[k]
    sibling ← path[k]

    if bit = 0:
        current ← H(current || sibling)   // current is left child
    else:
        current ← H(sibling || current)   // current is right child

return current == R
```

## Index Tracking

The leaf index `i` determines the left/right ordering at each level:

```
level_index[k] = i >> k
is_right_child[k] = level_index[k] & 1
```

## Poseidon2 Node Hashing

For STARK compatibility, each internal node is hashed as:

```
node = poseidon2_hash([left, right])
```

Using the 2-input sponge (absorb left, absorb right, squeeze).

## Security

Collision resistance relies on Poseidon2 preimage resistance over BN254 Fr.
Path length is `log₂(n)` hashes — for `n = 2^20` (1M leaves), this is 20
Poseidon2 calls per authentication path.
