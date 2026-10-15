"""Small independent Rescue-Prime vector generator for BN254 Fr.

The parameter choices and permutation follow KULeuven-COSIC/Marvellous's
``rescue_prime.sage`` reference implementation:
https://github.com/KULeuven-COSIC/Marvellous/blob/master/rescue_prime.sage

Only Python's standard library is required. Run this file to print the
permutation and sponge vectors asserted by the Rust tests.
"""

from hashlib import shake_256

P = 21888242871839275222246405745257275088548364400416034343698204186575808495617
WIDTH = 3
CAPACITY = 1
SECURITY = 128
ALPHA = 5
ROUNDS = 14

# Transpose of the right half of the systematic Vandermonde matrix generated
# by the reference's primitive element g=5 and Sage echelon_form().
MDS = (
    (125, P - 155, 31),
    (3875, P - 4680, 806),
    (100750, P - 116055, 20306),
)


def round_constants():
    seed = f"Rescue-XLIX({P},{WIDTH},{CAPACITY},{SECURITY})".encode("ascii")
    chunk_size = (P.bit_length() + 7) // 8 + 1
    stream = shake_256(seed).digest(chunk_size * 2 * WIDTH * ROUNDS)
    return tuple(
        int.from_bytes(stream[i : i + chunk_size], "little") % P
        for i in range(0, len(stream), chunk_size)
    )


def permute(state):
    constants = round_constants()
    state = list(state)
    alpha_inverse = pow(ALPHA, -1, P - 1)
    for r in range(ROUNDS):
        state = [pow(x, ALPHA, P) for x in state]
        state = [sum(MDS[i][j] * state[j] for j in range(WIDTH)) % P for i in range(WIDTH)]
        state = [(state[i] + constants[2 * WIDTH * r + i]) % P for i in range(WIDTH)]
        state = [pow(x, alpha_inverse, P) for x in state]
        state = [sum(MDS[i][j] * state[j] for j in range(WIDTH)) % P for i in range(WIDTH)]
        state = [(state[i] + constants[2 * WIDTH * r + WIDTH + i]) % P for i in range(WIDTH)]
    return tuple(state)


def hash_fields(message):
    padded = list(message) + [1]
    while len(padded) % (WIDTH - CAPACITY):
        padded.append(0)
    state = [0] * WIDTH
    rate = WIDTH - CAPACITY
    for start in range(0, len(padded), rate):
        for i in range(rate):
            state[i] = (state[i] + padded[start + i]) % P
        state = list(permute(state))
    return state[0]


if __name__ == "__main__":
    print("permute([1, 2, 3]) =", permute([1, 2, 3]))
    print("hash_fields([1, 2]) =", hash_fields([1, 2]))
