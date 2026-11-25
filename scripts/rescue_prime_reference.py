#!/usr/bin/env python3
"""Independent pure-Python reference implementation for Rescue-Prime on BN254 Fr.

Matches `crates/soroban-zk-core/src/rescue.rs` and
`crates/soroban-zk-std/src/gadgets/hash/rescue_prime.rs` (IACR ePrint 2020/1143):
  - Field: BN254 scalar field Fr (p = FR_MODULUS)
  - State: width m = 3 (rate = 2, capacity = 1), 6 rounds (12 half-round keys)
  - S-box: alpha = 5, alpha_inv = 5^-1 mod (p - 1)
  - MDS: Cauchy matrix M[i][j] = (x_i - y_j)^-1 mod p for x=[1,2,3], y=[4,5,6]
  - Round keys: SHAKE-256("Rescue-XLIX(p,3,1,128)")
  - Sponge: pad10* (rate = 2, capacity = 1), squeezing state[1]

Usage:
  python3 scripts/rescue_prime_reference.py --self-test
  python3 scripts/rescue_prime_reference.py --emit-vectors
"""

import argparse
import hashlib
import math

FR_MODULUS = 21888242871839275222246405745257275088548364400416034343698204186575808495617
STATE = 3
CAPACITY = 1
RATE = STATE - CAPACITY
ROUNDS = 6
SECURITY_LEVEL = 128
ALPHA = 5
ALPHA_INV = pow(ALPHA, -1, FR_MODULUS - 1)


def cauchy_mds():
    return [
        [pow((i + 1) - (STATE + j + 1), -1, FR_MODULUS) for j in range(STATE)]
        for i in range(STATE)
    ]


def shake256_round_keys():
    bytes_per_int = math.ceil(FR_MODULUS.bit_length() / 8) + 1  # 33 bytes
    seed = f"Rescue-XLIX({FR_MODULUS},{STATE},{CAPACITY},{SECURITY_LEVEL})".encode("ascii")
    stream = hashlib.shake_256(seed).digest(2 * ROUNDS * STATE * bytes_per_int)
    keys = []
    for r in range(2 * ROUNDS):
        row = []
        for j in range(STATE):
            start = (r * STATE + j) * bytes_per_int
            val = int.from_bytes(stream[start : start + bytes_per_int], "little") % FR_MODULUS
            row.append(val)
        keys.append(row)
    return keys


MDS = cauchy_mds()
ROUND_KEYS = shake256_round_keys()


def mds_multiply(state):
    return [
        sum(MDS[i][j] * state[j] for j in range(STATE)) % FR_MODULUS
        for i in range(STATE)
    ]


def rescue_round(state, r):
    # Forward S-box + key + MDS
    state = [pow(s, ALPHA, FR_MODULUS) for s in state]
    state = [(state[i] + ROUND_KEYS[2 * r][i]) % FR_MODULUS for i in range(STATE)]
    state = mds_multiply(state)
    # Inverse S-box + key + MDS
    state = [pow(s, ALPHA_INV, FR_MODULUS) for s in state]
    state = [(state[i] + ROUND_KEYS[2 * r + 1][i]) % FR_MODULUS for i in range(STATE)]
    state = mds_multiply(state)
    return state


def rescue_permute(state, trace=False):
    st = [x % FR_MODULUS for x in state]
    rounds = []
    for r in range(ROUNDS):
        st = rescue_round(st, r)
        if trace:
            rounds.append(list(st))
    return (st, rounds) if trace else st


def rescue_sponge_hash(elems):
    """Matches soroban_zk_std::gadgets::hash::rescue_prime::rescue_prime_hash."""
    state = [0] * STATE
    rate_idx = 0
    for e in elems:
        state[rate_idx + 1] = (state[rate_idx + 1] + (e % FR_MODULUS)) % FR_MODULUS
        rate_idx += 1
        if rate_idx == RATE:
            state = rescue_permute(state)
            rate_idx = 0
    # pad10* squeeze
    state[rate_idx + 1] = (state[rate_idx + 1] + 1) % FR_MODULUS
    state = rescue_permute(state)
    return state[1]


def rescue_sponge_multi_squeeze(elems, count=2):
    state = [0] * STATE
    rate_idx = 0
    for e in elems:
        state[rate_idx + 1] = (state[rate_idx + 1] + (e % FR_MODULUS)) % FR_MODULUS
        rate_idx += 1
        if rate_idx == RATE:
            state = rescue_permute(state)
            rate_idx = 0
    out = []
    for _ in range(count):
        state[rate_idx + 1] = (state[rate_idx + 1] + 1) % FR_MODULUS
        state = rescue_permute(state)
        rate_idx = 0
        out.append(state[1])
    return out


def rescue_hash_bytes(data: bytes):
    """Matches rescue_prime_hash_bytes (32-byte big-endian blocks, zero-padded right)."""
    elems = []
    for i in range(0, len(data), 32):
        chunk = data[i : i + 32].ljust(32, b"\x00")
        elems.append(int.from_bytes(chunk, "big"))
    return rescue_sponge_hash(elems)


def fmt_u256_words(val: int) -> str:
    hi = (val >> 128) & ((1 << 128) - 1)
    lo = val & ((1 << 128) - 1)
    return f"u256::from_words(0x{hi:032x}_u128, 0x{lo:032x}_u128)"


def self_test():
    assert (ALPHA * ALPHA_INV) % (FR_MODULUS - 1) == 1
    assert len(MDS) == STATE and all(len(row) == STATE for row in MDS)
    assert len(ROUND_KEYS) == 2 * ROUNDS
    # Cross-check against existing rescue.rs vector for permute([1, 2, 3]).
    expected_123 = [
        (0x0f41a1a83517a6868cfd29c9cb049d5a << 128) | 0x3d1a545b966c592eb7f5b12f5c9c9314,
        (0x227039662dc2df70cf31d8fb94dbc29b << 128) | 0x9ed8ebbbed3698d44ecfe5d452471327,
        (0x1c81efcd19e26b5d96d931992c70d6fc << 128) | 0xb96fad2c3c86c07028234ad1ebc1ee98,
    ]
    assert rescue_permute([1, 2, 3]) == expected_123
    # Cross-check existing rescue_prime.rs hash vectors.
    assert rescue_sponge_hash([]) == (
        (0x2d3ac4cc3c9bf0f5c9b4d77704120b97 << 128) | 0x62eda93fc0baa4c28e0210e2a6c0a1b7
    )
    assert rescue_sponge_hash([1, 2]) == (
        (0x26fcae1af898fd39c30a2f44a478e38f << 128) | 0x67b3d418fee7eb2b84469d17a39ec20c
    )
    assert rescue_sponge_hash([42]) == (
        (0x153af6aa95b453dd3a38076f78dabdfe << 128) | 0xa0268c3a27ce041feef95e1b7092b2c9
    )
    print("rescue_prime_reference.py self-test OK")


def emit_vectors():
    print("// Generated by scripts/rescue_prime_reference.py --emit-vectors")
    print("ALPHA_INV =", fmt_u256_words(ALPHA_INV))
    print("MDS[0][0] =", fmt_u256_words(MDS[0][0]))
    print("MDS[2][2] =", fmt_u256_words(MDS[2][2]))
    for name, st in [
        ("zero", [0, 0, 0]),
        ("seq123", [1, 2, 3]),
        ("boundary", [FR_MODULUS - 1, FR_MODULUS - 2, 42]),
    ]:
        final, rounds = rescue_permute(st, trace=True)
        print(f"\n// permute({name}) round 0:")
        for v in rounds[0]:
            print(" ", fmt_u256_words(v) + ",")
        print(f"// permute({name}) final:")
        for v in final:
            print(" ", fmt_u256_words(v) + ",")
        # Double permute
        final2 = rescue_permute(final)
        print(f"// permute^2({name}) final:")
        for v in final2:
            print(" ", fmt_u256_words(v) + ",")

    print("\n// mds_multiply([1, 2, 3]):")
    for v in mds_multiply([1, 2, 3]):
        print(" ", fmt_u256_words(v) + ",")

    print("\n// mds_multiply([FR_MODULUS - 1, FR_MODULUS - 2, FR_MODULUS - 3]):")
    for v in mds_multiply([FR_MODULUS - 1, FR_MODULUS - 2, FR_MODULUS - 3]):
        print(" ", fmt_u256_words(v) + ",")

    print("\n// sponge hashes:")
    for label, elems in [
        ("empty", []),
        ("single_zero", [0]),
        ("double_zero", [0, 0]),
        ("seq_1_2_3", [1, 2, 3]),
        ("near_modulus", [FR_MODULUS - 1]),
        ("above_modulus_wraps", [FR_MODULUS + 7, FR_MODULUS - 1]),
    ]:
        print(f"  {label}: {fmt_u256_words(rescue_sponge_hash(elems))}")

    print("\n// multi-squeeze [1, 2]:")
    for idx, v in enumerate(rescue_sponge_multi_squeeze([1, 2], 2)):
        print(f"  squeeze_{idx}: {fmt_u256_words(v)}")

    print("\n// hash_bytes:")
    for label, payload in [
        ("empty", b""),
        ("abc", b"abc"),
        ("exact_32", bytes(range(32))),
        ("multi_65", bytes((i * 7) & 0xFF for i in range(65))),
    ]:
        print(f"  {label}: {fmt_u256_words(rescue_hash_bytes(payload))}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--emit-vectors", action="store_true")
    args = parser.parse_args()
    if args.self_test or not args.emit_vectors:
        self_test()
    if args.emit_vectors:
        emit_vectors()
