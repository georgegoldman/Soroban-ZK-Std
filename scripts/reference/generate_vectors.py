#!/usr/bin/env python3
"""Generate independent BN254 and Poseidon2 reference vectors."""

import argparse
import json
import random
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUTPUT = ROOT / "tests" / "vectors" / "reference_vectors.json"
POSEIDON_PARAMETERS = ROOT / "scripts" / "reference" / "poseidon2_parameters.json"
FQ = 21888242871839275222246405745257275088696311157297823662689037894645226208583
FR = 21888242871839275222246405745257275088548364400416034343698204186575808495617
SEED = 0x680
G1 = (1, 2)
G2 = (
    (10857046999023057135944570762232829481370756359578518086990519993285655852781,
     11559732032986387107991004021392285783925812861821192530917403151452391805634),
    (8495653923123431417604973247489272438418190587263600148770280649306958101930,
     4082367875863433681332203403145435568316851327593401208105741076214120093531),
)


def fp2_add(a, b):
    return ((a[0] + b[0]) % FQ, (a[1] + b[1]) % FQ)


def fp2_sub(a, b):
    return ((a[0] - b[0]) % FQ, (a[1] - b[1]) % FQ)


def fp2_mul(a, b):
    return ((a[0] * b[0] - a[1] * b[1]) % FQ,
            (a[0] * b[1] + a[1] * b[0]) % FQ)


def fp2_inv(a):
    norm = (a[0] * a[0] + a[1] * a[1]) % FQ
    norm_inv = pow(norm, FQ - 2, FQ)
    return (a[0] * norm_inv % FQ, -a[1] * norm_inv % FQ)


def curve_add(p, q, modulus, extension=False):
    if p is None:
        return q
    if q is None:
        return p
    if extension:
        zero = (0, 0)
        if p[0] == q[0] and fp2_add(p[1], q[1]) == zero:
            return None
        if p == q:
            slope = fp2_mul(fp2_mul((3, 0), fp2_mul(p[0], p[0])),
                            fp2_inv(fp2_mul((2, 0), p[1])))
        else:
            slope = fp2_mul(fp2_sub(q[1], p[1]),
                            fp2_inv(fp2_sub(q[0], p[0])))
        x = fp2_sub(fp2_sub(fp2_mul(slope, slope), p[0]), q[0])
        y = fp2_sub(fp2_mul(slope, fp2_sub(p[0], x)), p[1])
        return x, y
    if p[0] == q[0] and (p[1] + q[1]) % modulus == 0:
        return None
    if p == q:
        slope = (3 * p[0] * p[0] * pow(2 * p[1], -1, modulus)) % modulus
    else:
        slope = ((q[1] - p[1]) * pow(q[0] - p[0], -1, modulus)) % modulus
    x = (slope * slope - p[0] - q[0]) % modulus
    y = (slope * (p[0] - x) - p[1]) % modulus
    return x, y


def curve_mul(point, scalar, modulus, extension=False):
    result = None
    addend = point
    while scalar:
        if scalar & 1:
            result = curve_add(result, addend, modulus, extension)
        addend = curve_add(addend, addend, modulus, extension)
        scalar >>= 1
    return result


def poseidon_parameters():
    data = json.loads(POSEIDON_PARAMETERS.read_text())
    constants = [[int(value) for value in row] for row in data["round_constants"]]
    if len(constants) != 64 or any(len(row) != 3 for row in constants):
        raise ValueError("Poseidon2 reference parameters must contain 64 rows of width 3")
    return constants, int(data["domain_capacity"])


def poseidon_permute(state, constants, modulus=FR):
    def external(values):
        total = sum(values) % modulus
        return [(value + total) % modulus for value in values]

    def internal(values):
        total = sum(values) % modulus
        return [(values[0] + total) % modulus,
                (values[1] + total) % modulus,
                (values[2] + total + values[2]) % modulus]

    def sbox(value):
        square = value * value % modulus
        return square * square % modulus * value % modulus

    state = external(state)
    for row in constants[:4]:
        state = [sbox((value + rc) % modulus) for value, rc in zip(state, row)]
        state = external(state)
    for row in constants[4:60]:
        state[0] = sbox((state[0] + row[0]) % modulus)
        state = internal(state)
    for row in constants[60:]:
        state = [sbox((value + rc) % modulus) for value, rc in zip(state, row)]
        state = external(state)
    return state


def poseidon_sponge(values, constants, domain):
    state = [0, 0, 0]
    rate_index = 0
    for value in values:
        state[rate_index] = (state[rate_index] + value) % FR
        rate_index += 1
        if rate_index == 2:
            state = poseidon_permute(state, constants)
            rate_index = 0
    state[rate_index] = (state[rate_index] + 1) % FR
    state[2] = (state[2] + domain) % FR
    return poseidon_permute(state, constants)[0]


def compute_vectors():
    constants, domain = poseidon_parameters()
    rng = random.Random(SEED)
    a = rng.randrange(1, FR)
    b = rng.randrange(1, FQ)
    scalar = rng.randrange(2, 100)
    g1_double = curve_add(G1, G1, FQ)
    g2_double = curve_add(G2, G2, FQ, extension=True)
    message = b"soroban-zk-reference-680"
    chunks = [len(message)]
    chunks.extend(
        int.from_bytes(message[i : i + 31], "big")
        for i in range(0, len(message), 31)
    )
    return {
        "generator": {
            "name": "Python standard-library arithmetic and affine curve implementation",
            "version": "1",
            "seed": hex(SEED),
        },
        "fr": {
            "inputs": [str(a), str(b)],
            "add": str((a + b) % FR),
            "mul": str((a * b) % FR),
            "inv": str(pow(a, FR - 2, FR)),
        },
        "fq": {
            "inputs": [str(a), str(b)],
            "add": str((a + b) % FQ),
            "mul": str((a * b) % FQ),
            "inv": str(pow(a, FQ - 2, FQ)),
        },
        "g1": {
            "point": [str(G1[0]), str(G1[1])],
            "add": [str(v) for v in curve_add(G1, G1, FQ)],
            "double": [str(v) for v in g1_double],
            "scalar": str(scalar),
            "scalar_mul": [str(v) for v in curve_mul(G1, scalar, FQ)],
        },
        "g2": {
            "point": [[str(v) for v in G2[0]], [str(v) for v in G2[1]]],
            "add": [[str(v) for v in c] for c in g2_double],
            "double": [[str(v) for v in c] for c in g2_double],
            "scalar": str(scalar),
            "scalar_mul": [
                [str(v) for v in c]
                for c in curve_mul(G2, scalar, FQ, extension=True)
            ],
        },
        "poseidon2": {
            "permutation_input": ["0", "1", "2"],
            "permutation_output": [
                str(v) for v in poseidon_permute([0, 1, 2], constants)
            ],
            "hash_input_utf8": message.decode("ascii"),
            "hash_to_fq": str(poseidon_sponge(chunks, constants, domain)),
            "hash_to_fr": str(poseidon_sponge(chunks, constants, domain) % FR),
        },
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true", help="fail if committed vectors drift")
    args = parser.parse_args()
    generated = json.dumps(compute_vectors(), indent=2, sort_keys=True) + "\n"
    if args.check:
        if not OUTPUT.exists() or OUTPUT.read_text() != generated:
            raise SystemExit("reference vectors drifted; regenerate with scripts/reference/generate_vectors.py")
        print(f"Reference vectors are current: {OUTPUT.relative_to(ROOT)}")
    else:
        OUTPUT.parent.mkdir(parents=True, exist_ok=True)
        OUTPUT.write_text(generated)
        print(f"Wrote {OUTPUT.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
