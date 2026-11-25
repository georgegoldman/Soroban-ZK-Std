/**
 * BN254 field constants and the minimal big-integer arithmetic the packers
 * need for client-side validation (range checks and on-curve checks).
 */

import { ZkSdkError, type ZkSdkErrorCode } from "./errors.js";

/** BN254 base field modulus `q` (coordinates of G1/G2 points). */
export const BN254_FQ_MODULUS =
  21888242871839275222246405745257275088696311157297823662689037894645226208583n;

/** BN254 scalar field modulus `r` (public inputs / signals). */
export const BN254_FR_MODULUS =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

/** A value accepted wherever a field element is expected. */
export type FieldElementLike = string | bigint | number;

const DECIMAL_RE = /^[0-9]+$/;
const HEX_RE = /^0x[0-9a-fA-F]+$/;

/**
 * Parses a field element given as a decimal string (snarkjs style), a
 * `0x`-prefixed hex string, a `bigint`, or a safe non-negative integer.
 * Throws `ZkSdkError` unless `0 <= value < modulus`.
 */
export function parseFieldElement(
  value: FieldElementLike,
  modulus: bigint,
  what: string,
  code: ZkSdkErrorCode = "INVALID_FIELD_ELEMENT",
): bigint {
  let parsed: bigint;
  if (typeof value === "bigint") {
    parsed = value;
  } else if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) {
      throw new ZkSdkError(code, `${what}: ${value} is not a safe integer; pass a string or bigint`);
    }
    parsed = BigInt(value);
  } else if (typeof value === "string") {
    const trimmed = value.trim();
    if (!DECIMAL_RE.test(trimmed) && !HEX_RE.test(trimmed)) {
      throw new ZkSdkError(code, `${what}: "${value}" is not a decimal or 0x-hex integer`);
    }
    parsed = BigInt(trimmed);
  } else {
    throw new ZkSdkError(code, `${what}: expected a string, bigint or number`);
  }
  if (parsed < 0n) {
    throw new ZkSdkError(code, `${what}: must not be negative`);
  }
  if (parsed >= modulus) {
    throw new ZkSdkError(code, `${what}: ${parsed} is not below the field modulus ${modulus}`);
  }
  return parsed;
}

/** Writes `value` (< 2^256) into `out[offset..offset+32]`, big-endian. */
export function writeU256BE(out: Uint8Array, offset: number, value: bigint): void {
  let v = value;
  for (let i = 31; i >= 0; i--) {
    out[offset + i] = Number(v & 0xffn);
    v >>= 8n;
  }
}

const q = BN254_FQ_MODULUS;
const mod = (a: bigint): bigint => {
  const r = a % q;
  return r < 0n ? r + q : r;
};

/** `y² == x³ + 3 (mod q)`: the BN254 G1 curve equation. */
export function isOnG1Curve(x: bigint, y: bigint): boolean {
  return mod(y * y) === mod(x * x * x + 3n);
}

/** An Fq² element `c0 + c1·u` with `u² = −1`. */
type Fq2 = readonly [bigint, bigint];

const fq2Mul = (a: Fq2, b: Fq2): Fq2 => [
  mod(a[0] * b[0] - a[1] * b[1]),
  mod(a[0] * b[1] + a[1] * b[0]),
];

/** `b' = 3 / (9 + u)`, the BN254 G2 (twist) curve constant. */
const G2_B: Fq2 = [
  19485874751759354771024239261021720505790618469301721065564631296452457478373n,
  266929791119991161246907387137283842545076965332900288569378510910307636690n,
];

/** `y² == x³ + b'` over Fq²: the BN254 G2 twist curve equation. */
export function isOnG2Curve(x: Fq2, y: Fq2): boolean {
  const lhs = fq2Mul(y, y);
  const x3 = fq2Mul(fq2Mul(x, x), x);
  const rhs: Fq2 = [mod(x3[0] + G2_B[0]), mod(x3[1] + G2_B[1])];
  return lhs[0] === rhs[0] && lhs[1] === rhs[1];
}
