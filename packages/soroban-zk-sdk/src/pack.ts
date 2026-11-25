/**
 * Packing of SnarkJS Groth16 artefacts into the exact big-endian wire layouts
 * `soroban-zk-std` decodes:
 *
 * - G1 point: `x ‖ y`, 32-byte big-endian each (64 B), decoded by `groth16::g1_from_bytes`.
 * - G2 point: `x.c1 ‖ x.c0 ‖ y.c1 ‖ y.c0` (128 B, EIP-197 / CAP-0074 order),
 *   decoded by `groth16::g2_from_bytes`.
 * - Groth16 proof: `A (G1) ‖ B (G2) ‖ C (G1)` = 256 B, decoded by `Groth16Proof::from_bytes`.
 * - Verifying key: `α (G1) ‖ β (G2) ‖ γ (G2) ‖ δ (G2) ‖ len(IC) as u32 BE ‖ IC[i] (G1)…`
 *   = 452 + 64·len(IC) B, decoded by `vk::vk_from_bytes`.
 * - Public signals: `Vec<U256>`, each `< r`, as taken by `ZkContract::verify_proof`.
 *
 * SnarkJS stores Fq² elements as `[c0, c1]`; this module swaps them into the
 * `c1 ‖ c0` order the contract expects.
 *
 * Every coordinate is range-checked against `q`, every point is checked to be
 * on its curve (which also rejects the `(0, 0)` identity encoding the contract
 * rejects), and every public signal is range-checked against `r`, so malformed
 * input fails locally instead of costing a failed transaction. Prime-order
 * subgroup membership is still enforced on-chain.
 */

import { nativeToScVal, xdr } from "@stellar/stellar-sdk";

import { ZkSdkError } from "./errors.js";
import {
  BN254_FQ_MODULUS,
  BN254_FR_MODULUS,
  type FieldElementLike,
  isOnG1Curve,
  isOnG2Curve,
  parseFieldElement,
  writeU256BE,
} from "./field.js";

/** Size of a packed G1 point. */
export const G1_POINT_SIZE = 64;
/** Size of a packed G2 point. */
export const G2_POINT_SIZE = 128;
/** Size of a packed Groth16 proof (`Groth16Proof::from_bytes` requires exactly this). */
export const GROTH16_PROOF_SIZE = 256;
/** Size of the fixed part of a packed verifying key (α, β, γ, δ and the IC length). */
export const VERIFYING_KEY_HEADER_SIZE = 452;

/** A SnarkJS G1 point: `[x, y]` or projective `[x, y, z]` with `z == 1`. */
export type SnarkjsG1 = readonly FieldElementLike[];
/** A SnarkJS G2 point: `[[x.c0, x.c1], [y.c0, y.c1]]` or with a third `[1, 0]` entry. */
export type SnarkjsG2 = readonly (readonly FieldElementLike[])[];

/** A Groth16 proof as written by `snarkjs groth16 prove` (`proof.json`). */
export interface SnarkjsGroth16Proof {
  pi_a: SnarkjsG1;
  pi_b: SnarkjsG2;
  pi_c: SnarkjsG1;
  protocol?: string;
  curve?: string;
}

/** A Groth16 verifying key as written by `snarkjs zkey export verificationkey`. */
export interface SnarkjsGroth16VerifyingKey {
  vk_alpha_1: SnarkjsG1;
  vk_beta_2: SnarkjsG2;
  vk_gamma_2: SnarkjsG2;
  vk_delta_2: SnarkjsG2;
  IC: readonly SnarkjsG1[];
  nPublic?: number;
  protocol?: string;
  curve?: string;
}

const BN254_CURVE_NAMES = new Set(["bn128", "bn254", "alt_bn128"]);

function checkHeader(
  protocol: string | undefined,
  curve: string | undefined,
  code: "INVALID_PROOF" | "INVALID_VERIFYING_KEY",
): void {
  if (protocol !== undefined && protocol !== "groth16") {
    throw new ZkSdkError(code, `unsupported protocol "${protocol}"; expected "groth16"`);
  }
  if (curve !== undefined && !BN254_CURVE_NAMES.has(curve.toLowerCase())) {
    throw new ZkSdkError(code, `unsupported curve "${curve}"; expected BN254 ("bn128")`);
  }
}

function fq(value: FieldElementLike | undefined, what: string): bigint {
  if (value === undefined) {
    throw new ZkSdkError("INVALID_POINT", `${what}: missing coordinate`);
  }
  return parseFieldElement(value, BN254_FQ_MODULUS, what, "INVALID_POINT");
}

function isOne(value: FieldElementLike | undefined): boolean {
  if (value === undefined) return false;
  try {
    return parseFieldElement(value, BN254_FQ_MODULUS, "z") === 1n;
  } catch {
    return false;
  }
}

function isZero(value: FieldElementLike | undefined): boolean {
  if (value === undefined) return false;
  try {
    return parseFieldElement(value, BN254_FQ_MODULUS, "z") === 0n;
  } catch {
    return false;
  }
}

/** Packs one SnarkJS G1 point into `out[offset..offset+64]`. */
function writeG1(out: Uint8Array, offset: number, point: SnarkjsG1, what: string): void {
  if (!Array.isArray(point) || (point.length !== 2 && point.length !== 3)) {
    throw new ZkSdkError("INVALID_POINT", `${what}: expected [x, y] or [x, y, z]`);
  }
  if (point.length === 3 && !isOne(point[2])) {
    throw new ZkSdkError(
      "INVALID_POINT",
      `${what}: point is not affine (z must be 1; the point at infinity is not accepted)`,
    );
  }
  const x = fq(point[0], `${what}.x`);
  const y = fq(point[1], `${what}.y`);
  if (!isOnG1Curve(x, y)) {
    throw new ZkSdkError("INVALID_POINT", `${what}: not on the BN254 G1 curve y² = x³ + 3`);
  }
  writeU256BE(out, offset, x);
  writeU256BE(out, offset + 32, y);
}

function fq2(value: readonly FieldElementLike[] | undefined, what: string): [bigint, bigint] {
  if (!Array.isArray(value) || value.length !== 2) {
    throw new ZkSdkError("INVALID_POINT", `${what}: expected [c0, c1]`);
  }
  return [fq(value[0], `${what}.c0`), fq(value[1], `${what}.c1`)];
}

/** Packs one SnarkJS G2 point into `out[offset..offset+128]` as `x.c1 ‖ x.c0 ‖ y.c1 ‖ y.c0`. */
function writeG2(out: Uint8Array, offset: number, point: SnarkjsG2, what: string): void {
  if (!Array.isArray(point) || (point.length !== 2 && point.length !== 3)) {
    throw new ZkSdkError("INVALID_POINT", `${what}: expected [[x.c0, x.c1], [y.c0, y.c1]] (+ optional z)`);
  }
  if (point.length === 3) {
    const z = point[2];
    if (!Array.isArray(z) || z.length !== 2 || !isOne(z[0]) || !isZero(z[1])) {
      throw new ZkSdkError(
        "INVALID_POINT",
        `${what}: point is not affine (z must be [1, 0]; the point at infinity is not accepted)`,
      );
    }
  }
  const x = fq2(point[0], `${what}.x`);
  const y = fq2(point[1], `${what}.y`);
  if (!isOnG2Curve(x, y)) {
    throw new ZkSdkError("INVALID_POINT", `${what}: not on the BN254 G2 twist curve`);
  }
  writeU256BE(out, offset, x[1]);
  writeU256BE(out, offset + 32, x[0]);
  writeU256BE(out, offset + 64, y[1]);
  writeU256BE(out, offset + 96, y[0]);
}

function rethrowAs(code: "INVALID_PROOF" | "INVALID_VERIFYING_KEY", fn: () => void): void {
  try {
    fn();
  } catch (err) {
    if (err instanceof ZkSdkError && err.code === "INVALID_POINT") {
      throw new ZkSdkError(code, err.message, { cause: err });
    }
    throw err;
  }
}

/**
 * Packs a SnarkJS Groth16 proof into the 256-byte `A ‖ B ‖ C` layout accepted
 * by `ZkContract::verify_proof` (`proof_bytes: Bytes`).
 *
 * @throws ZkSdkError `INVALID_PROOF` if the proof is not a BN254 Groth16 proof,
 *   a coordinate is not below `q`, or a point is not affine and on its curve.
 */
export function packGroth16Proof(proof: SnarkjsGroth16Proof): Uint8Array {
  if (proof === null || typeof proof !== "object") {
    throw new ZkSdkError("INVALID_PROOF", "proof: expected a SnarkJS proof object");
  }
  checkHeader(proof.protocol, proof.curve, "INVALID_PROOF");
  const out = new Uint8Array(GROTH16_PROOF_SIZE);
  rethrowAs("INVALID_PROOF", () => {
    writeG1(out, 0, proof.pi_a, "pi_a");
    writeG2(out, 64, proof.pi_b, "pi_b");
    writeG1(out, 192, proof.pi_c, "pi_c");
  });
  return out;
}

/**
 * Packs a SnarkJS Groth16 verifying key into the layout accepted by
 * `ZkContract::set_verifying_key` (`vk_bytes: Bytes`, decoded by
 * `vk::vk_from_bytes`): `α ‖ β ‖ γ ‖ δ ‖ len(IC) (u32 BE) ‖ IC…`.
 *
 * @throws ZkSdkError `INVALID_VERIFYING_KEY` on a malformed key, an empty
 *   `IC`, an `nPublic` that disagrees with `IC.length - 1`, or an invalid point.
 */
export function packVerifyingKey(vk: SnarkjsGroth16VerifyingKey): Uint8Array {
  if (vk === null || typeof vk !== "object") {
    throw new ZkSdkError("INVALID_VERIFYING_KEY", "verifying key: expected a SnarkJS key object");
  }
  checkHeader(vk.protocol, vk.curve, "INVALID_VERIFYING_KEY");
  if (!Array.isArray(vk.IC) || vk.IC.length === 0) {
    throw new ZkSdkError("INVALID_VERIFYING_KEY", "IC: must contain at least one point");
  }
  if (vk.IC.length > 0xffff_ffff) {
    throw new ZkSdkError("INVALID_VERIFYING_KEY", "IC: too many points for a u32 length prefix");
  }
  if (vk.nPublic !== undefined && vk.nPublic !== vk.IC.length - 1) {
    throw new ZkSdkError(
      "INVALID_VERIFYING_KEY",
      `nPublic (${vk.nPublic}) must equal IC.length - 1 (${vk.IC.length - 1})`,
    );
  }

  const out = new Uint8Array(VERIFYING_KEY_HEADER_SIZE + G1_POINT_SIZE * vk.IC.length);
  rethrowAs("INVALID_VERIFYING_KEY", () => {
    writeG1(out, 0, vk.vk_alpha_1, "vk_alpha_1");
    writeG2(out, 64, vk.vk_beta_2, "vk_beta_2");
    writeG2(out, 192, vk.vk_gamma_2, "vk_gamma_2");
    writeG2(out, 320, vk.vk_delta_2, "vk_delta_2");
    new DataView(out.buffer, out.byteOffset, out.byteLength).setUint32(448, vk.IC.length, false);
    vk.IC.forEach((point, i) => {
      writeG1(out, VERIFYING_KEY_HEADER_SIZE + i * G1_POINT_SIZE, point, `IC[${i}]`);
    });
  });
  return out;
}

/** Options for {@link packPublicSignals}. */
export interface PackPublicSignalsOptions {
  /**
   * The number of public inputs the circuit expects (`vk.nPublic`, or
   * `IC.length - 1`). When set, a different count is rejected locally, the same
   * way the contract would reject it with `InvalidInput`.
   */
  expectedCount?: number;
}

/**
 * Converts SnarkJS public signals (`public.json`: decimal strings) into the
 * `U256` `ScVal`s of `ZkContract::verify_proof`'s `public_inputs: Vec<U256>`.
 * Wrap the result in `xdr.ScVal.scvVec(...)`, or use {@link packPublicSignalsVec}.
 *
 * @throws ZkSdkError `INVALID_FIELD_ELEMENT` if a signal is not an integer in
 *   `[0, r)` (the contract would return `InvalidFieldElement`), or
 *   `INVALID_ARGUMENT` if `expectedCount` does not match.
 */
export function packPublicSignals(
  signals: readonly FieldElementLike[],
  options: PackPublicSignalsOptions = {},
): xdr.ScVal[] {
  if (!Array.isArray(signals)) {
    throw new ZkSdkError("INVALID_ARGUMENT", "public signals: expected an array");
  }
  const { expectedCount } = options;
  if (expectedCount !== undefined && signals.length !== expectedCount) {
    throw new ZkSdkError(
      "INVALID_ARGUMENT",
      `public signals: expected ${expectedCount}, got ${signals.length}`,
    );
  }
  return signals.map((signal, i) =>
    nativeToScVal(parseFieldElement(signal, BN254_FR_MODULUS, `public signal [${i}]`), {
      type: "u256",
    }),
  );
}

/** {@link packPublicSignals}, wrapped as the single `Vec<U256>` contract argument. */
export function packPublicSignalsVec(
  signals: readonly FieldElementLike[],
  options?: PackPublicSignalsOptions,
): xdr.ScVal {
  return xdr.ScVal.scvVec(packPublicSignals(signals, options));
}

/**
 * Builds the three arguments of `ZkContract::verify_proof(proof_bytes,
 * public_inputs, anti_replay)` from SnarkJS output, ready for
 * `contract.call("verify_proof", ...args)`.
 */
export function buildVerifyProofArgs(
  proof: SnarkjsGroth16Proof,
  signals: readonly FieldElementLike[],
  antiReplay: boolean,
  options?: PackPublicSignalsOptions,
): [proofBytes: xdr.ScVal, publicInputs: xdr.ScVal, antiReplay: xdr.ScVal] {
  return [
    nativeToScVal(packGroth16Proof(proof)),
    packPublicSignalsVec(signals, options),
    xdr.ScVal.scvBool(antiReplay),
  ];
}
