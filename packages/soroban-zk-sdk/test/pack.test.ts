import { scValToBigInt, xdr } from "@stellar/stellar-sdk";
import { describe, expect, it } from "vitest";

import {
  BN254_FQ_MODULUS,
  BN254_FR_MODULUS,
  buildVerifyProofArgs,
  GROTH16_PROOF_SIZE,
  isOnG1Curve,
  packGroth16Proof,
  packPublicSignals,
  packPublicSignalsVec,
  packVerifyingKey,
  VERIFYING_KEY_HEADER_SIZE,
  ZkSdkError,
} from "../src/index.js";
import { clone, type Groth16Fixture, loadJson, toHex } from "./helpers.js";

const fx = loadJson<Groth16Fixture>("groth16.json");
const q = BN254_FQ_MODULUS;
const r = BN254_FR_MODULUS;

function expectSdkError(fn: () => unknown, code: string, message?: RegExp): void {
  let thrown: unknown;
  try {
    fn();
  } catch (err) {
    thrown = err;
  }
  expect(thrown).toBeInstanceOf(ZkSdkError);
  expect((thrown as ZkSdkError).code).toBe(code);
  if (message) expect((thrown as ZkSdkError).message).toMatch(message);
}

describe("packGroth16Proof", () => {
  it("matches the bytes soroban-zk-std verified on-chain", () => {
    const bytes = packGroth16Proof(fx.proof);
    expect(bytes).toBeInstanceOf(Uint8Array);
    expect(bytes.length).toBe(GROTH16_PROOF_SIZE);
    expect(toHex(bytes)).toBe(fx.proofHex);
  });

  it("writes G2 as x.c1 ‖ x.c0 ‖ y.c1 ‖ y.c0 (swapped from SnarkJS [c0, c1])", () => {
    const bytes = packGroth16Proof(fx.proof);
    const word = (i: number) => BigInt(`0x${toHex(bytes.subarray(i, i + 32))}`);
    const [[x0, x1], [y0, y1]] = fx.proof.pi_b as string[][] as [string[], string[]];
    expect(word(64)).toBe(BigInt(x1 as string));
    expect(word(96)).toBe(BigInt(x0 as string));
    expect(word(128)).toBe(BigInt(y1 as string));
    expect(word(160)).toBe(BigInt(y0 as string));
  });

  it("accepts affine [x, y] points and bigint / hex coordinates", () => {
    const p = clone(fx.proof);
    const affine = {
      pi_a: [BigInt(p.pi_a[0] as string), `0x${BigInt(p.pi_a[1] as string).toString(16)}`],
      pi_b: [p.pi_b[0], p.pi_b[1]] as string[][],
      pi_c: [p.pi_c[0] as string, p.pi_c[1] as string],
    };
    expect(toHex(packGroth16Proof(affine))).toBe(fx.proofHex);
  });

  it("rejects a coordinate equal to q (boundary) and above it", () => {
    for (const bad of [q, q + 1n]) {
      const p = clone(fx.proof);
      p.pi_a[0] = bad.toString();
      expectSdkError(() => packGroth16Proof(p), "INVALID_PROOF", /pi_a\.x.*not below the field modulus/);
    }
  });

  it("rejects negative, fractional, unsafe and non-numeric coordinates", () => {
    for (const bad of ["-1", "1.5", "abc", "", Number.MAX_SAFE_INTEGER + 1, -1n]) {
      const p = clone(fx.proof) as unknown as { pi_c: unknown[] };
      p.pi_c[1] = bad;
      expectSdkError(() => packGroth16Proof(p as never), "INVALID_PROOF");
    }
  });

  it("rejects non-affine points and the point at infinity", () => {
    const a = clone(fx.proof);
    a.pi_a[2] = "2";
    expectSdkError(() => packGroth16Proof(a), "INVALID_PROOF", /not affine/);

    const inf = clone(fx.proof);
    inf.pi_c = ["0", "1", "0"];
    expectSdkError(() => packGroth16Proof(inf), "INVALID_PROOF", /not affine/);

    const b = clone(fx.proof);
    b.pi_b[2] = ["0", "0"];
    expectSdkError(() => packGroth16Proof(b), "INVALID_PROOF", /pi_b.*not affine/);
  });

  it("rejects off-curve G1 and G2 points and the (0, 0) identity encoding", () => {
    const g1 = clone(fx.proof);
    g1.pi_a[1] = ((BigInt(g1.pi_a[1] as string) + 1n) % q).toString();
    expectSdkError(() => packGroth16Proof(g1), "INVALID_PROOF", /pi_a: not on the BN254 G1 curve/);

    const g2 = clone(fx.proof);
    (g2.pi_b[1] as string[])[0] = ((BigInt((g2.pi_b[1] as string[])[0] as string) + 1n) % q).toString();
    expectSdkError(() => packGroth16Proof(g2), "INVALID_PROOF", /pi_b: not on the BN254 G2/);

    const zero = clone(fx.proof);
    zero.pi_c = ["0", "0", "1"];
    expect(isOnG1Curve(0n, 0n)).toBe(false);
    expectSdkError(() => packGroth16Proof(zero), "INVALID_PROOF", /pi_c: not on/);
  });

  it("rejects wrong protocol, curve and shapes", () => {
    expectSdkError(() => packGroth16Proof({ ...fx.proof, protocol: "plonk" }), "INVALID_PROOF", /protocol/);
    expectSdkError(() => packGroth16Proof({ ...fx.proof, curve: "bls12381" }), "INVALID_PROOF", /curve/);
    expectSdkError(() => packGroth16Proof({ ...fx.proof, pi_a: ["1"] }), "INVALID_PROOF");
    expectSdkError(() => packGroth16Proof({ ...fx.proof, pi_b: [["1", "2"]] }), "INVALID_PROOF");
    expectSdkError(() => packGroth16Proof({ ...fx.proof, pi_b: [["1"], ["2"]] }), "INVALID_PROOF");
    expectSdkError(() => packGroth16Proof(null as never), "INVALID_PROOF");
    expect(toHex(packGroth16Proof({ ...fx.proof, curve: "BN254" }))).toBe(fx.proofHex);
  });
});

describe("packVerifyingKey", () => {
  it("matches the bytes soroban-zk-std accepted in set_verifying_key", () => {
    const bytes = packVerifyingKey(fx.verifyingKey);
    expect(bytes.length).toBe(VERIFYING_KEY_HEADER_SIZE + 64 * fx.verifyingKey.IC.length);
    expect(toHex(bytes)).toBe(fx.verifyingKeyHex);
  });

  it("writes the IC length as a big-endian u32 at offset 448", () => {
    const bytes = packVerifyingKey(fx.verifyingKey);
    expect(new DataView(bytes.buffer).getUint32(448, false)).toBe(2);
    expect(Array.from(bytes.subarray(448, 452))).toEqual([0, 0, 0, 2]);
  });

  it("packs a key with a single IC point (zero public inputs)", () => {
    const vk = clone(fx.verifyingKey);
    vk.IC = [vk.IC[0] as string[]];
    vk.nPublic = 0;
    const bytes = packVerifyingKey(vk);
    expect(bytes.length).toBe(VERIFYING_KEY_HEADER_SIZE + 64);
    expect(toHex(bytes)).toBe(fx.verifyingKeyHex.slice(0, (VERIFYING_KEY_HEADER_SIZE + 64) * 2).replace(/^(.{896})00000002/, "$100000001"));
  });

  it("rejects an empty IC and an nPublic that disagrees with IC", () => {
    expectSdkError(() => packVerifyingKey({ ...fx.verifyingKey, IC: [] }), "INVALID_VERIFYING_KEY", /IC/);
    expectSdkError(() => packVerifyingKey({ ...fx.verifyingKey, nPublic: 2 }), "INVALID_VERIFYING_KEY", /nPublic/);
  });

  it("rejects invalid points with INVALID_VERIFYING_KEY and names the point", () => {
    const vk = clone(fx.verifyingKey);
    (vk.IC[1] as string[])[0] = q.toString();
    expectSdkError(() => packVerifyingKey(vk), "INVALID_VERIFYING_KEY", /IC\[1\]\.x/);

    const delta = clone(fx.verifyingKey);
    (delta.vk_delta_2 as string[][])[0] = ["1", "2"];
    expectSdkError(() => packVerifyingKey(delta), "INVALID_VERIFYING_KEY", /vk_delta_2/);

    expectSdkError(() => packVerifyingKey({ ...fx.verifyingKey, protocol: "fflonk" }), "INVALID_VERIFYING_KEY");
  });
});

describe("packPublicSignals", () => {
  it("encodes each signal as a U256 ScVal", () => {
    const [sv] = packPublicSignals(fx.publicSignals);
    expect(sv?.switch()).toBe(xdr.ScValType.scvU256());
    expect(scValToBigInt(sv as xdr.ScVal)).toBe(9n);
  });

  it("accepts 0 and r - 1 and rejects r (boundary)", () => {
    const vals = packPublicSignals(["0", (r - 1n).toString(), r - 1n]);
    expect(vals.map((v) => scValToBigInt(v))).toEqual([0n, r - 1n, r - 1n]);
    expectSdkError(() => packPublicSignals([r.toString()]), "INVALID_FIELD_ELEMENT", /public signal \[0\]/);
    expectSdkError(() => packPublicSignals(["1", (r + 5n).toString()]), "INVALID_FIELD_ELEMENT", /\[1\]/);
  });

  it("rejects negative and non-integer signals", () => {
    expectSdkError(() => packPublicSignals(["-3"]), "INVALID_FIELD_ELEMENT");
    expectSdkError(() => packPublicSignals([-3]), "INVALID_FIELD_ELEMENT");
    expectSdkError(() => packPublicSignals(["9.0"]), "INVALID_FIELD_ELEMENT");
    expectSdkError(() => packPublicSignals("9" as never), "INVALID_ARGUMENT");
  });

  it("checks expectedCount, including an empty list", () => {
    expect(packPublicSignals([], { expectedCount: 0 })).toEqual([]);
    expectSdkError(() => packPublicSignals(["1", "2"], { expectedCount: 1 }), "INVALID_ARGUMENT", /expected 1, got 2/);
  });

  it("wraps signals as Vec<U256> and builds verify_proof args", () => {
    const vec = packPublicSignalsVec(fx.publicSignals);
    expect(vec.switch()).toBe(xdr.ScValType.scvVec());
    expect(vec.vec()?.length).toBe(1);

    const [proofArg, inputsArg, replayArg] = buildVerifyProofArgs(fx.proof, fx.publicSignals, true, {
      expectedCount: 1,
    });
    expect(proofArg.switch()).toBe(xdr.ScValType.scvBytes());
    expect(Buffer.from(proofArg.bytes()).toString("hex")).toBe(fx.proofHex);
    expect(inputsArg.toXDR("base64")).toBe(vec.toXDR("base64"));
    expect(replayArg.b()).toBe(true);
  });
});
