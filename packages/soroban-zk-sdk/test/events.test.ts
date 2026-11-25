import { Contract, nativeToScVal, xdr } from "@stellar/stellar-sdk";
import { describe, expect, it } from "vitest";

import {
  isZkVerificationEvent,
  parseZkVerificationEvent,
  parseZkVerificationEvents,
  ZkContractError,
  ZkSdkError,
} from "../src/index.js";
import { type EventsFixture, type Groth16Fixture, loadJson } from "./helpers.js";

const { events } = loadJson<EventsFixture>("events.json");
const g16 = loadJson<Groth16Fixture>("groth16.json");
const CONTRACT_ID = "CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC";

const ev = (name: string) => {
  const e = events[name];
  if (!e) throw new Error(`missing fixture ${name}`);
  return e;
};

/** The same event as `rpc.Server.getEvents` returns it (parsed ScVals). */
const parsed = (raw: { topic: string[]; value: string }) => ({
  id: "0000123-0000000001",
  type: "contract" as const,
  ledger: 123,
  ledgerClosedAt: "2026-11-25T08:00:00Z",
  transactionIndex: 1,
  operationIndex: 0,
  inSuccessfulContractCall: true,
  txHash: "ab".repeat(32),
  contractId: new Contract(CONTRACT_ID),
  topic: raw.topic.map((t) => xdr.ScVal.fromXDR(t, "base64")),
  value: xdr.ScVal.fromXDR(raw.value, "base64"),
});

function expectInvalid(fn: () => unknown, message?: RegExp): void {
  let thrown: unknown;
  try {
    fn();
  } catch (err) {
    thrown = err;
  }
  expect(thrown).toBeInstanceOf(ZkSdkError);
  expect((thrown as ZkSdkError).code).toBe("INVALID_EVENT");
  if (message) expect((thrown as ZkSdkError).message).toMatch(message);
}

describe("parseZkVerificationEvent", () => {
  it("decodes the success event the contract published for a verified proof", () => {
    const decoded = parseZkVerificationEvent(g16.contractSuccessEvent);
    expect(decoded).toEqual({
      success: true,
      proofSystem: "groth16",
      publicInputsCount: 1,
      proofLength: 256,
      antiReplay: false,
      failure: null,
      context: null,
      meta: {},
    });
  });

  it("decodes a success event with anti-replay on", () => {
    const decoded = parseZkVerificationEvent(ev("success"));
    expect(decoded.success).toBe(true);
    expect(decoded.publicInputsCount).toBe(2);
    expect(decoded.antiReplay).toBe(true);
  });

  it("decodes a deserialization failure with a byte offset", () => {
    const d = parseZkVerificationEvent(ev("deserialization_failure"));
    expect(d.success).toBe(false);
    expect(d.proofLength).toBe(255);
    expect(d.failure).toEqual({
      errorType: "DeserializationError",
      contractError: ZkContractError.DeserializationError,
      description: "Proof or point data could not be deserialized into valid structures",
      stage: "ProofDeserialization",
      additionalInfo: {
        invalidInputIndex: null,
        byteOffset: 255,
        invalidPoint: null,
        invalidPairIndex: null,
        contextInfo: null,
      },
    });
  });

  it("decodes a pairing failure (no ZkContractError code)", () => {
    const d = parseZkVerificationEvent(ev("pairing_failure"));
    expect(d.failure?.errorType).toBe("PairingCheckFailed");
    expect(d.failure?.contractError).toBeUndefined();
    expect(d.failure?.stage).toBe("PairingCheck");
    expect(d.failure?.additionalInfo?.contextInfo).toBe(
      "e(A,B) * e(-alpha,beta) * e(-acc,gamma) * e(-C,delta) != 1",
    );
  });

  it("decodes replay, field-element and curve failures and the event context", () => {
    const replay = parseZkVerificationEvent(ev("replay_detected_with_context"));
    expect(replay.failure?.contractError).toBe(ZkContractError.ReplayDetected);
    expect(replay.failure?.stage).toBe("AntiReplayCheck");
    expect(replay.failure?.additionalInfo).toBeNull();
    expect(replay.context).toBe("nullifier already spent");

    const field = parseZkVerificationEvent(ev("invalid_field_element"));
    expect(field.failure?.contractError).toBe(ZkContractError.InvalidFieldElement);
    expect(field.failure?.stage).toBe("PublicInputsValidation");
    expect(field.failure?.additionalInfo?.invalidInputIndex).toBe(1);

    const curve = parseZkVerificationEvent(ev("curve_validation_point_b"));
    expect(curve.failure?.stage).toBe("CurveValidation");
    expect(curve.failure?.additionalInfo?.invalidPoint).toBe("B");
  });

  it("decodes parsed RPC events and copies their metadata", () => {
    const d = parseZkVerificationEvent(parsed(ev("success")));
    expect(d.success).toBe(true);
    expect(d.meta).toEqual({
      id: "0000123-0000000001",
      ledger: 123,
      ledgerClosedAt: "2026-11-25T08:00:00Z",
      txHash: "ab".repeat(32),
      contractId: CONTRACT_ID,
      inSuccessfulContractCall: true,
    });
    const raw = parseZkVerificationEvent({ ...ev("success"), contractId: CONTRACT_ID });
    expect(raw.meta.contractId).toBe(CONTRACT_ID);
  });

  it("rejects events whose topics disagree with the payload", () => {
    const e = ev("success");
    const wrongSuccess = { topic: [e.topic[0], e.topic[1], xdr.ScVal.scvBool(false).toXDR("base64")], value: e.value };
    expectInvalid(() => parseZkVerificationEvent(wrongSuccess as never), /disagree/);

    const wrongSystem = { topic: [e.topic[0], nativeToScVal("plonk", { type: "string" }).toXDR("base64"), e.topic[2]], value: e.value };
    expectInvalid(() => parseZkVerificationEvent(wrongSystem as never), /disagree/);
  });

  it("rejects other topics, bad XDR and malformed payloads", () => {
    const e = ev("success");
    expectInvalid(() => parseZkVerificationEvent({ topic: [e.topic[1] as string], value: e.value }), /topics/);
    expectInvalid(() => parseZkVerificationEvent({ topic: e.topic, value: "not-xdr!!" }), /base64/);
    expectInvalid(() => parseZkVerificationEvent({ topic: e.topic, value: xdr.ScVal.scvU32(1) }), /map/);

    // A payload missing `proof_length`.
    const m = xdr.ScVal.fromXDR(e.value, "base64");
    const trimmed = xdr.ScVal.scvMap((m.map() ?? []).filter((x) => x.key().sym().toString() !== "proof_length"));
    expectInvalid(() => parseZkVerificationEvent({ topic: e.topic, value: trimmed }), /proof_length/);

    // An unknown failure stage.
    const f = xdr.ScVal.fromXDR(ev("pairing_failure").value, "base64");
    const patched = xdr.ScVal.fromXDR(
      f.toXDR("base64"),
      "base64",
    );
    for (const entry of patched.map() ?? []) {
      if (entry.key().sym().toString() !== "failure_details") continue;
      for (const inner of entry.val().map() ?? []) {
        if (inner.key().sym().toString() === "failure_stage") {
          inner.val(xdr.ScVal.scvVec([xdr.ScVal.scvSymbol("Teleport")]));
        }
      }
    }
    expectInvalid(
      () => parseZkVerificationEvent({ topic: ev("pairing_failure").topic, value: patched }),
      /unknown failure_stage "Teleport"/,
    );
  });

  it("rejects success == true with failure details present", () => {
    const fail = ev("pairing_failure");
    const v = xdr.ScVal.fromXDR(fail.value, "base64");
    for (const entry of v.map() ?? []) {
      if (entry.key().sym().toString() === "success") entry.val(xdr.ScVal.scvBool(true));
    }
    const topic = [fail.topic[0], fail.topic[1], xdr.ScVal.scvBool(true).toXDR("base64")] as string[];
    expectInvalid(() => parseZkVerificationEvent({ topic, value: v }), /failure_details/);
  });
});

describe("parseZkVerificationEvents", () => {
  const legacy = {
    topic: [nativeToScVal("legacy", { type: "string" }).toXDR("base64"), nativeToScVal("zk", { type: "string" }).toXDR("base64")],
    value: nativeToScVal("ok", { type: "string" }).toXDR("base64"),
  };
  const telemetry = {
    topic: [xdr.ScVal.scvSymbol("zk_verify").toXDR("base64"), xdr.ScVal.scvSymbol("groth16").toXDR("base64")],
    value: xdr.ScVal.scvU32(1).toXDR("base64"),
  };

  it("keeps only ZkVerificationEvents, in order, from a mixed list", () => {
    const list = [legacy, ev("success"), telemetry, ev("pairing_failure"), { value: "AAAAAQ==" }];
    const out = parseZkVerificationEvents(list);
    expect(out.map((e) => e.success)).toEqual([true, false]);
    expect(isZkVerificationEvent(legacy)).toBe(false);
    expect(isZkVerificationEvent(ev("success"))).toBe(true);
  });

  it("accepts a getEvents response object and parsed events", () => {
    const out = parseZkVerificationEvents({ events: Object.values(events).map(parsed) });
    expect(out).toHaveLength(6);
    expect(out.every((e) => e.meta.contractId === CONTRACT_ID)).toBe(true);
  });

  it("returns [] for an empty list and throws on a non-list", () => {
    expect(parseZkVerificationEvents([])).toEqual([]);
    expect(() => parseZkVerificationEvents({} as never)).toThrow(ZkSdkError);
  });

  it("throws on a malformed zk event in strict mode and skips it otherwise", () => {
    const broken = { topic: ev("success").topic, value: xdr.ScVal.scvVoid().toXDR("base64") };
    expect(() => parseZkVerificationEvents([ev("success"), broken])).toThrow(ZkSdkError);
    const lenient = parseZkVerificationEvents([ev("success"), broken], { strict: false });
    expect(lenient).toHaveLength(1);
  });
});
