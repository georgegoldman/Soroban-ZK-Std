/**
 * Decoding of `ZkVerificationEvent`s published by
 * `soroban_zk_std::events::publish_verification_event`.
 *
 * On-chain shape:
 * - topics: `(String("zk_verification"), String(proof_system), bool success)`
 * - value: a `Map<Symbol, Val>` with keys `success`, `proof_system`,
 *   `public_inputs_count`, `proof_length`, `anti_replay`, `failure_details`
 *   and `context`. `None` is encoded as `Void`. `failure_details` is a map
 *   with `error_type`, `description`, `failure_stage` (a `#[contracttype]`
 *   unit enum, i.e. `Vec[Symbol(<variant>)]`) and `additional_info` (a
 *   `ZkFailureContext` struct map or `Void`).
 */

import { type rpc, xdr } from "@stellar/stellar-sdk";

import { ZkContractError, ZkSdkError, zkContractErrorFromName } from "./errors.js";

/** First topic of every `ZkVerificationEvent`. */
export const ZK_VERIFICATION_TOPIC = "zk_verification";

/** Stages of `soroban_zk_std::events::ZkVerificationStage`. */
export const ZK_VERIFICATION_STAGES = [
  "AntiReplayCheck",
  "VerifyingKeyLoad",
  "ProofDeserialization",
  "PublicInputsValidation",
  "CurveValidation",
  "PairingCheck",
  "NullifierRecording",
  "Unknown",
] as const;

export type ZkVerificationStage = (typeof ZK_VERIFICATION_STAGES)[number];

/** `soroban_zk_std::events::ZkFailureContext`. */
export interface ZkFailureContext {
  invalidInputIndex: number | null;
  byteOffset: number | null;
  invalidPoint: string | null;
  invalidPairIndex: number | null;
  contextInfo: string | null;
}

/** `soroban_zk_std::events::ZkVerificationFailure`. */
export interface ZkVerificationFailure {
  /** The error name, e.g. `"ReplayDetected"` or `"PairingCheckFailed"`. */
  errorType: string;
  /** The `ZkContractError` code for `errorType`, when it names one (`PairingCheckFailed` does not). */
  contractError?: ZkContractError;
  description: string;
  stage: ZkVerificationStage;
  additionalInfo: ZkFailureContext | null;
}

/** Where an event came from, copied from the RPC event when present. */
export interface ZkEventMeta {
  id?: string;
  ledger?: number;
  ledgerClosedAt?: string;
  txHash?: string;
  contractId?: string;
  inSuccessfulContractCall?: boolean;
}

/** A decoded `soroban_zk_std::events::ZkVerificationEvent`. */
export interface ZkVerificationEvent {
  success: boolean;
  proofSystem: string;
  publicInputsCount: number;
  proofLength: number;
  antiReplay: boolean;
  failure: ZkVerificationFailure | null;
  context: string | null;
  meta: ZkEventMeta;
}

/**
 * An event as Stellar RPC `getEvents` returns it: parsed (`rpc.Api.EventResponse`,
 * `xdr.ScVal` topics and value) or raw (`rpc.Api.RawEventResponse`, base64 XDR).
 */
export type RpcContractEvent =
  | rpc.Api.EventResponse
  | rpc.Api.RawEventResponse
  | {
      topic?: readonly (xdr.ScVal | string)[];
      value: xdr.ScVal | string;
      id?: string;
      ledger?: number;
      ledgerClosedAt?: string;
      txHash?: string;
      contractId?: unknown;
      inSuccessfulContractCall?: boolean;
    };

/** Options for {@link parseZkVerificationEvents}. */
export interface ParseZkEventsOptions {
  /**
   * When `true` (default), an event whose topics mark it as a
   * `ZkVerificationEvent` but whose payload does not decode throws
   * `ZkSdkError` `INVALID_EVENT`. When `false`, such events are skipped.
   */
  strict?: boolean;
}

function fail(message: string): never {
  throw new ZkSdkError("INVALID_EVENT", `ZkVerificationEvent: ${message}`);
}

function toScVal(value: xdr.ScVal | string, what: string): xdr.ScVal {
  if (typeof value === "string") {
    try {
      return xdr.ScVal.fromXDR(value, "base64");
    } catch (err) {
      throw new ZkSdkError("INVALID_EVENT", `ZkVerificationEvent: ${what} is not base64 ScVal XDR`, {
        cause: err,
      });
    }
  }
  return value;
}

const T = xdr.ScValType;

function isString(v: xdr.ScVal, expected?: string): boolean {
  return v.switch() === T.scvString() && (expected === undefined || v.str().toString() === expected);
}

function str(v: xdr.ScVal | undefined, what: string): string {
  if (!v || v.switch() !== T.scvString()) fail(`${what} must be a String`);
  return v.str().toString();
}

function optStr(v: xdr.ScVal | undefined, what: string): string | null {
  if (!v || v.switch() === T.scvVoid()) return null;
  return str(v, what);
}

function bool(v: xdr.ScVal | undefined, what: string): boolean {
  if (!v || v.switch() !== T.scvBool()) fail(`${what} must be a bool`);
  return v.b();
}

function u32(v: xdr.ScVal | undefined, what: string): number {
  if (!v || v.switch() !== T.scvU32()) fail(`${what} must be a u32`);
  return v.u32();
}

function optU32(v: xdr.ScVal | undefined, what: string): number | null {
  if (!v || v.switch() === T.scvVoid()) return null;
  return u32(v, what);
}

/** Reads a `Map<Symbol, Val>` into a lookup by key name. */
function symbolMap(v: xdr.ScVal | undefined, what: string): Map<string, xdr.ScVal> {
  if (!v || v.switch() !== T.scvMap()) fail(`${what} must be a map`);
  const out = new Map<string, xdr.ScVal>();
  for (const entry of v.map() ?? []) {
    const key = entry.key();
    if (key.switch() !== T.scvSymbol()) fail(`${what} has a non-Symbol key`);
    out.set(key.sym().toString(), entry.val());
  }
  return out;
}

function stage(v: xdr.ScVal | undefined): ZkVerificationStage {
  // `#[contracttype]` unit variants encode as `Vec[Symbol(name)]`.
  if (!v || v.switch() !== T.scvVec()) fail("failure_stage must be an enum (Vec[Symbol])");
  const items = v.vec() ?? [];
  const head = items[0];
  if (items.length !== 1 || !head || head.switch() !== T.scvSymbol()) {
    fail("failure_stage must be a unit enum variant");
  }
  const name = head.sym().toString();
  if (!(ZK_VERIFICATION_STAGES as readonly string[]).includes(name)) {
    fail(`unknown failure_stage "${name}"`);
  }
  return name as ZkVerificationStage;
}

function failureContext(v: xdr.ScVal | undefined): ZkFailureContext | null {
  if (!v || v.switch() === T.scvVoid()) return null;
  const m = symbolMap(v, "additional_info");
  return {
    invalidInputIndex: optU32(m.get("invalid_input_index"), "invalid_input_index"),
    byteOffset: optU32(m.get("byte_offset"), "byte_offset"),
    invalidPoint: optStr(m.get("invalid_point"), "invalid_point"),
    invalidPairIndex: optU32(m.get("invalid_pair_index"), "invalid_pair_index"),
    contextInfo: optStr(m.get("context_info"), "context_info"),
  };
}

function failureDetails(v: xdr.ScVal | undefined): ZkVerificationFailure | null {
  if (!v || v.switch() === T.scvVoid()) return null;
  const m = symbolMap(v, "failure_details");
  const errorType = str(m.get("error_type"), "error_type");
  const failure: ZkVerificationFailure = {
    errorType,
    description: str(m.get("description"), "description"),
    stage: stage(m.get("failure_stage")),
    additionalInfo: failureContext(m.get("additional_info")),
  };
  const contractError = zkContractErrorFromName(errorType);
  if (contractError !== undefined) failure.contractError = contractError;
  return failure;
}

function meta(event: RpcContractEvent): ZkEventMeta {
  const out: ZkEventMeta = {};
  if (typeof event.id === "string") out.id = event.id;
  if (typeof event.ledger === "number") out.ledger = event.ledger;
  if (typeof event.ledgerClosedAt === "string") out.ledgerClosedAt = event.ledgerClosedAt;
  if (typeof event.txHash === "string") out.txHash = event.txHash;
  if (typeof event.inSuccessfulContractCall === "boolean") {
    out.inSuccessfulContractCall = event.inSuccessfulContractCall;
  }
  const cid = (event as { contractId?: unknown }).contractId;
  if (typeof cid === "string") {
    out.contractId = cid;
  } else if (cid && typeof (cid as { contractId?: unknown }).contractId === "function") {
    out.contractId = (cid as { contractId(): string }).contractId();
  }
  return out;
}

function topicsOf(event: RpcContractEvent): xdr.ScVal[] {
  const topic = (event as { topic?: readonly (xdr.ScVal | string)[] }).topic ?? [];
  return topic.map((t, i) => toScVal(t, `topic[${i}]`));
}

/** `true` when the event's topics mark it as a `ZkVerificationEvent`. */
export function isZkVerificationEvent(event: RpcContractEvent): boolean {
  try {
    const topics = topicsOf(event);
    return topics.length === 3 && isString(topics[0] as xdr.ScVal, ZK_VERIFICATION_TOPIC);
  } catch {
    return false;
  }
}

/**
 * Decodes one RPC event into a {@link ZkVerificationEvent}.
 *
 * @throws ZkSdkError `INVALID_EVENT` if the event is not a `ZkVerificationEvent`
 *   or its payload does not match the on-chain shape (including topics that
 *   disagree with the payload's `proof_system` / `success`).
 */
export function parseZkVerificationEvent(event: RpcContractEvent): ZkVerificationEvent {
  if (event === null || typeof event !== "object") fail("expected an RPC event object");
  const topics = topicsOf(event);
  if (topics.length !== 3 || !isString(topics[0] as xdr.ScVal, ZK_VERIFICATION_TOPIC)) {
    fail(`topics must be ("${ZK_VERIFICATION_TOPIC}", proof_system, success)`);
  }
  const topicSystem = str(topics[1], "topic[1] (proof_system)");
  const topicSuccess = bool(topics[2], "topic[2] (success)");

  const m = symbolMap(toScVal(event.value, "value"), "value");
  const decoded: ZkVerificationEvent = {
    success: bool(m.get("success"), "success"),
    proofSystem: str(m.get("proof_system"), "proof_system"),
    publicInputsCount: u32(m.get("public_inputs_count"), "public_inputs_count"),
    proofLength: u32(m.get("proof_length"), "proof_length"),
    antiReplay: bool(m.get("anti_replay"), "anti_replay"),
    failure: failureDetails(m.get("failure_details")),
    context: optStr(m.get("context"), "context"),
    meta: meta(event),
  };

  if (decoded.proofSystem !== topicSystem || decoded.success !== topicSuccess) {
    fail("topics disagree with the payload's proof_system/success");
  }
  if (decoded.success !== (decoded.failure === null)) {
    fail("success must be true exactly when failure_details is None");
  }
  return decoded;
}

/**
 * Decodes every `ZkVerificationEvent` in an RPC `getEvents` result (the
 * response object or its `events` array, parsed or raw). Events from other
 * topics are skipped.
 */
export function parseZkVerificationEvents(
  rpcEvents: readonly RpcContractEvent[] | { events: readonly RpcContractEvent[] },
  options: ParseZkEventsOptions = {},
): ZkVerificationEvent[] {
  const strict = options.strict ?? true;
  const list = Array.isArray(rpcEvents)
    ? rpcEvents
    : (rpcEvents as { events?: readonly RpcContractEvent[] } | null)?.events;
  if (!Array.isArray(list)) {
    throw new ZkSdkError("INVALID_ARGUMENT", "expected an array of RPC events or a getEvents response");
  }
  const out: ZkVerificationEvent[] = [];
  for (const event of list) {
    if (!isZkVerificationEvent(event)) continue;
    try {
      out.push(parseZkVerificationEvent(event));
    } catch (err) {
      if (strict) throw err;
    }
  }
  return out;
}
