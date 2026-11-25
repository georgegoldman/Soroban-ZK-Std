/**
 * Error types and the `ZkContractError` code table.
 *
 * `ZkContractError` mirrors `soroban_zk_std::ZkContractError`
 * (`#[contracterror] #[repr(u32)]`), which reaches clients as
 * `Error(Contract, #<code>)` in simulation and transaction results.
 */

/** Numeric codes of `soroban_zk_std::ZkContractError` (`1..=7`). */
export enum ZkContractError {
  InvalidFieldElement = 1,
  InvalidInput = 2,
  DeserializationError = 3,
  HostError = 4,
  StorageError = 5,
  ConstraintUnsatisfied = 6,
  ReplayDetected = 7,
}

/** Name of each contract error, as `ZkVerificationEvent.failure_details.error_type` spells it. */
export type ZkContractErrorName = keyof typeof ZkContractError;

/**
 * Human-readable descriptions for each `ZkContractError` code. The wording
 * matches `soroban_zk_std::events::ZkVerificationEvent::failure` so on-chain
 * events and client-side errors read the same.
 */
export const ZK_CONTRACT_ERROR_MESSAGES: Readonly<Record<ZkContractError, string>> = Object.freeze({
  [ZkContractError.InvalidFieldElement]:
    "One or more public inputs exceed the BN254 scalar field modulus",
  [ZkContractError.InvalidInput]: "Invalid input parameters (wrong lengths, empty data, etc.)",
  [ZkContractError.DeserializationError]:
    "Proof or point data could not be deserialized into valid structures",
  [ZkContractError.HostError]: "Soroban host function call failed or trapped",
  [ZkContractError.StorageError]:
    "Ledger storage operation failed (for verify_proof: no verifying key is stored)",
  [ZkContractError.ConstraintUnsatisfied]:
    "Zero-knowledge constraint or gadget invariant was violated",
  [ZkContractError.ReplayDetected]:
    "Proof has already been verified (anti-replay protection triggered)",
});

/** Returns the `ZkContractError` for a numeric code, or `undefined` if the code is not `1..=7`. */
export function zkContractErrorFromCode(code: number): ZkContractError | undefined {
  return Number.isInteger(code) && code >= 1 && code <= 7 ? (code as ZkContractError) : undefined;
}

/** Returns the `ZkContractError` for an error name such as `"ReplayDetected"`, or `undefined`. */
export function zkContractErrorFromName(name: string): ZkContractError | undefined {
  const value = (ZkContractError as unknown as Record<string, unknown>)[name];
  return typeof value === "number" ? (value as ZkContractError) : undefined;
}

/** Codes for errors raised by this SDK itself (client-side validation). */
export type ZkSdkErrorCode =
  | "INVALID_FIELD_ELEMENT"
  | "INVALID_POINT"
  | "INVALID_PROOF"
  | "INVALID_VERIFYING_KEY"
  | "INVALID_ARGUMENT"
  | "INVALID_EVENT"
  | "SIMULATION_FAILED"
  | "RESTORE_REQUIRED";

/** Base class for every error this SDK throws. */
export class ZkSdkError extends Error {
  readonly code: ZkSdkErrorCode;

  constructor(code: ZkSdkErrorCode, message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = "ZkSdkError";
    this.code = code;
  }
}

/**
 * Thrown by `simulateAndAssembleZkTx` when simulation fails. When the failure
 * is a `ZkContractError`, `contractError` holds its code and `message` its
 * human-readable description.
 */
export class ZkSimulationError extends ZkSdkError {
  /** The contract error, when the host reported `Error(Contract, #1..=7)`. */
  readonly contractError?: ZkContractError;
  /** The raw error string returned by the RPC server. */
  readonly rpcError: string;

  constructor(
    code: Extract<ZkSdkErrorCode, "SIMULATION_FAILED" | "RESTORE_REQUIRED">,
    message: string,
    rpcError: string,
    contractError?: ZkContractError,
  ) {
    super(code, message);
    this.name = "ZkSimulationError";
    this.rpcError = rpcError;
    if (contractError !== undefined) this.contractError = contractError;
  }
}

const CONTRACT_ERROR_RE = /Error\(\s*Contract\s*,\s*#(\d+)\s*\)/;

/**
 * Extracts the `ZkContractError` from a host error string such as
 * `"HostError: Error(Contract, #3)\n…"`. Returns `undefined` when the string
 * carries no contract error or the code is outside `1..=7`.
 */
export function parseZkContractError(error: string): ZkContractError | undefined {
  const match = CONTRACT_ERROR_RE.exec(error);
  if (!match || match[1] === undefined) return undefined;
  return zkContractErrorFromCode(Number(match[1]));
}
