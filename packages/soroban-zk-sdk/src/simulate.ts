/**
 * Simulation and assembly of `soroban-zk-std` contract calls with a resource
 * report and readable errors.
 */

import {
  type FeeBumpTransaction,
  rpc,
  SorobanDataBuilder,
  type Transaction,
  type xdr,
} from "@stellar/stellar-sdk";

import {
  parseZkContractError,
  ZK_CONTRACT_ERROR_MESSAGES,
  ZkContractError,
  ZkSdkError,
  ZkSimulationError,
} from "./errors.js";

/**
 * The part of `rpc.Server` this module uses. A real `rpc.Server` satisfies it;
 * tests can pass a stub.
 *
 * When `_simulateTransaction` is present it is preferred, because the raw RPC
 * response is the only place the server's `cost.memBytes` (RAM) figure appears.
 */
export interface ZkSimulationServer {
  simulateTransaction(tx: Transaction | FeeBumpTransaction): Promise<rpc.Api.SimulateTransactionResponse>;
  _simulateTransaction?(
    tx: Transaction | FeeBumpTransaction,
  ): Promise<rpc.Api.RawSimulateTransactionResponse>;
}

/** Resources the simulated invocation needs. */
export interface ZkResourceUsage {
  /** CPU instructions the host metered during simulation. */
  cpuInstructions: number;
  /** CPU instruction limit written to the transaction (simulated value plus the safety margin). */
  cpuInstructionsLimit: number;
  /**
   * Memory (RAM) bytes the host metered, from the RPC response's `cost.memBytes`.
   * `null` when the server does not report it (recent Stellar RPC versions drop the field).
   */
  memoryBytes: number | null;
  /** Bytes read from disk-backed ledger entries (`diskReadBytes`). */
  readBytes: number;
  /** Bytes written to ledger entries. */
  writeBytes: number;
  /** Number of read-only ledger keys in the footprint. */
  readOnlyEntries: number;
  /** Number of read-write ledger keys in the footprint. */
  readWriteEntries: number;
}

/** Fees of the assembled transaction, in stroops. */
export interface ZkFeeBreakdown {
  /** The classic inclusion fee carried over from the input transaction. */
  inclusionFee: bigint;
  /** `minResourceFee` reported by simulation. */
  minResourceFee: bigint;
  /** Resource fee written to the transaction (`minResourceFee` plus the safety margin). */
  resourceFee: bigint;
  /** Total fee of the assembled transaction (`inclusionFee + resourceFee`). */
  totalFee: bigint;
}

/** Result of {@link simulateAndAssembleZkTx}. */
export interface ZkAssembledTransaction {
  /** The transaction with footprint, auth, resources and fee set; sign and submit it. */
  transaction: Transaction;
  resources: ZkResourceUsage;
  fees: ZkFeeBreakdown;
  /** The safety margin that was applied, in percent. */
  safetyMarginPct: number;
  /** The simulated return value (for `verify_proof`, `scvBool(true)` on success). */
  returnValue?: xdr.ScVal;
  /** Latest ledger the RPC server knew when simulating. */
  latestLedger: number;
}

/** Default safety margin applied to CPU instructions and the resource fee. */
export const DEFAULT_SAFETY_MARGIN_PCT = 15;
/** Largest accepted safety margin. */
export const MAX_SAFETY_MARGIN_PCT = 1000;

const U32_MAX = 0xffff_ffff;

/** `ceil(value * (100 + pct) / 100)` for a non-negative bigint, using basis points. */
function withMarginBigInt(value: bigint, pct: number): bigint {
  const factorBp = BigInt(10_000 + Math.round(pct * 100));
  return (value * factorBp + 9_999n) / 10_000n;
}

function withMarginU32(value: number, pct: number): number {
  return Math.min(U32_MAX, Number(withMarginBigInt(BigInt(value), pct)));
}

function readMemBytes(raw: rpc.Api.RawSimulateTransactionResponse): number | null {
  const cost = (raw as { cost?: { memBytes?: unknown } }).cost;
  const mem = cost?.memBytes;
  if (typeof mem === "string" && /^[0-9]+$/.test(mem)) return Number(mem);
  if (typeof mem === "number" && Number.isFinite(mem) && mem >= 0) return mem;
  return null;
}

/** Builds the readable message for a failed simulation. */
export function describeSimulationError(error: string): {
  message: string;
  contractError?: ZkContractError;
} {
  const contractError = parseZkContractError(error);
  if (contractError !== undefined) {
    return {
      contractError,
      message: `contract returned ${ZkContractError[contractError]} (#${contractError}): ${ZK_CONTRACT_ERROR_MESSAGES[contractError]}`,
    };
  }
  const firstLine = error.split("\n", 1)[0]?.trim() || "unknown error";
  return { message: `simulation failed: ${firstLine}` };
}

/**
 * Simulates `tx` (a single `invokeHostFunction` call into a `soroban-zk-std`
 * contract, typically `verify_proof`), reports the resources and fees it
 * needs, and returns the transaction assembled with those resources.
 *
 * `safetyMarginPct` (default 15) is added to the simulated CPU instructions and
 * to the resource fee, rounding up, so small differences between simulation
 * and execution do not make the transaction fail. Read and write bytes come
 * from the footprint and are used as simulated.
 *
 * @throws ZkSimulationError `SIMULATION_FAILED`, with `contractError` set when
 *   the host reported a `ZkContractError` (`1..=7`); `RESTORE_REQUIRED` when
 *   archived ledger entries must be restored first.
 * @throws ZkSdkError `INVALID_ARGUMENT` for an out-of-range margin.
 */
export async function simulateAndAssembleZkTx(
  server: ZkSimulationServer,
  tx: Transaction,
  safetyMarginPct: number = DEFAULT_SAFETY_MARGIN_PCT,
): Promise<ZkAssembledTransaction> {
  if (
    typeof safetyMarginPct !== "number" ||
    !Number.isFinite(safetyMarginPct) ||
    safetyMarginPct < 0 ||
    safetyMarginPct > MAX_SAFETY_MARGIN_PCT
  ) {
    throw new ZkSdkError(
      "INVALID_ARGUMENT",
      `safetyMarginPct must be a number between 0 and ${MAX_SAFETY_MARGIN_PCT}`,
    );
  }

  let memoryBytes: number | null = null;
  let sim: rpc.Api.SimulateTransactionResponse;
  if (typeof server._simulateTransaction === "function") {
    const raw = await server._simulateTransaction(tx);
    memoryBytes = readMemBytes(raw);
    sim = rpc.parseRawSimulation(raw);
  } else {
    sim = await server.simulateTransaction(tx);
  }

  if (rpc.Api.isSimulationError(sim)) {
    const { message, contractError } = describeSimulationError(sim.error);
    throw new ZkSimulationError("SIMULATION_FAILED", message, sim.error, contractError);
  }
  if (rpc.Api.isSimulationRestore(sim)) {
    throw new ZkSimulationError(
      "RESTORE_REQUIRED",
      `archived ledger entries must be restored before this call (restore resource fee: ${sim.restorePreamble.minResourceFee} stroops); submit a RestoreFootprint transaction first`,
      "restore required",
    );
  }
  if (!rpc.Api.isSimulationSuccess(sim)) {
    throw new ZkSimulationError("SIMULATION_FAILED", "simulation failed: unrecognized response", "");
  }

  const simulatedData = sim.transactionData.build();
  const res = simulatedData.resources();
  const footprint = res.footprint();
  const cpuInstructions = res.instructions();
  const readBytes = res.diskReadBytes();
  const writeBytes = res.writeBytes();
  const minResourceFee = BigInt(sim.minResourceFee);

  const cpuInstructionsLimit = withMarginU32(cpuInstructions, safetyMarginPct);
  const resourceFee = withMarginBigInt(minResourceFee, safetyMarginPct);

  const transactionData = new SorobanDataBuilder(simulatedData)
    .setResources(cpuInstructionsLimit, readBytes, writeBytes)
    .setResourceFee(resourceFee);

  const transaction = rpc
    .assembleTransaction(tx, {
      ...sim,
      transactionData,
      minResourceFee: resourceFee.toString(),
    })
    .build();

  const totalFee = BigInt(transaction.fee);
  const result: ZkAssembledTransaction = {
    transaction,
    resources: {
      cpuInstructions,
      cpuInstructionsLimit,
      memoryBytes,
      readBytes,
      writeBytes,
      readOnlyEntries: footprint.readOnly().length,
      readWriteEntries: footprint.readWrite().length,
    },
    fees: {
      inclusionFee: totalFee - resourceFee,
      minResourceFee,
      resourceFee,
      totalFee,
    },
    safetyMarginPct,
    latestLedger: sim.latestLedger,
  };
  if (sim.result?.retval !== undefined) result.returnValue = sim.result.retval;
  return result;
}
