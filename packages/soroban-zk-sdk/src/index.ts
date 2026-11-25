/**
 * `@soroban-zk/sdk`: TypeScript client for `soroban-zk-std`.
 *
 * - {@link packGroth16Proof}, {@link packVerifyingKey}, {@link packPublicSignals}:
 *   SnarkJS output to the contract's big-endian wire layouts, validated locally.
 * - {@link simulateAndAssembleZkTx}: simulate a call, report CPU / RAM / read /
 *   write bytes and stroop fees, and assemble the transaction with a safety margin.
 * - {@link parseZkVerificationEvents}: decode `ZkVerificationEvent`s from RPC events.
 */

export {
  ZkContractError,
  type ZkContractErrorName,
  ZK_CONTRACT_ERROR_MESSAGES,
  zkContractErrorFromCode,
  zkContractErrorFromName,
  parseZkContractError,
  ZkSdkError,
  type ZkSdkErrorCode,
  ZkSimulationError,
} from "./errors.js";

export {
  BN254_FQ_MODULUS,
  BN254_FR_MODULUS,
  type FieldElementLike,
  isOnG1Curve,
  isOnG2Curve,
} from "./field.js";

export {
  G1_POINT_SIZE,
  G2_POINT_SIZE,
  GROTH16_PROOF_SIZE,
  VERIFYING_KEY_HEADER_SIZE,
  type SnarkjsG1,
  type SnarkjsG2,
  type SnarkjsGroth16Proof,
  type SnarkjsGroth16VerifyingKey,
  type PackPublicSignalsOptions,
  packGroth16Proof,
  packVerifyingKey,
  packPublicSignals,
  packPublicSignalsVec,
  buildVerifyProofArgs,
} from "./pack.js";

export {
  type ZkSimulationServer,
  type ZkResourceUsage,
  type ZkFeeBreakdown,
  type ZkAssembledTransaction,
  DEFAULT_SAFETY_MARGIN_PCT,
  MAX_SAFETY_MARGIN_PCT,
  describeSimulationError,
  simulateAndAssembleZkTx,
} from "./simulate.js";

export {
  ZK_VERIFICATION_TOPIC,
  ZK_VERIFICATION_STAGES,
  type ZkVerificationStage,
  type ZkFailureContext,
  type ZkVerificationFailure,
  type ZkEventMeta,
  type ZkVerificationEvent,
  type RpcContractEvent,
  type ParseZkEventsOptions,
  isZkVerificationEvent,
  parseZkVerificationEvent,
  parseZkVerificationEvents,
} from "./events.js";
