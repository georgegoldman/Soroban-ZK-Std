import { GasCalculatorInputs, GasEstimationResult, ProofType } from '../types/gas';
import { protocol25ProofConfigs } from '../data/mockProofConfigs';

/** Soroban Protocol 25 per-transaction CPU instruction cap */
export const SOROBAN_TX_INSTRUCTION_CAP = 400_000_000;

/** 1 XLM = 10,000,000 stroops */
export const STROOPS_PER_XLM = 10_000_000;

/** Base inclusion fee per operation in stroops */
export const BASE_INCLUSION_FEE_STROOPS = 100;

/** Protocol 25 resource fee schedule (stroops) */
export const FEE_PER_10K_INSTRUCTIONS_STROOPS = 25;
export const FEE_PER_1KB_READ_STROOPS = 1_786;
export const FEE_PER_1KB_WRITE_STROOPS = 11_800;
export const FEE_PER_READ_ENTRY_STROOPS = 6_250;
export const FEE_PER_WRITE_ENTRY_STROOPS = 10_000;
export const FEE_PER_1KB_TX_SIZE_STROOPS = 1_624;

/** 30-day persistent storage TTL rent constants (~5s/ledger -> 518,400 ledgers) */
export const LEDGERS_PER_30_DAYS = 518_400;
export const PERSISTENT_RENT_STROOPS_PER_KB_30_DAYS = 1_200_000;

function sanitizeNonNegative(value: number, fallback = 0): number {
  if (!Number.isFinite(value)) return fallback;
  return Math.max(0, Math.trunc(value));
}

export function stroopsToXlm(stroops: number): number {
  return Number((stroops / STROOPS_PER_XLM).toFixed(7));
}

export function estimateGas(inputs: GasCalculatorInputs): GasEstimationResult {
  const config = protocol25ProofConfigs[inputs.proofType] ?? protocol25ProofConfigs['Groth16'];

  const publicInputs = sanitizeNonNegative(inputs.publicInputs, 0);
  const constraints = sanitizeNonNegative(inputs.constraints, 0);
  const hashRounds = sanitizeNonNegative(inputs.hashRounds, 0);
  const proofSize = sanitizeNonNegative(inputs.proofSize, config.defaultProofSize);
  const iterationCount = Math.max(1, sanitizeNonNegative(inputs.iterationCount, 1));

  let singleCost = config.baseCost;

  if (config.perInputCost) {
    singleCost += publicInputs * config.perInputCost;
  }

  if (config.perConstraintCost) {
    singleCost += constraints * config.perConstraintCost;
  }

  if (config.perRoundCost) {
    singleCost += hashRounds * config.perRoundCost;
  }

  // Batch proof types amortize pairing/setup cost across proofs
  let instructionCount = singleCost;
  if (iterationCount > 1) {
    if (config.batchPerProofCost !== undefined) {
      const perExtraProof = config.batchPerProofCost + publicInputs * config.perInputCost;
      instructionCount = singleCost + (iterationCount - 1) * perExtraProof;
    } else {
      instructionCount = singleCost * iterationCount;
    }
  }

  instructionCount = Math.round(instructionCount);

  const instructionCapPercent = Number(
    ((instructionCount / SOROBAN_TX_INSTRUCTION_CAP) * 100).toFixed(2),
  );

  // Ledger read/write byte footprint
  const ledgerReadBytes =
    config.vkBytes + (proofSize + publicInputs * config.perInputBytes) * iterationCount;
  const ledgerWriteBytes = config.nullifierWriteBytes * iterationCount;

  // Soroban Protocol 25 resource fee estimation (stroops)
  const cpuFeeStroops = Math.ceil((instructionCount / 10_000) * FEE_PER_10K_INSTRUCTIONS_STROOPS);
  const readBytesFeeStroops = Math.ceil((ledgerReadBytes / 1024) * FEE_PER_1KB_READ_STROOPS);
  const writeBytesFeeStroops = Math.ceil((ledgerWriteBytes / 1024) * FEE_PER_1KB_WRITE_STROOPS);
  const entryFeeStroops =
    config.ledgerReadEntries * FEE_PER_READ_ENTRY_STROOPS +
    config.ledgerWriteEntries * iterationCount * FEE_PER_WRITE_ENTRY_STROOPS;
  const txSizeBytes = 256 + proofSize * iterationCount + publicInputs * config.perInputBytes;
  const bandwidthFeeStroops = Math.ceil((txSizeBytes / 1024) * FEE_PER_1KB_TX_SIZE_STROOPS);

  const inclusionFeeStroops = BASE_INCLUSION_FEE_STROOPS;
  const resourceFeeStroops =
    cpuFeeStroops +
    readBytesFeeStroops +
    writeBytesFeeStroops +
    entryFeeStroops +
    bandwidthFeeStroops;
  const totalFeeStroops = inclusionFeeStroops + resourceFeeStroops;
  const totalFeeXlm = stroopsToXlm(totalFeeStroops);

  // 30-day persistent storage TTL rent for VK + nullifier entries
  const persistentStorageBytes = config.vkBytes + ledgerWriteBytes;
  const ttlRent30DaysStroops = Math.ceil(
    (persistentStorageBytes / 1024) * PERSISTENT_RENT_STROOPS_PER_KB_30_DAYS,
  );
  const ttlRent30DaysXlm = stroopsToXlm(ttlRent30DaysStroops);

  // Determine relative complexity
  let relativeComplexity: GasEstimationResult['relativeComplexity'] = 'Low';
  if (instructionCount >= config.complexityThresholds.extreme) {
    relativeComplexity = 'Extreme';
  } else if (instructionCount >= config.complexityThresholds.high) {
    relativeComplexity = 'High';
  } else if (instructionCount >= config.complexityThresholds.medium) {
    relativeComplexity = 'Medium';
  }

  // Efficiency level (0-100) relative to the 400M Soroban tx instruction cap
  let efficiencyLevel = 100 - (instructionCount / SOROBAN_TX_INSTRUCTION_CAP) * 100;
  efficiencyLevel = Math.max(0, Math.min(100, efficiencyLevel));

  // Generate warnings
  const warnings: string[] = [];
  if (instructionCount > SOROBAN_TX_INSTRUCTION_CAP) {
    warnings.push(
      'Instruction count exceeds the 400M Soroban transaction cap. Split into multiple transactions or use batch verification.',
    );
  } else if (relativeComplexity === 'Extreme') {
    warnings.push(
      'Instruction count reaches the 400M Soroban transaction cap. May hit Soroban resource limits.',
    );
  }
  if (publicInputs > 100) {
    warnings.push('High number of public inputs can bloat transaction size.');
  }
  if (proofSize > 4096) {
    warnings.push('Proof size is larger than 4KB, which increases base transaction cost.');
  }

  return {
    instructionCount,
    instructionCapPercent,
    ledgerReadBytes,
    ledgerWriteBytes,
    inclusionFeeStroops,
    resourceFeeStroops,
    totalFeeStroops,
    totalFeeXlm,
    ttlRent30DaysStroops,
    ttlRent30DaysXlm,
    relativeComplexity,
    efficiencyLevel: Math.round(efficiencyLevel),
    warnings,
  };
}

const VALID_PROOF_TYPES = new Set<string>(Object.keys(protocol25ProofConfigs));

export function parseGasParams(
  search: string,
  defaults: GasCalculatorInputs,
): GasCalculatorInputs {
  const params = new URLSearchParams(search);
  const rawProof = params.get('proof');
  const proofType: ProofType =
    rawProof && VALID_PROOF_TYPES.has(rawProof)
      ? (rawProof as ProofType)
      : defaults.proofType;

  const parseNum = (key: string, fallback: number, min = 0): number => {
    const raw = params.get(key);
    if (raw === null || raw.trim() === '') return fallback;
    const parsed = Number(raw);
    if (!Number.isFinite(parsed)) return fallback;
    return Math.max(min, Math.trunc(parsed));
  };

  return {
    proofType,
    publicInputs: parseNum('inputs', defaults.publicInputs, 0),
    proofSize: parseNum('size', protocol25ProofConfigs[proofType].defaultProofSize, 0),
    iterationCount: parseNum('iters', defaults.iterationCount, 1),
    hashRounds: parseNum('rounds', defaults.hashRounds, 1),
    constraints: parseNum('constraints', defaults.constraints, 0),
  };
}

export function serializeGasParams(inputs: GasCalculatorInputs): string {
  const config = protocol25ProofConfigs[inputs.proofType];
  const params = new URLSearchParams();
  params.set('proof', inputs.proofType);
  params.set('inputs', String(sanitizeNonNegative(inputs.publicInputs, 0)));
  params.set('size', String(sanitizeNonNegative(inputs.proofSize, config.defaultProofSize)));
  params.set('iters', String(Math.max(1, sanitizeNonNegative(inputs.iterationCount, 1))));
  if (config.perRoundCost !== undefined) {
    params.set('rounds', String(Math.max(1, sanitizeNonNegative(inputs.hashRounds, 1))));
  }
  if (config.perConstraintCost !== undefined) {
    params.set('constraints', String(sanitizeNonNegative(inputs.constraints, 0)));
  }
  return `?${params.toString()}`;
}
