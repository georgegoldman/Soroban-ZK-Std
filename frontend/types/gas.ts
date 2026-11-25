export type ProofType =
  | 'Groth16'
  | 'Groth16 Batch'
  | 'PLONK'
  | 'PLONK-KZG Batch'
  | 'Bulletproofs'
  | 'Halo2 IPA'
  | 'STARK / FRI'
  | 'Poseidon2 / Rescue-Prime'
  | 'Poseidon Hash'
  | 'Pairing Check'
  | 'Merkle Proof'
  | 'Custom Verification';

export interface GasCalculatorInputs {
  proofType: ProofType;
  constraints: number;
  proofSize: number; // in bytes
  publicInputs: number;
  iterationCount: number;
  hashRounds: number;
}

export interface GasEstimationResult {
  instructionCount: number;
  instructionCapPercent: number; // % of 400M Soroban tx instruction cap
  ledgerReadBytes: number;
  ledgerWriteBytes: number;
  inclusionFeeStroops: number;
  resourceFeeStroops: number;
  totalFeeStroops: number;
  totalFeeXlm: number;
  ttlRent30DaysStroops: number;
  ttlRent30DaysXlm: number;
  relativeComplexity: 'Low' | 'Medium' | 'High' | 'Extreme';
  efficiencyLevel: number; // 0 to 100
  warnings: string[];
}

export interface ProofConfig {
  id: ProofType;
  name: string;
  description: string;
  protocolSpec: 'CAP-0074' | 'CAP-0075' | 'CAP-0074/CAP-0075' | 'WASM';
  baseCost: number;
  perInputCost: number;
  perConstraintCost?: number;
  perRoundCost?: number;
  batchPerProofCost?: number;
  defaultProofSize: number;
  vkBytes: number;
  perInputBytes: number;
  nullifierWriteBytes: number;
  ledgerReadEntries: number;
  ledgerWriteEntries: number;
  complexityThresholds: {
    medium: number;
    high: number;
    extreme: number;
  };
}
