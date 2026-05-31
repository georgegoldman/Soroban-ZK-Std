export type ProofType = 
  | 'Groth16' 
  | 'PLONK' 
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
  relativeComplexity: 'Low' | 'Medium' | 'High' | 'Extreme';
  efficiencyLevel: number; // 0 to 100
  warnings: string[];
}

export interface ProofConfig {
  id: ProofType;
  name: string;
  description: string;
  baseCost: number;
  perInputCost: number;
  perConstraintCost?: number;
  perRoundCost?: number;
  complexityThresholds: {
    medium: number;
    high: number;
    extreme: number;
  };
}
