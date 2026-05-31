import { GasCalculatorInputs, GasEstimationResult, ProofConfig } from '../types/gas';
import { mockProofConfigs } from '../data/mockProofConfigs';

export function estimateGas(inputs: GasCalculatorInputs): GasEstimationResult {
  const config = mockProofConfigs[inputs.proofType];
  
  let instructionCount = config.baseCost;
  
  // Apply costs based on inputs
  if (config.perInputCost) {
    instructionCount += inputs.publicInputs * config.perInputCost;
  }
  
  if (config.perConstraintCost) {
    instructionCount += inputs.constraints * config.perConstraintCost;
  }
  
  if (config.perRoundCost) {
    instructionCount += inputs.hashRounds * config.perRoundCost;
  }
  
  // Apply iteration multiplier if applicable (e.g., for multiple verifications)
  if (inputs.iterationCount > 1) {
    instructionCount *= inputs.iterationCount;
  }
  
  // Determine relative complexity
  let relativeComplexity: GasEstimationResult['relativeComplexity'] = 'Low';
  if (instructionCount >= config.complexityThresholds.extreme) {
    relativeComplexity = 'Extreme';
  } else if (instructionCount >= config.complexityThresholds.high) {
    relativeComplexity = 'High';
  } else if (instructionCount >= config.complexityThresholds.medium) {
    relativeComplexity = 'Medium';
  }
  
  // Calculate efficiency level (0-100), where 100 is most efficient (lowest cost)
  // We use a logarithmic scale relative to extreme threshold
  const maxAcceptable = config.complexityThresholds.extreme * 2;
  let efficiencyLevel = 100 - (instructionCount / maxAcceptable) * 100;
  efficiencyLevel = Math.max(0, Math.min(100, efficiencyLevel)); // clamp between 0-100
  
  // Generate warnings
  const warnings: string[] = [];
  if (relativeComplexity === 'Extreme') {
    warnings.push('Instruction count exceeds extreme threshold. May hit Soroban resource limits.');
  }
  if (inputs.publicInputs > 100) {
    warnings.push('High number of public inputs can bloat transaction size.');
  }
  if (inputs.proofSize > 4096) {
    warnings.push('Proof size is larger than 4KB, which increases base transaction cost.');
  }

  return {
    instructionCount: Math.round(instructionCount),
    relativeComplexity,
    efficiencyLevel: Math.round(efficiencyLevel),
    warnings,
  };
}
