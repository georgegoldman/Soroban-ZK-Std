import { ProofConfig, ProofType } from '../types/gas';

export const mockProofConfigs: Record<ProofType, ProofConfig> = {
  'Groth16': {
    id: 'Groth16',
    name: 'Groth16 Verification',
    description: 'Standard Groth16 zkSNARK proof verification (3 pairings).',
    baseCost: 2000000,
    perInputCost: 50000,
    complexityThresholds: {
      medium: 2500000,
      high: 5000000,
      extreme: 10000000,
    },
  },
  'PLONK': {
    id: 'PLONK',
    name: 'PLONK Verification',
    description: 'Universal zkSNARK with Kate polynomial commitments.',
    baseCost: 3500000,
    perInputCost: 80000,
    complexityThresholds: {
      medium: 4000000,
      high: 8000000,
      extreme: 15000000,
    },
  },
  'Poseidon Hash': {
    id: 'Poseidon Hash',
    name: 'Poseidon Hash',
    description: 'ZK-friendly hash function over BN254 scalar field.',
    baseCost: 10000,
    perInputCost: 5000,
    perRoundCost: 2000,
    complexityThresholds: {
      medium: 50000,
      high: 200000,
      extreme: 1000000,
    },
  },
  'Pairing Check': {
    id: 'Pairing Check',
    name: 'Pairing Check (BN254)',
    description: 'Optimal Ate pairing check over BN254 curve.',
    baseCost: 1500000,
    perInputCost: 1000000, // Cost per pairing
    complexityThresholds: {
      medium: 3000000,
      high: 6000000,
      extreme: 12000000,
    },
  },
  'Merkle Proof': {
    id: 'Merkle Proof',
    name: 'Merkle Tree Proof',
    description: 'Path verification in a Merkle tree using Poseidon.',
    baseCost: 50000,
    perInputCost: 0,
    perRoundCost: 12000, // Cost per depth level
    complexityThresholds: {
      medium: 200000,
      high: 500000,
      extreme: 2000000,
    },
  },
  'Custom Verification': {
    id: 'Custom Verification',
    name: 'Custom Constraint Verification',
    description: 'Flexible constraint evaluation for custom ZK logic.',
    baseCost: 100000,
    perInputCost: 10000,
    perConstraintCost: 5000,
    complexityThresholds: {
      medium: 1000000,
      high: 5000000,
      extreme: 20000000,
    },
  },
};
