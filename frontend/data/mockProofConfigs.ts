import { ProofConfig, ProofType } from '../types/gas';

/**
 * Calibrated Soroban Protocol 25 (CAP-0074 BLS12-381 & CAP-0075 BN254 / Poseidon2)
 * CPU instruction and ledger byte footprint models.
 *
 * Baseline measurements anchored to BENCHMARKS.md (soroban-sdk v25.3.0):
 * - groth16_verify (1 public input): 29,327,515 CPU instructions (7.33% of 400M cap)
 * - poseidon2_hash_1: 1,007,753 CPU instructions (0.25% of 400M cap)
 * - poseidon2_hash_2: 2,010,994 CPU instructions (0.50% of 400M cap)
 * - poseidon2_hash_4: 3,024,708 CPU instructions (0.75% of 400M cap)
 */
export const protocol25ProofConfigs: Record<ProofType, ProofConfig> = {
  'Groth16': {
    id: 'Groth16',
    name: 'Groth16 (Single)',
    description:
      'Protocol 25 CAP-0075 BN254 Groth16 verification (4-pair multi-pairing + MSM).',
    protocolSpec: 'CAP-0075',
    baseCost: 28_727_515,
    perInputCost: 600_000,
    defaultProofSize: 256,
    vkBytes: 640,
    perInputBytes: 32,
    nullifierWriteBytes: 64,
    ledgerReadEntries: 2,
    ledgerWriteEntries: 1,
    complexityThresholds: {
      medium: 80_000_000,
      high: 200_000_000,
      extreme: 400_000_000,
    },
  },
  'Groth16 Batch': {
    id: 'Groth16 Batch',
    name: 'Groth16 (Batch)',
    description:
      'Amortized BN254 Groth16 batch verification via random linear combination (CAP-0075).',
    protocolSpec: 'CAP-0075',
    baseCost: 28_727_515,
    perInputCost: 600_000,
    batchPerProofCost: 6_850_000,
    defaultProofSize: 256,
    vkBytes: 640,
    perInputBytes: 32,
    nullifierWriteBytes: 64,
    ledgerReadEntries: 2,
    ledgerWriteEntries: 1,
    complexityThresholds: {
      medium: 100_000_000,
      high: 250_000_000,
      extreme: 400_000_000,
    },
  },
  'PLONK': {
    id: 'PLONK',
    name: 'PLONK-KZG (Single)',
    description:
      'Universal zkSNARK with KZG polynomial commitments over BN254 (CAP-0075).',
    protocolSpec: 'CAP-0075',
    baseCost: 34_800_000,
    perInputCost: 650_000,
    defaultProofSize: 768,
    vkBytes: 1_536,
    perInputBytes: 32,
    nullifierWriteBytes: 64,
    ledgerReadEntries: 2,
    ledgerWriteEntries: 1,
    complexityThresholds: {
      medium: 100_000_000,
      high: 250_000_000,
      extreme: 400_000_000,
    },
  },
  'PLONK-KZG Batch': {
    id: 'PLONK-KZG Batch',
    name: 'PLONK-KZG (Batch)',
    description:
      'Batched KZG opening verification amortizing pairing checks across proofs (CAP-0075).',
    protocolSpec: 'CAP-0075',
    baseCost: 34_800_000,
    perInputCost: 650_000,
    batchPerProofCost: 9_400_000,
    defaultProofSize: 768,
    vkBytes: 1_536,
    perInputBytes: 32,
    nullifierWriteBytes: 64,
    ledgerReadEntries: 2,
    ledgerWriteEntries: 1,
    complexityThresholds: {
      medium: 120_000_000,
      high: 260_000_000,
      extreme: 400_000_000,
    },
  },
  'Bulletproofs': {
    id: 'Bulletproofs',
    name: 'Bulletproofs (IPA Range)',
    description:
      'Transparent inner-product argument range proof without trusted setup (CAP-0074/CAP-0075).',
    protocolSpec: 'CAP-0074/CAP-0075',
    baseCost: 18_500_000,
    perInputCost: 420_000,
    perRoundCost: 2_850_000,
    defaultProofSize: 672,
    vkBytes: 512,
    perInputBytes: 32,
    nullifierWriteBytes: 64,
    ledgerReadEntries: 2,
    ledgerWriteEntries: 1,
    complexityThresholds: {
      medium: 100_000_000,
      high: 240_000_000,
      extreme: 400_000_000,
    },
  },
  'Halo2 IPA': {
    id: 'Halo2 IPA',
    name: 'Halo2 IPA',
    description:
      'PLONKish arithmetization with IPA polynomial commitment and recursive folding.',
    protocolSpec: 'CAP-0074',
    baseCost: 42_000_000,
    perInputCost: 700_000,
    perRoundCost: 3_400_000,
    defaultProofSize: 1_408,
    vkBytes: 2_048,
    perInputBytes: 32,
    nullifierWriteBytes: 64,
    ledgerReadEntries: 3,
    ledgerWriteEntries: 1,
    complexityThresholds: {
      medium: 120_000_000,
      high: 260_000_000,
      extreme: 400_000_000,
    },
  },
  'STARK / FRI': {
    id: 'STARK / FRI',
    name: 'STARK / FRI',
    description:
      'Post-quantum transparent STARK verification with FRI folding and Poseidon2 Merkle paths.',
    protocolSpec: 'CAP-0075',
    baseCost: 68_000_000,
    perInputCost: 350_000,
    perRoundCost: 6_200_000,
    defaultProofSize: 12_288,
    vkBytes: 1_024,
    perInputBytes: 32,
    nullifierWriteBytes: 64,
    ledgerReadEntries: 2,
    ledgerWriteEntries: 1,
    complexityThresholds: {
      medium: 150_000_000,
      high: 280_000_000,
      extreme: 400_000_000,
    },
  },
  'Poseidon2 / Rescue-Prime': {
    id: 'Poseidon2 / Rescue-Prime',
    name: 'Poseidon2 / Rescue-Prime',
    description:
      'Algebraic ZK-friendly sponge permutation over BN254/BLS12-381 via CAP-0075 host functions.',
    protocolSpec: 'CAP-0075',
    baseCost: 7_753,
    perInputCost: 1_000_000,
    perRoundCost: 125_000,
    defaultProofSize: 32,
    vkBytes: 128,
    perInputBytes: 32,
    nullifierWriteBytes: 32,
    ledgerReadEntries: 1,
    ledgerWriteEntries: 0,
    complexityThresholds: {
      medium: 20_000_000,
      high: 100_000_000,
      extreme: 400_000_000,
    },
  },
  'Poseidon Hash': {
    id: 'Poseidon Hash',
    name: 'Poseidon2 Hash (BN254)',
    description:
      'Measured CAP-0075 Poseidon2 hash_to_field over BN254 scalar field.',
    protocolSpec: 'CAP-0075',
    baseCost: 7_753,
    perInputCost: 1_000_000,
    perRoundCost: 125_000,
    defaultProofSize: 32,
    vkBytes: 128,
    perInputBytes: 32,
    nullifierWriteBytes: 32,
    ledgerReadEntries: 1,
    ledgerWriteEntries: 0,
    complexityThresholds: {
      medium: 20_000_000,
      high: 100_000_000,
      extreme: 400_000_000,
    },
  },
  'Pairing Check': {
    id: 'Pairing Check',
    name: 'Pairing Check (BN254)',
    description:
      'Optimal Ate multi-pairing check via CAP-0075 bn254_multi_pairing_check host function.',
    protocolSpec: 'CAP-0075',
    baseCost: 11_200_000,
    perInputCost: 4_400_000,
    defaultProofSize: 192,
    vkBytes: 256,
    perInputBytes: 192,
    nullifierWriteBytes: 0,
    ledgerReadEntries: 1,
    ledgerWriteEntries: 0,
    complexityThresholds: {
      medium: 80_000_000,
      high: 200_000_000,
      extreme: 400_000_000,
    },
  },
  'Merkle Proof': {
    id: 'Merkle Proof',
    name: 'Merkle Tree Proof (Poseidon2)',
    description:
      'Path verification in a Poseidon2 Merkle tree (1,007,753 instructions per depth level).',
    protocolSpec: 'CAP-0075',
    baseCost: 120_000,
    perInputCost: 0,
    perRoundCost: 1_007_753,
    defaultProofSize: 256,
    vkBytes: 128,
    perInputBytes: 32,
    nullifierWriteBytes: 32,
    ledgerReadEntries: 2,
    ledgerWriteEntries: 1,
    complexityThresholds: {
      medium: 40_000_000,
      high: 150_000_000,
      extreme: 400_000_000,
    },
  },
  'Custom Verification': {
    id: 'Custom Verification',
    name: 'Custom Constraint Verification',
    description:
      'Flexible WASM constraint evaluation for custom ZK verification logic.',
    protocolSpec: 'WASM',
    baseCost: 500_000,
    perInputCost: 50_000,
    perConstraintCost: 4_500,
    defaultProofSize: 512,
    vkBytes: 512,
    perInputBytes: 32,
    nullifierWriteBytes: 64,
    ledgerReadEntries: 2,
    ledgerWriteEntries: 1,
    complexityThresholds: {
      medium: 80_000_000,
      high: 200_000_000,
      extreme: 400_000_000,
    },
  },
};

/**
 * Backward-compatible alias for protocol25ProofConfigs.
 */
export const mockProofConfigs: Record<ProofType, ProofConfig> = protocol25ProofConfigs;
