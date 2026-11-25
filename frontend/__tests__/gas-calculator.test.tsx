import React from 'react';
import { fireEvent, render, screen } from '@testing-library/react';
import '@testing-library/jest-dom';
import { GasCalculator } from '@/components/gas-calculator/GasCalculator';
import {
  estimateGas,
  parseGasParams,
  serializeGasParams,
  SOROBAN_TX_INSTRUCTION_CAP,
} from '@/utils/gasEstimators';
import { protocol25ProofConfigs, mockProofConfigs } from '@/data/mockProofConfigs';
import { GasCalculatorInputs } from '@/types/gas';

const defaultInputs: GasCalculatorInputs = {
  proofType: 'Groth16',
  constraints: 1000,
  proofSize: 256,
  publicInputs: 1,
  iterationCount: 1,
  hashRounds: 8,
};

describe('estimateGas (Protocol 25 calibrated)', () => {
  it('matches BENCHMARKS.md groth16_verify (1 public input = 29,327,515) and computes cap % + fees', () => {
    const result = estimateGas(defaultInputs);

    expect(result.instructionCount).toBe(29_327_515);
    expect(result.instructionCapPercent).toBe(7.33);
    expect(result.ledgerReadBytes).toBe(640 + 256 + 32);
    expect(result.ledgerWriteBytes).toBe(64);
    expect(result.totalFeeStroops).toBeGreaterThan(result.inclusionFeeStroops);
    expect(result.totalFeeXlm).toBeGreaterThan(0);
    expect(result.ttlRent30DaysStroops).toBeGreaterThan(0);
    expect(result.ttlRent30DaysXlm).toBeGreaterThan(0);
    expect(result.efficiencyLevel).toBeGreaterThanOrEqual(0);
    expect(result.efficiencyLevel).toBeLessThanOrEqual(100);
    expect(result.warnings).toEqual([]);
  });

  it('keeps mockProofConfigs aliased to protocol25ProofConfigs', () => {
    expect(mockProofConfigs).toBe(protocol25ProofConfigs);
  });

  it('amortizes batch verification for Groth16 Batch vs single Groth16', () => {
    const single4 = estimateGas({ ...defaultInputs, proofType: 'Groth16', iterationCount: 4 });
    const batch4 = estimateGas({ ...defaultInputs, proofType: 'Groth16 Batch', iterationCount: 4 });

    expect(batch4.instructionCount).toBeLessThan(single4.instructionCount);
  });

  it('estimates Bulletproofs, Halo2 IPA, STARK / FRI, and Poseidon2 / Rescue-Prime', () => {
    for (const proofType of [
      'Bulletproofs',
      'Halo2 IPA',
      'STARK / FRI',
      'Poseidon2 / Rescue-Prime',
      'PLONK-KZG Batch',
    ] as const) {
      const res = estimateGas({ ...defaultInputs, proofType });
      expect(res.instructionCount).toBeGreaterThan(0);
      expect(res.instructionCapPercent).toBeGreaterThan(0);
      expect(res.totalFeeStroops).toBeGreaterThan(0);
    }
  });

  it('handles negative and non-finite inputs safely (boundary & negative rejection)', () => {
    const res = estimateGas({
      proofType: 'Groth16',
      constraints: -100,
      proofSize: Number.NaN,
      publicInputs: -5,
      iterationCount: 0,
      hashRounds: -2,
    });

    expect(res.instructionCount).toBe(protocol25ProofConfigs['Groth16'].baseCost);
    expect(res.ledgerReadBytes).toBeGreaterThan(0);
  });

  it('reports threshold warnings when limits or 400M cap are exceeded', () => {
    expect(estimateGas({ ...defaultInputs, publicInputs: 100 }).warnings).toEqual([]);
    expect(estimateGas({ ...defaultInputs, publicInputs: 101 }).warnings).toContain(
      'High number of public inputs can bloat transaction size.',
    );
    expect(estimateGas({ ...defaultInputs, proofSize: 4096 }).warnings).toEqual([]);
    expect(estimateGas({ ...defaultInputs, proofSize: 4097 }).warnings).toContain(
      'Proof size is larger than 4KB, which increases base transaction cost.',
    );

    const overCap = estimateGas({ ...defaultInputs, proofType: 'Groth16', iterationCount: 15 });
    expect(overCap.instructionCount).toBeGreaterThan(SOROBAN_TX_INSTRUCTION_CAP);
    expect(overCap.relativeComplexity).toBe('Extreme');
    expect(overCap.efficiencyLevel).toBe(0);
    expect(overCap.warnings[0]).toContain('400M Soroban transaction cap');
  });
});

describe('URL query parameter sync helpers', () => {
  it('parses valid query params and rejects invalid proof types / negative values', () => {
    const parsed = parseGasParams('?proof=Halo2+IPA&inputs=4&iters=2&rounds=10', defaultInputs);
    expect(parsed.proofType).toBe('Halo2 IPA');
    expect(parsed.publicInputs).toBe(4);
    expect(parsed.iterationCount).toBe(2);
    expect(parsed.hashRounds).toBe(10);

    const invalid = parseGasParams('?proof=UnknownProof&inputs=-3&iters=0', defaultInputs);
    expect(invalid.proofType).toBe('Groth16');
    expect(invalid.publicInputs).toBe(0);
    expect(invalid.iterationCount).toBe(1);
  });

  it('round-trips serialized query params', () => {
    const query = serializeGasParams({ ...defaultInputs, proofType: 'Groth16', publicInputs: 4 });
    expect(query).toContain('proof=Groth16');
    expect(query).toContain('inputs=4');
    const parsed = parseGasParams(query, defaultInputs);
    expect(parsed.proofType).toBe('Groth16');
    expect(parsed.publicInputs).toBe(4);
  });
});

describe('GasCalculator component', () => {
  beforeEach(() => {
    window.history.replaceState(null, '', '/tools/gas-calculator');
  });

  it('renders Protocol 25 Groth16 estimate, cap %, fees, TTL rent, and updates URL on change', () => {
    render(<GasCalculator />);

    expect(screen.getByText('29,327,515')).toBeInTheDocument();
    expect(screen.getByText(/7\.33% of 400M tx cap/)).toBeInTheDocument();
    expect(screen.getByText(/30-Day Persistent TTL Rent/)).toBeInTheDocument();

    fireEvent.change(screen.getByLabelText('Public Inputs'), {
      target: { value: '4' },
    });
    expect(screen.getByText('31,127,515')).toBeInTheDocument();
    expect(window.location.search).toContain('proof=Groth16');
    expect(window.location.search).toContain('inputs=4');

    fireEvent.change(screen.getByLabelText('Proof System / Operation'), {
      target: { value: 'Bulletproofs' },
    });
    expect(screen.getByLabelText('Depth / Rounds')).toBeInTheDocument();
    expect(screen.queryByLabelText('Constraints')).not.toBeInTheDocument();
  });

  it('hydrates initial state from URL query parameters', () => {
    window.history.replaceState(null, '', '/tools/gas-calculator?proof=Groth16&inputs=4');
    render(<GasCalculator />);

    expect(screen.getByLabelText('Public Inputs')).toHaveValue(4);
    expect(screen.getByText('31,127,515')).toBeInTheDocument();
  });
});
