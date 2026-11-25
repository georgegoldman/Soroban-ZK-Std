import React from 'react';
import { fireEvent, render, screen } from '@testing-library/react';
import '@testing-library/jest-dom';
import { GasCalculator } from '@/components/gas-calculator/GasCalculator';
import { estimateGas } from '@/utils/gasEstimators';
import { GasCalculatorInputs } from '@/types/gas';

const defaultInputs: GasCalculatorInputs = {
  proofType: 'Groth16',
  constraints: 1000,
  proofSize: 256,
  publicInputs: 1,
  iterationCount: 1,
  hashRounds: 8,
};

describe('estimateGas', () => {
  it('uses the base cost at zero public inputs and keeps efficiency in range', () => {
    const result = estimateGas({ ...defaultInputs, publicInputs: 0 });

    expect(result.instructionCount).toBe(2_000_000);
    expect(result.efficiencyLevel).toBeGreaterThanOrEqual(0);
    expect(result.efficiencyLevel).toBeLessThanOrEqual(100);
    expect(result.warnings).toEqual([]);
  });

  it('reports threshold warnings only after a limit is exceeded', () => {
    expect(estimateGas({ ...defaultInputs, publicInputs: 100 }).warnings).toEqual([]);
    expect(estimateGas({ ...defaultInputs, publicInputs: 101 }).warnings).toContain(
      'High number of public inputs can bloat transaction size.'
    );
    expect(estimateGas({ ...defaultInputs, proofSize: 4096 }).warnings).toEqual([]);
    expect(estimateGas({ ...defaultInputs, proofSize: 4097 }).warnings).toContain(
      'Proof size is larger than 4KB, which increases base transaction cost.'
    );
  });

  it('classifies the extreme threshold and clamps efficiency for repeated iterations', () => {
    const result = estimateGas({
      ...defaultInputs,
      proofType: 'Groth16',
      publicInputs: 0,
      iterationCount: 5,
    });

    expect(result.instructionCount).toBe(10_000_000);
    expect(result.relativeComplexity).toBe('Extreme');
    expect(result.efficiencyLevel).toBe(50);
    expect(result.warnings).toContain(
      'Instruction count exceeds extreme threshold. May hit Soroban resource limits.'
    );
  });
});

describe('GasCalculator', () => {
  it('updates the displayed estimate when inputs and proof type change', () => {
    render(<GasCalculator />);

    expect(screen.getByText('2,050,000')).toBeInTheDocument();

    fireEvent.change(screen.getByLabelText('Public Inputs'), {
      target: { value: '3' },
    });
    expect(screen.getByText('2,150,000')).toBeInTheDocument();

    fireEvent.change(screen.getByLabelText('Proof System / Operation'), {
      target: { value: 'Poseidon Hash' },
    });
    expect(screen.getByText('Poseidon Hash')).toBeInTheDocument();
    expect(screen.getByLabelText('Depth / Rounds')).toBeInTheDocument();
    expect(screen.queryByLabelText('Constraints')).not.toBeInTheDocument();
  });
});
