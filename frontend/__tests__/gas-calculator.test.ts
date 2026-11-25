import { getIntegrationSnippet } from '@/components/gas-calculator/GasCalculator';

describe('getIntegrationSnippet', () => {
  it('uses groth16_verify for Groth16 with the selected public-input count', () => {
    const snippet = getIntegrationSnippet('Groth16', 3, 1, 8);

    expect(snippet).toContain('groth16_verify');
    expect(snippet).toContain('[u256; 3]');
  });

  it('uses verify_plonk_kzg for PLONK', () => {
    const snippet = getIntegrationSnippet('PLONK', 1, 1, 8);

    expect(snippet).toContain('verify_plonk_kzg');
  });

  it('uses hash_to_field for Poseidon Hash and rounds for Merkle Proof', () => {
    expect(getIntegrationSnippet('Poseidon Hash', 1, 1, 8)).toContain('hash_to_field');
    expect(getIntegrationSnippet('Merkle Proof', 1, 1, 4)).toContain('[U256; 4]');
  });

  it('normalizes negative and non-finite public-input values', () => {
    expect(getIntegrationSnippet('Groth16', -5, 1, 8)).toContain('[u256; 0]');
    expect(getIntegrationSnippet('Groth16', Number.NaN, 1, 8)).toContain('[u256; 0]');
  });
});
