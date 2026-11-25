import {
  getIntegrationSnippet,
  getStellarCliCommand,
} from '@/components/gas-calculator/GasCalculator';

describe('getIntegrationSnippet', () => {
  it('uses groth16_verify for Groth16 with the selected public-input count', () => {
    const snippet = getIntegrationSnippet('Groth16', 3, 1, 8);

    expect(snippet).toContain('groth16_verify');
    expect(snippet).toContain('[u256; 3]');
  });

  it('uses groth16_verify_batch for Groth16 Batch', () => {
    const snippet = getIntegrationSnippet('Groth16 Batch', 2, 4, 8);

    expect(snippet).toContain('groth16_verify_batch');
    expect(snippet).toContain('[Groth16Proof; 4]');
  });

  it('uses verify_plonk_kzg for PLONK and verify_plonk_kzg_batch for PLONK-KZG Batch', () => {
    expect(getIntegrationSnippet('PLONK', 1, 1, 8)).toContain('verify_plonk_kzg');
    expect(getIntegrationSnippet('PLONK-KZG Batch', 1, 5, 8)).toContain('verify_plonk_kzg_batch');
  });

  it('supports Bulletproofs, Halo2 IPA, STARK / FRI, and Poseidon2 / Rescue-Prime', () => {
    expect(getIntegrationSnippet('Bulletproofs', 1, 1, 6)).toContain('verify_range_proof');
    expect(getIntegrationSnippet('Halo2 IPA', 1, 1, 10)).toContain('verify_ipa_proof');
    expect(getIntegrationSnippet('STARK / FRI', 1, 1, 8)).toContain('verify_fri_proof');
    expect(getIntegrationSnippet('Poseidon2 / Rescue-Prime', 2, 1, 8)).toContain('hash_to_field');
  });

  it('uses hash_to_field for Poseidon Hash and rounds for Merkle Proof', () => {
    expect(getIntegrationSnippet('Poseidon Hash', 1, 1, 8)).toContain('hash_to_field');
    expect(getIntegrationSnippet('Merkle Proof', 1, 1, 4)).toContain('[U256; 4]');
  });

  it('normalizes negative and non-finite public-input values', () => {
    expect(getIntegrationSnippet('Groth16', -5, 1, 8)).toContain('[u256; 0]');
    expect(getIntegrationSnippet('Groth16', Number.NaN, 1, 8)).toContain('[u256; 0]');
  });

  it('returns valid stellar CLI commands for all new proof systems', () => {
    expect(getStellarCliCommand('Groth16 Batch')).toContain('groth16_verify_batch');
    expect(getStellarCliCommand('Bulletproofs')).toContain('verify_range_proof');
    expect(getStellarCliCommand('Halo2 IPA')).toContain('verify_ipa_proof');
    expect(getStellarCliCommand('STARK / FRI')).toContain('verify_fri_proof');
  });
});
