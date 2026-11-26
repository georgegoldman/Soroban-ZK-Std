import { expect, test } from '@playwright/test';
import { instructionCount } from './fixtures';

// Expected values come from data/mockProofConfigs.ts + utils/gasEstimators.ts.
const fmt = (n: number) => n.toLocaleString('en-US');

test.describe('gas calculator', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/tools/gas-calculator');
    await expect(page.getByRole('heading', { level: 1, name: 'Gas Estimator Tool' })).toBeVisible();
  });

  test('shows a default estimate for Groth16', async ({ page }) => {
    await expect(page.getByLabel('Proof System / Operation')).toHaveValue('Groth16');
    // 2,000,000 base + 1 public input * 50,000
    await expect(instructionCount(page)).toHaveText(fmt(2_050_000));
    await expect(page.getByText('Warnings')).toHaveCount(0);
  });

  test('recomputes when inputs change', async ({ page }) => {
    await page.getByLabel('Public Inputs').fill('10');
    await expect(instructionCount(page)).toHaveText(fmt(2_500_000));
    await expect(page.getByText('Medium', { exact: true })).toBeVisible();

    await page.getByLabel('Iteration Count').fill('2');
    await expect(instructionCount(page)).toHaveText(fmt(5_000_000));
    await expect(page.getByText('High', { exact: true })).toBeVisible();
  });

  test('switching proof type shows type-specific inputs', async ({ page }) => {
    await expect(page.getByLabel('Depth / Rounds')).toHaveCount(0);
    await page.getByLabel('Proof System / Operation').selectOption('Poseidon Hash');
    await expect(page.getByLabel('Depth / Rounds')).toBeVisible();
    // 10,000 base + 1 * 5,000 per input + 8 rounds * 2,000
    await expect(instructionCount(page)).toHaveText(fmt(31_000));
    await expect(page.getByText('Low', { exact: true })).toBeVisible();

    await page.getByLabel('Proof System / Operation').selectOption('Custom Verification');
    await expect(page.getByLabel('Constraints')).toBeVisible();
    await expect(page.getByLabel('Depth / Rounds')).toHaveCount(0);
  });

  test('warns about oversized proofs and excessive public inputs', async ({ page }) => {
    await page.getByLabel('Proof Size (bytes)').fill('5000');
    await expect(page.getByText('Proof size is larger than 4KB')).toBeVisible();

    await page.getByLabel('Public Inputs').fill('101');
    await expect(page.getByText('High number of public inputs')).toBeVisible();
  });

  test('flags estimates past the extreme threshold', async ({ page }) => {
    await page.getByLabel('Proof System / Operation').selectOption('Pairing Check');
    await page.getByLabel('Public Inputs').fill('20');
    // 1,500,000 base + 20 pairings * 1,000,000
    await expect(instructionCount(page)).toHaveText(fmt(21_500_000));
    await expect(page.getByText('Extreme', { exact: true })).toBeVisible();
    await expect(page.getByText('May hit Soroban resource limits')).toBeVisible();
  });
});
