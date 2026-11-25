import { expect, test } from '@playwright/test';
import { instructionCount } from './fixtures';

// Expected values come from data/mockProofConfigs.ts + utils/gasEstimators.ts (Protocol 25 calibrated).
const fmt = (n: number) => n.toLocaleString('en-US');

test.describe('gas calculator', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/tools/gas-calculator');
    await expect(page.getByRole('heading', { level: 1, name: 'Gas Estimator Tool' })).toBeVisible();
  });

  test('shows a default Protocol 25 estimate for Groth16', async ({ page }) => {
    await expect(page.getByLabel('Proof System / Operation')).toHaveValue('Groth16');
    // 28,727,515 base + 1 public input * 600,000 = 29,327,515 (BENCHMARKS.md)
    await expect(instructionCount(page)).toHaveText(fmt(29_327_515));
    await expect(page.getByText('7.33% of 400M tx cap')).toBeVisible();
    await expect(page.getByText('Warnings')).toHaveCount(0);
  });

  test('recomputes when inputs change and syncs URL query parameters', async ({ page }) => {
    await page.getByLabel('Public Inputs').fill('4');
    await expect(instructionCount(page)).toHaveText(fmt(31_127_515));
    await expect(page).toHaveURL(/proof=Groth16/);
    await expect(page).toHaveURL(/inputs=4/);

    await page.getByLabel('Iteration Count').fill('3');
    await expect(instructionCount(page)).toHaveText(fmt(93_382_545));
    await expect(page.getByText('Medium', { exact: true })).toBeVisible();
  });

  test('switching proof type shows type-specific inputs', async ({ page }) => {
    await expect(page.getByLabel('Depth / Rounds')).toHaveCount(0);
    await page.getByLabel('Proof System / Operation').selectOption('Bulletproofs');
    await expect(page.getByLabel('Depth / Rounds')).toBeVisible();
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

  test('flags estimates past the 400M tx cap', async ({ page }) => {
    await page.getByLabel('Iteration Count').fill('15');
    await expect(page.getByText('Extreme', { exact: true })).toBeVisible();
    await expect(page.getByText(/400M Soroban transaction cap/)).toBeVisible();
  });
});
