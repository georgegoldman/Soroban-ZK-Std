import { expect, test, type Page } from '@playwright/test';
import {
  DOC_PAGE,
  KNOWN_A11Y_DEBT,
  openSearch,
  partitionViolations,
  seriousA11yViolations,
} from './fixtures';

const PAGES = [
  { name: 'home', path: '/' },
  { name: 'docs index', path: '/docs' },
  { name: 'docs page', path: DOC_PAGE.path },
  { name: 'gas calculator', path: '/tools/gas-calculator' },
];

/** Fails on serious/critical violations that are not baselined a11y debt. */
async function expectNoBlockingViolations(page: Page) {
  const { blocking, known } = partitionViolations(await seriousA11yViolations(page));
  for (const v of known) {
    test.info().annotations.push({
      type: 'known a11y debt',
      description: `${v.id} (${v.impact}): ${v.targets.join(', ')}`,
    });
  }
  expect(blocking, 'serious/critical axe violations').toEqual([]);
}

test.describe('accessibility (axe: no serious/critical violations)', () => {
  for (const { name, path } of PAGES) {
    test(name, async ({ page }) => {
      await page.goto(path);
      await page.waitForLoadState('networkidle');
      await expectNoBlockingViolations(page);
    });
  }

  test('search modal (open, with results)', async ({ page }) => {
    await page.goto('/docs');
    const { dialog, input } = await openSearch(page);
    await input.fill('poseidon');
    await expect(dialog.getByRole('link').first()).toBeVisible();
    await expectNoBlockingViolations(page);
  });
});

test.describe('accessibility gate logic', () => {
  const sample = (id: string, impact: string) => ({ id, impact, help: '', targets: ['x'] });

  test('a new serious rule is blocking', () => {
    const { blocking } = partitionViolations([sample('image-alt', 'serious')], false);
    expect(blocking.map((v) => v.id)).toEqual(['image-alt']);
  });

  test('critical violations are never baselined', () => {
    const id = Object.keys(KNOWN_A11Y_DEBT)[0];
    const { blocking, known } = partitionViolations([sample(id, 'critical')], false);
    expect(blocking).toHaveLength(1);
    expect(known).toHaveLength(0);
  });

  test('strict mode ignores the baseline', () => {
    const id = Object.keys(KNOWN_A11Y_DEBT)[0];
    expect(partitionViolations([sample(id, 'serious')], true).blocking).toHaveLength(1);
    expect(partitionViolations([sample(id, 'serious')], false).blocking).toHaveLength(0);
  });
});
