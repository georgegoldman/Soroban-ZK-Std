import AxeBuilder from '@axe-core/playwright';
import { expect, type Page } from '@playwright/test';

/** Docs page used by the smoke tests: present in the sidebar and in search. */
export const DOC_PAGE = {
  path: '/docs/polynomial-operations',
  navTitle: 'Polynomial Operations',
  heading: 'API Reference: Polynomial Operations',
};

/** Impacts that fail the accessibility checks. */
export const BLOCKING_IMPACTS = ['serious', 'critical'] as const;

/**
 * Pre-existing serious violations found when this suite was introduced
 * (#686). They come from shared components (Navbar search button, code-block
 * headers, gas-calculator text colours, home page code sample) and are tracked
 * as a11y debt to fix in follow-up PRs. They are reported as test annotations
 * instead of failing the run, so the gate still fails on any NEW serious or
 * critical rule. `critical` violations are never baselined.
 *
 * Run with A11Y_STRICT=1 to ignore this list and see every violation.
 * When an entry is fixed, delete it here.
 */
export const KNOWN_A11Y_DEBT: Record<string, string> = {
  'color-contrast':
    'Low-contrast neutral/zinc text: navbar search hint + kbd, version badge, code-block headers, gas-calculator labels, home code sample.',
  'label-content-name-mismatch':
    'Navbar search button: aria-label "Search documentation" does not contain its visible text "Search documentation... ⌘K".',
};

export interface A11yViolation {
  id: string;
  impact: string | null | undefined;
  help: string;
  targets: string[];
}

/** Runs axe-core with the WCAG 2.0/2.1 A + AA rule set on the current page. */
export async function seriousA11yViolations(page: Page): Promise<A11yViolation[]> {
  const results = await new AxeBuilder({ page })
    .withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'])
    .analyze();

  return results.violations
    .filter((v) => (BLOCKING_IMPACTS as readonly string[]).includes(v.impact ?? ''))
    .map((v) => ({
      id: v.id,
      impact: v.impact,
      help: v.help,
      targets: v.nodes.slice(0, 5).map((n) => n.target.join(' ')),
    }));
}

/**
 * Splits serious/critical violations into the ones that must fail the test
 * and the known, baselined ones (see KNOWN_A11Y_DEBT).
 */
export function partitionViolations(
  violations: A11yViolation[],
  strict = !!process.env.A11Y_STRICT,
) {
  const known = violations.filter(
    (v) => !strict && v.impact !== 'critical' && v.id in KNOWN_A11Y_DEBT,
  );
  const blocking = violations.filter((v) => !known.includes(v));
  return { blocking, known };
}

/** Opens the search modal from the navbar button and returns its locators. */
export async function openSearch(page: Page) {
  await page.getByRole('button', { name: 'Search documentation' }).click();
  const dialog = page.getByRole('dialog');
  await expect(dialog).toBeVisible();
  const input = dialog.getByRole('textbox', { name: 'Search input' });
  await expect(input).toBeFocused();
  return { dialog, input };
}

/** The big "Estimated Instructions" figure in the gas calculator output. */
export function instructionCount(page: Page) {
  return page
    .getByText('Estimated Instructions', { exact: true })
    .locator('xpath=following-sibling::div[1]');
}
