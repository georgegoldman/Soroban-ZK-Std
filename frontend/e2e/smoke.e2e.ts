import { expect, test } from '@playwright/test';
import { navigation } from '../lib/navigation';
import { DOC_PAGE, openSearch } from './fixtures';

test.describe('home page', () => {
  test('renders the hero and links to the guides', async ({ page }) => {
    const response = await page.goto('/');
    expect(response?.status()).toBe(200);
    await expect(page).toHaveTitle('Soroban-ZK-Std Docs');
    await expect(page.getByRole('heading', { level: 1, name: 'Soroban-ZK-Std' })).toBeVisible();

    await page.getByRole('link', { name: 'Guides', exact: true }).click();
    await expect(page).toHaveURL(/\/docs$/);
    await expect(page.getByRole('heading', { level: 1, name: 'Introduction' })).toBeVisible();
  });
});

test.describe('docs pages', () => {
  test('docs index renders inside the docs layout', async ({ page }) => {
    await page.goto('/docs');
    await expect(page.getByRole('heading', { level: 1, name: 'Introduction' })).toBeVisible();
    await expect(page.getByRole('complementary', { name: 'Sidebar Navigation' })).toBeVisible();
    await expect(page.getByRole('link', { name: 'Edit this page on GitHub' })).toBeVisible();
  });

  test('an MDX docs page renders its content', async ({ page }) => {
    const response = await page.goto(DOC_PAGE.path);
    expect(response?.status()).toBe(200);
    await expect(page.getByRole('heading', { level: 1, name: DOC_PAGE.heading })).toBeVisible();
    await expect(page.getByRole('heading', { level: 2, name: 'Overview' })).toBeVisible();
  });

  test('an unknown docs slug returns the 404 page', async ({ page }) => {
    const response = await page.goto('/docs/this-page-does-not-exist');
    expect(response?.status()).toBe(404);
    await expect(page.getByRole('heading', { name: 'Page not found.' })).toBeVisible();
    await page.getByRole('link', { name: 'Browse docs' }).click();
    await expect(page).toHaveURL(/\/docs$/);
  });
});

test.describe('sidebar navigation', () => {
  test('navigates to a docs page and highlights it', async ({ page }) => {
    await page.goto('/docs');
    const sidebar = page.getByRole('complementary', { name: 'Sidebar Navigation' });

    await sidebar.getByRole('link', { name: DOC_PAGE.navTitle, exact: true }).click();
    await expect(page).toHaveURL(new RegExp(`${DOC_PAGE.path}$`));
    await expect(page.getByRole('heading', { level: 1, name: DOC_PAGE.heading })).toBeVisible();
    await expect(sidebar.getByRole('link', { name: DOC_PAGE.navTitle, exact: true })).toHaveClass(
      /text-blue-600/,
    );
  });

  test('collapses and expands a section', async ({ page }) => {
    await page.goto('/docs');
    const sidebar = page.getByRole('complementary', { name: 'Sidebar Navigation' });
    const toggle = sidebar.getByRole('button', { name: 'Math & Cryptography' });

    await expect(toggle).toHaveAttribute('aria-expanded', 'true');
    await toggle.click();
    await expect(toggle).toHaveAttribute('aria-expanded', 'false');
    // Collapsed links are taken out of the tab order.
    await expect(sidebar.getByRole('link', { name: DOC_PAGE.navTitle, exact: true })).toHaveAttribute(
      'tabindex',
      '-1',
    );
    await toggle.click();
    await expect(toggle).toHaveAttribute('aria-expanded', 'true');
  });

  test('every sidebar link resolves to a page (no 404s)', async ({ request }) => {
    const hrefs = navigation.flatMap((section) =>
      (section.children ?? []).flatMap((child) => (child.href ? [child.href] : [])),
    );
    expect(hrefs.length).toBeGreaterThan(0);
    for (const href of hrefs) {
      const res = await request.get(href);
      expect(res.status(), `sidebar link ${href}`).toBe(200);
    }
  });
});

test.describe('search modal', () => {
  test('opens from the navbar and returns matching results', async ({ page }) => {
    await page.goto('/docs');
    const { dialog, input } = await openSearch(page);
    await expect(dialog.getByText('Start typing to search documentation')).toBeVisible();

    await input.fill('poseidon');
    const result = dialog.getByRole('link', { name: 'Poseidon2' });
    await expect(result).toBeVisible();

    await result.click();
    await expect(page).toHaveURL(/\/docs\/poseidon2$/);
    await expect(page.getByRole('dialog')).toHaveCount(0);
  });

  test('matches multiple terms against titles', async ({ page }) => {
    await page.goto('/docs');
    const { dialog, input } = await openSearch(page);
    await input.fill('polynomial operations');
    await expect(dialog.getByRole('link')).toHaveCount(1);
    await expect(dialog.getByRole('link', { name: DOC_PAGE.navTitle })).toBeVisible();
  });

  test('shows an empty state for a query with no matches', async ({ page }) => {
    await page.goto('/docs');
    const { dialog, input } = await openSearch(page);
    await input.fill('zzz-no-such-doc');
    await expect(dialog.getByText('No results found for')).toBeVisible();
    await expect(dialog.getByRole('link')).toHaveCount(0);
  });

  test('opens with Ctrl+K and closes with Escape', async ({ page }) => {
    await page.goto('/docs');
    await page.keyboard.press('Control+k');
    await expect(page.getByRole('dialog')).toBeVisible();
    await page.keyboard.press('Escape');
    await expect(page.getByRole('dialog')).toHaveCount(0);
  });
});
