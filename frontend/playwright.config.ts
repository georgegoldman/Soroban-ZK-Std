import { defineConfig, devices } from '@playwright/test';

/**
 * End-to-end smoke + accessibility tests for the docs site.
 *
 * The suite runs against a production build served by `next start`:
 *   - locally, `pnpm test:e2e` builds the site and then serves it;
 *   - in CI the build happens in an earlier step, so set E2E_SKIP_BUILD=1 to
 *     only start the server.
 *
 * Test files use the `*.e2e.ts` suffix so Jest (which picks up `*.test.ts` /
 * `*.spec.ts`) never tries to run them.
 */
const PORT = Number(process.env.E2E_PORT ?? 3100);
const BASE_URL = `http://127.0.0.1:${PORT}`;
const serve = `npx next start --hostname 127.0.0.1 --port ${PORT}`;
const command = process.env.E2E_SKIP_BUILD ? serve : `npx next build && ${serve}`;

export default defineConfig({
  testDir: './e2e',
  testMatch: /.*\.e2e\.ts$/,
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  workers: process.env.CI ? 2 : undefined,
  reporter: process.env.CI ? [['list'], ['html', { open: 'never' }]] : 'list',
  use: {
    baseURL: BASE_URL,
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
  },
  projects: [
    {
      name: 'chromium',
      // Desktop viewport (1280px): the sidebar and the search button are
      // only rendered at the `lg` / `md` breakpoints.
      use: { ...devices['Desktop Chrome'] },
    },
  ],
  webServer: {
    command,
    url: BASE_URL,
    reuseExistingServer: !process.env.CI,
    timeout: 300_000,
    env: { NEXT_TELEMETRY_DISABLED: '1' },
  },
});
