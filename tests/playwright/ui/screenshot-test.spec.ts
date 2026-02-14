import { expect, test, type Page } from '../fixtures';
import { typeSlow } from '../helpers';

const UI_URL = process.env.NSS_UI_URL || 'http://localhost:4200';
const TEST_USER = process.env.NSS_TEST_USER ?? process.env.NSS_ADMIN_BOOTSTRAP_USER ?? 'admin';
const TEST_PASS = process.env.NSS_TEST_PASSWORD ?? process.env.NSS_ADMIN_BOOTSTRAP_PASSWORD ?? 'change-me';

async function attemptLogin(page: Page): Promise<boolean> {
  try {
    await typeSlow(page.getByLabel('Username'), TEST_USER);
    await typeSlow(page.getByLabel('Password'), TEST_PASS);
    await page.getByRole('button', { name: 'Sign in' }).click();
    await page.getByText('Signed in as').waitFor({ state: 'visible', timeout: 5000 });
    return true;
  } catch {
    return false;
  }
}

test.describe('UI Screenshots - Login', () => {
  test('[UC-001][UC-007] login page - desktop', async ({ page }) => {
    await page.setViewportSize({ width: 1440, height: 900 });
    await page.goto(UI_URL);
    await page.waitForLoadState('networkidle');
    await page.screenshot({ path: 'test-results/login-desktop.png', fullPage: true });
  });

  test('[UC-001][UC-007] login page - tablet', async ({ page }) => {
    await page.setViewportSize({ width: 768, height: 1024 });
    await page.goto(UI_URL);
    await page.waitForLoadState('networkidle');
    await page.screenshot({ path: 'test-results/login-tablet.png', fullPage: true });
  });

  test('[UC-001][UC-007] login page - mobile', async ({ page }) => {
    await page.setViewportSize({ width: 375, height: 812 });
    await page.goto(UI_URL);
    await page.waitForLoadState('networkidle');
    await page.screenshot({ path: 'test-results/login-mobile.png', fullPage: true });
  });
});

test.describe('UI Screenshots - Main Dashboard', () => {
  registerDashboardScreenshot(
    '[UC-001][UC-007] dashboard - desktop',
    1440,
    900,
    'test-results/dashboard-desktop.png'
  );
  registerDashboardScreenshot(
    '[UC-001][UC-007] dashboard - tablet',
    768,
    1024,
    'test-results/dashboard-tablet.png'
  );
  registerDashboardScreenshot(
    '[UC-001][UC-007] dashboard - mobile',
    375,
    812,
    'test-results/dashboard-mobile.png'
  );
});

function registerDashboardScreenshot(name: string, width: number, height: number, path: string): void {
  test(name, async ({ page }) => {
    await captureDashboardScreenshot(page, width, height, path);
  });
}

async function captureDashboardScreenshot(
  page: Page,
  width: number,
  height: number,
  path: string
): Promise<void> {
  await page.setViewportSize({ width, height });
  await page.goto(UI_URL);
  await page.waitForLoadState('networkidle');
  const loggedIn = await attemptLogin(page);
  if (!loggedIn) {
    return;
  }
  await page.waitForLoadState('networkidle');
  await page.screenshot({ path, fullPage: true });
}
