import { expect, test, type Page } from '../fixtures';
import { typeSlow, uiUrl } from '../helpers';

const expectedMode = process.env.NSS_EXPECTED_AUTH_MODE ?? 'oidc';
const idpBase = process.env.NSS_EXTERNAL_IDP_URL ?? 'http://keycloak:8080';
const username = process.env.NSS_EXTERNAL_USER ?? 'admin';
const password = process.env.NSS_EXTERNAL_PASSWORD ?? 'admin';
const externalAuthEnabled = process.env.NSS_EXTERNAL_AUTH_TEST === '1';

function escapeRegex(input: string): string {
  return input.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

async function assertAuthConfig(page: Page): Promise<void> {
  const response = await page.request.get(`${uiUrl}/console/v1/auth/config`);
  expect(response.ok()).toBeTruthy();
  const config = await response.json();
  expect(config.mode).toBe(expectedMode);
  expect(config.externalLoginPath).toBe('/console/v1/oidc/start');
}

async function loginViaKeycloak(page: Page): Promise<void> {
  await page.getByRole('button', { name: 'Continue with external identity' }).click();
  await expect(page).toHaveURL(new RegExp(`^${escapeRegex(idpBase)}`));
  await page.locator('#username').waitFor({ state: 'visible', timeout: 30_000 });
  await typeSlow(page.locator('#username'), username);
  await typeSlow(page.locator('#password'), password);
  await page.locator('#kc-login').click();
}

test.describe('external auth', () => {
  test.skip(!externalAuthEnabled, 'External auth tests run only in external auth stack');

  test('[UC-012][UC-015] keycloak login works for configured external auth mode', async ({ page }) => {
    await assertAuthConfig(page);
    await page.goto(uiUrl, { waitUntil: 'domcontentloaded' });
    await expect(page.getByRole('button', { name: 'Continue with external identity' })).toBeVisible();

    await loginViaKeycloak(page);
    await expect(page.getByText('Signed in as admin')).toBeVisible({ timeout: 30_000 });
    await page.getByRole('tab', { name: 'Admin' }).click();
    await expect(page.getByRole('heading', { name: 'Cluster' })).toBeVisible();
  });
});
