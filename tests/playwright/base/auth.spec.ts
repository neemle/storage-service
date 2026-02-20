import { expect, test } from '../fixtures';
import { adminPass, adminUser, humanClick, typeSlow, uiUrl, waitAfterNavigation } from '../helpers';

test('[SEC][UC-001] login rejects bad credentials and preserves authenticated logout flow', async ({ page }) => {
  await page.goto(uiUrl, { waitUntil: 'domcontentloaded' });
  await waitAfterNavigation(page);
  await humanClick(page.getByRole('button', { name: 'Sign in' }));
  await expect(page.getByText('Username and password are required')).toBeVisible();

  await typeSlow(page.getByLabel('Username'), 'invalid-user');
  await typeSlow(page.getByLabel('Password'), 'invalid-pass');
  await humanClick(page.getByRole('button', { name: 'Sign in' }));
  await expect(page.locator('.error')).toBeVisible();

  await typeSlow(page.getByLabel('Username'), adminUser);
  await typeSlow(page.getByLabel('Password'), adminPass);
  await humanClick(page.getByRole('button', { name: 'Sign in' }));
  await expect(page.getByRole('button', { name: 'Sign out' })).toBeVisible();

  await humanClick(page.getByRole('button', { name: 'Sign out' }));
  await expect(page.getByText('Neemle Storage Service Console')).toBeVisible();
  await expect(page.getByRole('button', { name: 'Sign in' })).toBeVisible();
});
