import { expect, test } from '../fixtures';
import { adminPass, adminUser, typeSlow, uiUrl } from '../helpers';

test('[UC-001] login validates fields, rejects bad credentials, and logs out', async ({ page }) => {
  await page.goto(uiUrl, { waitUntil: 'domcontentloaded' });
  await page.getByRole('button', { name: 'Sign in' }).click();
  await expect(page.getByText('Username and password are required')).toBeVisible();

  await typeSlow(page.getByLabel('Username'), 'invalid-user');
  await typeSlow(page.getByLabel('Password'), 'invalid-pass');
  await page.getByRole('button', { name: 'Sign in' }).click();
  await expect(page.locator('.error')).toBeVisible();

  await typeSlow(page.getByLabel('Username'), adminUser);
  await typeSlow(page.getByLabel('Password'), adminPass);
  await page.getByRole('button', { name: 'Sign in' }).click();
  await expect(page.getByText('Signed in as')).toBeVisible();

  await page.getByRole('button', { name: 'Sign out' }).click();
  await expect(page.getByText('Neemle Storage Service Console')).toBeVisible();
  await expect(page.getByRole('button', { name: 'Sign in' })).toBeVisible();
});
