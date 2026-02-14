import { expect, test } from '../fixtures';
import {
  adminPass,
  adminUser,
  createUser,
  loginAdmin,
  loginConsole,
  readSecretField,
  typeSlow,
  uniqueSuffix
} from '../helpers';

test('[UC-001][UC-002][UC-004] admin creates user and console manages access key', async ({ browser }) => {
  const adminPage = await browser.newPage();
  await loginAdmin(adminPage);

  const username = `user-${uniqueSuffix()}`;
  const password = `pass-${uniqueSuffix()}`;
  await createUser(adminPage, username, password);

  await adminPage.getByRole('button', { name: 'Generate join token' }).click();
  await expect(adminPage.getByText('Replica join token')).toBeVisible();
  const tokenText = await adminPage.locator('.token-box').textContent();
  if (!tokenText || tokenText.trim().length < 10) {
    throw new Error('join token missing');
  }

  const consolePage = await browser.newPage();
  await loginConsole(consolePage, username, password);
  await consolePage.getByRole('tab', { name: 'Keys' }).click();
  const label = `key-${uniqueSuffix()}`;
  await typeSlow(consolePage.getByLabel('Label'), label);
  await consolePage.getByRole('button', { name: 'Create key' }).click();
  await expect(consolePage.getByText('Access key created')).toBeVisible();
  const accessKeyId = await readSecretField(consolePage, 0);
  await consolePage.getByRole('button', { name: 'I have saved this' }).click();

  const row = consolePage.locator('.table-row', { hasText: accessKeyId });
  await row.getByRole('button', { name: 'Disable' }).click();
  await expect(row.getByText('disabled')).toBeVisible();
});
