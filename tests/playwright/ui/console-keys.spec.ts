import { expect, test } from '../fixtures';
import { adminPass, adminUser, loginConsole, typeSlow, uniqueSuffix } from '../helpers';

test('[UC-002] console key lifecycle disables and deletes keys', async ({ page }) => {
  await loginConsole(page, adminUser, adminPass);
  await page.getByRole('tab', { name: 'Keys' }).click();

  const label = `key-${uniqueSuffix()}`;
  await typeSlow(page.getByLabel('Label'), label);
  await page.getByRole('button', { name: 'Create key' }).click();
  await expect(page.getByText('Access key created')).toBeVisible();
  await page.getByRole('button', { name: 'I have saved this' }).click();

  const row = page.locator('.key-table .table-row', { hasText: label });
  await expect(row).toBeVisible();
  await row.getByRole('button', { name: 'Disable' }).click();
  await expect(row.getByText('disabled')).toBeVisible();

  await row.getByRole('button', { name: 'Delete' }).click();
  await expect(row).toHaveCount(0);
});
