import { expect, test } from '../fixtures';
import { adminPass, adminUser, loginConsole, readSecretField, typeSlow, uniqueSuffix } from '../helpers';

test('[UC-001][UC-002] console login creates access key', async ({ page }) => {
  await loginConsole(page, adminUser, adminPass);
  await page.getByRole('tab', { name: 'Keys' }).click();
  const label = `base-${uniqueSuffix()}`;
  await typeSlow(page.getByLabel('Label'), label);
  await page.getByRole('button', { name: 'Create key' }).click();
  await expect(page.getByText('Access key created')).toBeVisible();
  const accessKeyId = await readSecretField(page, 0);
  await page.getByRole('button', { name: 'I have saved this' }).click();
  await expect(page.getByText(accessKeyId)).toBeVisible();
});
