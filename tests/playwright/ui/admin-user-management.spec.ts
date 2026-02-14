import { expect, test } from '../fixtures';
import { createUser, loginAdmin, loginConsole, uniqueSuffix } from '../helpers';

test('[UC-001][UC-004] admin manages users and join tokens', async ({ browser }) => {
  const adminPage = await browser.newPage();
  await loginAdmin(adminPage);

  const username = `user-${uniqueSuffix()}`;
  const password = `pass-${uniqueSuffix()}`;
  await createUser(adminPage, username, password);

  const userRow = adminPage.locator('mat-list-item', { hasText: username });
  await expect(userRow).toBeVisible();

  await userRow.getByRole('button', { name: 'Toggle' }).click();
  await expect(userRow.getByText('disabled')).toBeVisible();
  await userRow.getByRole('button', { name: 'Toggle' }).click();
  await expect(userRow.getByText('active')).toBeVisible();

  const newPassword = `reset-${uniqueSuffix()}`;
  adminPage.once('dialog', (dialog) => dialog.accept(newPassword));
  await userRow.getByRole('button', { name: 'Reset' }).click();

  await adminPage.getByRole('button', { name: 'Generate join token' }).click();
  await expect(adminPage.getByText('Replica join token')).toBeVisible();
  await adminPage.getByRole('button', { name: 'Dismiss' }).click();
  await expect(adminPage.getByText('Replica join token')).toHaveCount(0);

  const userPage = await browser.newPage();
  await loginConsole(userPage, username, newPassword);
  await expect(userPage.getByRole('tab', { name: 'Admin' })).toHaveCount(0);
});
