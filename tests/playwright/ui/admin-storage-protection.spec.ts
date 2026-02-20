import { expect, test, type Locator, type Page } from '../fixtures';
import { loginAdmin, typeSlow, uniqueSuffix } from '../helpers';

interface StorageSetup {
  backupBucket: string;
  card: Locator;
  sourceBucket: string;
}

async function activateButton(button: Locator): Promise<void> {
  await button.focus();
  await button.press('Enter');
}

async function openPrimaryTab(page: Page, tabLabel: 'Admin' | 'Buckets'): Promise<void> {
  const mainTabs = page.getByRole('tablist').first();
  await mainTabs.getByRole('tab', { name: tabLabel, exact: true }).click();
}

async function openStorageTab(page: Page, tabLabel: 'Nodes' | 'Buckets' | 'Snapshots' | 'Backups'): Promise<void> {
  const card = page.getByTestId('storage-protection-card');
  await card.getByRole('tab', { name: tabLabel, exact: true }).click();
}

async function expectStorageTabsWork(page: Page): Promise<void> {
  const card = page.getByTestId('storage-protection-card');
  await openStorageTab(page, 'Nodes');
  await expect(card.getByTestId('node-mode-section')).toBeVisible();
  await openStorageTab(page, 'Buckets');
  await expect(card.getByTestId('worm-section')).toBeVisible();
  await openStorageTab(page, 'Snapshots');
  await expect(card.getByTestId('snapshot-section')).toBeVisible();
  await openStorageTab(page, 'Backups');
  await expect(card.getByTestId('backup-policy-section')).toBeVisible();
}

async function createBucketFromConsole(page: Page, bucketName: string): Promise<void> {
  await openPrimaryTab(page, 'Buckets');
  const input = page.getByLabel('New bucket name');
  await typeSlow(input, bucketName);
  await expect(input).toHaveValue(bucketName);
  await page.getByRole('button', { name: 'Create bucket' }).click();
  const row = page.locator('.bucket-table .table-row', { hasText: bucketName });
  await expect(row).toBeVisible({ timeout: 20000 });
}

async function chooseBucketInSection(
  page: Page,
  storageTab: 'Buckets' | 'Snapshots' | 'Backups',
  sectionTestId: string,
  label: string,
  bucketName: string
): Promise<void> {
  await openStorageTab(page, storageTab);
  const section = page.getByTestId(sectionTestId);
  const bucketSelect = section.getByRole('combobox', { name: label, exact: true });
  await bucketSelect.scrollIntoViewIfNeeded();
  await bucketSelect.focus();
  await bucketSelect.press('Enter');
  await page.getByRole('option', { name: bucketName, exact: true }).click();
  await expect(bucketSelect).toContainText(bucketName);
}

async function ensureToggleEnabled(
  page: Page,
  storageTab: 'Buckets' | 'Snapshots' | 'Backups',
  sectionTestId: string,
  toggleName: string
): Promise<void> {
  await openStorageTab(page, storageTab);
  const toggle = page.getByTestId(sectionTestId).getByRole('switch', { name: toggleName });
  const checked = await toggle.getAttribute('aria-checked');
  if (checked !== 'true') {
    await toggle.focus();
    await toggle.press('Space');
  }
}

async function setupStorage(page: Page): Promise<StorageSetup> {
  await loginAdmin(page);
  const sourceBucket = `src-${uniqueSuffix()}`;
  const backupBucket = `backup-${uniqueSuffix()}`;
  await createBucketFromConsole(page, sourceBucket);
  await createBucketFromConsole(page, backupBucket);
  await openPrimaryTab(page, 'Admin');
  const card = page.getByTestId('storage-protection-card');
  await expect(card).toBeVisible();
  return { backupBucket, card, sourceBucket };
}

async function enableWorm(page: Page, card: Locator, backupBucket: string): Promise<void> {
  await chooseBucketInSection(page, 'Buckets', 'worm-section', 'WORM bucket', backupBucket);
  await ensureToggleEnabled(page, 'Buckets', 'worm-section', 'Enable WORM');
  const applyButton = card.getByRole('button', { name: 'Apply WORM' });
  await activateButton(applyButton);
}

async function expectBackupBucketMustBeWorm(
  page: Page,
  card: Locator,
  sourceBucket: string,
  backupBucket: string
): Promise<void> {
  await openStorageTab(page, 'Backups');
  await typeSlow(card.getByLabel('Policy name'), `invalid-${uniqueSuffix()}`);
  await chooseBucketInSection(page, 'Backups', 'backup-policy-section', 'Source bucket', sourceBucket);
  await chooseBucketInSection(page, 'Backups', 'backup-policy-section', 'Backup bucket', backupBucket);
  await activateButton(card.getByRole('button', { name: 'Create backup policy' }));
  await expect(page.locator('.error')).toContainText(/worm/i);
}

async function selectSnapshotTrigger(section: Locator, trigger: 'hourly' | 'on_create_change'): Promise<void> {
  const select = section.getByRole('combobox', { name: 'Snapshot trigger', exact: true });
  await select.focus();
  await select.press('Enter');
  await section.page().getByRole('option', { name: trigger, exact: true }).click();
  await expect(select).toContainText(trigger);
}

async function saveAndEditSnapshotPolicy(page: Page, card: Locator, sourceBucket: string): Promise<void> {
  await chooseBucketInSection(page, 'Snapshots', 'snapshot-section', 'Snapshot bucket', sourceBucket);
  const section = card.getByTestId('snapshot-section');
  await selectSnapshotTrigger(section, 'hourly');
  await activateButton(card.getByRole('button', { name: 'Save snapshot policy' }));
  const policyRow = card.getByTestId('snapshot-policy-row').first();
  await expect(policyRow).toBeVisible({ timeout: 20000 });
  await expect(policyRow).toContainText('hourly');
  await activateButton(policyRow.getByRole('button', { name: 'Edit snapshot policy' }));
  await selectSnapshotTrigger(section, 'on_create_change');
  await typeSlow(section.getByLabel('Retention'), '3');
  await activateButton(card.getByRole('button', { name: 'Save snapshot policy' }));
  await expect(policyRow).toContainText('on_create_change', { timeout: 20000 });
  await expect(policyRow).toContainText('3', { timeout: 20000 });
}

async function createSnapshotAndRestore(page: Page, card: Locator): Promise<void> {
  await openStorageTab(page, 'Snapshots');
  await activateButton(card.getByRole('button', { name: 'Create snapshot now' }));
  const snapshotRow = card.getByTestId('snapshot-row').first();
  await expect(snapshotRow).toBeVisible({ timeout: 20000 });
  const restoredBucket = `restored-${uniqueSuffix()}`;
  const responsePromise = page.waitForResponse((resp) => {
    return resp.request().method() === 'POST' &&
      resp.url().includes('/admin/v1/storage/snapshots/') &&
      resp.ok();
  });
  page.once('dialog', (dialog) => dialog.accept(restoredBucket));
  await activateButton(snapshotRow.getByRole('button', { name: 'Restore' }));
  await responsePromise;
  await openPrimaryTab(page, 'Buckets');
  const row = page.locator('.bucket-table .table-row', { hasText: restoredBucket });
  await expect(row).toBeVisible({ timeout: 20000 });
  await openPrimaryTab(page, 'Admin');
}

async function createAndEditBackupPolicy(
  page: Page,
  card: Locator,
  sourceBucket: string,
  backupBucket: string
): Promise<Locator> {
  const { policyName, policyRow } = await createBackupPolicy(page, card, sourceBucket, backupBucket);
  return editBackupPolicy(page, card, policyRow, policyName);
}

async function createBackupPolicy(
  page: Page,
  card: Locator,
  sourceBucket: string,
  backupBucket: string
): Promise<{ policyName: string; policyRow: Locator }> {
  await openStorageTab(page, 'Backups');
  const policyName = `policy-${uniqueSuffix()}`;
  await typeSlow(card.getByLabel('Policy name'), policyName);
  await chooseBucketInSection(page, 'Backups', 'backup-policy-section', 'Source bucket', sourceBucket);
  await chooseBucketInSection(page, 'Backups', 'backup-policy-section', 'Backup bucket', backupBucket);
  const createPromise = page.waitForResponse((resp) => {
    return resp.request().method() === 'POST' &&
      resp.url().includes('/admin/v1/storage/backup-policies');
  });
  await activateButton(card.getByRole('button', { name: 'Create backup policy' }));
  expect((await createPromise).ok()).toBeTruthy();
  const policyRow = card.getByTestId('backup-policy-row').filter({ hasText: policyName });
  await expect(policyRow).toBeVisible({ timeout: 20000 });
  return { policyName, policyRow };
}

async function editBackupPolicy(page: Page, card: Locator, policyRow: Locator, policyName: string): Promise<Locator> {
  await activateButton(policyRow.getByRole('button', { name: 'Edit policy' }));
  const wizard = page.locator('.backup-wizard-modal');
  await expect(wizard).toBeVisible({ timeout: 10000 });
  await activateButton(wizard.getByRole('button', { name: 'Next' }));
  await activateButton(wizard.getByRole('button', { name: 'Next' }));
  const updatedPolicyName = `${policyName}-updated`;
  await typeSlow(wizard.getByLabel('Policy name'), updatedPolicyName);
  await activateButton(wizard.getByRole('button', { name: 'Next' }));
  await activateButton(wizard.getByRole('button', { name: 'Save policy' }));
  await expect(wizard).not.toBeVisible({ timeout: 30000 });
  const updatedPolicyRow = card.getByTestId('backup-policy-row').filter({ hasText: updatedPolicyName });
  await expect(updatedPolicyRow).toBeVisible({ timeout: 20000 });
  return updatedPolicyRow;
}

async function validateBackupTargetJson(page: Page, card: Locator): Promise<void> {
  await openStorageTab(page, 'Backups');
  const targets = card.getByLabel('External targets JSON');
  await typeSlow(targets, '{');
  await activateButton(card.getByRole('button', { name: 'Test remote targets' }));
  await expect(page.locator('.error')).toContainText('valid JSON target objects');
  await activateButton(card.getByRole('button', { name: 'Show example' }));
  await activateButton(page.getByRole('button', { name: 'Use this example' }));
  await expect(targets).toHaveValue(/archive-sftp-gateway/);
  await typeSlow(targets, '[]');
  await expect(targets).toHaveValue('[]');
}

async function runAndExportBackup(page: Page, card: Locator, policyRow: Locator): Promise<void> {
  await openStorageTab(page, 'Backups');
  const runPromise = page.waitForResponse((resp) => {
    return resp.request().method() === 'POST' &&
      resp.url().includes('/admin/v1/storage/backups/') &&
      resp.ok();
  });
  await activateButton(policyRow.getByRole('button', { name: 'Run backup' }));
  const runResponse = await runPromise;
  const runJson = await runResponse.json();
  const runId = String(runJson.id ?? '');
  if (runId.length < 10) {
    throw new Error('backup run id missing in response');
  }
  const runRow = card.getByTestId('backup-run-row').filter({ hasText: runId });
  await expect(runRow).toContainText('success', { timeout: 20000 });

  const exportPromise = page.waitForResponse((resp) => {
    return resp.url().includes(`/admin/v1/storage/backups/runs/${runId}/export`) && resp.ok();
  });
  await activateButton(runRow.getByRole('button', { name: 'Export tar.gz' }));
  await exportPromise;
}

test('[UC-009][UC-010][UC-012] admin manages snapshots and backups from UI', async ({ page }) => {
  const setup = await setupStorage(page);
  await expectStorageTabsWork(page);
  await expectBackupBucketMustBeWorm(page, setup.card, setup.sourceBucket, setup.backupBucket);
  await enableWorm(page, setup.card, setup.backupBucket);
  await saveAndEditSnapshotPolicy(page, setup.card, setup.sourceBucket);
  await validateBackupTargetJson(page, setup.card);
  await createSnapshotAndRestore(page, setup.card);
  const updatedPolicyRow = await createAndEditBackupPolicy(
    page,
    setup.card,
    setup.sourceBucket,
    setup.backupBucket
  );
  await runAndExportBackup(page, setup.card, updatedPolicyRow);
});
