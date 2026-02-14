import { expect, test, type Locator, type Page } from '../fixtures';
import { loginAdmin, typeSlow, uniqueSuffix } from '../helpers';

interface StorageSetup {
  backupBucket: string;
  card: Locator;
  sourceBucket: string;
}

async function createBucketFromConsole(page: Page, bucketName: string): Promise<void> {
  await page.getByRole('tab', { name: 'Buckets' }).click();
  const input = page.getByLabel('New bucket name');
  await typeSlow(input, bucketName);
  await expect(input).toHaveValue(bucketName);
  await page.getByRole('button', { name: 'Create bucket' }).click();
  const row = page.locator('.bucket-table .table-row', { hasText: bucketName });
  await expect(row).toBeVisible({ timeout: 20000 });
}

async function chooseBucketInSection(
  page: Page,
  sectionTestId: string,
  label: string,
  bucketName: string
): Promise<void> {
  const section = page.getByTestId(sectionTestId);
  await section.getByLabel(label).click();
  await page.getByRole('option', { name: bucketName, exact: true }).click();
}

async function ensureToggleEnabled(page: Page, sectionTestId: string, toggleName: string): Promise<void> {
  const toggle = page.getByTestId(sectionTestId).getByRole('switch', { name: toggleName });
  const checked = await toggle.getAttribute('aria-checked');
  if (checked !== 'true') {
    await toggle.click();
  }
}

async function setupStorage(page: Page): Promise<StorageSetup> {
  await loginAdmin(page);
  const sourceBucket = `src-${uniqueSuffix()}`;
  const backupBucket = `backup-${uniqueSuffix()}`;
  await createBucketFromConsole(page, sourceBucket);
  await createBucketFromConsole(page, backupBucket);
  await page.getByRole('tab', { name: 'Admin' }).click();
  const card = page.getByTestId('storage-protection-card');
  await expect(card).toBeVisible();
  return { backupBucket, card, sourceBucket };
}

async function enableWorm(page: Page, card: Locator, backupBucket: string): Promise<void> {
  await chooseBucketInSection(page, 'worm-section', 'WORM bucket', backupBucket);
  await ensureToggleEnabled(page, 'worm-section', 'Enable WORM');
  const responsePromise = page.waitForResponse((resp) => {
    return resp.request().method() === 'PATCH' &&
      resp.url().includes(`/admin/v1/storage/buckets/${backupBucket}/worm`);
  });
  await card.getByRole('button', { name: 'Apply WORM' }).click();
  const response = await responsePromise;
  expect(response.ok()).toBeTruthy();
}

async function saveAndEditSnapshotPolicy(page: Page, card: Locator, sourceBucket: string): Promise<void> {
  await chooseBucketInSection(page, 'snapshot-section', 'Snapshot bucket', sourceBucket);
  await card.getByRole('button', { name: 'Save snapshot policy' }).click();
  const policyRow = card.getByTestId('snapshot-policy-row').first();
  await expect(policyRow).toBeVisible({ timeout: 20000 });
  await policyRow.getByRole('button', { name: 'Edit snapshot policy' }).click();
  const section = card.getByTestId('snapshot-section');
  await typeSlow(section.getByLabel('Retention'), '3');
  await card.getByRole('button', { name: 'Save snapshot policy' }).click();
  await expect(policyRow).toContainText('3', { timeout: 20000 });
}

async function createSnapshotAndRestore(page: Page, card: Locator): Promise<void> {
  await card.getByRole('button', { name: 'Create snapshot now' }).click();
  const snapshotRow = card.getByTestId('snapshot-row').first();
  await expect(snapshotRow).toBeVisible({ timeout: 20000 });
  const restoredBucket = `restored-${uniqueSuffix()}`;
  const responsePromise = page.waitForResponse((resp) => {
    return resp.request().method() === 'POST' &&
      resp.url().includes('/admin/v1/storage/snapshots/') &&
      resp.ok();
  });
  page.once('dialog', (dialog) => dialog.accept(restoredBucket));
  await snapshotRow.getByRole('button', { name: 'Restore' }).click();
  await responsePromise;
  await page.getByRole('tab', { name: 'Buckets' }).click();
  const row = page.locator('.bucket-table .table-row', { hasText: restoredBucket });
  await expect(row).toBeVisible({ timeout: 20000 });
  await page.getByRole('tab', { name: 'Admin' }).click();
}

async function createAndEditBackupPolicy(
  page: Page,
  card: Locator,
  sourceBucket: string,
  backupBucket: string
): Promise<Locator> {
  const policyName = `policy-${uniqueSuffix()}`;
  await typeSlow(card.getByLabel('Policy name'), policyName);
  await chooseBucketInSection(page, 'backup-policy-section', 'Source bucket', sourceBucket);
  await chooseBucketInSection(page, 'backup-policy-section', 'Backup bucket', backupBucket);
  const createPromise = page.waitForResponse((resp) => {
    return resp.request().method() === 'POST' &&
      resp.url().includes('/admin/v1/storage/backup-policies');
  });
  await card.getByRole('button', { name: 'Create backup policy' }).click();
  expect((await createPromise).ok()).toBeTruthy();
  const policyRow = card.getByTestId('backup-policy-row').filter({ hasText: policyName });
  await expect(policyRow).toBeVisible({ timeout: 20000 });

  await policyRow.getByRole('button', { name: 'Edit policy' }).click();
  const updatedPolicyName = `${policyName}-updated`;
  await typeSlow(card.getByLabel('Policy name'), updatedPolicyName);
  await card.getByRole('button', { name: 'Update backup policy' }).click();
  const updatedPolicyRow = card.getByTestId('backup-policy-row').filter({ hasText: updatedPolicyName });
  await expect(updatedPolicyRow).toBeVisible({ timeout: 20000 });
  return updatedPolicyRow;
}

async function runAndExportBackup(page: Page, card: Locator, policyRow: Locator): Promise<void> {
  const runPromise = page.waitForResponse((resp) => {
    return resp.request().method() === 'POST' &&
      resp.url().includes('/admin/v1/storage/backups/') &&
      resp.ok();
  });
  await policyRow.getByRole('button', { name: 'Run backup' }).click();
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
  await runRow.getByRole('button', { name: 'Export tar.gz' }).click();
  await exportPromise;
}

test('[UC-009][UC-010][UC-012] admin manages snapshots and backups from UI', async ({ page }) => {
  const setup = await setupStorage(page);
  await enableWorm(page, setup.card, setup.backupBucket);
  await saveAndEditSnapshotPolicy(page, setup.card, setup.sourceBucket);
  await createSnapshotAndRestore(page, setup.card);
  const updatedPolicyRow = await createAndEditBackupPolicy(
    page,
    setup.card,
    setup.sourceBucket,
    setup.backupBucket
  );
  await runAndExportBackup(page, setup.card, updatedPolicyRow);
});
