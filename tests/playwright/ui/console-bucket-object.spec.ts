import { expect, test, type Locator, type Page } from '../fixtures';
import { adminPass, adminUser, loginConsole, typeSlow, uiUrl, uniqueSuffix } from '../helpers';

async function openPrimaryTab(page: Page, tabLabel: 'Admin' | 'Buckets' | 'Keys' | 'Objects'): Promise<void> {
  const mainTabs = page.getByRole('tablist').first();
  await mainTabs.getByRole('tab', { name: tabLabel, exact: true }).click();
}

async function createBucket(page: Page, bucketName: string): Promise<Locator> {
  await openPrimaryTab(page, 'Buckets');
  await typeSlow(page.getByLabel('New bucket name'), bucketName);
  const [presignResponse, createResponse] = await Promise.all([
    page.waitForResponse((resp) => resp.url().includes('/console/v1/presign') && resp.request().method() === 'POST'),
    page.waitForResponse(
      (resp) =>
        resp.request().method() === 'PUT' &&
        resp.url().includes(':9000') &&
        resp.url().includes(`/${bucketName}`)
    ),
    page.getByRole('button', { name: 'Create bucket' }).click()
  ]);
  expect(presignResponse.ok()).toBeTruthy();
  expect(createResponse.ok()).toBeTruthy();
  const row = page.locator('.bucket-table .table-row', { hasText: bucketName });
  await expect(row).toBeVisible({ timeout: 20000 });
  return row;
}

async function deleteBucket(page: Page, bucketName: string): Promise<void> {
  await openPrimaryTab(page, 'Buckets');
  const row = page.locator('.bucket-table .table-row', { hasText: bucketName });
  await expect(row).toBeVisible();
  page.once('dialog', (dialog) => dialog.accept());
  await row.getByRole('button', { name: 'Delete' }).click();
  await expect(row).toHaveCount(0);
}

async function selectBucket(page: Page, bucketName: string): Promise<void> {
  await openPrimaryTab(page, 'Objects');
  await page.getByRole('combobox', { name: 'Bucket', exact: true }).click();
  await page.getByRole('option', { name: bucketName, exact: true }).click();
  await expect(page.getByLabel('Object name (optional)')).toBeEnabled();
}

async function enableWorm(page: Page, bucketName: string): Promise<void> {
  await openPrimaryTab(page, 'Admin');
  const card = page.getByTestId('storage-protection-card');
  await card.getByRole('tab', { name: 'Buckets', exact: true }).click();
  const section = card.getByTestId('worm-section');
  const bucketSelect = section.getByRole('combobox', { name: 'WORM bucket', exact: true });
  await bucketSelect.scrollIntoViewIfNeeded();
  await bucketSelect.focus();
  await bucketSelect.press('Enter');
  await page.getByRole('option', { name: bucketName, exact: true }).click();
  await expect(bucketSelect).toContainText(bucketName);
  const toggle = section.getByRole('switch', { name: 'Enable WORM' });
  const checked = await toggle.getAttribute('aria-checked');
  if (checked !== 'true') {
    await toggle.focus();
    await toggle.press('Space');
    await expect(toggle).toHaveAttribute('aria-checked', 'true');
  }
  const applyButton = section.getByRole('button', { name: 'Apply WORM' });
  await applyButton.focus();
  await applyButton.press('Enter');
}

async function uploadObject(
  page: Page,
  objectKey: string,
  fileName: string,
  content: string
): Promise<Locator> {
  const baseName = objectKey.split('/').filter(Boolean).pop() ?? objectKey;
  await typeSlow(page.getByLabel('Object name (optional)'), objectKey);
  const listResponse = page.waitForResponse((resp) => resp.url().includes('/objects') && resp.ok());
  await page.locator('input[type=\"file\"]').setInputFiles({
    name: fileName,
    mimeType: 'text/plain',
    buffer: Buffer.from(content)
  });
  await listResponse;
  const row = page.locator('.file-table .table-row', { hasText: baseName });
  await expect(row).toBeVisible();
  return row;
}

async function expectWormOverwriteBlocked(page: Page, bucketName: string, key: string): Promise<void> {
  const overwritePromise = page.waitForResponse((resp) => {
    return resp.request().method() === 'PUT' &&
      resp.url().includes(':9000') &&
      resp.url().includes(`/${bucketName}/${key}`);
  });
  await typeSlow(page.getByLabel('Object name (optional)'), key);
  await page.locator('input[type="file"]').setInputFiles({
    name: 'worm-overwrite.txt',
    mimeType: 'text/plain',
    buffer: Buffer.from('overwrite')
  });
  const overwrite = await overwritePromise;
  expect(overwrite.status()).toBe(403);
}

async function expectWormDeleteBlocked(page: Page, row: Locator, bucketName: string, key: string): Promise<void> {
  const deletePromise = page.waitForResponse((resp) => {
    return resp.request().method() === 'DELETE' &&
      resp.url().includes(':9000') &&
      resp.url().includes(`/${bucketName}/${key}`);
  });
  page.once('dialog', (dialog) => dialog.accept());
  await row.getByRole('button', { name: 'Delete' }).click();
  const deletion = await deletePromise;
  expect(deletion.status()).toBe(403);
  await expect(row).toBeVisible();
}

async function deleteObject(page: Page, row: Locator): Promise<void> {
  page.once('dialog', (dialog) => dialog.accept());
  await row.getByRole('button', { name: 'Delete' }).click();
  await expect(row).toHaveCount(0);
}

async function uploadNestedObject(page: Page, folderKey: string): Promise<void> {
  await typeSlow(page.getByLabel('Object name (optional)'), folderKey);
  const listResponse = page.waitForResponse((resp) => resp.url().includes('/objects') && resp.ok());
  await page.locator('input[type=\"file\"]').setInputFiles({
    name: 'nested.txt',
    mimeType: 'text/plain',
    buffer: Buffer.from('nested file')
  });
  await listResponse;
}

async function openFolderAndAssertRows(
  page: Page,
  folderName: string,
  rootKey: string
): Promise<{ folderRow: Locator; nestedRow: Locator; rootRow: Locator }> {
  const folderRow = page.locator('.file-table .file-row', { hasText: folderName });
  await expect(folderRow).toBeVisible();
  await folderRow.getByRole('button', { name: folderName }).click();
  const nestedRow = page.locator('.file-table .file-row', { hasText: 'nested.txt' });
  await expect(nestedRow).toBeVisible();
  const crumb = page.locator('.path-bar').getByRole('button', { name: folderName });
  await expect(crumb).toBeVisible();
  await page.getByRole('button', { name: '..' }).click();
  const rootRow = page.locator('.file-table .file-row', { hasText: rootKey });
  await expect(rootRow).toBeVisible();
  return { folderRow, nestedRow, rootRow };
}

async function assertObjectSearchFilter(page: Page, rootRow: Locator, folderName: string): Promise<void> {
  await typeSlow(page.getByLabel('Search files or folders'), 'root');
  await expect(rootRow).toBeVisible();
  await expect(page.locator('.file-table .file-row', { hasText: folderName })).toHaveCount(0);
  await typeSlow(page.getByLabel('Search files or folders'), '');
  await expect(page.locator('.file-table .file-row', { hasText: folderName })).toBeVisible();
}

async function editMetadataWithValidation(page: Page, details: Locator): Promise<void> {
  await details.getByRole('button', { name: 'Edit' }).click();
  await typeSlow(details.getByLabel('Metadata JSON'), '{"owner": 123}');
  await details.getByRole('button', { name: 'Save metadata' }).click();
  await expect(page.getByText('Metadata must be valid JSON with string values')).toBeVisible();
  await typeSlow(details.getByLabel('Metadata JSON'), JSON.stringify({ owner: 'console' }, null, 2));
  await details.getByRole('button', { name: 'Save metadata' }).click();
  await expect(details.getByText('owner')).toBeVisible();
}

async function renameObjectWithValidation(page: Page, objectRow: Locator): Promise<Locator> {
  await objectRow.getByRole('button', { name: 'Rename' }).click();
  await typeSlow(page.getByLabel('New name'), '');
  await page.getByRole('button', { name: 'Save name' }).click();
  await expect(page.getByText('New object name is required')).toBeVisible();
  const renamedKey = `renamed-${uniqueSuffix()}.txt`;
  await typeSlow(page.getByLabel('New name'), renamedKey);
  await page.getByRole('button', { name: 'Save name' }).click();
  const renamedRow = page.locator('.file-table .table-row', { hasText: renamedKey });
  await expect(renamedRow).toBeVisible();
  return renamedRow;
}

async function verifyGeneratedObjectUrl(page: Page, details: Locator): Promise<void> {
  await details.getByRole('button', { name: 'Generate URL' }).click();
  await expect(details.getByText('Download URL')).toBeVisible();
  const urlField = details.getByLabel('URL');
  await expect(urlField).toHaveValue(/http/);
  await details.getByRole('button', { name: 'Copy' }).click();
  const popupPromise = page.waitForEvent('popup');
  await details.getByRole('button', { name: 'Open' }).click();
  const popup = await popupPromise;
  await expect(popup).toHaveURL(/http/);
  await popup.close();
}

test('[UC-003] console manages buckets', async ({ page }) => {
  await loginConsole(page, adminUser, adminPass);
  const bucketName = `bucket-${uniqueSuffix()}`;
  const bucketItem = await createBucket(page, bucketName);

  await bucketItem.getByRole('switch').click();
  await expect(bucketItem.getByText('Public')).toBeVisible();

  const renamedBucket = `${bucketName}-renamed`;
  await bucketItem.getByRole('button', { name: 'Rename' }).click();
  await typeSlow(bucketItem.getByLabel('New bucket name'), renamedBucket);
  await bucketItem.getByRole('button', { name: 'Save' }).click();
  const renamedBucketItem = page.locator('.bucket-table .table-row', { hasText: renamedBucket });
  await expect(renamedBucketItem).toBeVisible();

  await deleteBucket(page, renamedBucket);
});

test('[UC-003][UC-005] console manages object metadata and public urls', async ({ page }) => {
  await loginConsole(page, adminUser, adminPass);
  const bucketName = `bucket-${uniqueSuffix()}`;
  const bucketItem = await createBucket(page, bucketName);
  await bucketItem.getByRole('switch').click();
  await expect(bucketItem.getByText('Public')).toBeVisible();

  await selectBucket(page, bucketName);
  const objectKey = `hello-${uniqueSuffix()}.txt`;
  const objectRow = await uploadObject(page, objectKey, 'hello.txt', 'hello from playwright');

  await objectRow.getByRole('button', { name: 'Details' }).click();
  const details = page.locator('.object-details');
  await expect(details.getByText('Object properties')).toBeVisible();
  await details.getByRole('button', { name: 'Edit' }).click();
  await typeSlow(details.getByLabel('Metadata JSON'), JSON.stringify({ owner: 'playwright' }, null, 2));
  await details.getByRole('button', { name: 'Save metadata' }).click();
  await expect(details.getByText('owner')).toBeVisible();

  await details.getByRole('button', { name: 'Generate URL' }).click();
  await expect(details.getByText('Public URL')).toBeVisible();
  const urlField = details.getByLabel('URL');
  await expect(urlField).toHaveValue(/http/);

  await deleteObject(page, objectRow);
  await deleteBucket(page, bucketName);
});

test('[UC-003] console renames objects', async ({ page }) => {
  await loginConsole(page, adminUser, adminPass);
  const bucketName = `bucket-${uniqueSuffix()}`;
  await createBucket(page, bucketName);
  await selectBucket(page, bucketName);

  const objectKey = `rename-${uniqueSuffix()}.txt`;
  const objectRow = await uploadObject(page, objectKey, 'rename.txt', 'rename flow');
  await objectRow.getByRole('button', { name: 'Details' }).click();
  await expect(page.locator('.object-details').getByText('Object properties')).toBeVisible();

  const renamedObject = `renamed-${uniqueSuffix()}.txt`;
  await objectRow.getByRole('button', { name: 'Rename' }).click();
  await typeSlow(page.getByLabel('New name'), renamedObject);
  await page.getByRole('button', { name: 'Save name' }).click();
  const renamedObjectRow = page.locator('.file-table .table-row', { hasText: renamedObject });
  await expect(renamedObjectRow).toBeVisible();

  await deleteObject(page, renamedObjectRow);
  await deleteBucket(page, bucketName);
});

test('[UC-003] console uploads unicode object keys', async ({ page }) => {
  await loginConsole(page, adminUser, adminPass);
  const bucketName = `bucket-${uniqueSuffix()}`;
  await createBucket(page, bucketName);
  await selectBucket(page, bucketName);

  const unicodeKey = `space ü-${uniqueSuffix()}.txt`;
  const unicodeRow = await uploadObject(page, unicodeKey, 'space ü.txt', 'unicode upload');
  const details = page.locator('.object-details');
  await unicodeRow.getByRole('button', { name: 'Details' }).click();
  await expect(details.getByText('Download URL')).toBeVisible();
  await details.getByRole('button', { name: 'Generate URL' }).click();
  await expect(details.getByLabel('URL')).toHaveValue(/http/);

  await deleteObject(page, unicodeRow);
  await deleteBucket(page, bucketName);
});

test('[UC-003] console WORM allows first upload but blocks overwrite and delete', async ({ page }) => {
  await loginConsole(page, adminUser, adminPass);
  const bucketName = `bucket-${uniqueSuffix()}`;
  await createBucket(page, bucketName);
  await enableWorm(page, bucketName);
  await selectBucket(page, bucketName);

  const key = `worm-${uniqueSuffix()}.txt`;
  const row = await uploadObject(page, key, 'worm.txt', 'first upload');
  await expectWormOverwriteBlocked(page, bucketName, key);
  await expectWormDeleteBlocked(page, row, bucketName, key);
});

test('[UC-003] console validates bucket fields and cancel delete', async ({ page }) => {
  await loginConsole(page, adminUser, adminPass);
  await openPrimaryTab(page, 'Buckets');
  await page.getByRole('button', { name: 'Create bucket' }).click();
  await expect(page.getByText('Bucket name is required')).toBeVisible();

  const bucketName = `bucket-${uniqueSuffix()}`;
  const row = await createBucket(page, bucketName);
  await row.getByRole('button', { name: 'Rename' }).click();
  await typeSlow(row.getByLabel('New bucket name'), '');
  await row.getByRole('button', { name: 'Save' }).click();
  await expect(page.getByText('Bucket name is required')).toBeVisible();

  page.once('dialog', (dialog) => dialog.dismiss());
  await row.getByRole('button', { name: 'Delete' }).click();
  await expect(row).toBeVisible();

  await deleteBucket(page, bucketName);
});

test('[UC-003] console object browser navigation and search', async ({ page }) => {
  await loginConsole(page, adminUser, adminPass);
  const bucketName = `bucket-${uniqueSuffix()}`;
  await createBucket(page, bucketName);
  await selectBucket(page, bucketName);
  const rootKey = `root-${uniqueSuffix()}.txt`;
  const folderKey = `folder-${uniqueSuffix()}/nested.txt`;
  await uploadObject(page, rootKey, 'root.txt', 'root file');
  await uploadNestedObject(page, folderKey);
  const folderName = folderKey.split('/')[0];
  const { folderRow, nestedRow, rootRow } = await openFolderAndAssertRows(page, folderName, rootKey);
  await assertObjectSearchFilter(page, rootRow, folderName);
  await folderRow.getByRole('button', { name: folderName }).click();
  await deleteObject(page, nestedRow);
  await expect(page.getByText('No objects found in this path.')).toBeVisible();
  await page.locator('.path-bar').getByRole('button', { name: 'Root' }).click();
  await deleteObject(page, rootRow);
  await deleteBucket(page, bucketName);
});

test('[UC-003][UC-005] console object details validate metadata, rename, and urls', async ({ page }) => {
  await loginConsole(page, adminUser, adminPass);
  await page.context().grantPermissions(['clipboard-write'], { origin: uiUrl });
  const bucketName = `bucket-${uniqueSuffix()}`;
  await createBucket(page, bucketName);
  await selectBucket(page, bucketName);

  const objectKey = `meta-${uniqueSuffix()}.txt`;
  const objectRow = await uploadObject(page, objectKey, 'meta.txt', 'meta content');
  await objectRow.getByRole('button', { name: 'Details' }).click();
  const details = page.locator('.object-details');
  await expect(details.getByText('Object properties')).toBeVisible();
  await editMetadataWithValidation(page, details);
  const renamedRow = await renameObjectWithValidation(page, objectRow);
  await verifyGeneratedObjectUrl(page, details);
  await deleteObject(page, renamedRow);
  await deleteBucket(page, bucketName);
});
