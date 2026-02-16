import { expect, test, type Browser, type Locator, type Page } from '../fixtures';
import {
  createUser,
  loginAdmin,
  loginConsole,
  readSecretField,
  typeSlow,
  uniqueSuffix
} from '../helpers';

interface Credentials {
  password: string;
  username: string;
}

interface KeyPair {
  accessKey: string;
  secretKey: string;
}

interface LinkScenario {
  bucketName: string;
  content: string;
  expectPresigned: boolean;
  key: string;
  makePublic: boolean;
}

interface AnonymousReadOptions {
  maxAttempts?: number;
  requestTimeoutMs?: number;
  retryDelayMs?: number;
}

async function openPrimaryTab(page: Page, tabLabel: 'Admin' | 'Buckets' | 'Keys' | 'Objects'): Promise<void> {
  const mainTabs = page.getByRole('tablist').first();
  await mainTabs.getByRole('tab', { name: tabLabel, exact: true }).click();
}

async function newVideoContext(browser: Browser) {
  return browser.newContext({
    recordVideo: {
      dir: 'test-results'
    }
  });
}

async function setRequirePasswordChange(page: Page, required: boolean): Promise<void> {
  const toggle = page.getByRole('switch', { name: 'Require password change' });
  const checked = (await toggle.getAttribute('aria-checked')) === 'true';
  if (checked !== required) {
    await toggle.click();
  }
}

async function createConsoleUser(page: Page, requirePasswordChange: boolean): Promise<Credentials> {
  const username = `user-${uniqueSuffix()}`;
  const password = `pass-${uniqueSuffix()}`;
  await setRequirePasswordChange(page, requirePasswordChange);
  await createUser(page, username, password);
  return { password, username };
}

async function openSettings(page: Page): Promise<void> {
  await page.locator('.user-menu-btn').click();
  await page.getByRole('button', { name: 'Settings' }).click();
  await expect(page.getByRole('heading', { name: 'Settings' })).toBeVisible();
}

async function setTheme(page: Page, themeLabel: 'Dark' | 'Light'): Promise<void> {
  const expectedTheme = themeLabel.toLowerCase();
  const modal = page.locator('.settings-modal');
  await modal.getByRole('button', { name: themeLabel, exact: true }).click();
  await expect
    .poll(() => page.evaluate(() => document.documentElement.getAttribute('data-theme')))
    .toBe(expectedTheme);
}

async function changePasswordInSettings(page: Page, current: string, next: string): Promise<void> {
  const modal = page.locator('.settings-modal');
  await typeSlow(modal.getByLabel('Current password'), current);
  await typeSlow(modal.getByLabel('New password'), next);
  await typeSlow(modal.getByLabel('Confirm password'), next);
  await modal.getByRole('button', { name: 'Change Password' }).click();
  await expect(modal.getByLabel('Current password')).toHaveValue('');
  await expect(modal.getByLabel('New password')).toHaveValue('');
  await expect(modal.getByLabel('Confirm password')).toHaveValue('');
}

async function closeSettings(page: Page): Promise<void> {
  await page.locator('.settings-modal button[title="Close"]').click();
  await expect(page.locator('.settings-modal')).toBeHidden();
}

async function createAccessKeyPair(page: Page, label: string): Promise<KeyPair> {
  await openPrimaryTab(page, 'Keys');
  await typeSlow(page.getByLabel('Label'), label);
  await page.getByRole('button', { name: 'Create key' }).click();
  await expect(page.getByText('Access key created')).toBeVisible();
  const accessKey = await readSecretField(page, 0);
  const secretKey = await readSecretField(page, 1);
  await page.getByRole('button', { name: 'I have saved this' }).click();
  return { accessKey, secretKey };
}

async function createBucket(page: Page, bucketName: string): Promise<Locator> {
  await openPrimaryTab(page, 'Buckets');
  const panel = page.getByRole('tabpanel', { name: 'Buckets' });
  await expect(panel).toBeVisible();
  const input = panel.getByLabel('New bucket name');
  await typeSlow(input, bucketName);
  await expect(input).toHaveValue(bucketName);
  await panel.getByRole('button', { name: 'Create bucket' }).click();
  const row = panel.locator('.bucket-table .table-row', { hasText: bucketName });
  await expect(row).toBeVisible({ timeout: 20000 });
  return row;
}

async function setBucketPublic(page: Page, bucketName: string, makePublic: boolean): Promise<void> {
  await openPrimaryTab(page, 'Buckets');
  const row = page.locator('.bucket-table .table-row', { hasText: bucketName });
  await expect(row).toBeVisible();
  const toggle = row.getByRole('switch');
  const checked = (await toggle.getAttribute('aria-checked')) === 'true';
  if (checked !== makePublic) {
    await toggle.click();
  }
}

async function selectBucket(page: Page, bucketName: string): Promise<void> {
  await openPrimaryTab(page, 'Objects');
  await page.getByRole('combobox', { name: 'Bucket', exact: true }).click();
  await page.getByRole('option', { name: bucketName, exact: true }).click();
  await expect(page.getByLabel('Object name (optional)')).toBeEnabled();
}

async function uploadTextObject(page: Page, key: string, content: string): Promise<Locator> {
  await typeSlow(page.getByLabel('Object name (optional)'), key);
  await page.locator('input[type="file"]').setInputFiles({
    buffer: Buffer.from(content),
    mimeType: 'text/plain',
    name: `${key}.txt`
  });
  const row = page.locator('.file-table .table-row', { hasText: key });
  await expect(row).toBeVisible();
  return row;
}

async function generateObjectUrl(page: Page, row: Locator): Promise<string> {
  await row.getByRole('button', { name: 'Details' }).click();
  const details = page.locator('.object-details');
  await details.getByRole('button', { name: 'Generate URL' }).click();
  const urlField = details.getByLabel('URL');
  await expect(urlField).toHaveValue(/http/);
  const url = (await urlField.inputValue()).trim();
  if (!url) {
    throw new Error('object URL not generated');
  }
  return url;
}

interface AnonymousReadResult {
  body: string;
  bodyReadFailed: boolean;
  contentLength: number | null;
  status: number | null;
}

async function fetchAnonymousContent(url: string, requestTimeoutMs: number): Promise<AnonymousReadResult> {
  try {
    const response = await fetch(url, { signal: AbortSignal.timeout(requestTimeoutMs) });
    const contentLengthHeader = response.headers.get('content-length');
    const contentLength = contentLengthHeader ? Number.parseInt(contentLengthHeader, 10) : null;
    let body = '';
    let bodyReadFailed = false;
    try {
      body = await response.text();
    } catch {
      body = '';
      bodyReadFailed = true;
    }
    return {
      body,
      bodyReadFailed,
      contentLength: Number.isNaN(contentLength) ? null : contentLength,
      status: response.status
    };
  } catch {
    return { body: '', bodyReadFailed: false, contentLength: null, status: null };
  }
}

async function sleep(delayMs: number): Promise<void> {
  await new Promise((resolve) => setTimeout(resolve, delayMs));
}

async function expectAnonymousContent(
  url: string,
  expectedText: string,
  options: AnonymousReadOptions = {}
): Promise<void> {
  const maxAttempts = options.maxAttempts ?? 45;
  const requestTimeoutMs = options.requestTimeoutMs ?? 2500;
  const retryDelayMs = options.retryDelayMs ?? 800;
  const expectedBytes = Buffer.byteLength(expectedText, 'utf8');
  let lastStatus = 'no-response';
  let lastPreview = '';
  for (let attempt = 0; attempt < maxAttempts; attempt += 1) {
    const result = await fetchAnonymousContent(url, requestTimeoutMs);
    const statusOk = result.status !== null && result.status >= 200 && result.status < 300;
    const bodyMatch = result.body.includes(expectedText);
    const lengthMatch = result.contentLength !== null && result.contentLength === expectedBytes;
    if (statusOk && (bodyMatch || (result.bodyReadFailed && lengthMatch))) {
      return;
    }
    lastStatus = result.status === null ? 'no-response' : String(result.status);
    lastPreview = result.body.slice(0, 200);
    await sleep(retryDelayMs);
  }
  throw new Error(`anonymous content check failed for ${url}; status=${lastStatus}; body_preview=${lastPreview}`);
}

async function waitForEndpointReachable(url: string): Promise<void> {
  for (let attempt = 0; attempt < 45; attempt += 1) {
    const result = await fetchAnonymousContent(url, 2500);
    if (result.status !== null) {
      return;
    }
    await sleep(1000);
  }
  throw new Error(`endpoint not reachable: ${url}`);
}

async function readReplicaNodeUrl(row: Locator): Promise<string> {
  const text = (await row.textContent()) ?? '';
  const candidates = text.match(/https?:\/\/[^\s"'<>]+/g) ?? [];
  for (const candidate of candidates) {
    try {
      return new URL(candidate).toString();
    } catch {
      continue;
    }
  }
  return 'http://replica:9010';
}

function toReplicaS3ProbeUrl(replicaNodeUrl: string): string {
  const replica = new URL(replicaNodeUrl);
  replica.protocol = 'http:';
  replica.port = '9000';
  replica.pathname = '/';
  replica.search = '';
  replica.hash = '';
  return replica.toString();
}

function toReplicaDeliveryUrl(masterUrl: string, replicaNodeUrl: string): string {
  const target = new URL(masterUrl);
  const replica = new URL(replicaNodeUrl);
  target.protocol = 'http:';
  target.hostname = replica.hostname;
  target.port = '9000';
  return target.toString();
}

async function runLinkScenario(page: Page, scenario: LinkScenario): Promise<void> {
  await createBucket(page, scenario.bucketName);
  await setBucketPublic(page, scenario.bucketName, scenario.makePublic);
  await selectBucket(page, scenario.bucketName);
  const row = await uploadTextObject(page, scenario.key, scenario.content);
  const url = await generateObjectUrl(page, row);
  if (scenario.expectPresigned) {
    expect(url).toContain('X-Amz-');
  } else {
    expect(url).not.toContain('X-Amz-');
  }
  await expectAnonymousContent(url, scenario.content);
}

async function generateJoinToken(page: Page): Promise<string> {
  await openPrimaryTab(page, 'Admin');
  await page.getByRole('button', { name: 'Generate join token' }).click();
  await expect(page.getByText('Replica join token')).toBeVisible();
  const token = (await page.locator('.token-box').textContent())?.trim() ?? '';
  if (token.length < 10) {
    throw new Error('join token missing');
  }
  return token;
}

async function firstReplicaModeRow(page: Page): Promise<Locator> {
  const section = page.getByTestId('node-mode-section');
  const noReplica = section.getByText('No replica nodes connected');
  if (await noReplica.isVisible().catch(() => false)) {
    throw new Error('replica node is not connected in dockerized test stack');
  }
  const row = section.locator('mat-list-item').first();
  await expect(row).toBeVisible({ timeout: 30000 });
  return row;
}

async function setReplicaMode(
  page: Page,
  row: Locator,
  mode: 'slave-backup' | 'slave-delivery' | 'slave-volume'
): Promise<void> {
  const modeSelect = row.getByRole('combobox', { name: 'Mode' });
  const currentValue = ((await modeSelect.textContent()) ?? '').trim();
  if (currentValue === mode) {
    return;
  }
  const responsePromise = page.waitForResponse((response) => {
    const isPatch = response.request().method() === 'PATCH';
    return isPatch && response.url().includes('/admin/v1/cluster/') && response.url().endsWith('/mode');
  });
  await modeSelect.focus();
  await modeSelect.press('Enter');
  await page.getByRole('option', { name: mode, exact: true }).click();
  const response = await responsePromise;
  expect(response.ok()).toBeTruthy();
  await expect(modeSelect).toContainText(mode);
}

async function assertDeliveryUrls(masterUrl: string, replicaNodeUrl: string, content: string): Promise<void> {
  await expectAnonymousContent(masterUrl, content, {
    maxAttempts: 20,
    requestTimeoutMs: 2500,
    retryDelayMs: 500
  });
  const replicaUrl = toReplicaDeliveryUrl(masterUrl, replicaNodeUrl);
  await expectAnonymousContent(replicaUrl, content, {
    maxAttempts: 60,
    requestTimeoutMs: 4000,
    retryDelayMs: 1000
  });
}

test('[UC-001][UC-007] user changes password and theme from settings', async ({ browser }) => {
  const adminContext = await newVideoContext(browser);
  const adminPage = await adminContext.newPage();
  await loginAdmin(adminPage);
  const creds = await createConsoleUser(adminPage, false);

  const userContext = await newVideoContext(browser);
  const userPage = await userContext.newPage();
  await loginConsole(userPage, creds.username, creds.password);
  await openSettings(userPage);
  await setTheme(userPage, 'Dark');
  const nextPassword = `${creds.password}-next`;
  await changePasswordInSettings(userPage, creds.password, nextPassword);
  await closeSettings(userPage);
  await userPage.getByRole('button', { name: 'Sign out' }).click();
  await loginConsole(userPage, creds.username, nextPassword);
  await expect(userPage.getByText(`Signed in as ${creds.username}`)).toBeVisible();
  await userContext.close();
  await adminContext.close();
});

test('[UC-002] admin and user can create access and secret keys', async ({ browser }) => {
  const adminContext = await newVideoContext(browser);
  const adminPage = await adminContext.newPage();
  await loginAdmin(adminPage);
  const creds = await createConsoleUser(adminPage, false);
  const adminPair = await createAccessKeyPair(adminPage, `admin-${uniqueSuffix()}`);
  expect(adminPair.accessKey.startsWith('NSS')).toBeTruthy();
  expect(adminPair.secretKey.length).toBeGreaterThan(20);

  const userContext = await newVideoContext(browser);
  const userPage = await userContext.newPage();
  await loginConsole(userPage, creds.username, creds.password);
  const userPair = await createAccessKeyPair(userPage, `user-${uniqueSuffix()}`);
  expect(userPair.accessKey.startsWith('NSS')).toBeTruthy();
  expect(userPair.secretKey.length).toBeGreaterThan(20);
  await userContext.close();
  await adminContext.close();
});

test('[UC-003][UC-004][UC-011] admin creates bucket, joins replica, and sets replica mode', async ({ page }) => {
  await loginAdmin(page);
  await createBucket(page, `admin-${uniqueSuffix()}`);
  const token = await generateJoinToken(page);
  expect(token.length).toBeGreaterThan(10);
  const row = await firstReplicaModeRow(page);
  await setReplicaMode(page, row, 'slave-backup');
  await setReplicaMode(page, row, 'slave-volume');
  await setReplicaMode(page, row, 'slave-delivery');
});

test('[UC-004][UC-005][UC-011] delivery node serves public object links', async ({ browser }) => {
  const adminContext = await newVideoContext(browser);
  const adminPage = await adminContext.newPage();
  await loginAdmin(adminPage);
  const row = await firstReplicaModeRow(adminPage);
  const replicaNodeUrl = await readReplicaNodeUrl(row);
  await setReplicaMode(adminPage, row, 'slave-delivery');
  await waitForEndpointReachable(toReplicaS3ProbeUrl(replicaNodeUrl));
  const creds = await createConsoleUser(adminPage, false);

  const userContext = await newVideoContext(browser);
  const userPage = await userContext.newPage();
  await loginConsole(userPage, creds.username, creds.password);
  const bucketName = `delivery-${uniqueSuffix()}`;
  await createBucket(userPage, bucketName);
  await setBucketPublic(userPage, bucketName, true);
  await selectBucket(userPage, bucketName);
  const content = `delivery-${uniqueSuffix()}`;
  const rowItem = await uploadTextObject(userPage, `delivery-${uniqueSuffix()}.txt`, content);
  const masterUrl = await generateObjectUrl(userPage, rowItem);
  await assertDeliveryUrls(masterUrl, replicaNodeUrl, content);
  await userContext.close();
  await adminContext.close();
});

test('[UC-005] user validates private and public object links in anonymous mode', async ({ browser }) => {
  const adminContext = await newVideoContext(browser);
  const adminPage = await adminContext.newPage();
  await loginAdmin(adminPage);
  const creds = await createConsoleUser(adminPage, false);

  const userContext = await newVideoContext(browser);
  const userPage = await userContext.newPage();
  await loginConsole(userPage, creds.username, creds.password);
  await runLinkScenario(userPage, {
    bucketName: `private-${uniqueSuffix()}`,
    content: `private-${uniqueSuffix()}`,
    expectPresigned: true,
    key: `private-${uniqueSuffix()}.txt`,
    makePublic: false
  });
  await runLinkScenario(userPage, {
    bucketName: `public-${uniqueSuffix()}`,
    content: `public-${uniqueSuffix()}`,
    expectPresigned: false,
    key: `public-${uniqueSuffix()}.txt`,
    makePublic: true
  });
  await userContext.close();
  await adminContext.close();
});
