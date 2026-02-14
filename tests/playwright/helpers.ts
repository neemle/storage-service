import { expect, Locator, Page } from '@playwright/test';

export const uiUrl =
  process.env.NSS_UI_URL ??
  process.env.NSS_CONSOLE_URL ??
  process.env.NSS_ADMIN_URL ??
  'http://master:9001';
export const adminUser = process.env.NSS_ADMIN_BOOTSTRAP_USER ?? 'admin';
export const adminPass = process.env.NSS_ADMIN_BOOTSTRAP_PASSWORD ?? 'change-me';
export const typingDelayMs = 200;

export async function typeSlow(locator: Locator, value: string): Promise<void> {
  await locator.fill('');
  if (value.length > 0) {
    await locator.pressSequentially(value, { delay: typingDelayMs });
  }
}

export function uniqueSuffix(): string {
  const time = Date.now().toString(36);
  const rand = Math.floor(Math.random() * 10_000).toString(36);
  return `${time}-${rand}`;
}

async function waitForSignedIn(page: Page): Promise<boolean> {
  const signedIn = page.getByText('Signed in as');
  try {
    await signedIn.waitFor({ state: 'visible', timeout: 8000 });
    return true;
  } catch {
    return false;
  }
}

async function waitForLoginReady(page: Page): Promise<'signed-in' | 'login-form'> {
  const signedIn = page.getByText('Signed in as');
  const signInButton = page.getByRole('button', { name: 'Sign in' });
  for (let attempt = 0; attempt < 40; attempt += 1) {
    if (await signedIn.isVisible().catch(() => false)) {
      return 'signed-in';
    }
    if (await signInButton.isVisible().catch(() => false)) {
      return 'login-form';
    }
    await page.waitForTimeout(250);
  }
  return 'login-form';
}

async function recoverFromRateLimit(
  page: Page,
  username: string,
  password: string,
  signInButton: Locator
): Promise<boolean> {
  const error = page.locator('.error');
  if (!(await error.isVisible())) {
    return false;
  }
  const text = (await error.textContent())?.toLowerCase() ?? '';
  if (!text.includes('too many attempts')) {
    return false;
  }

  await page.waitForTimeout(1500);
  await typeSlow(page.getByLabel('Username'), username);
  await typeSlow(page.getByLabel('Password'), password);
  await signInButton.click();
  return waitForSignedIn(page);
}

async function handleForcedPasswordChange(page: Page, currentPassword: string): Promise<boolean> {
  const prompt = page.getByText('You must change your password to continue');
  const needsChange = await prompt.isVisible({ timeout: 1500 }).catch(() => false);
  if (!needsChange) {
    return false;
  }

  const updatedPassword = `${currentPassword}-updated`;
  await typeSlow(page.getByLabel('Current password'), currentPassword);
  await typeSlow(page.getByLabel('New password'), updatedPassword);
  await typeSlow(page.getByLabel('Confirm new password'), updatedPassword);
  await page.getByRole('button', { name: 'Change Password' }).click();
  return waitForSignedIn(page);
}

async function login(page: Page, baseUrl: string, username: string, password: string): Promise<void> {
  await page.goto(baseUrl, { waitUntil: 'domcontentloaded' });
  const signInButton = page.getByRole('button', { name: 'Sign in' });
  const state = await waitForLoginReady(page);
  if (state === 'signed-in') {
    return;
  }

  await page.getByLabel('Username').waitFor({ state: 'visible', timeout: 8000 });
  if (await signInButton.isVisible()) {
    await typeSlow(page.getByLabel('Username'), username);
    await typeSlow(page.getByLabel('Password'), password);
    await signInButton.click();
  }

  if (await waitForSignedIn(page)) {
    return;
  }

  if (await recoverFromRateLimit(page, username, password, signInButton)) {
    return;
  }

  if (await handleForcedPasswordChange(page, password)) {
    return;
  }

  throw new Error('login failed');
}

export async function loginAdmin(page: Page): Promise<void> {
  await login(page, uiUrl, adminUser, adminPass);
  const adminTab = page.getByRole('tab', { name: 'Admin' });
  await adminTab.click();
  await expect(page.getByRole('heading', { name: 'Cluster' })).toBeVisible();
}

export async function loginConsole(page: Page, username: string, password: string): Promise<void> {
  await login(page, uiUrl, username, password);
  await expect(page.getByText('Neemle Storage Service Console')).toBeVisible();
}

export async function createUser(page: Page, username: string, password: string): Promise<void> {
  await typeSlow(page.getByLabel('Username'), username);
  await typeSlow(page.getByLabel('Display name'), `User ${username}`);
  await typeSlow(page.getByLabel('Temporary password'), password);
  await page.getByRole('button', { name: 'Create user' }).click();
  await expect(page.getByText(username)).toBeVisible();
}

export async function readSecretField(page: Page, index: number): Promise<string> {
  const locator = page.locator('.secret-grid strong').nth(index);
  const text = await locator.textContent();
  if (!text) {
    throw new Error('secret field missing');
  }
  return text.trim();
}
