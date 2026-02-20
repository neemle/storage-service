import { expect, Locator, Page } from '@playwright/test';

export const uiUrl =
  process.env.NSS_UI_URL ??
  process.env.NSS_CONSOLE_URL ??
  process.env.NSS_ADMIN_URL ??
  'http://master:9001';
export const adminUser = process.env.NSS_ADMIN_BOOTSTRAP_USER ?? 'admin';
export const adminPass = process.env.NSS_ADMIN_BOOTSTRAP_PASSWORD ?? 'change-me';
export const typingDelayMs = 350;
export const clickDelayMs = 350;
export const fieldTransitionDelayMs = 250;
export const navigationPauseMs = 1000;
export const submitPauseMs = 1200;

export async function waitForHuman(page: Page, delayMs: number = navigationPauseMs): Promise<void> {
  await page.waitForTimeout(delayMs);
}

export async function humanClick(locator: Locator): Promise<void> {
  await waitForHuman(locator.page(), clickDelayMs);
  await locator.click();
  await waitForHuman(locator.page(), clickDelayMs);
}

export async function waitAfterNavigation(page: Page): Promise<void> {
  await waitForHuman(page, navigationPauseMs);
}

export async function typeSlow(locator: Locator, value: string): Promise<void> {
  const page = locator.page();
  await locator.scrollIntoViewIfNeeded();
  try {
    await locator.focus();
  } catch {
    await locator.click({ force: true });
  }
  await locator.press('Control+A');
  await locator.press('Backspace');
  if (value.length > 0) {
    await locator.type(value, { delay: typingDelayMs });
  }
  if (value.length > 0) {
    await waitForHuman(page, fieldTransitionDelayMs);
  }
}

export function uniqueSuffix(): string {
  const time = Date.now().toString(36);
  const rand = Math.floor(Math.random() * 10_000).toString(36);
  return `${time}-${rand}`;
}

async function hasVisible(locator: Locator): Promise<boolean> {
  const count = await locator.count();
  for (let index = 0; index < count; index += 1) {
    if (await locator.nth(index).isVisible().catch(() => false)) {
      return true;
    }
  }
  return false;
}

async function isSignedInState(page: Page): Promise<boolean> {
  if (await page.getByText('Signed in as').isVisible().catch(() => false)) {
    return true;
  }
  return hasVisible(page.getByRole('button', { name: 'Sign out' }));
}

async function waitForSignedIn(page: Page): Promise<boolean> {
  for (let attempt = 0; attempt < 32; attempt += 1) {
    if (await isSignedInState(page)) {
      return true;
    }
    await page.waitForTimeout(250);
  }
  return false;
}

async function waitForLoginReady(page: Page): Promise<'signed-in' | 'login-form'> {
  const signInButtons = page.getByRole('button', { name: 'Sign in' });
  for (let attempt = 0; attempt < 40; attempt += 1) {
    if (await isSignedInState(page)) {
      return 'signed-in';
    }
    if (await hasVisible(signInButtons)) {
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
  await humanClick(signInButton);
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
  await humanClick(page.getByRole('button', { name: 'Change Password' }));
  await waitForHuman(page, submitPauseMs);
  return waitForSignedIn(page);
}

async function login(page: Page, baseUrl: string, username: string, password: string): Promise<void> {
  await page.goto(baseUrl, { waitUntil: 'domcontentloaded' });
  await waitAfterNavigation(page);
  const signInButton = page.getByRole('button', { name: 'Sign in' });
  const state = await waitForLoginReady(page);
  if (state === 'signed-in') {
    return;
  }

  await page.getByLabel('Username').waitFor({ state: 'visible', timeout: 8000 });
  if (await signInButton.isVisible()) {
    await typeSlow(page.getByLabel('Username'), username);
    await typeSlow(page.getByLabel('Password'), password);
    await humanClick(signInButton);
    await waitForHuman(page, submitPauseMs);
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
  await humanClick(adminTab);
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
  await humanClick(page.getByRole('button', { name: 'Create user' }));
  await waitForHuman(page, submitPauseMs);
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
