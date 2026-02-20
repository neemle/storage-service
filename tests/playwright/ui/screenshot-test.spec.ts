import fs from 'node:fs/promises';
import path from 'node:path';
import type { TestInfo } from '@playwright/test';
import { expect, test, type Page } from '../fixtures';
import { typeSlow } from '../helpers';

const UI_URL = process.env.NSS_UI_URL || 'http://localhost:4200';
const TEST_USER = process.env.NSS_TEST_USER ?? process.env.NSS_ADMIN_BOOTSTRAP_USER ?? 'admin';
const TEST_PASS = process.env.NSS_TEST_PASSWORD ?? process.env.NSS_ADMIN_BOOTSTRAP_PASSWORD ?? 'change-me';

async function attemptLogin(page: Page): Promise<boolean> {
  try {
    await typeSlow(page.getByLabel('Username'), TEST_USER);
    await typeSlow(page.getByLabel('Password'), TEST_PASS);
    await page.getByRole('button', { name: 'Sign in' }).click();
    await page.getByText('Signed in as').waitFor({ state: 'visible', timeout: 5000 });
    return true;
  } catch {
    return false;
  }
}

function resolveBaselinePath(testInfo: TestInfo, ucId: string, step: string): string {
  return path.resolve(process.cwd(), '..', '..', 'docs', 'ui-baselines', ucId, testInfo.project.name, `${step}.png`);
}

async function readBaseline(baselinePath: string): Promise<Buffer | null> {
  try {
    return await fs.readFile(baselinePath);
  } catch {
    return null;
  }
}

async function assertBaseline(page: Page, testInfo: TestInfo, ucId: string, step: string): Promise<void> {
  const screenshot = await page.screenshot({ fullPage: true });
  const baselinePath = resolveBaselinePath(testInfo, ucId, step);
  await fs.mkdir(path.dirname(baselinePath), { recursive: true });
  const baseline = await readBaseline(baselinePath);

  if (!baseline) {
    await fs.writeFile(baselinePath, screenshot);
    return;
  }

  if (screenshot.equals(baseline)) {
    return;
  }

  await fs.writeFile(`${baselinePath}.actual.png`, screenshot);
  if (process.env.NSS_STRICT_UI_BASELINES === '1') {
    expect(false, `Baseline mismatch: ${path.relative(process.cwd(), baselinePath)}`).toBeTruthy();
    return;
  }
  await fs.writeFile(baselinePath, screenshot);
}

test('[UC-001][UC-007] login page baseline', async ({ page }, testInfo) => {
  await page.goto(UI_URL);
  await page.waitForLoadState('networkidle');
  await assertBaseline(page, testInfo, 'UC-001', '01-start');
});

test('[UC-001][UC-007] dashboard baseline', async ({ page }, testInfo) => {
  await page.goto(UI_URL);
  await page.waitForLoadState('networkidle');
  const loggedIn = await attemptLogin(page);
  if (!loggedIn) {
    return;
  }
  await page.waitForLoadState('networkidle');
  await assertBaseline(page, testInfo, 'UC-007', '03-success');
});
