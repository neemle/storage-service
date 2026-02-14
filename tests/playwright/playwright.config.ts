import { defineConfig } from '@playwright/test';

export default defineConfig({
  testDir: '.',
  timeout: 600_000,
  outputDir: 'test-results',
  expect: {
    timeout: 20_000
  },
  reporter: [
    ['list'],
    ['html', { outputFolder: 'playwright-report', open: 'never' }],
    ['json', { outputFile: 'test-results/playwright-report.json' }]
  ],
  use: {
    headless: true,
    actionTimeout: 120_000,
    navigationTimeout: 60_000,
    launchOptions: {
      slowMo: 1000
    },
    trace: 'on-first-retry',
    screenshot: 'on',
    video: 'on'
  },
  projects: [
    {
      name: 'base',
      testDir: './base'
    },
    {
      name: 'ui',
      testDir: './ui'
    }
  ]
});
