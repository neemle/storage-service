import { defineConfig } from '@playwright/test';

const desktopViewport = { width: 1920, height: 1080 };
const tabletPortraitViewport = { width: 1024, height: 1366 };
const tabletLandscapeViewport = { width: 1366, height: 1024 };
const iphoneViewport = { width: 430, height: 932 };
const pixelViewport = { width: 412, height: 915 };
const samsungViewport = { width: 412, height: 915 };

function projectVideo(width: number, height: number): { mode: 'on'; size: { width: number; height: number } } {
  return { mode: 'on', size: { width, height } };
}

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
      slowMo: 350
    },
    trace: 'on-first-retry',
    screenshot: 'on',
    video: projectVideo(1920, 1080)
  },
  projects: [
    {
      name: 'base-desktop-chromium',
      testDir: './base',
      use: {
        viewport: desktopViewport,
        video: projectVideo(desktopViewport.width, desktopViewport.height)
      }
    },
    {
      name: 'base-tablet-portrait',
      testDir: './base',
      use: {
        viewport: tabletPortraitViewport,
        video: projectVideo(tabletPortraitViewport.width, tabletPortraitViewport.height)
      }
    },
    {
      name: 'base-tablet-landscape',
      testDir: './base',
      use: {
        viewport: tabletLandscapeViewport,
        video: projectVideo(tabletLandscapeViewport.width, tabletLandscapeViewport.height)
      }
    },
    {
      name: 'base-mobile-iphone',
      testDir: './base',
      use: {
        viewport: iphoneViewport,
        isMobile: true,
        hasTouch: true,
        video: projectVideo(iphoneViewport.width, iphoneViewport.height)
      }
    },
    {
      name: 'base-mobile-pixel',
      testDir: './base',
      use: {
        viewport: pixelViewport,
        isMobile: true,
        hasTouch: true,
        video: projectVideo(pixelViewport.width, pixelViewport.height)
      }
    },
    {
      name: 'base-mobile-samsung',
      testDir: './base',
      use: {
        viewport: samsungViewport,
        isMobile: true,
        hasTouch: true,
        video: projectVideo(samsungViewport.width, samsungViewport.height)
      }
    },
    {
      name: 'ui-desktop-chromium',
      testDir: './ui',
      use: {
        viewport: desktopViewport,
        video: projectVideo(desktopViewport.width, desktopViewport.height)
      }
    },
    {
      name: 'ui-tablet-portrait',
      testDir: './ui',
      use: {
        viewport: tabletPortraitViewport,
        video: projectVideo(tabletPortraitViewport.width, tabletPortraitViewport.height)
      }
    },
    {
      name: 'ui-tablet-landscape',
      testDir: './ui',
      use: {
        viewport: tabletLandscapeViewport,
        video: projectVideo(tabletLandscapeViewport.width, tabletLandscapeViewport.height)
      }
    },
    {
      name: 'ui-mobile-iphone',
      testDir: './ui',
      use: {
        viewport: iphoneViewport,
        isMobile: true,
        hasTouch: true,
        video: projectVideo(iphoneViewport.width, iphoneViewport.height)
      }
    },
    {
      name: 'ui-mobile-pixel',
      testDir: './ui',
      use: {
        viewport: pixelViewport,
        isMobile: true,
        hasTouch: true,
        video: projectVideo(pixelViewport.width, pixelViewport.height)
      }
    },
    {
      name: 'ui-mobile-samsung',
      testDir: './ui',
      use: {
        viewport: samsungViewport,
        isMobile: true,
        hasTouch: true,
        video: projectVideo(samsungViewport.width, samsungViewport.height)
      }
    }
  ]
});
