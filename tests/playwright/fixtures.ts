import { expect, test as base } from '@playwright/test';

const pointerOverlayScript = [
  "(function () {",
  "  if (window.__nssPointerOverlayInstalled) return;",
  "  window.__nssPointerOverlayInstalled = true;",
  "  var boot = function () {",
  "    if (document.getElementById('nss-pointer-overlay')) return;",
  "    const style = document.createElement('style');",
  "    style.textContent = [",
  "      '#nss-pointer-overlay{position:fixed;z-index:2147483647;pointer-events:none;left:0;top:0;',",
  "      'width:14px;height:14px;border-radius:50%;background:rgba(255,82,82,.95);',",
  "      'border:2px solid #fff;box-shadow:0 0 0 2px rgba(0,0,0,.22);transform:translate(-999px,-999px);}',",
  "      '#nss-pointer-click{position:fixed;z-index:2147483646;pointer-events:none;left:0;top:0;width:30px;',",
  "      'height:30px;border-radius:50%;border:2px solid rgba(255,82,82,.9);opacity:0;',",
  "      'transform:translate(-999px,-999px) scale(.55);transition:transform .22s ease,opacity .22s ease;}',",
  "      '#nss-pointer-click.active{opacity:1;transform:translate(var(--x),var(--y)) scale(1);}'",
  "    ].join('');",
  "    document.head.append(style);",
  "    const cursor = document.createElement('div');",
  "    cursor.id = 'nss-pointer-overlay';",
  "    const clickPulse = document.createElement('div');",
  "    clickPulse.id = 'nss-pointer-click';",
  "    document.documentElement.append(cursor, clickPulse);",
  "    var move = function (event) {",
  "      cursor.style.transform = `translate(${event.clientX - 7}px,${event.clientY - 7}px)`;",
  "      clickPulse.style.setProperty('--x', `${event.clientX - 15}px`);",
  "      clickPulse.style.setProperty('--y', `${event.clientY - 15}px`);",
  "    };",
  "    var pulse = function (event) {",
  "      move(event);",
  "      clickPulse.classList.remove('active');",
  "      void clickPulse.offsetWidth;",
  "      clickPulse.classList.add('active');",
  "      setTimeout(function () { clickPulse.classList.remove('active'); }, 240);",
  "    };",
  "    document.addEventListener('mousemove', move, true);",
  "    document.addEventListener('mousedown', pulse, true);",
  "  };",
  "  if (document.readyState === 'loading') {",
  "    window.addEventListener('DOMContentLoaded', boot, { once: true });",
  "  } else {",
  "    boot();",
  "  }",
  "})();"
].join('');

const test = base.extend({
  page: async ({ page }, use) => {
    await page.addInitScript({ content: pointerOverlayScript });
    await use(page);
  }
});

export { expect, test };
export type { Browser, Locator, Page, Response } from '@playwright/test';
