/* global indexedDB, document */
// Deterministic browser captures: no backend or external network is used.
import { chromium } from '@playwright/test';
import { createServer } from 'node:http';
import { readFile, mkdir } from 'node:fs/promises';
import { defaultState, DISCLAIMER_VERSION } from '../src/state.js';
import { PRODUCTS } from '../src/data.js';

const now = Date.parse('2026-11-18T15:00:00Z');
const makeCase = (index, complex) => {
  const id = `CVE-2026-${String(1000 + index).padStart(4, '0')}`;
  const products = complex ? PRODUCTS.map((p) => p.id) : ['rhel9', 'debian12'];
  return {
    id,
    products,
    customProducts: true,
    notes: '',
    checked: now,
    created: now - index * 3600000,
    updatedAt: now,
    hasUpdate: index % 3 === 0,
    record: {
      cveMetadata: { cveId: id, state: 'PUBLISHED' },
      containers: {
        cna: {
          title: complex
            ? 'Kernel memory safety vulnerability across supported distributions'
            : 'Example package security update',
          descriptions: [
            {
              lang: 'en',
              value:
                'Mocked review data. A local attacker may escalate privileges. Vendor fixes and mitigations are shown below.',
            },
          ],
          metrics: [
            {
              cvssV3_1: {
                baseScore: 7.8,
                baseSeverity: 'HIGH',
                vectorString: 'CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H',
              },
            },
          ],
        },
      },
    },
    vendorData: {
      id,
      evidence: Object.fromEntries(
        products.map((p, i) => [
          p,
          [
            {
              name: complex ? 'kernel' : 'example-package',
              status: ['fixed', 'affected', 'unaffected', 'unknown'][i % 4],
              fix: i % 4 === 0 ? ['6.1.112-1'] : [],
              affected: [],
              unaffected: [],
              mitigation: [],
              links: [],
              source: 'Mock vendor advisory',
            },
          ],
        ]),
      ),
      sources: {},
    },
  };
};
const types = { '.js': 'text/javascript', '.css': 'text/css', '.svg': 'image/svg+xml', '.html': 'text/html' };
const server = createServer(async (req, res) => {
  try {
    const path = req.url.split('?')[0];
    const file = path === '/' || /^\/CVE-/.test(path) ? 'index.html' : path.slice(1);
    if (file.includes('..')) throw Error('Invalid path');
    const body = await readFile(file);
    res.setHeader('Content-Type', types[file.slice(file.lastIndexOf('.'))] || 'application/octet-stream');
    res.end(body);
  } catch {
    res.writeHead(404).end();
  }
});
await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
const origin = `http://127.0.0.1:${server.address().port}`;
const browser = await chromium.launch();
await mkdir('screenshots', { recursive: true });
try {
  for (const device of ['desktop', 'mobile'])
    for (const theme of ['light', 'dark'])
      for (const scene of ['home', 'small', 'complex']) {
        const context = await browser.newContext({
          viewport: device === 'desktop' ? { width: 1440, height: 1000 } : { width: 390, height: 844 },
          colorScheme: theme,
          reducedMotion: 'reduce',
        });
        const page = await context.newPage();
        const errors = [];
        page.on('pageerror', (error) => errors.push(error.message));
        await page.clock.install({ time: now });
        await page.route('**/*', async (route) => {
          const url = new URL(route.request().url());
          if (url.origin !== origin) return route.abort();
          if (!url.pathname.startsWith('/api/')) return route.continue();
          const data =
            url.pathname === '/api/config'
              ? { version: 'mock-review', tmds: true }
              : url.pathname === '/api/tmds'
                ? { products: {}, checked: now }
                : { ok: true };
          return route.fulfill({ json: data });
        });
        // Seed the real persistence boundary before application modules run.
        await page.goto(origin + '/seed');
        await page.evaluate(
          async ({ state, theme }) => {
            await new Promise((resolve, reject) => {
              const request = indexedDB.open('isitfixed', 1);
              request.onupgradeneeded = () => request.result.createObjectStore('settings');
              request.onerror = () => reject(request.error);
              request.onsuccess = () => {
                const db = request.result;
                const tx = db.transaction('settings', 'readwrite');
                tx.objectStore('settings').put(state, 'workspace');
                tx.objectStore('settings').put(theme, 'theme');
                tx.oncomplete = () => {
                  db.close();
                  resolve();
                };
              };
            });
          },
          {
            state: {
              ...defaultState(),
              auto: false,
              theme,
              disclaimerAccepted: DISCLAIMER_VERSION,
              cases: Array.from({ length: scene === 'complex' ? 18 : 2 }, (_, i) => makeCase(i, scene === 'complex')),
            },
            theme,
          },
        );
        await page.goto(origin + (scene === 'home' ? '/' : '/CVE-2026-1000'));
        await page.waitForFunction(() => document.querySelector('main')?.textContent.length > 100);
        await page.evaluate(() => document.fonts.ready);
        if (device === 'mobile') await page.locator('#cases-toggle').click();
        if (errors.length) throw Error(errors.join('\n'));
        await page.screenshot({
          path: `screenshots/${device}-${theme}-${scene}.png`,
          fullPage: true,
          animations: 'disabled',
        });
        await context.close();
      }
} finally {
  await browser.close();
  server.close();
}
