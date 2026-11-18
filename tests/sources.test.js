import { test } from 'node:test';
import assert from 'node:assert/strict';
import { PRODUCTS } from '../src/data.js';
import { sourceCards, sourceSummary } from '../src/sources.js';

const NOW = Date.parse('2026-11-18T15:00:00Z');
const products = ['rhel9', 'sles15', 'ubuntu2404', 'debian12', 'windows11'].map((id) =>
  PRODUCTS.find((p) => p.id === id),
);
const base = {
  id: 'CVE-2024-1086',
  checked: NOW - 60000,
  record: { cveMetadata: { cveId: 'CVE-2024-1086', dateUpdated: '2026-08-07T20:45:00Z' } },
  vendorData: {
    sources: {
      rhel: { url: 'https://security.access.redhat.com/x.json', checked: NOW - 60000, sourceUpdated: '2026-11-04' },
      sles: {
        url: 'https://ftp.suse.com/x.json',
        checked: NOW - 3 * 3600000,
        excludedImages: 394,
        advisories: [{ url: 'https://lists.suse.com/a.html', label: 'SUSE-SU-2024:0463-1' }],
      },
      ubuntu: {
        url: 'https://ubuntu.com/x.json',
        checked: NOW - 60000,
        error: 'Vendor source unavailable: temporarily paused after repeated failures; next attempt after 15:42 UTC',
        retryAfter: NOW + 900000,
      },
      debian: { checked: NOW - 60000, notPublished: 'The vendor has not published this CVE.' },
    },
  },
};

test('vendor cards carry state, times, links and warnings', () => {
  const cards = sourceCards(base, products, { now: NOW });
  assert.deepEqual(
    cards.map((c) => [c.id, c.state]),
    [
      ['cve', 'ok'],
      ['rhel', 'ok'],
      ['sles', 'stale'],
      ['ubuntu', 'paused'],
      ['debian', 'not-published'],
      ['windows', 'cve-record'],
    ],
  );
  const ubuntu = cards.find((c) => c.id === 'ubuntu');
  assert.equal(ubuntu.retryAfter, NOW + 900000);
  assert.equal(
    ubuntu.warnings[0],
    'Vendor source unavailable: temporarily paused after repeated failures. Showing saved evidence if available.',
  );
  const sles = cards.find((c) => c.id === 'sles');
  assert.equal(sles.excludedImages, 394);
  assert.equal(sles.advisories.length, 1);
  assert.deepEqual(sourceSummary(cards), { checked: NOW - 60000, count: 6, warnings: 2 });
});

test('TMDS cards appear only when enabled and reflect the inventory', () => {
  assert.equal(sourceCards(base, products, { now: NOW }).length, 6);
  const loading = sourceCards(base, products, { tmds: true, now: NOW });
  assert.deepEqual(
    loading.slice(-2).map((c) => [c.id, c.state]),
    [
      ['tmds-agent', 'loading'],
      ['tmds-ksp', 'loading'],
    ],
  );
  const data = {
    products: { rhel9: [{}, {}], sles15: [{}] },
    checked: NOW - 600000,
    source: 'https://s3.amazonaws.com/feed.json',
    ksp: {
      products: { rhel9: [{}] },
      checked: NOW - 600000,
      pageUpdated: 'November 18, 2026, 12:16 UTC',
      error: 'Kernel list unavailable',
    },
  };
  const [agent, ksp] = sourceCards(base, products, { tmds: true, inventory: { data, error: null }, now: NOW }).slice(
    -2,
  );
  assert.equal(agent.state, 'ok');
  assert.match(agent.notes[0], /^3 bundled agent builds/);
  assert.equal(ksp.state, 'error');
  assert.equal(ksp.updated, 'November 18, 2026, 12:16 UTC');
  assert.match(ksp.warnings[0], /Kernel list unavailable\. Showing the last list\./);
  const old = sourceCards(base, products, {
    tmds: true,
    inventory: { data: { ...data, ksp: undefined }, error: null },
    now: NOW,
  });
  assert.equal(old.at(-1).state, 'no-data');
});
