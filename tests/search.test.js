import { test } from 'node:test';
import assert from 'node:assert/strict';
import { matchesCase, searchRelevance, searchSuggestions } from '../src/search.js';
import { statusBar } from '../src/render/common.js';

const c = {
  id: 'CVE-2026-0001',
  archived: true,
  products: ['rhel9', 'ubuntu2404', 'debian13'],
  savedTitle: 'Kernel update',
  notes: 'Watch the db cluster',
  vendorData: { evidence: { ubuntu2404: [{ name: 'libsample', status: 'fixed', fix: ['sample-1'] }] } },
};

test('family, version and status qualifiers refer to the same selected row', () => {
  assert.equal(matchesCase(c, 'os:rhel version:rhel9 status:fixed'), false);
  assert.equal(matchesCase(c, 'os:rhel version:9 status:unknown'), true);
  assert.equal(matchesCase(c, 'os:canonical version:noble status:fix-available'), true);
  assert.equal(matchesCase(c, 'status:fixed -os:rhel'), false);
  assert.equal(matchesCase(c, 'os:"Red Hat"'), true);
  assert.equal(matchesCase(c, 'os:typo'), false);
});

test('plain search finds case details, package evidence, selected versions and archived notes', () => {
  for (const query of ['rhel', 'Trixie kernel', '"db cluster" libsample', 'sample-1', 'CVE-2026', '-absent'])
    assert.equal(matchesCase(c, query), true, query);
  assert.equal(matchesCase(c, 'missing'), false);
  assert.ok(searchRelevance(c, 'kernel') > searchRelevance(c, 'cluster'));
});

test('suggestions span all categories and replace only the active token', () => {
  assert.equal(new Set(searchSuggestions('').map((s) => s.group)).size, 3);
  assert.ok(searchSuggestions('kernel os:').every((s) => s.value.startsWith('kernel os:')));
  assert.equal(searchSuggestions('kernel -version:noble')[0].value, 'kernel -version:ubuntu2404 ');
  assert.equal(searchSuggestions('STATUS:fix')[0].value, 'status:fixed ');
});

test('status bar lists selected products and their individual verdict without nested controls', () => {
  const bar = statusBar(c);
  assert.equal((bar.match(/class="status-breakdown-row"/g) || []).length, 3);
  assert.match(bar, /Ubuntu 24.04<\/span><span class="status fix_available">Fix available/);
  assert.match(bar, /3 selected OS versions/);
  assert.doesNotMatch(bar, /title=|tabindex=|<button|<details/);
});
