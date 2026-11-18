import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  matchesCase,
  replaceSearchFilter,
  selectedSearchFilter,
  searchRelevance,
  searchFilterLabel,
} from '../src/search.js';
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

test('filter pills name the chosen OS family, version or status', () => {
  assert.equal(searchFilterLabel('kernel os:rhel', 'os'), 'RHEL');
  assert.equal(searchFilterLabel('version:ubuntu2404 status:fixed', 'os'), 'Ubuntu 24.04');
  assert.equal(searchFilterLabel('version:ubuntu2404 status:fixed', 'status'), 'Fix available');
  assert.equal(searchFilterLabel('-status:affected kernel', 'status'), '');
  assert.equal(searchFilterLabel('os:typo', 'os'), '');
});

test('the OS picker replaces both OS qualifiers while keeping terms, exclusions and status', () => {
  const query = '"db cluster" OS:"Red Hat" version:rhel9 -os:debian status:unknown';
  const next = replaceSearchFilter(query, 'os', 'version:ubuntu2404');
  assert.equal(next, '"db cluster" -os:debian status:unknown version:ubuntu2404');
  assert.equal(replaceSearchFilter(next, 'os'), '"db cluster" -os:debian status:unknown');
  assert.equal(
    replaceSearchFilter(next, 'status', 'status:fixed'),
    '"db cluster" -os:debian version:ubuntu2404 status:fixed',
  );
  assert.equal(selectedSearchFilter(query, 'os', 'rhel'), true);
  assert.equal(selectedSearchFilter(query, 'os', 'debian'), false);
});

test('status bar shows one pill per status with a logo per OS version, in segment order', () => {
  const two = { ...c, products: ['rhel9', 'rhel10', 'ubuntu2404', 'debian13'], apiChecked: 1234 };
  const bar = statusBar(two, { showChecked: true });
  assert.equal((bar.match(/class="status-group /g) || []).length, 2);
  // One logo per version, each with its own version tooltip; no counts.
  assert.equal((bar.match(/class="stack-logo"/g) || []).length, 4);
  assert.match(bar, /data-tip="RHEL 9"><img[^>]*logo-rhel[^>]*><\/span><span class="stack-logo" data-tip="RHEL 10">/);
  assert.match(bar, /class="status-group fix_available" role="img" aria-label="Fix available: Ubuntu 24.04"/);
  assert.match(bar, /aria-label="No data: RHEL 9, RHEL 10, Debian 13" data-tip="No data"/);
  assert.ok(bar.indexOf('Fix available') < bar.indexOf('No data'));
  assert.match(
    bar,
    /class="status-bar"[^>]*><span class="fix_available" data-flex="1"><\/span><span class="unknown" data-flex="3">/,
  );
  assert.match(bar, /data-checked-at="1234"/);
  assert.doesNotMatch(statusBar(c), /data-checked-at/);
  assert.match(bar, /4 OS versions/);
  assert.match(statusBar({ ...c, products: ['rhel9'] }), />1 OS version<\/span>/);
  assert.equal(statusBar({ ...c, products: [] }), '');
  assert.doesNotMatch(bar, /tabindex=|<button|<details/);
});
