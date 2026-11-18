import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { runInNewContext } from 'node:vm';
import { THEMES, validTheme } from '../src/cases.js';

test('theme setting accepts system, light and dark and falls back to system', () => {
  assert.deepEqual(THEMES, ['system', 'light', 'dark']);
  for (const theme of THEMES) assert.equal(validTheme(theme), theme);
  for (const theme of [undefined, null, '', 'Dark', 'sepia', 1, {}]) assert.equal(validTheme(theme), 'system');
});

// src/theme.js runs before the app module to avoid a flash of the wrong theme.
const script = await readFile(new URL('../src/theme.js', import.meta.url), 'utf8');
function runThemeScript(saved, { throws = false, theme = null } = {}) {
  const documentElement = { dataset: {} },
    reads = [];
  const localStorage = {
    getItem(key) {
      reads.push(key);
      if (throws) throw new Error('SecurityError');
      if (key === 'cve-desk-theme') return theme;
      return key === 'cve-desk-v1' ? saved : null;
    },
  };
  runInNewContext(script, { document: { documentElement }, localStorage, JSON });
  return Object.assign([documentElement.dataset.theme], { reads });
}
const applied = (...args) => runThemeScript(...args)[0];

test('early theme script applies only a saved light or dark theme', () => {
  assert.equal(applied(null, { theme: 'dark' }), 'dark');
  assert.equal(applied(null, { theme: 'light' }), 'light');
  assert.equal(applied(JSON.stringify({ theme: 'dark' }), { theme: 'system' }), undefined, 'the theme key wins');
  assert.equal(applied(null, { theme: '"><script>' }), undefined);
  // The workspace is parsed only while the theme key does not exist yet (saves from older versions).
  assert.deepEqual(runThemeScript(JSON.stringify({ theme: 'dark' }), { theme: 'light' }).reads, ['cve-desk-theme']);
  assert.equal(applied(JSON.stringify({ theme: 'dark' })), 'dark');
  assert.equal(applied(JSON.stringify({ theme: 'light' })), 'light');
  assert.equal(applied(JSON.stringify({ theme: 'system' })), undefined);
  assert.equal(applied(JSON.stringify({ theme: '"><script>' })), undefined);
  assert.equal(applied(JSON.stringify({ version: 1 })), undefined);
  assert.equal(applied(null), undefined);
  assert.equal(applied('{not json'), undefined);
  assert.equal(applied('', { throws: true }), undefined);
});
