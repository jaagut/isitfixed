// Settings dialog: appearance, default OS versions and order, severity,
// updates and notifications, TMDS, backup. The app passes accessors because
// restoring a backup replaces the state object.
import { CVSS_VERSIONS } from './data.js';
import { validTheme } from './cases.js';
import { validateState } from './state.js';
import { choices, orderedVendors } from './render/case.js';

const $ = (s) => document.querySelector(s);

/**
 * @param app {getState, getConfig, save, render, applyTheme, toast, setTmds(on), restore(next)}
 * @returns {{open(): void, sync(): void}}
 */
export function setupSettings(app) {
  const dialog = $('#settings-dialog'),
    defaults = $('#default-products');

  function renderDefaults(focus) {
    defaults.innerHTML = choices(app.getState(), app.getState().products, true);
    if (focus) defaults.querySelector(focus)?.focus();
  }
  function moveVendors(ids, id) {
    app.getState().osOrder = ids;
    app.save();
    renderDefaults(`[data-handle="${id}"]`);
    app.render();
  }
  defaults.onpointerdown = (e) => {
    const handle = e.target.closest('[data-handle]');
    if (!handle || e.button !== 0) return;
    // Window listeners: moving the row in the DOM releases pointer capture.
    e.preventDefault();
    handle.focus();
    const row = handle.closest('.vendor-choice'),
      stop = new AbortController();
    row.classList.add('dragging');
    defaults.classList.add('sorting');
    window.addEventListener(
      'pointermove',
      (ev) => {
        const next = [...defaults.querySelectorAll('.vendor-choice:not(.dragging)')].find((r) => {
          const b = r.getBoundingClientRect();
          return ev.clientY < b.top + b.height / 2;
        });
        if (next !== row.nextElementSibling) defaults.insertBefore(row, next || null);
      },
      { signal: stop.signal },
    );
    const end = () => {
      stop.abort();
      row.classList.remove('dragging');
      defaults.classList.remove('sorting');
      const order = [...defaults.querySelectorAll('.vendor-choice')].map((r) => r.dataset.vendor);
      moveVendors(order, handle.dataset.handle);
    };
    window.addEventListener('pointerup', end, { signal: stop.signal });
    window.addEventListener('pointercancel', end, { signal: stop.signal });
  };
  defaults.onkeydown = (e) => {
    const handle = e.target.closest('[data-handle]');
    if (!handle || !['ArrowUp', 'ArrowDown'].includes(e.key)) return;
    e.preventDefault();
    const ids = orderedVendors(app.getState()).map((v) => v.id),
      i = ids.indexOf(handle.dataset.handle),
      j = i + (e.key === 'ArrowUp' ? -1 : 1);
    if (j < 0 || j >= ids.length) return;
    [ids[i], ids[j]] = [ids[j], ids[i]];
    moveVendors(ids, handle.dataset.handle);
  };
  defaults.onchange = (e) => {
    app.getState().products = [...defaults.querySelectorAll('input[value]:checked')].map((i) => i.value);
    app.save();
    renderDefaults(`input[value="${e.target.value}"]`);
  };

  $('#theme').onchange = (e) => {
    app.getState().theme = validTheme(e.target.value);
    app.applyTheme();
    app.save();
  };
  $('#cvss-version').innerHTML = CVSS_VERSIONS.map(
    (v) => `<option value="${v}">CVSS ${v}${v === '3.1' ? ' (default)' : ''}</option>`,
  ).join('');
  $('#cvss-version').onchange = (e) => {
    app.getState().cvss = e.target.value;
    app.save();
    app.render();
  };
  $('#auto-refresh').onchange = (e) => {
    app.getState().auto = e.target.checked;
    app.save();
  };
  $('#tmds-toggle').onchange = (e) => app.setTmds(e.target.checked);

  function notificationStatus() {
    const status = $('#notification-status');
    if (!('Notification' in window)) status.textContent = 'Not supported by this browser.';
    else if (Notification.permission === 'granted') status.textContent = 'Enabled for this site.';
    else if (Notification.permission === 'denied') status.textContent = 'Blocked in the browser settings.';
    else status.textContent = '';
    $('#notifications').hidden = !('Notification' in window) || Notification.permission === 'granted';
  }
  $('#notifications').onclick = async () => {
    const p = await Notification.requestPermission();
    notificationStatus();
    app.toast(
      p === 'granted'
        ? 'Desktop notifications enabled.'
        : 'Desktop notifications are disabled. Updated cases are still marked in the sidebar.',
    );
  };

  $('#export').onclick = () => {
    const url = URL.createObjectURL(new Blob([JSON.stringify(app.getState(), null, 2)], { type: 'application/json' }));
    const a = document.createElement('a');
    a.href = url;
    a.download = `cve-desk-${new Date().toISOString().slice(0, 10)}.json`;
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  };
  $('#restore').onchange = async (e) => {
    try {
      const f = e.target.files[0];
      if (!f) return;
      if (f.size > 30000000) throw Error('Backup exceeds 30 MB.');
      const next = validateState(JSON.parse(await f.text()));
      if (!confirm(`Replace this workspace with ${next.cases.length} backed-up cases?`)) return;
      app.restore(next);
      dialog.close();
    } catch (err) {
      app.toast(err.message);
    } finally {
      e.target.value = '';
    }
  };

  // Reflects state and server settings in the controls.
  function sync() {
    const state = app.getState(),
      config = app.getConfig();
    $('#cvss-version').value = state.cvss || '3.1';
    $('#auto-refresh').checked = state.auto;
    $('#theme').value = state.theme;
    $('#tmds-toggle').checked = config.tmds && state.tmds !== false;
    $('#tmds-toggle').disabled = !config.tmds;
    $('#tmds-server-off').hidden = config.tmds;
    notificationStatus();
  }
  return {
    open() {
      renderDefaults();
      sync();
      dialog.showModal();
    },
    sync,
  };
}
