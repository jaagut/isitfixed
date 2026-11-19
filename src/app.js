// Is It Fixed app: state, routing, refreshes, notifications and event wiring.
// Rendering lives in src/render/*; matching and change detection are pure
// modules (tmds.js, changes.js, rows.js, sources.js).
import { hasCaseUpdate, recordUpdate, markCaseRead, sortedCases } from './cases.js';
import {
  streamCase,
  syncWatches,
  fetchAgents,
  fetchConfig,
  ping,
  connection,
  onConnectionChange,
  reportContact,
  DEFAULT_CONFIG,
} from './api.js';
import { validId, extractCveIds, PRODUCTS, VENDORS } from './data.js';
import { caseActionState, diffActions, withoutTmds, describeChanges } from './changes.js';
import { DISCLAIMER_VERSION, MAX_OPEN_CASES, MAX_CASES, saveable, followDefaults } from './state.js';
import { loadWorkspace, saveWorkspace, saveTheme, requestPersistence } from './storage.js';
import {
  matchesCase,
  replaceSearchFilter,
  selectedSearchFilter,
  searchFilterLabel,
  searchRelevance,
  toggleSearchFilter,
} from './search.js';
import { ago, esc, icons, time, HOUR } from './util.js';
import {
  selected,
  sum,
  statusDescription,
  statusBar,
  cvssChip,
  caseActions,
  logo,
  labels,
  STATUS_ORDER,
} from './render/common.js';
import { renderCase } from './render/case.js';
import { renderHome } from './render/home.js';
import { setupSettings, toggleAllVersions } from './settings.js';

const $ = (s) => document.querySelector(s);
const reducedMotion = () => matchMedia('(prefers-reduced-motion: reduce)').matches;
const applePlatform = /^(Mac|iPhone|iPad|iPod)/i.test(navigator.userAgentData?.platform || navigator.platform || '');
const searchChord = applePlatform ? '⌘K' : 'Ctrl+K';
const caseEntryForm = $('#case-entry-form');
const caseInput = $('#cve-input');

const loaded = await loadWorkspace();
let state = loaded.state,
  // Keep an unreadable IndexedDB workspace intact until exported.
  storageLocked = loaded.locked,
  config = { ...DEFAULT_CONFIG },
  active = null,
  chooserOpen = false,
  archivedOpen = false,
  homeFilter = null,
  storageFailed = false,
  persistenceRequested = false;
const busy = new Set(),
  groupOverride = new Map(),
  inventory = { data: null, error: null };

// Never writes a workspace that would fail validation on the next load.
async function save() {
  if (storageLocked) return;
  if (!saveable(state)) {
    toast('Changes were not saved: the workspace exceeds its limits. Delete or archive cases.');
    return;
  }
  const result = await saveWorkspace(state);
  if (!result.saved && !storageFailed) {
    toast('Browser storage is full or unavailable. Your changes are kept in this tab; export a backup.', {
      label: 'Export backup',
      run: () =>
        download(JSON.stringify(state, null, 2), `isitfixed-backup-${new Date().toISOString().slice(0, 10)}.json`),
    });
  }
  storageFailed = !result.saved;
  // Once there is work to lose, ask the browser not to evict it (once per page load).
  if (result.saved && state.cases.length && !persistenceRequested) {
    persistenceRequested = true;
    void requestPersistence();
  }
}
// `action` adds one button ({label, run}); such a toast stays longer and can be clicked.
function toast(message, action = null) {
  const el = $('#toast');
  el.textContent = message;
  el.classList.toggle('actionable', Boolean(action));
  if (action) {
    const button = document.createElement('button');
    button.type = 'button';
    button.textContent = action.label;
    button.onclick = () => {
      el.classList.remove('visible');
      action.run();
    };
    el.append(button);
  }
  el.classList.add('visible');
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => el.classList.remove('visible'), action ? 30000 : 6000);
}
function download(text, filename) {
  const url = URL.createObjectURL(new Blob([text], { type: 'application/json' }));
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
// 'system' removes the attribute so the stylesheet follows prefers-color-scheme. The early
// theme module reads the preference from IndexedDB.
function applyTheme() {
  if (state.theme === 'system') delete document.documentElement.dataset.theme;
  else document.documentElement.dataset.theme = state.theme;
  void saveTheme(state.theme);
}
applyTheme();

// TMDS: enabled by the server (config.tmds) and by the user (Settings). While
// off, /api/tmds is not requested and every TMDS element is hidden.
const tmdsOn = () => config.tmds && state.tmds !== false;
let inventoryTimer = null;
async function loadInventory() {
  // Without a completed server check (`checked`), TMDS is "not evaluated" (see changes.js).
  try {
    const data = await fetchAgents();
    if (data?.enabled === false) {
      config = { ...config, tmds: false };
      syncInventory();
      settings.sync();
      render();
      return;
    }
    inventory.data = data;
    inventory.error = null;
  } catch (e) {
    inventory.error = e.message;
  }
  if (!tmdsOn()) return;
  if (inventory.data) evaluateAll();
  render();
}
function syncInventory() {
  if (tmdsOn() && !inventoryTimer) {
    loadInventory();
    inventoryTimer = setInterval(loadInventory, HOUR);
  } else if (!tmdsOn() && inventoryTimer) {
    clearInterval(inventoryTimer);
    inventoryTimer = null;
  }
}
// The user's own toggle re-baselines silently in both directions.
function setTmds(on) {
  state.tmds = on;
  if (!on) for (const c of state.cases) c.actionBaseline = withoutTmds(c.actionBaseline);
  save();
  syncInventory();
  render();
}

// Server watches. A failed sync backs off exponentially (30 s up to an hour, or the server's
// Retry-After) instead of retrying on every case refresh; each distinct error is shown once.
let watchQueue = Promise.resolve(),
  lastWatchlist = '',
  watchFailure = null;
function syncWatchlist(force = false) {
  const cases = state.cases.filter((c) => !c.archived).map((c) => ({ id: c.id, products: [...c.products] })),
    key = JSON.stringify(cases);
  watchQueue = watchQueue.then(async () => {
    if (!force && key === lastWatchlist) return;
    if (watchFailure && watchFailure.key === key && Date.now() < watchFailure.until) return;
    try {
      await syncWatches(cases);
      lastWatchlist = key;
      watchFailure = null;
    } catch (e) {
      const delay = Math.min((watchFailure?.delay || 15000) * 2, HOUR),
        wait = Math.max(delay, (e.retryAfter || 0) * 1000);
      const shown = watchFailure?.message;
      watchFailure = { key, delay, until: Date.now() + wait, message: e.message };
      if (e.message !== shown) toast(`Could not sync server watches: ${e.message}`);
    }
  });
  return watchQueue;
}
// Watch limits (decision 6): open cases are watched by the server; archived ones are not.
const openCount = () => state.cases.filter((c) => !c.archived).length;
function capacityMessage(reopen = false) {
  if (!reopen && state.cases.length >= MAX_CASES)
    return `Is It Fixed keeps at most ${MAX_CASES.toLocaleString('en')} cases, including archived ones. Delete cases you no longer need to open new ones.`;
  if (openCount() >= MAX_OPEN_CASES)
    return `At most ${MAX_OPEN_CASES} cases can be open (checked for updates) at a time. Archive or delete a case first.`;
  return '';
}

// Actionable changes: compare the case with its stored baseline and report what changed.
function notifyDesktop(c, changes) {
  if (globalThis.Notification?.permission !== 'granted') return;
  try {
    const body = changes.length > 1 ? describeChanges(changes.slice(1)) : 'Open Is It Fixed to review.';
    new Notification(`${c.id}: ${changes[0].text}`, { body, tag: c.id });
  } catch {
    /* Notifications can be unavailable (for example in some mobile browsers). */
  }
}
function evaluateCase(c) {
  const { fingerprint, info } = caseActionState(c, selected(c), tmdsOn() ? inventory.data : null);
  const { baseline, changes } = diffActions(c.actionBaseline, fingerprint, info);
  c.actionBaseline = baseline;
  if (!changes.length || c.archived) return false;
  const at = Date.now(),
    ids = [...new Set(changes.map((x) => x.id).filter(Boolean))];
  if (ids.length) c.changedRows = { ids, at };
  recordUpdate(state, c.id, describeChanges(changes), at);
  notifyDesktop(c, changes);
  return true;
}
function evaluateAll() {
  for (const c of state.cases) if (!c.archived) safely(() => evaluateCase(c));
  save();
}
// One damaged case must not stop the others (or app start-up).
function safely(fn, fallback) {
  try {
    return fn();
  } catch (e) {
    console.error(e);
    return fallback;
  }
}

// Formatting
const context = () => ({
  state,
  config,
  inventory,
  tmdsOn: tmdsOn(),
  busy,
  chooserOpen,
  groupOverride,
  now: Date.now(),
});
// Set the segment width from its OS count without inline HTML styles.
function applyBars(root) {
  for (const el of root.querySelectorAll('[data-flex]')) el.style.flex = `${Number(el.dataset.flex) || 1} 1 0%`;
}

// Share sheet where available (mobile, some desktops); otherwise copy the link.
async function shareCase(c) {
  const url = `${location.origin}/${c.id}`,
    title = `${c.id} · ${sum(c.record, state.cvss).title}`;
  if (navigator.share && matchMedia('(pointer:coarse)').matches) {
    try {
      await navigator.share({ title, url });
      return;
    } catch (e) {
      if (e.name === 'AbortError') return;
    }
  }
  try {
    await navigator.clipboard.writeText(url);
    toast(`Link copied: ${url}`);
  } catch {
    prompt('Copy this link', url);
  }
}
function caseAction(e) {
  const meter = e.target.closest('.status-meter');
  if (meter && matchMedia('(hover: none)').matches) {
    meter.classList.toggle('expanded');
    e.preventDefault();
    return true;
  }
  const b = e.target.closest('[data-share],[data-archive],[data-delete]');
  if (!b) return false;
  const id = b.dataset.share || b.dataset.archive || b.dataset.delete,
    c = state.cases.find((c) => c.id === id);
  if (!c) return true;
  if (b.dataset.share) shareCase(c);
  else if (b.dataset.archive) {
    const homeRow = b.closest('.home-case-entry');
    const next = homeRow?.nextElementSibling || homeRow?.previousElementSibling;
    const nextId = next?.querySelector('[data-case]')?.dataset.case;
    const restoreFocus = homeRow && b === document.activeElement;
    setArchived(c, !c.archived);
    if (restoreFocus) {
      const target = (nextId && $(`.home-case[data-case="${nextId}"]`)) || $('.home-case') || caseInput;
      target.focus();
    }
  } else if (confirm(`Delete ${id}?`)) {
    state.cases = state.cases.filter((x) => x.id !== id);
    if (active === id) active = null;
    save();
    render();
    syncWatchlist();
  }
  return true;
}

// Sidebar
function caseEntry(c) {
  // The status bar shows each status; screen readers get the summary as text.
  const description = esc(`Selected OS versions: ${statusDescription(c)}`),
    archived = Boolean(c.archived);
  return [
    `<div class="case-entry ${archived ? 'archived' : ''}">`,
    `<button type="button" class="case-item" data-case="${c.id}">`,
    `<span class="case-id">${c.id}${cvssChip(sum(c.record, state.cvss))}<span class="case-update" aria-label="Unread update" hidden>New</span></span>`,
    `<small>${esc(c.record ? sum(c.record, state.cvss).title : c.savedTitle || 'Awaiting lookup')}</small>`,
    `<span class="visually-hidden">${description}</span>`,
    statusBar(c, { showChecked: true }),
    '</button>',
    caseActions(c),
    '</div>',
  ].join('');
}
function brokenEntry(c) {
  return [
    `<div class="case-entry ${c.archived ? 'archived' : ''}">`,
    `<button type="button" class="case-item" data-case="${esc(c.id)}">`,
    `<span class="case-id">${esc(c.id)}</span><small>Could not be displayed</small>`,
    '</button>',
    '</div>',
  ].join('');
}
const entry = (c) => safely(() => caseEntry(c), brokenEntry(c));
// Keep unchanged rows mounted so selection does not restart their hover transition or drop focus.
const entryMarkup = new WeakMap();
function renderSidebarEntries(list, cases, empty = '') {
  const previous = new Map([...list.children].map((row) => [row.querySelector('[data-case]')?.dataset.case, row]));
  if (!cases.length) {
    if (list.textContent !== empty || list.children.length !== Number(Boolean(empty))) {
      list.replaceChildren();
      if (empty) {
        const message = document.createElement('p');
        message.className = 'sidebar-empty';
        message.textContent = empty;
        list.append(message);
      }
    }
    return;
  }
  const ids = new Set(cases.map((c) => c.id));
  for (const [id, row] of previous) if (!ids.has(id)) row.remove();
  let next = list.firstElementChild;
  for (const c of cases) {
    const markup = entry(c);
    let row = previous.get(c.id);
    if (!row || entryMarkup.get(row) !== markup) {
      const template = document.createElement('template');
      template.innerHTML = markup;
      const updated = template.content.firstElementChild;
      if (row) {
        if (next === row) next = updated;
        row.replaceWith(updated);
      }
      row = updated;
      entryMarkup.set(row, markup);
      applyBars(row);
    }
    if (row !== next) list.insertBefore(row, next);
    next = row.nextElementSibling;
    const item = row.querySelector('.case-item');
    item.classList.toggle('selected', active === c.id);
    if (active === c.id) item.setAttribute('aria-current', 'page');
    else item.removeAttribute('aria-current');
    const unread = row.querySelector('.case-update');
    if (unread) unread.hidden = c.archived || !hasCaseUpdate(state, c);
  }
}
function updateSidebarCheckTimes() {
  const now = Date.now();
  for (const time of document.querySelectorAll('.sidebar [data-checked-at]')) {
    const text = 'Checked ' + ago(Number(time.dataset.checkedAt), now);
    if (time.textContent !== text) time.textContent = text;
  }
}
function renderSidebar() {
  const q = $('#search').value.trim().toLowerCase();
  const cases = sortedCases(state)
    .filter((c) => safely(() => matchesCase(c, q), false))
    .sort((a, b) => (q ? searchRelevance(b, q) - searchRelevance(a, q) : 0));
  const open = cases.filter((c) => !c.archived);
  const archived = cases.filter((c) => c.archived);
  const openCases = state.cases.filter((c) => !c.archived).length;
  $('#case-count').textContent = openCases;
  $('#cases-toggle-count').textContent = openCases;
  renderSidebarEntries($('#case-list'), open, q ? 'No matching open cases.' : 'No open cases.');
  const archive = $('#archived-list');
  const expanded = archivedOpen || Boolean(q);
  archive.hidden = !archived.length;
  if (archived.length && !archive.firstElementChild) {
    archive.innerHTML = `<button type="button" class="archive-toggle">${icons.chevron}Archived <span></span></button><div class="archived-entries collapsible animate"></div>`;
  }
  if (archive.firstElementChild) {
    archive.firstElementChild.setAttribute('aria-expanded', String(expanded));
    archive.querySelector('.archive-toggle span').textContent = archived.length;
    const entries = archive.querySelector('.archived-entries');
    entries.hidden = !expanded;
    renderSidebarEntries(entries, expanded ? archived : []);
  }
  updateSidebarCheckTimes();
}
function setArchived(c, archived) {
  const full = !archived && capacityMessage(true);
  if (full) {
    toast(full);
    return;
  }
  if (archived) {
    c.archived = Date.now();
    markCaseRead(state, c.id);
    if (active === c.id) archivedOpen = true;
  } else delete c.archived;
  save();
  syncWatchlist();
  render();
  toast(archived ? `${c.id} archived. It is no longer checked for updates.` : `${c.id} restored to your cases.`);
  if (!archived) refresh(c);
}

// Routing
function syncRoute() {
  const path = active ? `/${active}` : '/';
  document.title = active ? `${active} · Is It Fixed` : 'Is It Fixed — your vulnerability workspace';
  if (location.pathname === path) return;
  const method = location.pathname.toUpperCase() === path.toUpperCase() ? 'replaceState' : 'pushState';
  history[method](null, '', path + location.hash);
}
function routeFromURL() {
  let path = location.pathname;
  try {
    path = decodeURIComponent(path);
  } catch {
    /* Malformed escape sequence: match the raw path. */
  }
  const id = extractCveIds(path).filter(validId)[0];
  if (!id) {
    active = null;
    render();
    return;
  }
  if (state.cases.some((c) => c.id === id)) openCase(id);
  else addCase(id);
}
window.addEventListener('popstate', routeFromURL);

// Main view. Open <details> (facts, lists) survive re-renders, e.g. after an inventory refresh.
function render() {
  syncRoute();
  renderSidebar();
  const main = $('#main'),
    c = state.cases.find((c) => c.id === active);
  const fieldFocused = document.activeElement === caseInput;
  const selection = fieldFocused ? [caseInput.selectionStart, caseInput.selectionEnd] : null;
  const open = new Set([...main.querySelectorAll('details[data-detail][open]')].map((d) => d.dataset.detail));
  let viewFailed = false;
  try {
    main.innerHTML = c ? renderCase(c, context()) : renderHome(context(), homeFilter);
  } catch (e) {
    console.error(e);
    main.innerHTML = renderFailure(c);
    viewFailed = true;
  }
  for (const d of main.querySelectorAll('details[data-detail]')) if (open.has(d.dataset.detail)) d.open = true;
  applyBars(main);
  const sidebarSlot = $('#sidebar-case-entry');
  const slot = $('#home-case-entry-slot') || sidebarSlot;
  sidebarSlot.hidden = slot !== sidebarSlot;
  if (caseEntryForm.parentElement !== slot) slot.append(caseEntryForm);
  if (c && !viewFailed) bindCase(c);
  if (fieldFocused || (!c && document.activeElement === document.body)) {
    focusCaseInput();
    if (selection) caseInput.setSelectionRange(...selection);
  }
}
function focusCaseInput() {
  if (!document.querySelector('dialog[open]')) caseInput.focus({ preventScroll: true });
}
// Fallback when a view throws (for example on damaged saved data).
function renderFailure(c) {
  const actions = c
    ? `<div class="actions"><button type="button" data-delete="${esc(c.id)}">Delete case</button><a class="button" href="/">Back to overview</a></div>`
    : '';
  return [
    '<section class="panel render-failure" role="alert">',
    `<h1>${c ? esc(c.id) : 'Something went wrong'}</h1>`,
    `<p>This ${c ? 'case' : 'page'} could not be displayed. Its saved data may be damaged; refreshing the case or restoring a backup can help.</p>`,
    actions,
    '</section>',
  ].join('');
}
function bindCase(c) {
  $('#share-case').onclick = () => shareCase(c);
  $('#archive-case').onclick = () => setArchived(c, !c.archived);
  const refreshButton = $('#refresh');
  if (refreshButton) refreshButton.onclick = () => refresh(c, true);
  $('#edit-products').onclick = (e) => {
    chooserOpen = !chooserOpen;
    // Animate only this toggle (see .collapsible); re-renders show the chooser without motion.
    $('#case-products').classList.add('animate');
    $('#case-products').hidden = !chooserOpen;
    e.currentTarget.setAttribute('aria-expanded', chooserOpen);
  };
  // Any change here makes the selection the case's own; it then stops following the defaults.
  const chooser = $('#case-products');
  const applyChoice = (focus) => {
    c.products = [...chooser.querySelectorAll('input[value]:checked')].map((i) => i.value);
    c.customProducts = true;
    save();
    syncWatchlist();
    render();
    $(`#case-products ${focus}`)?.focus();
    refresh(c);
  };
  chooser.onchange = (e) => applyChoice(`input[value="${e.target.value}"]`);
  chooser.onclick = (e) => {
    const all = e.target.closest('[data-all]');
    if (!all) return;
    toggleAllVersions(all);
    applyChoice(`[data-all="${all.dataset.all}"]`);
  };
}
// One delegated handler for both views.
$('#main').addEventListener('click', (e) => {
  if (caseAction(e)) return;
  const scroll = e.target.closest('[data-scroll]');
  if (scroll) {
    e.preventDefault();
    const target = document.getElementById(scroll.dataset.scroll);
    if (target?.tagName === 'DETAILS') target.open = true;
    target?.scrollIntoView({ behavior: reducedMotion() ? 'auto' : 'smooth', block: 'start' });
    target?.querySelector('summary, [tabindex="-1"]')?.focus({ preventScroll: true });
    return;
  }
  const f = e.target.closest('[data-filter]');
  if (f) {
    homeFilter = homeFilter === f.dataset.filter ? null : f.dataset.filter;
    render();
    $(`[data-filter="${f.dataset.filter}"].home-stat`)?.focus();
    return;
  }
  const ex = e.target.closest('[data-example]');
  if (ex) {
    addCase(ex.dataset.example);
    return;
  }
  const b = e.target.closest('[data-case]');
  if (b) openCase(b.dataset.case);
});
document.addEventListener(
  'toggle',
  (e) => {
    if (e.target.matches?.('.os-group')) groupOverride.set(e.target.dataset.os, e.target.open);
  },
  true,
);

// Opening and refreshing cases
// Highlights stay while the case is on screen and clear once you leave it after reading.
function openCase(id) {
  const previous = state.cases.find((c) => c.id === active);
  if (previous && previous.id !== id && !previous.hasUpdate) delete previous.changedRows;
  active = id;
  markCaseRead(state, id);
  save();
  render();
}
// Returns false when the case could not be opened (limits); the message goes to `error` or a toast.
async function addCase(id, error = null) {
  let c = state.cases.find((c) => c.id === id);
  if (c) {
    const full = c.archived && capacityMessage(true);
    const wasArchived = Boolean(c.archived) && !full;
    if (wasArchived) {
      delete c.archived;
      syncWatchlist();
    }
    openCase(id);
    toast(full || (wasArchived ? 'Restored from the archive.' : 'Opened existing case.'));
    if (wasArchived) refresh(c);
    return true;
  }
  const full = capacityMessage();
  if (full) {
    if (error) error.textContent = full;
    else toast(full);
    return false;
  }
  // A new case follows the default OS selection until its own selection is changed.
  c = { id, products: [...state.products], customProducts: false, notes: '', created: Date.now() };
  state.cases.unshift(c);
  active = id;
  save();
  render();
  // A new case is fetched on demand; it never forces an upstream refresh.
  await refresh(c);
  return true;
}
// `force` asks the server to re-check upstream sources; only offered when the server allows it.
async function refresh(c, force = false) {
  if (busy.has(c.id)) return;
  busy.add(c.id);
  if (active === c.id) render();
  const requestedProducts = [...c.products];
  try {
    await syncWatchlist();
    const data = await streamCase(c.id, c.products, force && config.manualRefresh, (area) => {
      if (area.record) {
        c.record = area.record;
        c.checked = area.checked;
      }
      c.vendorData = area.vendorData;
      save();
      if (active === c.id) render();
    });
    if (data.record) {
      c.record = data.record;
      c.checked = data.checked;
    }
    c.vendorData = data.vendorData;
    c.apiChecked = Date.now();
    c.cache = data.cache;
    if (data.error) c.error = data.error;
    else delete c.error;
    evaluateCase(c);
  } catch (e) {
    c.error = e.message;
    c.attempted = Date.now();
  } finally {
    busy.delete(c.id);
    save();
    // The home page summarizes every case, so it re-renders too.
    if (active === c.id || !active) render();
    else renderSidebar();
    if (JSON.stringify(requestedProducts) !== JSON.stringify(c.products)) refresh(c);
  }
}

// Sidebar resizing
const resizeHandle = $('#sidebar-resize');
const SIDEBAR_MIN = 300;
const SIDEBAR_DEFAULT = 320;
const SIDEBAR_MAX = 480;
function sidebarWidth(value, persist = false) {
  const max = Math.min(SIDEBAR_MAX, Math.max(SIDEBAR_MIN, window.innerWidth - 420));
  const width = Math.round(Math.max(SIDEBAR_MIN, Math.min(max, Number(value) || SIDEBAR_DEFAULT)));
  document.documentElement.style.setProperty('--sidebar-width', `${width}px`);
  resizeHandle.setAttribute('aria-valuenow', width);
  resizeHandle.setAttribute('aria-valuetext', `${width} pixels`);
  resizeHandle.setAttribute('aria-valuemax', max);
  if (persist) {
    state.sidebarWidth = width;
    save();
  }
}
sidebarWidth(state.sidebarWidth);
let resizeStart = null;
resizeHandle.onpointerdown = (e) => {
  if (e.button !== 0) return;
  e.preventDefault();
  resizeHandle.focus({ preventScroll: true });
  resizeStart = { x: e.clientX, width: Number(resizeHandle.getAttribute('aria-valuenow')) };
  resizeHandle.setPointerCapture(e.pointerId);
  document.body.classList.add('resizing-sidebar');
};
resizeHandle.onpointermove = (e) => {
  if (resizeStart) sidebarWidth(resizeStart.width + e.clientX - resizeStart.x);
};
function finishResize() {
  if (!resizeStart) return;
  const initialWidth = resizeStart.width;
  resizeStart = null;
  document.body.classList.remove('resizing-sidebar');
  const width = Number(resizeHandle.getAttribute('aria-valuenow'));
  if (width !== initialWidth) sidebarWidth(width, true);
}
resizeHandle.onpointerup = finishResize;
resizeHandle.onpointercancel = finishResize;
resizeHandle.onlostpointercapture = finishResize;
resizeHandle.onkeydown = (e) => {
  const current = Number(resizeHandle.getAttribute('aria-valuenow')),
    step = e.shiftKey ? 40 : 10;
  const values = { ArrowLeft: current - step, ArrowRight: current + step, Home: SIDEBAR_MIN, End: SIDEBAR_MAX };
  if (e.key in values) {
    e.preventDefault();
    sidebarWidth(values[e.key], true);
  }
};
resizeHandle.ondblclick = () => sidebarWidth(SIDEBAR_DEFAULT, true);
window.addEventListener('resize', () => sidebarWidth(state.sidebarWidth));

// Settings
const settings = setupSettings({
  getState: () => state,
  getConfig: () => config,
  save,
  render,
  applyTheme,
  toast,
  setTmds,
  // Cases that still follow the default OS selection take it over and fetch new vendors.
  defaultsChanged() {
    const changed = followDefaults(state);
    if (!changed.length) return;
    save();
    syncWatchlist();
    render();
    for (const c of changed) if (!c.archived) refresh(c);
  },
  restore(next) {
    if (busy.size) throw Error('Wait for running refreshes to finish before restoring.');
    // The disclaimer acknowledgement belongs to this browser, not to the backup.
    if (state.disclaimerAccepted) next.disclaimerAccepted = state.disclaimerAccepted;
    else delete next.disclaimerAccepted;
    state = next;
    active = null;
    applyTheme();
    save();
    syncWatchlist();
    syncInventory();
    render();
    toast('Workspace restored.');
  },
});
// Footer, sidebar and disclaimer links depend on the server configuration.
function renderFooter() {
  for (const k of ['imprint', 'privacy']) {
    $(`[data-legal="${k}"]`).hidden = !config.legal[k];
    $(`[data-legal-link="${k}"]`).hidden = !config.legal[k];
  }
  $('.disclaimer-links').hidden = !config.legal.imprint && !config.legal.privacy;
  $('[data-source]').hidden = !config.sourceUrl;
  // Build: "v1.1.0 · abc1234"; the commit links to the source repository when one is configured.
  const { version, commit, sourceUrl } = config,
    short = commit && esc(commit.slice(0, 7)),
    commitHtml =
      commit && sourceUrl
        ? `<a href="${esc(`${sourceUrl.replace(/\/+$/, '')}/commit/${commit}`)}" target="_blank" rel="noopener noreferrer" title="Commit ${esc(commit)}">${short}</a>`
        : short,
    build = $('[data-build]');
  build.innerHTML = [version && esc(`v${version}`), commitHtml].filter(Boolean).join(' · ');
  build.hidden = !build.innerHTML;
  for (const a of document.querySelectorAll('[data-source-link]')) {
    a.hidden = !config.sourceUrl;
    if (config.sourceUrl) a.href = config.sourceUrl;
  }
}

// First-visit disclaimer: shown until this version is acknowledged; Escape does not dismiss it.
const disclaimer = $('#disclaimer-dialog');
const disclaimerPending = () => state.disclaimerAccepted !== DISCLAIMER_VERSION;
function showDisclaimer() {
  if (!disclaimerPending() || disclaimer.open) return;
  for (const d of document.querySelectorAll('dialog[open]')) d.close();
  disclaimer.showModal();
  $('#disclaimer-accept').focus();
}
disclaimer.addEventListener('cancel', (e) => e.preventDefault());
// Browsers may still close a modal on repeated Escape; reopen until acknowledged.
disclaimer.addEventListener('close', () => setTimeout(showDisclaimer));
$('#disclaimer-accept').onclick = () => {
  state.disclaimerAccepted = DISCLAIMER_VERSION;
  save();
  disclaimer.close();
  focusCaseInput();
};

// Global controls
$('#search-chord').textContent = searchChord;
$('#search').title = `Search your cases (S or ${searchChord})`;
caseInput.title = 'Open a case (/)';
caseInput.setAttribute('aria-keyshortcuts', '/');
$('#search').setAttribute('aria-keyshortcuts', applePlatform ? 'S Meta+K' : 'S Control+K');
let searchField = null;
let searchFamily = null;
const filterPanel = $('#search-filter-panel');
const filterOptions = $('#search-options');
const filterBack = $('#back-search-filter');
const filterButtons = [...document.querySelectorAll('[data-search-field]')];
const filterTrigger = () => filterButtons.find((b) => b.dataset.searchField === searchField);

function filterChoice(label, token, icon = '', selected = false) {
  return `<button type="button" data-search-token="${token}" aria-pressed="${selected}"><span class="filter-icon">${icon}</span><span>${esc(label)}</span><span aria-hidden="true">${selected ? '✓' : ''}</span></button>`;
}
function renderSearchOptions() {
  const query = $('#search').value;
  const selected = (field, id) => selectedSearchFilter(query, field, id);
  const family = VENDORS.find((v) => v.id === searchFamily);
  filterBack.hidden = !family;
  $('#close-search-filter').hidden = !searchFilterLabel(query, searchField);
  $('#search-filter-title').textContent = family?.name || (searchField === 'os' ? 'Operating system' : 'Status');
  if (family) {
    filterOptions.innerHTML =
      filterChoice('Any version', `os:${family.id}`, logo(family.id), selected('os', family.id)) +
      PRODUCTS.filter((p) => p.family === family.id)
        .map((p) => filterChoice(p.name, `version:${p.id}`, logo(family.id), selected('version', p.id)))
        .join('');
  } else if (searchField === 'os') {
    filterOptions.innerHTML =
      filterChoice('All operating systems', '', '', replaceSearchFilter(query, 'os') === query.trim()) +
      VENDORS.map(
        (v) =>
          `<button type="button" data-search-family="${v.id}"><span class="filter-icon">${logo(v.id)}</span><span>${esc(v.name)}</span>${icons.chevron}</button>`,
      ).join('');
  } else {
    filterOptions.innerHTML =
      filterChoice('All statuses', '', '', replaceSearchFilter(query, 'status') === query.trim()) +
      STATUS_ORDER.map((status) => {
        const key = status === 'fix_available' ? 'fixed' : status;
        return filterChoice(
          labels[status],
          `status:${key}`,
          `<span class="filter-status-dot ${status}"></span>`,
          selected('status', key),
        );
      }).join('');
  }
}
function focusFilterChoice() {
  (filterOptions.querySelector('[aria-pressed="true"]') || filterOptions.querySelector('button'))?.focus();
}
function openSearchFilter(field) {
  searchField = field;
  searchFamily = null;
  filterPanel.hidden = false;
  for (const button of filterButtons)
    button.setAttribute('aria-expanded', String(button.dataset.searchField === field));
  renderSearchOptions();
  focusFilterChoice();
}
function hideSearchOptions(restoreFocus = false) {
  if (filterPanel.hidden) return;
  filterPanel.hidden = true;
  for (const button of filterButtons) button.setAttribute('aria-expanded', 'false');
  if (restoreFocus) filterTrigger()?.focus();
}
function updateSearch() {
  const query = $('#search').value;
  $('#clear-search').hidden = !query;
  // The pickers keep their names ("OS", "Status") and are tinted while one of their filters is set.
  for (const button of filterButtons)
    button.classList.toggle('filter-active', Boolean(searchFilterLabel(query, button.dataset.searchField)));
  renderSidebar();
}
$('#search').oninput = () => {
  hideSearchOptions();
  updateSearch();
};
$('#search').onkeydown = (e) => {
  if (e.key === 'Escape' && !filterPanel.hidden) {
    e.preventDefault();
    hideSearchOptions();
  } else if (e.key === 'ArrowDown') {
    e.preventDefault();
    openSearchFilter('os');
  }
};
for (const button of filterButtons) {
  button.onclick = () => {
    if (!filterPanel.hidden && searchField === button.dataset.searchField) hideSearchOptions(true);
    else openSearchFilter(button.dataset.searchField);
  };
}
filterOptions.onclick = (e) => {
  const family = e.target.closest('[data-search-family]');
  if (family) {
    searchFamily = family.dataset.searchFamily;
    renderSearchOptions();
    focusFilterChoice();
    return;
  }
  const button = e.target.closest('[data-search-token]');
  if (!button) return;
  const input = $('#search');
  const token = button.dataset.searchToken;
  // Options toggle, so several values of one filter can be combined; "All …" clears the filter.
  // The panel stays open for further choices.
  input.value = token ? toggleSearchFilter(input.value, token) : replaceSearchFilter(input.value, searchField);
  updateSearch();
  renderSearchOptions();
  filterOptions.querySelector(`[data-search-token="${token}"]`)?.focus();
};
filterPanel.onkeydown = (e) => {
  const buttons = [...filterOptions.querySelectorAll('button')];
  const current = buttons.indexOf(document.activeElement);
  if (e.key === 'Escape') {
    e.preventDefault();
    hideSearchOptions(true);
  } else if (current >= 0 && ['ArrowDown', 'ArrowUp'].includes(e.key)) {
    e.preventDefault();
    buttons[(current + (e.key === 'ArrowDown' ? 1 : -1) + buttons.length) % buttons.length]?.focus();
  }
};
filterBack.onclick = () => {
  const family = searchFamily;
  searchFamily = null;
  renderSearchOptions();
  filterOptions.querySelector(`[data-search-family="${family}"]`)?.focus();
};
// The panel's × removes this picker's filter (OS or status) and closes the panel.
$('#close-search-filter').onclick = () => {
  const input = $('#search');
  input.value = replaceSearchFilter(input.value, searchField);
  updateSearch();
  hideSearchOptions(true);
};
// Collapse after outside clicks so the in-flow panel cannot move a case before its click lands.
// composedPath() is recorded at dispatch: choosing a family re-renders the options, so the
// clicked button is no longer in the document when this listener runs.
document.addEventListener('click', (e) => {
  if (!e.composedPath().includes($('.search-area'))) hideSearchOptions();
});
$('#clear-search').onclick = () => {
  $('#search').value = '';
  hideSearchOptions();
  updateSearch();
  $('#search').focus();
};
// Small screens fold the case list (with search) behind a toggle and close it after a choice.
const smallScreen = matchMedia('(max-width: 760px)');
function setCasesOpen(open) {
  $('.sidebar').classList.toggle('cases-open', open);
  $('#cases-toggle').setAttribute('aria-expanded', String(open));
}
$('#cases-toggle').onclick = () => setCasesOpen(!$('.sidebar').classList.contains('cases-open'));
$('#case-list').onclick = $('#archived-list').onclick = (e) => {
  if (caseAction(e)) return;
  if (e.target.closest('.archive-toggle')) {
    archivedOpen = !archivedOpen;
    renderSidebar();
    $('.archive-toggle')?.focus();
    return;
  }
  const b = e.target.closest('[data-case]');
  if (!b) return;
  if (smallScreen.matches) setCasesOpen(false);
  openCase(b.dataset.case);
};
function openFromText(text, error) {
  const ids = extractCveIds(text).filter(validId);
  if (!ids.length) {
    error.textContent = 'No CVE ID found. Try CVE-2024-3094 or an advisory link.';
    return false;
  }
  const full = !state.cases.some((c) => c.id === ids[0]) && capacityMessage();
  if (full) {
    error.textContent = full;
    return false;
  }
  addCase(ids[0]);
  if (ids.length > 1) setTimeout(() => toast(`Found ${ids.length} CVE IDs; opened ${ids[0]}.`), 50);
  return true;
}
caseEntryForm.querySelector('form').onsubmit = (e) => {
  e.preventDefault();
  const error = $('#add-error');
  error.textContent = '';
  if (openFromText(caseInput.value, error)) caseInput.value = '';
};
caseInput.oninput = () => {
  $('#add-error').textContent = '';
};
for (const b of document.querySelectorAll('[data-close]')) {
  b.onclick = () => document.getElementById(b.dataset.close).close();
}
$('#settings-button').onclick = () => settings.open();
// Settings closes on a click outside the dialog box (on its backdrop).
$('#settings-dialog').addEventListener('click', (e) => {
  const box = e.currentTarget.getBoundingClientRect();
  const outside = e.clientX < box.left || e.clientX > box.right || e.clientY < box.top || e.clientY > box.bottom;
  if (e.target === e.currentTarget && outside) e.currentTarget.close();
});
$('.brand').onclick = (e) => {
  if (e.button || e.ctrlKey || e.metaKey || e.shiftKey) return;
  e.preventDefault();
  const previous = state.cases.find((c) => c.id === active);
  if (previous && !previous.hasUpdate) delete previous.changedRows;
  active = null;
  render();
  focusCaseInput();
};
document.addEventListener('keydown', (e) => {
  const key = e.key.toLowerCase(),
    mod = e.ctrlKey || e.metaKey,
    typing =
      ['INPUT', 'TEXTAREA', 'SELECT'].includes(document.activeElement.tagName) ||
      document.activeElement.isContentEditable;
  if (document.querySelector('dialog[open]') || e.altKey || e.isComposing) return;
  if (
    ((applePlatform ? e.metaKey && !e.ctrlKey : e.ctrlKey && !e.metaKey) && key === 'k') ||
    (key === 's' && !mod && !typing)
  ) {
    e.preventDefault();
    $('#search').focus();
    $('#search').select();
    return;
  }
  if (key === '/' && !mod && !typing) {
    e.preventDefault();
    focusCaseInput();
  }
});

// Sidebar connection indicator: a slowly breathing green dot while the server answers, a red
// warning once a request failed more recently than the last answer.
function renderConnection() {
  const el = $('#connection-status');
  const { lastOk, lastFailure } = connection;
  const status = lastFailure > lastOk ? 'offline' : lastOk ? 'online' : 'pending';
  const text = { online: 'Cases re-checked hourly', offline: 'Server not responding', pending: 'Connecting…' }[status];
  el.className = `connection ${status}`;
  if (el.querySelector('.connection-text').textContent !== text)
    el.querySelector('.connection-text').textContent = text;
  el.title = {
    online: `Server reachable (last answer ${time(lastOk)}). Your cases are stored in this browser; the server re-checks them every hour.`,
    offline: `No answer from the server${lastOk ? ` since ${time(lastOk)}` : ''}. Showing saved data; retrying automatically.`,
    pending: 'Contacting the server…',
  }[status];
}
onConnectionChange(renderConnection);
const checkConnection = () => {
  if (!document.hidden) ping();
};
setInterval(checkConnection, 120000);
document.addEventListener('visibilitychange', checkConnection);
window.addEventListener('offline', () => reportContact(false));

// Hourly catch-up while open and on returning to the tab (never a forced refresh).
async function catchUp() {
  if (!state.auto || document.hidden) return;
  for (const c of state.cases.filter((c) => !c.archived)) {
    if (Date.now() - Math.max(c.apiChecked || 0, c.attempted || 0) >= HOUR) await refresh(c);
  }
}
setInterval(() => {
  updateSidebarCheckTimes();
  catchUp();
}, 60000);
setInterval(() => syncWatchlist(true), 300000);
document.addEventListener('visibilitychange', catchUp);
window.addEventListener('online', () => {
  if (watchFailure) watchFailure.until = 0;
  syncWatchlist(true).then(catchUp);
});

// Startup: render from saved state, then apply the server configuration. Nothing here may
// stop the rest: configuration, inventory and watch sync must start even if a case fails.
// Unchanged saved cases get their first action baseline silently.
for (const c of state.cases) if (!c.actionBaseline) safely(() => evaluateCase(c));
save();
safely(showDisclaimer);
safely(routeFromURL);
startupNotices();
fetchConfig().then((c) => {
  config = c;
  renderFooter();
  settings.sync();
  syncInventory();
  render();
});
syncWatchlist().then(catchUp);

// Problems found while loading the saved workspace.
function startupNotices() {
  const day = new Date().toISOString().slice(0, 10);
  if (loaded.locked) {
    toast('Your saved workspace could not be read. Export it before replacing it.', {
      label: 'Export',
      run() {
        download(JSON.stringify(loaded.raw || {}, null, 2), `isitfixed-recovery-${day}.json`);
        storageLocked = false;
        save();
      },
    });
  } else if (loaded.report.archivedCases || loaded.report.droppedCases) {
    const archived = loaded.report.archivedCases
      ? `${loaded.report.archivedCases} cases were archived: at most ${MAX_OPEN_CASES} can be open.`
      : '';
    const dropped = loaded.report.droppedCases ? `${loaded.report.droppedCases} damaged cases were removed.` : '';
    toast([archived, dropped].filter(Boolean).join(' '));
  }
}
