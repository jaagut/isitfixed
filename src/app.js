// Is It Fixed app: state, routing, refreshes, notifications and event wiring.
// Rendering lives in src/render/*; matching and change detection are pure
// modules (tmds.js, changes.js, rows.js, sources.js).
import { hasCaseUpdate, recordUpdate, markCaseRead, sortedCases } from './cases.js';
import { streamCase, syncWatches, fetchAgents, fetchConfig, DEFAULT_CONFIG } from './api.js';
import { validId, extractCveIds } from './data.js';
import { caseActionState, diffActions, withoutTmds, describeChanges } from './changes.js';
import {
  THEME_KEY,
  DISCLAIMER_VERSION,
  MAX_OPEN_CASES,
  MAX_CASES,
  loadWorkspace,
  saveable,
  persistWorkspace,
  caseSearchText,
} from './state.js';
import { esc, icons, HOUR } from './util.js';
import {
  selected,
  sum,
  caseStatus,
  statusDescription,
  statusBar,
  statusSymbols,
  cvssChip,
  caseActions,
} from './render/common.js';
import { renderCase } from './render/case.js';
import { renderHome } from './render/home.js';
import { setupSettings } from './settings.js';

const $ = (s) => document.querySelector(s);
const reducedMotion = () => matchMedia('(prefers-reduced-motion: reduce)').matches;

const loaded = loadWorkspace(localStorage);
let state = loaded.state,
  // The saved workspace could not be read or moved aside: saving would overwrite it.
  storageLocked = loaded.locked,
  config = { ...DEFAULT_CONFIG },
  active = null,
  chooserOpen = false,
  archivedOpen = false,
  homeFilter = null,
  storageFailed = false;
const busy = new Set(),
  groupOverride = new Map(),
  inventory = { data: null, error: null };

// Never writes a workspace that would fail validation on the next load.
function save() {
  if (storageLocked) return;
  if (!saveable(state)) {
    toast('Changes were not saved: the workspace exceeds its limits. Delete or archive cases.');
    return;
  }
  const result = persistWorkspace(localStorage, state);
  if (!result.saved && !storageFailed) {
    toast('Browser storage is full or unavailable. Your changes are kept in this tab; export a backup.', {
      label: 'Export backup',
      run: () =>
        download(JSON.stringify(state, null, 2), `isitfixed-backup-${new Date().toISOString().slice(0, 10)}.json`),
    });
  }
  storageFailed = !result.saved;
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
// theme script reads its own key, so it never parses the workspace.
function applyTheme() {
  if (state.theme === 'system') delete document.documentElement.dataset.theme;
  else document.documentElement.dataset.theme = state.theme;
  try {
    localStorage.setItem(THEME_KEY, state.theme);
  } catch {
    /* Storage unavailable: the theme still applies for this visit. */
  }
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
// Status bar segment widths come from data-flex (no inline style attributes under the CSP).
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
  const b = e.target.closest('[data-share],[data-archive],[data-delete]');
  if (!b) return false;
  const id = b.dataset.share || b.dataset.archive || b.dataset.delete,
    c = state.cases.find((c) => c.id === id);
  if (!c) return true;
  if (b.dataset.share) shareCase(c);
  else if (b.dataset.archive) setArchived(c, !c.archived);
  else if (confirm(`Delete ${id}?`)) {
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
  const s = caseStatus(c),
    description = esc(`Selected OS versions: ${statusDescription(c)}`),
    archived = Boolean(c.archived),
    current = active === c.id;
  const icon = `<span class="case-status ${s}" role="img" aria-label="${description}" title="${description}">${statusSymbols[s]}</span>`;
  const unread =
    hasCaseUpdate(state, c) && !archived ? '<span class="case-update" aria-label="Unread update">New</span>' : '';
  return [
    `<div class="case-entry ${archived ? 'archived' : ''}">`,
    `<button type="button" class="case-item ${current ? 'selected' : ''}" data-case="${c.id}" ${current ? 'aria-current="page"' : ''} title="${description}">`,
    `<span class="case-id">${icon}${c.id}${cvssChip(sum(c.record, state.cvss))}${unread}</span>`,
    `<small>${esc(c.record ? sum(c.record, state.cvss).title : c.savedTitle || 'Awaiting lookup')}</small>`,
    statusBar(c),
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
function renderSidebar() {
  const q = $('#search').value.trim().toLowerCase(),
    terms = q.split(/\s+/).filter(Boolean),
    match = (c) => safely(() => terms.every((term) => caseSearchText(c).includes(term)), true);
  const cases = sortedCases(state).filter(match),
    open = cases.filter((c) => !c.archived),
    archived = cases.filter((c) => c.archived);
  $('#case-count').textContent = state.cases.filter((c) => !c.archived).length;
  // Show archived matches while searching and keep the open case visible.
  const showArchived = archivedOpen || Boolean(q);
  $('#case-list').innerHTML =
    open.map(entry).join('') || `<p class="sidebar-empty">${q ? 'No matching cases.' : 'No open cases.'}</p>`;
  applyBars($('#case-list'));
  $('#archived-list').hidden = !archived.length;
  if (!archived.length) {
    $('#archived-list').innerHTML = '';
    return;
  }
  const toggle = `<button type="button" class="archive-toggle" aria-expanded="${showArchived}">${icons.chevron}Archived <span>${archived.length}</span></button>`;
  const entries = showArchived ? `<div class="archived-entries">${archived.map(entry).join('')}</div>` : '';
  $('#archived-list').innerHTML = toggle + entries;
  applyBars($('#archived-list'));
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
  const homeInput = $('#home-input'),
    homeDraft = homeInput?.value,
    homeFocused = document.activeElement === homeInput,
    selection = homeFocused ? [homeInput.selectionStart, homeInput.selectionEnd] : null;
  const open = new Set([...main.querySelectorAll('details[data-detail][open]')].map((d) => d.dataset.detail));
  try {
    main.innerHTML = c ? renderCase(c, context()) : renderHome(context(), homeFilter);
  } catch (e) {
    console.error(e);
    main.innerHTML = renderFailure(c);
    return;
  }
  for (const d of main.querySelectorAll('details[data-detail]')) if (open.has(d.dataset.detail)) d.open = true;
  applyBars(main);
  if (c) bindCase(c);
  else {
    bindHome();
    if (homeDraft) $('#home-input').value = homeDraft;
    if (homeFocused || document.activeElement === document.body) focusHome();
    if (selection) $('#home-input')?.setSelectionRange(...selection);
  }
}
function focusHome() {
  if (!active && !document.querySelector('dialog[open]')) $('#home-input')?.focus({ preventScroll: true });
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
    $('#case-products').hidden = !chooserOpen;
    e.currentTarget.setAttribute('aria-expanded', chooserOpen);
  };
  $('#case-products').onchange = (e) => {
    c.products = [...$('#case-products').querySelectorAll('input[value]:checked')].map((i) => i.value);
    save();
    syncWatchlist();
    render();
    $(`#case-products input[value="${e.target.value}"]`)?.focus();
    refresh(c);
  };
}
function bindHome() {
  $('#home-form').onsubmit = (e) => {
    e.preventDefault();
    openFromText($('#home-input').value, $('#home-error'));
  };
}
// One delegated handler for both views.
$('#main').addEventListener('click', (e) => {
  if (caseAction(e)) return;
  const scroll = e.target.closest('[data-scroll]');
  if (scroll) {
    e.preventDefault();
    const target = document.getElementById(scroll.dataset.scroll);
    target?.scrollIntoView({ behavior: reducedMotion() ? 'auto' : 'smooth', block: 'start' });
    target?.querySelector('[tabindex="-1"]')?.focus({ preventScroll: true });
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
function openAdd() {
  $('#add-error').textContent = '';
  $('#add-dialog').showModal();
  $('#cve-input').focus();
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
  c = { id, products: [...state.products], notes: '', created: Date.now() };
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
    if (active === c.id) render();
    else renderSidebar();
    if (JSON.stringify(requestedProducts) !== JSON.stringify(c.products)) refresh(c);
  }
}

// Sidebar resizing
const resizeHandle = $('#sidebar-resize');
function sidebarWidth(value, persist = false) {
  const max = Math.min(480, Math.max(220, window.innerWidth - 420));
  const width = Math.round(Math.max(220, Math.min(max, Number(value) || 265)));
  document.documentElement.style.setProperty('--sidebar-width', `${width}px`);
  resizeHandle.setAttribute('aria-valuenow', width);
  resizeHandle.setAttribute('aria-valuemax', max);
  if (persist) {
    state.sidebarWidth = width;
    save();
  }
}
sidebarWidth(state.sidebarWidth);
let resizing = false;
resizeHandle.onpointerdown = (e) => {
  if (e.button !== 0) return;
  e.preventDefault();
  resizing = true;
  resizeHandle.setPointerCapture(e.pointerId);
  document.body.classList.add('resizing-sidebar');
};
resizeHandle.onpointermove = (e) => {
  if (resizing) sidebarWidth(e.clientX);
};
function finishResize() {
  if (!resizing) return;
  resizing = false;
  document.body.classList.remove('resizing-sidebar');
  sidebarWidth(resizeHandle.getAttribute('aria-valuenow'), true);
}
resizeHandle.onpointerup = finishResize;
resizeHandle.onpointercancel = finishResize;
resizeHandle.onlostpointercapture = finishResize;
resizeHandle.onkeydown = (e) => {
  const current = Number(resizeHandle.getAttribute('aria-valuenow')),
    step = e.shiftKey ? 40 : 10;
  const values = { ArrowLeft: current - step, ArrowRight: current + step, Home: 220, End: 480 };
  if (e.key in values) {
    e.preventDefault();
    sidebarWidth(values[e.key], true);
  }
};
resizeHandle.ondblclick = () => sidebarWidth(265, true);
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
  focusHome();
};

// Global controls
$('#new-case').onclick = openAdd;
$('#search').oninput = renderSidebar;
$('#case-list').onclick = $('#archived-list').onclick = (e) => {
  if (caseAction(e)) return;
  if (e.target.closest('.archive-toggle')) {
    archivedOpen = !archivedOpen;
    renderSidebar();
    $('.archive-toggle')?.focus();
    return;
  }
  const b = e.target.closest('[data-case]');
  if (b) openCase(b.dataset.case);
};
function openFromText(text, error) {
  const ids = extractCveIds(text).filter(validId);
  if (!ids.length) {
    error.textContent = 'No CVE ID found. Paste an ID such as CVE-2024-3094 or a link that contains one.';
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
$('#add-form').onsubmit = (e) => {
  e.preventDefault();
  if (openFromText($('#cve-input').value, $('#add-error'))) {
    $('#add-dialog').close();
    $('#cve-input').value = '';
  }
};
for (const b of document.querySelectorAll('[data-close]')) {
  b.onclick = () => document.getElementById(b.dataset.close).close();
}
$('#settings-button').onclick = () => settings.open();
$('.brand').onclick = (e) => {
  if (e.button || e.ctrlKey || e.metaKey || e.shiftKey) return;
  e.preventDefault();
  const previous = state.cases.find((c) => c.id === active);
  if (previous && !previous.hasUpdate) delete previous.changedRows;
  active = null;
  render();
};
document.addEventListener('keydown', (e) => {
  const key = e.key.toLowerCase(),
    mod = e.ctrlKey || e.metaKey,
    typing =
      ['INPUT', 'TEXTAREA', 'SELECT'].includes(document.activeElement.tagName) ||
      document.activeElement.isContentEditable;
  if (document.querySelector('dialog[open]') || e.altKey) return;
  if ((mod && key === 'k') || (key === '/' && !mod && !typing)) {
    e.preventDefault();
    openAdd();
  }
});

// Hourly catch-up while open and on returning to the tab (never a forced refresh).
async function catchUp() {
  if (!state.auto || document.hidden) return;
  for (const c of state.cases.filter((c) => !c.archived)) {
    if (Date.now() - Math.max(c.apiChecked || 0, c.attempted || 0) >= HOUR) await refresh(c);
  }
}
setInterval(catchUp, 60000);
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
  if (loaded.recovery) {
    toast('Your saved workspace could not be read, so Is It Fixed started empty. A copy is kept in this browser.', {
      label: 'Export copy',
      run: () => download(localStorage.getItem(loaded.recovery) || '', `isitfixed-recovery-${day}.json`),
    });
  } else if (loaded.locked) {
    toast('Your saved workspace could not be read. Export it before making changes; nothing is saved until then.', {
      label: 'Export',
      run() {
        download(loaded.raw || '', `isitfixed-recovery-${day}.json`);
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
