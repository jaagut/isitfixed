// Home page: hero with the open-case form, status filters, case lists,
// recent activity and (with TMDS enabled) the TMDS inventory status. Pure.
import { esc, ago, plural } from '../util.js';
import { hasCaseUpdate } from '../cases.js';
import {
  STATUS_ORDER,
  labels,
  statusSymbols,
  sum,
  caseStatus,
  statusDescription,
  statusBar,
  cvssChip,
  caseActions,
} from './common.js';

const EXAMPLES = ['CVE-2024-3094', 'CVE-2024-6387', 'CVE-2024-1086', 'CVE-2024-21338'];

function howItWorks(tmdsOn) {
  const steps = [
    ['Open a case', 'One CVE, checked against Red Hat, SUSE, Debian, Ubuntu, Alpine and Microsoft sources.'],
    [
      'See what to do',
      `Status, fixed builds and mitigations per OS version, each linked to its vendor source${tmdsOn ? ', plus Trend Micro Deep Security kernel support' : ''}.`,
    ],
    ['Stay informed', 'Cases are re-checked hourly. You hear about changes you can act on, not about every edit.'],
  ];
  return [
    '<section class="panel home-how"><h2>How it works</h2><ol>',
    ...steps.map(([title, text]) => `<li><strong>${title}</strong><span>${text}</span></li>`),
    '</ol></section>',
  ].join('');
}

function homeCaseRow(c, ctx) {
  const s = sum(c.record, ctx.state.cvss),
    st = caseStatus(c);
  const update = hasCaseUpdate(ctx.state, c) ? '<span class="case-update">New</span>' : '';
  return [
    '<div class="home-case-entry">',
    `<button type="button" class="home-case" data-case="${c.id}">`,
    `<span class="case-status ${st}" aria-hidden="true">${statusSymbols[st]}</span>`,
    '<span class="home-case-main">',
    `<span class="home-case-id">${c.id}${cvssChip(s)}${update}</span>`,
    `<small>${esc(c.record ? s.title : 'Awaiting lookup')}</small>`,
    '</span>',
    '<span class="home-case-meta">',
    `<span>${esc(statusDescription(c))}</span>`,
    statusBar(c),
    `<small>Checked ${ago(c.apiChecked || c.checked, ctx.now)}</small>`,
    '</span>',
    '</button>',
    caseActions(c),
    '</div>',
  ].join('');
}

function homeHero(open, attention, ctx) {
  const n = attention.length;
  let title = 'Check a vulnerability',
    lede =
      'Paste a CVE ID or any advisory link. CVE Desk checks the vendor trackers for the OS versions you care about.';
  if (open.length) {
    title = n ? `${plural(n, 'case')} need${n > 1 ? '' : 's'} a look` : 'All clear for now';
    const tracking = `Tracking ${plural(open.length, 'CVE')} across ${plural(ctx.state.products.length, 'default OS version')}.`;
    lede = `${tracking} ${ctx.state.auto ? 'Cases are re-checked every hour while CVE Desk is open.' : 'Cases are checked when you open them.'}`;
  }
  const examples = EXAMPLES.map(
    (id) => `<button type="button" class="example" data-example="${id}">${id}</button>`,
  ).join('');
  return [
    '<section class="home-hero"><div>',
    `<h1>${title}</h1>`,
    `<p class="home-lede">${lede}</p>`,
    '<form id="home-form" class="home-open">',
    '<input id="home-input" placeholder="CVE-2024-3094 or a link that contains it" autocomplete="off" spellcheck="false" aria-label="CVE ID or link">',
    '<button class="primary">Open case →</button>',
    '</form>',
    '<p id="home-error" class="error" role="alert"></p>',
    open.length ? '' : `<p class="home-examples">Try ${examples}</p>`,
    '</div></section>',
  ].join('');
}

function homeStats(counts, filter) {
  const stat = (s) =>
    [
      `<button type="button" class="home-stat ${s} ${counts[s] ? '' : 'empty'}" data-filter="${s}" aria-pressed="${filter === s}" ${counts[s] || filter === s ? '' : 'disabled'}>`,
      `<span class="case-status ${s}" aria-hidden="true">${statusSymbols[s]}</span>`,
      `<strong>${counts[s]}</strong>`,
      `<span>${labels[s]}</span>`,
      '</button>',
    ].join('');
  return `<div class="home-stats" role="group" aria-label="Filter cases by status">${STATUS_ORDER.map(stat).join('')}</div>`;
}

const homeList = (heading, cases, ctx, empty = '') =>
  `<section class="panel home-list"><h2>${heading}</h2>${cases.map((c) => homeCaseRow(c, ctx)).join('') || empty}</section>`;

function homeActivity(ctx) {
  const item = (a) =>
    [
      `<button type="button" class="activity-item" data-case="${esc(a.id)}">`,
      `<span>${esc(a.id)}</span><small>${esc(a.text)}</small><small>${ago(a.time, ctx.now)}</small>`,
      '</button>',
    ].join('');
  const items =
    ctx.state.activity.slice(0, 6).map(item).join('') ||
    '<p class="muted">Actionable changes to your cases appear here.</p>';
  return `<section class="panel home-side"><h2>Recent activity</h2>${items}</section>`;
}

// Agent and KSP inventory status; hidden when TMDS is off.
function homeInventory(ctx) {
  if (!ctx.tmdsOn) return '';
  const { data, error } = ctx.inventory;
  let agent, ksp;
  if (!data) agent = ksp = error ? 'Unavailable right now.' : 'Loading…';
  else {
    const builds = Object.values(data.products || {}).reduce((n, r) => n + r.length, 0);
    const checked = data.checked ?? data.attempted;
    agent = builds
      ? `${plural(builds, 'bundled agent build')}, checked ${ago(checked, ctx.now)}.`
      : 'The first inventory can take a few minutes.';
    if (data.error) agent += ' The last refresh failed.';
    const k = data.ksp;
    if (!k) ksp = 'Not provided by this server.';
    else {
      const packages = Object.values(k.products || {}).reduce((n, r) => n + r.length, 0);
      ksp = packages
        ? `${plural(packages, 'package')}${k.pageUpdated ? `, list of ${k.pageUpdated}` : ''}.`
        : 'Not loaded yet.';
      if (k.error) ksp += ' The last refresh failed.';
    }
  }
  return [
    '<section class="panel home-side home-tmds"><h2>Trend Micro Deep Security</h2>',
    '<dl>',
    `<div><dt>Agent inventory</dt><dd>${esc(agent)}</dd></div>`,
    `<div><dt>Kernel Support Packages</dt><dd>${esc(ksp)}</dd></div>`,
    '</dl>',
    '<p class="muted">Kernel fixes are matched against kernels bundled in Deep Security Agent 20 LTS and the published Kernel Support Package list.</p>',
    '</section>',
  ].join('');
}

export function renderHome(ctx, filter) {
  const { state } = ctx;
  const open = state.cases.filter((c) => !c.archived),
    counts = Object.fromEntries(STATUS_ORDER.map((s) => [s, 0]));
  const statuses = new Map(open.map((c) => [c, caseStatus(c)]));
  open.forEach((c) => counts[statuses.get(c)]++);
  const rank = (c) => STATUS_ORDER.indexOf(statuses.get(c)) * 100 - (sum(c.record, state.cvss).score || 0);
  const attention = open
    .filter((c) => ['affected', 'fix_available', 'inconclusive'].includes(statuses.get(c)) || hasCaseUpdate(state, c))
    .sort((a, b) => Number(hasCaseUpdate(state, b)) - Number(hasCaseUpdate(state, a)) || rank(a) - rank(b));
  const rest = open.filter((c) => !attention.includes(c));
  let lists;
  if (filter) {
    const filtered = open.filter((c) => statuses.get(c) === filter).sort((a, b) => rank(a) - rank(b));
    const clear = `<button type="button" class="text-button clear-filter" data-filter="${filter}">Show all</button>`;
    lists = homeList(
      `${labels[filter]} ${clear}`,
      filtered,
      ctx,
      '<p class="muted home-empty">No cases with this status.</p>',
    );
  } else {
    lists =
      (attention.length ? homeList('Needs attention', attention, ctx) : '') +
      (rest.length ? homeList(attention.length ? 'Other cases' : 'Your cases', rest, ctx) : '');
  }
  return [
    homeHero(open, attention, ctx),
    open.length ? homeStats(counts, filter) : '',
    '<div class="home-grid">',
    `<div>${lists}${open.length ? '' : howItWorks(ctx.tmdsOn)}</div>`,
    `<aside>${homeActivity(ctx)}${homeInventory(ctx)}</aside>`,
    '</div>',
  ].join('');
}
