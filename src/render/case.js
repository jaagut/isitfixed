// Case page: header with actions and source status line, overview, OS rows and
// the Sources section. Pure: returns HTML for a case and a render context:
//   { state, config, inventory: {data, error}, tmdsOn, busy: Set, chooserOpen, groupOverride: Map, now }
import { VENDORS, PRODUCTS, vendorURL, groupFixes, splitPackage } from '../data.js';
import { rowAssessment, CNA_SOURCE, cleanMitigation } from '../rows.js';
import { kernelSupport, supportSummary, productInventory, isKernelFix, kspName, kernelFamilies } from '../tmds.js';
import { sourceCards, sourceSummary, SOURCE_STATES } from '../sources.js';
import { esc, safeURL, externalLink, sourceLink, isSafeURL, date, time, day, plural, icons } from '../util.js';
import { labels, badge, selected, sum, statusCounts, logo } from './common.js';

export function renderCase(c, ctx) {
  const s = sum(c.record, ctx.state.cvss);
  // Source cards follow the user's OS order.
  const order = orderedVendors(ctx.state).map((v) => v.id);
  const products = selected(c).sort((a, b) => order.indexOf(a.family) - order.indexOf(b.family));
  const cards = sourceCards(c, products, { tmds: ctx.tmdsOn, inventory: ctx.inventory, now: ctx.now });
  return [
    caseHeader(c, s, ctx, sourceSummary(cards)),
    caseAlerts(c, s),
    caseOverview(c, s, ctx),
    productsSection(c, ctx),
    sourcesSection(cards),
  ].join('');
}

// Header: title block, a compact action group and one status line linking to Sources.
function caseHeader(c, s, ctx, summary) {
  const loading = ctx.busy.has(c.id);
  const action = (id, icon, label, attrs = '') =>
    `<button type="button" id="${id}" class="case-action" aria-label="${label}" title="${label}" ${attrs}>${icon}<span class="case-action-label">${label}</span></button>`;
  const actions = [
    action('share-case', icons.share, 'Share'),
    action('archive-case', c.archived ? icons.unarchive : icons.archive, c.archived ? 'Unarchive' : 'Archive'),
    ctx.config.manualRefresh
      ? action('refresh', icons.refresh, loading ? 'Checking…' : 'Refresh', loading ? 'disabled' : '')
      : '',
  ].join('');
  const parts = [
    loading
      ? '<span>Checking sources…</span>'
      : `<span>Sources checked ${summary.checked ? esc(date(summary.checked)) : 'never'}</span>`,
    `<span>${plural(summary.count, 'source')}</span>`,
    summary.warnings ? `<span class="status-line-warning">${plural(summary.warnings, 'warning')}</span>` : '',
  ].join('');
  return [
    '<header class="case-header">',
    '<div class="case-heading">',
    `<h1>${esc(c.id)}</h1>`,
    `<p class="case-title">${esc(s.title)}</p>`,
    `<p class="case-status-line" ${loading ? 'aria-busy="true"' : ''}>`,
    `<a href="#case-sources" class="status-link" data-scroll="case-sources" aria-label="${esc(
      `${loading ? 'Checking sources' : `Sources checked ${summary.checked ? date(summary.checked) : 'never'}`}, ${plural(summary.count, 'source')}${summary.warnings ? `, ${plural(summary.warnings, 'warning')}` : ''}. Show sources`,
    )}">${parts}</a>`,
    '</p>',
    '</div>',
    `<div class="case-toolbar" role="group" aria-label="Case actions">${actions}</div>`,
    '</header>',
  ].join('');
}

function caseAlerts(c, s) {
  const alerts = [];
  if (c.archived) {
    const until = 'This case is not checked for updates until you unarchive it.';
    alerts.push(`<div class="alert archived-note">Archived ${esc(date(c.archived))}. ${until}</div>`);
  }
  if (c.error) {
    const fallback = c.record ? 'Showing the last saved snapshot.' : 'It will be retried automatically.';
    alerts.push(`<div class="alert" role="alert">${esc(c.error)} ${fallback}</div>`);
  }
  if (s.rejected)
    alerts.push('<div class="alert">This CVE has been rejected. Review the source before taking action.</div>');
  return alerts.join('');
}

function caseOverview(c, s, ctx) {
  const preferred = ctx.state.cvss || '3.1';
  const fallback =
    s.score != null && s.cvssVersion !== preferred
      ? `title="CVSS ${esc(preferred)} not published; showing ${esc(s.cvssVersion)}"`
      : '';
  const score = [
    `<div class="score ${esc(s.severity.toLowerCase())}">`,
    `<strong>${esc(s.score ?? '—')}</strong>`,
    `<span ${fallback}>${esc(s.severity)}${s.score != null ? ` · CVSS ${esc(s.cvssVersion)}` : ''}</span>`,
    '</div>',
  ].join('');
  const updated = s.updated && day(s.updated) !== day(s.published) ? `<span>Updated ${day(s.updated)}</span>` : '';
  const dates = s.published ? `<p class="case-dates"><span>Published ${day(s.published)}</span>${updated}</p>` : '';
  const description = [
    '<details class="description" data-detail="description">',
    '<summary>Vulnerability description</summary>',
    `<p>${esc(s.description)}</p>`,
    s.vector ? `<code>${esc(s.vector)}</code>` : '',
    '</details>',
  ].join('');
  const references = [
    externalLink(`https://www.cve.org/CVERecord?id=${c.id}`, 'CVE record ↗'),
    externalLink(`https://nvd.nist.gov/vuln/detail/${c.id}`, 'NIST / NVD ↗'),
    externalLink('https://euvd.enisa.europa.eu/', 'EUVD search ↗'),
  ].join('');
  return [
    '<section class="overview panel">',
    score,
    '<div class="overview-content">',
    `<div class="overview-meta"><div class="eyebrow">${esc(s.category)}</div>${dates}</div>`,
    description,
    `<div class="reference-links">${references}</div>`,
    '</div>',
    '</section>',
  ].join('');
}

// OS choices (also used by Settings)
export function orderedVendors(state) {
  const order = Array.isArray(state.osOrder) ? state.osOrder : [];
  const position = (v) => (order.includes(v.id) ? order.indexOf(v.id) : 99);
  return [...VENDORS].sort((a, b) => position(a) - position(b));
}
function vendorChoice(v, ids, sortable) {
  const products = PRODUCTS.filter((p) => p.family === v.id),
    count = products.filter((p) => ids.includes(p.id)).length;
  const handle = sortable
    ? `<button type="button" class="drag-handle" data-handle="${v.id}" aria-label="Move ${esc(v.name)}. Drag, or press the up and down arrow keys." title="Drag to reorder">${icons.grip}</button>`
    : '';
  const version = (p) =>
    [
      '<label class="version-chip">',
      `<input type="checkbox" value="${p.id}" ${ids.includes(p.id) ? 'checked' : ''}>`,
      `<span>${esc(p.version)}</span>`,
      '</label>',
    ].join('');
  const selection = count ? `${count} of ${products.length} selected` : 'None selected';
  return [
    `<div class="vendor-choice ${count ? 'enabled' : ''}" data-vendor="${v.id}">`,
    handle,
    '<div class="vendor-choice-name">',
    logo(v.id),
    `<div><strong>${esc(v.name)}</strong><small>${selection}</small></div>`,
    '</div>',
    `<div class="version-choices" role="group" aria-label="${esc(v.name)} versions">${products.map(version).join('')}</div>`,
    '</div>',
  ].join('');
}
export function choices(state, ids, sortable = false) {
  return orderedVendors(state)
    .map((v) => vendorChoice(v, ids, sortable))
    .join('');
}

function productsSection(c, ctx) {
  const rows = groupRows(c, ctx) || '<p class="empty-row">Select products to start assessing this case.</p>';
  return [
    '<section class="products-section">',
    '<div class="section-heading">',
    `<div><h2>Operating systems <span class="count">${c.products.length}</span></h2></div>`,
    `<button type="button" id="edit-products" class="disclosure-button" aria-expanded="${ctx.chooserOpen}" aria-controls="case-products">${icons.chevron}Choose OS versions</button>`,
    '</div>',
    `<div id="case-products" class="product-choices panel" ${ctx.chooserOpen ? '' : 'hidden'}>${choices(ctx.state, c.products)}</div>`,
    '<div class="panel product-table">',
    unlistedNote(c, ctx),
    rows,
    '</div>',
    '</section>',
  ].join('');
}
function unlistedNote(c, ctx) {
  if (!c.record || ctx.busy.has(c.id)) return '';
  const rows = selected(c);
  if (!rows.length || rows.some((p) => rowAssessment(c, p).assessment.evidence.length)) return '';
  const affected = c.record.containers?.cna?.affected || [];
  const listed = [
    ...new Set(affected.map((a) => [a.vendor, a.product].filter((v) => v && v !== 'n/a').join(' ')).filter(Boolean)),
  ];
  const more = listed.length > 3 ? ` and ${listed.length - 3} more` : '';
  const names = listed.length ? ` The CVE record names ${esc(listed.slice(0, 3).join(', '))}${more}.` : '';
  return `<p class="unlisted-note">None of the selected OS vendors list this CVE.${names}</p>`;
}
function groupRows(c, ctx) {
  return orderedVendors(ctx.state)
    .map((v) => osGroup(c, v, ctx))
    .join('');
}
function osGroup(c, v, ctx) {
  const rows = selected(c).filter((p) => p.family === v.id);
  if (!rows.length) return '';
  const counts = statusCounts(c, rows),
    key = `${c.id}:${v.id}`;
  const quiet =
    counts.unaffected + counts.unknown === rows.length && !rows.some((p) => c.changedRows?.ids?.includes(p.id));
  const open = ctx.groupOverride.has(key) ? ctx.groupOverride.get(key) : !quiet;
  const statuses = Object.entries(counts)
    .filter(([, n]) => n)
    .map(([s, n]) => `<span class="status ${s}">${n} ${labels[s]}</span>`)
    .join('');
  return [
    `<details class="os-group ${quiet ? 'quiet' : ''}" data-os="${key}" ${open ? 'open' : ''}>`,
    `<summary>${icons.chevron}${logo(v.id)}<strong>${esc(v.name)}</strong>`,
    `<span class="os-status-summary">${statuses}</span></summary>`,
    rows.map((p) => productRow(c, p, ctx)).join(''),
    '</details>',
  ].join('');
}

// Where a piece of evidence came from: vendor feed, CVE record (CNA statement) or an imported file.
function sourceRef(c, p, name) {
  let url;
  if (name === CNA_SOURCE) url = `https://www.cve.org/CVERecord?id=${c.id}`;
  else url = c.vendorData?.sources?.[p.family]?.url || vendorURL(p, c.id);
  return url && isSafeURL(url) ? externalLink(safeURL(url), `${esc(name)} ↗`) : `${esc(name)} (local file)`;
}
function advisoryLabel(url) {
  const last = String(url).split('/').filter(Boolean).pop() || String(url);
  try {
    return esc(decodeURIComponent(last));
  } catch {
    return esc(last); // Malformed percent-encoding: show it as published.
  }
}
// Row-level advisories stay with the version they apply to; vendor data links live in Sources.
function rowAdvisories(p, row) {
  const advisories = row.advisories.filter(isSafeURL);
  if (!advisories.length) return '';
  const link = (url) => externalLink(safeURL(url), `${advisoryLabel(url)} ↗`);
  const extra = advisories.slice(2);
  const more = extra.length
    ? `<details class="advisory-list" data-detail="${p.id}:advisories"><summary aria-label="Show ${extra.length} more advisor${extra.length === 1 ? 'y' : 'ies'}">+${extra.length}</summary><div>${extra.map(link).join('')}</div></details>`
    : '';
  return `<div class="row-advisories"><span>Advisor${advisories.length > 1 ? 'ies' : 'y'}: ${advisories.slice(0, 2).map(link).join(', ')}</span>${more}</div>`;
}

// One line of the fix column. With details it expands in place, below its own summary.
// `key` identifies the details element so it stays open across re-renders.
function fact(label, value, body = '', cls = '', key = '') {
  const head = `<span class="fact-label">${label}</span><span class="fact-value">${value}</span>`;
  return body
    ? `<details class="fact ${cls}" data-detail="${key}"><summary>${head}${icons.chevron}</summary><div class="fact-body">${body}</div></details>`
    : `<div class="fact ${cls}">${head}</div>`;
}

// Windows: label builds by release (23H2 · 22H3), main edition first, newest build first.
function labelWindowsBuilds(groups) {
  const release = (n) => n.replace(/^windows (?:\d+|server \d{4})\b,?\s*(?:version\s*)?/i, '') || n;
  for (const g of groups) g.main = [...new Set(g.packages.map((f) => release(splitPackage(f).name)))].join(' · ');
  const edition = (g) => (/edition/i.test(g.main) ? 1 : 0);
  groups.sort((x, y) => edition(x) - edition(y) || y.version.localeCompare(x.version, undefined, { numeric: true }));
}
const buildLabel = (g) => (g.version ? `<code><span>${esc(g.main)}</span> ${esc(g.version)}</code>` : esc(g.main));
const packageCount = (n) => plural(n, 'package');
// Closed: the main build. Open: a count, with every build listed once below by package name.
function fixFact(groups, windows, key) {
  if (!groups.length) return fact('Fix', '<span class="fact-none">None in available evidence</span>');
  const [first] = groups,
    total = groups.reduce((n, g) => n + g.packages.length, 0);
  let more = '';
  if (groups.length > 1)
    more = ` <span class="fact-more">+${plural(groups.length - 1, 'more build', 'more builds')}</span>`;
  else if (first.packages.length > 1 && !windows)
    more = ` <span class="fact-more">${packageCount(first.packages.length)}</span>`;
  const builds = `${plural(groups.length, 'build')}${windows ? '' : ` · ${packageCount(total)}`}`;
  const value = `<span class="when-closed">${buildLabel(first)}${more}</span><span class="when-open">${builds}</span>`;
  const packages = (g) => {
    if (windows) return '';
    const names = g.packages.map((f) => `<span>${esc(g.version ? splitPackage(f).name : f)}</span>`);
    return `<div class="package-list">${names.join('')}</div>`;
  };
  const build = (g) => `<div class="build"><div class="build-head">${buildLabel(g)}</div>${packages(g)}</div>`;
  const body = groups.length > 1 || first.packages.length > 1 ? groups.map(build).join('') : '';
  return fact('Fix', value, body, 'fix', key);
}
// Each mitigation lists the sources that published it.
function mitigationFact(c, p, mitigations, row) {
  if (!mitigations.length) return fact('Mitigation', '<span class="fact-none">None reported</span>');
  const first = mitigations[0].text.split('\n').find((l) => l.trim());
  const more = mitigations.length > 1 ? ` <span class="fact-more">+${mitigations.length - 1}</span>` : '';
  const attribution = (m) =>
    m.sources
      .map((name) => {
        // Prefer the human advisory attached to the evidence carrying this mitigation.
        const advisories = row.assessment.evidence
          .filter(
            (e) =>
              (e.source || CNA_SOURCE) === name &&
              (e.mitigation || []).some((text) => cleanMitigation(text) === m.text),
          )
          .flatMap((e) => e.links || [])
          .filter((url) => isSafeURL(url) && !/\.(?:json|xml)(?:[?#]|$)|\/(?:csaf|vex)\//i.test(url));
        if (advisories.length)
          return [...new Set(advisories)]
            .map((url) => externalLink(safeURL(url), `${advisoryLabel(url)} ↗`))
            .join(', ');
        if (name !== CNA_SOURCE) return externalLink(safeURL(vendorURL(p, c.id)), `${esc(p.vendor)} advisory ↗`);
        return sourceRef(c, p, name);
      })
      .join(', ');
  const body = mitigations
    .map(
      (m) =>
        `<div class="mitigation-item"><p>${esc(m.text)}</p><p class="fact-source">Source: ${attribution(m)}</p></div>`,
    )
    .join('');
  return fact(
    'Mitigation',
    `<span class="when-closed"><span class="fact-text">${esc(first)}</span>${more}</span><span class="when-open">${plural(mitigations.length, 'mitigation')}</span>`,
    body,
    'mitigation',
    `${p.id}:mitigation`,
  );
}

// TMDS
export const tmdsLabels = {
  supported: 'Supported',
  partial: 'Partly supported',
  pending: 'Not yet supported',
  unknown: 'Not verifiable',
};
const DEBIAN_ABI =
  'Debian kernels named by ABI (such as 6.1.0-N-amd64) do not reveal the package version, so this cannot be matched automatically.';
// The fix is a later package revision of an upstream version that is listed (Debian respins).
const revisionText = (kernel) =>
  `Lists <code>${esc(kernel)}</code> of the same upstream version; whether that build includes this package revision cannot be verified.`;
function agentText(cell, family) {
  const a = cell.agent;
  if (a.revision) return `Agent ${esc(a.release.release)}: ${revisionText(a.kernel)}`;
  if (a.status === 'supported') {
    const kind = a.exact ? 'bundles' : 'bundles newer';
    return `${sourceLink(a.release.download, `Agent ${a.release.release} or later`)} · ${kind} <code>${esc(a.kernel)}</code>`;
  }
  if (a.status === 'pending')
    return `Not bundled yet (newest bundled: <code>${esc(a.kernel)}</code> in Agent ${esc(a.release.release)})`;
  if (a.status === 'unknown') return family === 'debian' ? DEBIAN_ABI : 'No bundled kernel of this stream.';
  return 'No agent package for this architecture in the inventory.';
}
function kspText(cell, family) {
  const k = cell.ksp;
  if (k.status === 'supported' || k.status === 'partial') {
    const since = k.since
      ? `supports it since KSP ${esc(k.since)}`
      : `supports it in the current KSP ${esc(k.entry.release)} or earlier`;
    const delta = k.partial
      ? ' · <abbr title="Only WRS/FW/IPS features in the latest KSP">Δ</abbr> WRS/FW/IPS only'
      : '';
    return `${sourceLink(k.entry.download, kspName(k.entry))} — ${since} (lists <code>${esc(k.kernel)}</code>)${delta}`;
  }
  if (k.revision) return revisionText(k.kernel);
  if (k.status === 'pending') return `Not yet supported (newest listed: <code>${esc(k.kernel)}</code>)`;
  if (k.status === 'unknown') return family === 'debian' ? DEBIAN_ABI : 'No listed kernel of this stream.';
  return 'No Kernel Support Package for this architecture.';
}
function tmdsBranch(b, family, many) {
  // Architectures with the same result share one entry.
  const groups = new Map();
  for (const cell of b.cells) {
    const html = `<p><strong>Agent (bundled):</strong> ${agentText(cell, family)}</p><p><strong>Kernel Support Package:</strong> ${kspText(cell, family)}</p>`;
    groups.set(html, [...(groups.get(html) || []), cell.arch]);
  }
  const cells = [...groups].map(([html, arches]) => `<div><dt>${esc(arches.join(', '))}</dt><dd>${html}</dd></div>`);
  const head = many
    ? `<div class="tmds-branch-head"><span class="dot"></span><code>${esc(b.fix)}</code><span>${tmdsLabels[b.status] || 'No data'}</span></div>`
    : '';
  return `<div class="tmds-branch ${b.status}">${head}<dl class="tmds-cells">${cells.join('')}</dl></div>`;
}
function tmdsFact(p, fixes, ctx) {
  // Only families Trend Micro kernel lists can be matched for (not Alpine or Windows).
  if (!kernelFamilies.includes(p.family)) return '';
  const kernels = fixes.filter(isKernelFix);
  if (!kernels.length) return '';
  const { data, error } = ctx.inventory;
  if (!data) {
    const text = error ? 'Inventory unavailable right now' : 'Checking inventory…';
    return fact('TMDS', `<span class="tmds-state unknown">${text}</span>`, '', 'tmds');
  }
  const t = kernelSupport(p.family, kernels, productInventory(data, p.id));
  if (t.status === 'none') return '';
  const many = t.branches.length > 1;
  const notes = [];
  if (t.arches.length > 1 && t.primary.length === 1)
    notes.push(`Status reflects ${t.primary[0]}; other architectures are listed separately.`);
  if (t.branches.some((b) => b.cells.some((c) => c.ksp.partial)))
    notes.push('Δ: the latest KSP supports only the WRS, firewall and IPS features for this kernel.');
  for (const n of data.ksp?.notes || []) if (typeof n === 'string') notes.push(n);
  notes.push(
    'Matched against kernels bundled in Deep Security Agent 20 LTS and the published Kernel Support Package list. This is package and catalog evidence, not a runtime certification.',
  );
  const items = t.branches.length
    ? t.branches.map((b) => tmdsBranch(b, p.family, many)).join('')
    : `<p>${p.family === 'debian' ? DEBIAN_ABI : 'No comparable kernel in the inventory.'}</p>`;
  const body = `${items}${notes.map((n) => `<p class="fact-note">${esc(n)}</p>`).join('')}`;
  const label = tmdsLabels[t.status];
  const value = `<span class="tmds-state ${t.status}" title="${label}"><span class="dot"></span><span class="visually-hidden">${label}: </span>${esc(supportSummary(t))}</span>`;
  return fact('TMDS', value, body, `tmds ${t.status}`, `${p.id}:tmds`);
}

function productRow(c, p, ctx) {
  const row = rowAssessment(c, p),
    a = row.assessment;
  const groups = groupFixes(row.fixes),
    windows = p.family === 'windows';
  if (windows) labelWindowsBuilds(groups);
  const changed = c.changedRows?.ids?.includes(p.id);
  const updated = changed
    ? `<span class="row-updated" title="Changed in the update of ${esc(date(c.changedRows.at))}">Updated</span>`
    : '';
  const assessment = [
    badge(row.status),
    a.fixAvailable && a.status === 'affected' ? '<small>Older builds / other components remain affected</small>' : '',
    row.status === 'inconclusive' ? '<small>Available evidence does not establish status</small>' : '',
    row.notes.length && row.notes.length <= 2 ? row.notes.map((n) => `<small>${esc(n)}</small>`).join('') : '',
    rowAdvisories(p, row),
  ].join('');
  const facts = [
    fixFact(groups, windows, `${p.id}:fix`),
    ctx.tmdsOn ? tmdsFact(p, row.fixes, ctx) : '',
    mitigationFact(c, p, row.mitigations, row),
  ];
  return [
    `<div class="product-row ${changed ? 'changed' : ''}" data-row="${p.id}">`,
    `<div class="product-name"><strong>${esc(p.name)}</strong><div class="assessment">${assessment}</div>${updated}</div>`,
    `<div class="fix-summary">${facts.join('')}</div>`,
    '</div>',
  ].join('');
}

// Sources section: one card per source with state, times, link, warnings and notes.
function sourceCard(s) {
  const rows = [
    s.checked ? `<div><dt>Checked</dt><dd>${esc(date(s.checked))}</dd></div>` : '',
    s.updated
      ? `<div><dt>Source updated</dt><dd>${esc(typeof s.updated === 'number' || /^\d{4}-/.test(s.updated) ? date(s.updated) : s.updated)}</dd></div>`
      : '',
  ].join('');
  const retry = s.retryAfter ? ` Next attempt ${esc(time(s.retryAfter))}.` : '';
  const warnings = s.warnings.map((w, i) => `<p class="source-warning">${esc(w)}${i === 0 ? retry : ''}</p>`).join('');
  const images = Math.max(0, Math.floor(Number(s.excludedImages) || 0));
  const excluded = images
    ? `<p class="source-note">${plural(images, 'public-cloud image entry', 'public-cloud image entries')} not counted in OS rows; see the vendor source.</p>`
    : '';
  const advisories = s.advisories.length
    ? [
        `<details class="source-advisories" data-detail="source:${s.id}">`,
        `<summary>${icons.chevron}Advisories in source document (${s.advisories.length})</summary>`,
        "<p>Check each advisory's product and service-pack scope.</p>",
        `<div>${s.advisories.map((a) => sourceLink(a.url, a.label || a.url)).join('')}</div>`,
        '</details>',
      ].join('')
    : '';
  return [
    `<article class="source-card ${s.state}">`,
    `<header><h3>${esc(s.name)}</h3><span class="source-state ${s.state}">${SOURCE_STATES[s.state]}</span></header>`,
    rows ? `<dl class="source-times">${rows}</dl>` : '',
    s.url && isSafeURL(s.url) ? `<p class="source-link">${sourceLink(s.url, s.urlLabel)}</p>` : '',
    warnings,
    s.notes.map((n) => `<p class="source-note">${esc(n)}</p>`).join(''),
    excluded,
    advisories,
    '</article>',
  ].join('');
}
function sourcesSection(cards) {
  return [
    '<section class="sources-section" id="case-sources" aria-labelledby="sources-heading">',
    '<div class="section-heading">',
    '<h2 id="sources-heading" tabindex="-1">Sources</h2>',
    '<p class="section-hint">The server caches vendor data and re-checks watched cases every hour.</p>',
    '</div>',
    `<div class="source-grid">${cards.map(sourceCard).join('')}</div>`,
    '</section>',
  ].join('');
}
