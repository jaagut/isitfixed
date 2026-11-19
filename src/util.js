// Shared HTML, link and time helpers. Pure: no DOM or storage access.

const ESCAPES = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };
export const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ESCAPES[c]);

export const HOUR = 3600000;

// Escaped https URL for an attribute, or '#' for anything else.
export function safeURL(url) {
  try {
    const u = new URL(url);
    return u.protocol === 'https:' ? esc(u.href) : '#';
  } catch {
    return '#';
  }
}
export const isSafeURL = (url) => safeURL(url) !== '#';
// `href` must already be safe for an attribute (see safeURL); `text` is HTML.
export const externalLink = (href, text) => `<a href="${href}" target="_blank" rel="noopener noreferrer">${text}</a>`;
// External link with a trailing arrow, or the plain text when the URL is not https.
export const sourceLink = (url, text) => (isSafeURL(url) ? externalLink(safeURL(url), `${esc(text)} ↗`) : esc(text));

export const date = (t) =>
  t
    ? new Date(t).toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })
    : 'Never';
export const time = (t) => new Date(t).toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' });
export const day = (t) =>
  t ? new Date(t).toLocaleDateString(undefined, { day: 'numeric', month: 'short', year: 'numeric' }) : '';
export function ago(t, now = Date.now()) {
  if (!t) return 'never';
  const m = Math.round((now - t) / 60000);
  if (m < 1) return 'just now';
  if (m < 60) return `${m} min ago`;
  if (m < 1440) return `${Math.round(m / 60)} h ago`;
  return `${Math.round(m / 1440)} d ago`;
}
export const plural = (n, word, many = `${word}s`) => `${n} ${n === 1 ? word : many}`;

// Icons
const svgIcon = (path) =>
  `<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="${path}"/></svg>`;
export const icons = {
  share: svgIcon('M12 15V3M8 7l4-4 4 4M5 12v7a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2v-7'),
  archive: svgIcon('M3 4h18v4H3zM5 8v12h14V8M10 12h4'),
  unarchive: svgIcon('M3 4h18v4H3zM5 8v12h14V8M12 18v-6M9 14l3-3 3 3'),
  trash: svgIcon('M3 6h18M9 6V4h6v2M5 6l1 14h12l1-14M10 10v6M14 10v6'),
  refresh: svgIcon('M20 11a8 8 0 1 0-2.3 5.7M20 4v7h-7'),
  chevron:
    '<svg class="chevron" viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m9 6 6 6-6 6"/></svg>',
  grip: [
    '<svg viewBox="0 0 24 24" width="16" height="16" fill="currentColor" aria-hidden="true">',
    '<circle cx="9" cy="6" r="1.6"/><circle cx="15" cy="6" r="1.6"/>',
    '<circle cx="9" cy="12" r="1.6"/><circle cx="15" cy="12" r="1.6"/>',
    '<circle cx="9" cy="18" r="1.6"/><circle cx="15" cy="18" r="1.6"/>',
    '</svg>',
  ].join(''),
};
