import { API_BASE } from './config.js';
import { PRODUCTS } from './data.js';
const implemented = new Set(['rhel', 'sles', 'debian', 'ubuntu', 'alpine']);
const families = (products) =>
  [
    ...new Set(products.map((id) => PRODUCTS.find((p) => p.id === id)?.family).filter((f) => implemented.has(f))),
  ].sort();
const url = (path) => `${API_BASE.replace(/\/$/, '')}${path}`;
const OFFLINE =
  'CVE API unavailable. Check your connection or backend configuration. Saved evidence is still available.';
// User-facing error for a failed response: the API's `detail`, plus when to retry after a 429.
export async function responseError(response) {
  let message = `CVE API returned HTTP ${response.status}.`;
  try {
    const body = await response.json();
    if (typeof body.detail === 'string') message = body.detail;
  } catch {
    /* Non-JSON error body: keep the HTTP status message. */
  }
  const retry = Number(response.headers?.get?.('Retry-After'));
  if (response.status === 429 && retry > 0)
    message += ` Try again in ${retry < 90 ? `${Math.ceil(retry)} s` : `${Math.ceil(retry / 60)} min`}.`;
  const error = Error(message);
  error.status = response.status;
  if (retry > 0) error.retryAfter = retry;
  return error;
}
async function request(path, options = {}, timeout = 180000) {
  let response;
  try {
    response = await fetch(url(path), { ...options, signal: AbortSignal.timeout(timeout), cache: 'no-store' });
  } catch {
    throw Error(OFFLINE);
  }
  if (!response.ok) throw await responseError(response);
  return response.json();
}

// Server settings (GET /api/config). Unknown or missing values fall back to these.
export const DEFAULT_CONFIG = Object.freeze({
  version: null,
  manualRefresh: false,
  tmds: true,
  legal: Object.freeze({ imprint: false, privacy: false }),
  sourceUrl: null,
  retentionDays: null,
});
export function normalizeConfig(raw) {
  const c = raw && typeof raw === 'object' ? raw : {};
  let sourceUrl = null;
  try {
    if (typeof c.sourceUrl === 'string' && new URL(c.sourceUrl).protocol === 'https:') sourceUrl = c.sourceUrl;
  } catch {
    /* Not a URL: no source link. */
  }
  return {
    version: typeof c.version === 'string' ? c.version : null,
    manualRefresh: c.manualRefresh === true,
    tmds: c.tmds !== false,
    legal: { imprint: c.legal?.imprint === true, privacy: c.legal?.privacy === true },
    sourceUrl,
    retentionDays: Number.isFinite(c.retentionDays) ? c.retentionDays : null,
  };
}
// Never fails: an unreachable or old backend yields the defaults.
export async function fetchConfig() {
  try {
    return normalizeConfig(await request('/config', {}, 10000));
  } catch {
    return normalizeConfig(null);
  }
}

export async function fetchCase(id, products, force = false) {
  const params = new URLSearchParams({ families: families(products).join(','), refresh: String(force) });
  const data = await request(`/cves/${encodeURIComponent(id)}?${params}`);
  if (data.id !== id || data.vendorData?.id !== id) throw Error('CVE API returned mismatched case data.');
  return data;
}
let workspace;
function workspaceId() {
  if (workspace) return workspace;
  // Preserve the existing anonymous watch identity across the product rename.
  workspace = localStorage.getItem('cve-desk-workspace');
  if (!workspace) {
    if (crypto.randomUUID) workspace = crypto.randomUUID();
    else {
      const bytes = crypto.getRandomValues(new Uint8Array(16));
      bytes[6] = (bytes[6] & 15) | 64;
      bytes[8] = (bytes[8] & 63) | 128;
      const hex = [...bytes].map((b) => b.toString(16).padStart(2, '0')).join('');
      workspace = `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
    }
    localStorage.setItem('cve-desk-workspace', workspace);
  }
  return workspace;
}
export async function syncWatches(cases) {
  return request(`/workspaces/${workspaceId()}/watches`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ cases: cases.map((c) => ({ id: c.id, families: families(c.products) })) }),
  });
}

export async function streamCase(id, products, force, onArea) {
  const params = new URLSearchParams({ families: families(products).join(','), refresh: String(force) });
  let response;
  try {
    response = await fetch(url(`/cves/${encodeURIComponent(id)}/stream?${params}`), {
      signal: AbortSignal.timeout(180000),
      cache: 'no-store',
    });
  } catch {
    throw Error(OFFLINE);
  }
  if (!response.ok) throw await responseError(response);
  const reader = response.body.getReader(),
    decoder = new TextDecoder();
  let buffer = '',
    latest;
  const consume = (line) => {
    if (!line.trim()) return;
    const data = JSON.parse(line);
    if (data.failed) throw Error(data.error);
    if (data.id !== id || data.vendorData?.id !== id) throw Error('Mismatched case data');
    latest = data;
    onArea(data);
  };
  try {
    while (true) {
      const { value, done } = await reader.read();
      buffer += decoder.decode(value, { stream: !done });
      const lines = buffer.split('\n');
      buffer = lines.pop();
      lines.forEach(consume);
      if (done) break;
    }
    if (buffer.trim()) consume(buffer);
    return latest;
  } finally {
    await reader.cancel();
  }
}

export const fetchAgents = () => request('/tmds');
