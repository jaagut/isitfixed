import { workspaceId } from './storage.js';
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

// Server reachability for the sidebar indicator. Any HTTP answer below 500 counts as contact
// (a 404 or 429 still comes from a working server); network errors, timeouts and 5xx do not.
export const connection = { lastOk: 0, lastFailure: 0 };
const connectionListeners = new Set();
export const onConnectionChange = (listener) => connectionListeners.add(listener);
export function reportContact(ok, now = Date.now()) {
  if (ok) connection.lastOk = now;
  else connection.lastFailure = now;
  for (const listener of connectionListeners) listener(connection);
}
async function send(target, options, timeout) {
  try {
    const response = await fetch(target, { ...options, signal: AbortSignal.timeout(timeout), cache: 'no-store' });
    reportContact(response.status < 500);
    return response;
  } catch {
    reportContact(false);
    throw Error(OFFLINE);
  }
}
async function request(path, options = {}, timeout = 180000) {
  const response = await send(url(path), options, timeout);
  if (!response.ok) throw await responseError(response);
  return response.json();
}
// Lightweight reachability check; errors are reported through the connection state only.
export const ping = () => request('/health', {}, 10000).catch(() => null);

// Server settings (GET /api/config). Unknown or missing values fall back to these.
export const DEFAULT_CONFIG = Object.freeze({
  version: null,
  commit: null,
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
    commit: typeof c.commit === 'string' && /^[0-9a-f]{7,64}$/.test(c.commit) ? c.commit : null,
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
export async function syncWatches(cases) {
  return request(`/workspaces/${await workspaceId()}/watches`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ cases: cases.map((c) => ({ id: c.id, families: families(c.products) })) }),
  });
}

export async function streamCase(id, products, force, onArea) {
  const params = new URLSearchParams({ families: families(products).join(','), refresh: String(force) });
  const response = await send(url(`/cves/${encodeURIComponent(id)}/stream?${params}`), {}, 180000);
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
