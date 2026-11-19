// Browser persistence uses IndexedDB exclusively. Each write commits atomically;
// quota or permission errors leave the last committed workspace intact.
import { defaultState, saveable, validateState } from './state.js';
import { validTheme } from './cases.js';

const DATABASE = 'isitfixed';
const STORE = 'settings';
const OPEN_TIMEOUT = 5000;

export function createStore(factory = globalThis.indexedDB) {
  let pending;
  function open() {
    if (pending) return pending;
    pending = new Promise((resolve, reject) => {
      if (!factory) {
        reject(Error('Browser storage is unavailable.'));
        return;
      }
      const request = factory.open(DATABASE, 1);
      let abandoned = false;
      const fail = (error) => {
        abandoned = true;
        clearTimeout(timer);
        reject(error);
      };
      const timer = setTimeout(() => fail(Error('Browser storage did not open in time.')), OPEN_TIMEOUT);
      request.onupgradeneeded = () => {
        if (!request.result.objectStoreNames.contains(STORE)) request.result.createObjectStore(STORE);
      };
      request.onerror = () => fail(request.error || Error('Browser storage could not be opened.'));
      request.onblocked = () => fail(Error('Browser storage upgrade is blocked by another tab.'));
      request.onsuccess = () => {
        clearTimeout(timer);
        const db = request.result;
        if (abandoned) {
          db.close();
          return;
        }
        db.onversionchange = () => {
          db.close();
          pending = null;
        };
        resolve(db);
      };
    }).catch((error) => {
      pending = null;
      throw error;
    });
    return pending;
  }
  async function transaction(mode, work) {
    const db = await open();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(STORE, mode);
      let result;
      tx.oncomplete = () => resolve(result);
      tx.onabort = tx.onerror = () => reject(tx.error || Error('Browser storage transaction failed.'));
      try {
        work(tx.objectStore(STORE), (value) => {
          result = value;
        });
      } catch (error) {
        tx.abort();
        reject(error);
      }
    });
  }
  return {
    get: (key) =>
      transaction('readonly', (store, result) => {
        store.get(key).onsuccess = (event) => result(event.target.result);
      }),
    put: (entries) =>
      transaction('readwrite', (store) => {
        for (const [key, value] of entries) store.put(value, key);
      }),
    // A read/write transaction serializes competing tabs so they share one identity.
    identity: (generate) =>
      transaction('readwrite', (store, result) => {
        store.get('identity').onsuccess = (event) => {
          let id = event.target.result;
          if (typeof id !== 'string' || !/^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/i.test(id)) {
            id = generate();
            store.put(id, 'identity');
          }
          result(id);
        };
      }),
  };
}

let browserStore;
const currentStore = () => (browserStore ||= createStore());
export async function loadWorkspace(store = currentStore()) {
  const report = {};
  let raw;
  try {
    raw = await store.get('workspace');
  } catch (error) {
    return { state: defaultState(), report, locked: false, error: error.message };
  }
  if (raw === undefined) return { state: defaultState(), report, locked: false };
  try {
    return { state: validateState(structuredClone(raw), report), report, locked: false };
  } catch {
    return { state: defaultState(), report, locked: true, raw, error: 'The saved workspace could not be read.' };
  }
}
let writes = Promise.resolve();
export async function saveWorkspace(state, store = currentStore()) {
  if (!saveable(state)) return { saved: false, reason: 'invalid' };
  try {
    // Copy immediately: asynchronous writes must not observe later state mutations.
    const snapshot = structuredClone(state);
    for (const c of snapshot.cases) delete c.vex;
    const theme = validTheme(snapshot.theme);
    const write = writes.then(() =>
      store.put([
        ['workspace', snapshot],
        ['theme', theme],
      ]),
    );
    writes = write.catch(() => {});
    await write;
    return { saved: true };
  } catch (error) {
    return { saved: false, reason: error.name === 'QuotaExceededError' ? 'full' : 'unavailable' };
  }
}
// Asks the browser to exempt this origin from automatic eviction under storage pressure.
// Browsers decide silently (Chromium, Safari) or prompt (Firefox); any failure means "not
// persisted" and never affects saving. Resolves to whether storage is persisted.
export async function requestPersistence(storage = globalThis.navigator?.storage) {
  try {
    if (!storage?.persist) return false;
    if (storage.persisted && (await storage.persisted())) return true;
    return Boolean(await storage.persist());
  } catch {
    return false;
  }
}
export async function loadTheme(store = currentStore()) {
  try {
    return validTheme(await store.get('theme'));
  } catch {
    return 'system';
  }
}
export async function saveTheme(theme, store = currentStore()) {
  try {
    await store.put([['theme', validTheme(theme)]]);
    return true;
  } catch {
    return false;
  }
}
function generateId() {
  if (crypto.randomUUID) return crypto.randomUUID();
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  bytes[6] = (bytes[6] & 15) | 64;
  bytes[8] = (bytes[8] & 63) | 128;
  const hex = [...bytes].map((b) => b.toString(16).padStart(2, '0')).join('');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}
let identity;
export function workspaceId(store = currentStore()) {
  return (identity ||= store.identity(generateId).catch(() => generateId()));
}
