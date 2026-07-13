/**
 * IndexedDB persistence for Tor consensus and microdescriptors.
 * Used by the service worker (no sessionStorage/localStorage).
 */

import type { CachedMicrodesc } from 'browser';

const DB_NAME = 'tor-cache';
const DB_VERSION = 2;
const CONSENSUS_STORE = 'consensus';
const MICRODESCS_STORE = 'microdescs';
const DEBUG_LOG_STORE = 'debuglog';
const CONSENSUS_KEY = 'current';
const DEBUG_LOG_KEY = 'current';

// Serializable shape for CachedMicrodesc (Buffers as base64 strings)
type StoredMicrodesc = {
  lastReferenced: number;
  microdesc: {
    ntorOnionKeyB64?: string;
    ed25519IdentityB64?: string;
    exitPolicy?: { type: 'accept' | 'reject'; ports: { start: number; end: number }[] };
  };
};

function openDB(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onerror = () => reject(req.error);
    req.onsuccess = () => resolve(req.result);
    req.onupgradeneeded = (e) => {
      const db = (e.target as IDBOpenDBRequest).result;
      if (!db.objectStoreNames.contains(CONSENSUS_STORE)) {
        db.createObjectStore(CONSENSUS_STORE);
      }
      if (!db.objectStoreNames.contains(MICRODESCS_STORE)) {
        db.createObjectStore(MICRODESCS_STORE, { keyPath: null });
      }
      if (!db.objectStoreNames.contains(DEBUG_LOG_STORE)) {
        db.createObjectStore(DEBUG_LOG_STORE);
      }
    };
  });
}

function toStored(entry: CachedMicrodesc): StoredMicrodesc {
  const md = entry.microdesc;
  const microdesc: StoredMicrodesc['microdesc'] = {};
  if (md.ntorOnionKey?.length) {
    microdesc.ntorOnionKeyB64 = Buffer.from(md.ntorOnionKey).toString('base64');
  }
  if (md.ed25519Identity?.length) {
    microdesc.ed25519IdentityB64 = Buffer.from(md.ed25519Identity).toString('base64');
  }
  if (md.exitPolicy) {
    microdesc.exitPolicy = md.exitPolicy;
  }
  return {
    lastReferenced: entry.lastReferenced,
    microdesc,
  };
}

function fromStored(stored: StoredMicrodesc): CachedMicrodesc {
  const md = stored.microdesc;
  const microdesc: CachedMicrodesc['microdesc'] = {};
  if (md.ntorOnionKeyB64) {
    microdesc.ntorOnionKey = Buffer.from(md.ntorOnionKeyB64, 'base64');
  }
  if (md.ed25519IdentityB64) {
    microdesc.ed25519Identity = Buffer.from(md.ed25519IdentityB64, 'base64');
  }
  if (md.exitPolicy) {
    microdesc.exitPolicy = md.exitPolicy;
  }
  return { microdesc, lastReferenced: stored.lastReferenced };
}

// ---------------------------------------------------------------------------
// Consensus
// ---------------------------------------------------------------------------

export const consensusIDB = {
  async get(): Promise<string | undefined> {
    const db = await openDB();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(CONSENSUS_STORE, 'readonly');
      const store = tx.objectStore(CONSENSUS_STORE);
      const req = store.get(CONSENSUS_KEY);
      req.onerror = () => reject(req.error);
      req.onsuccess = () => {
        db.close();
        resolve(req.result as string | undefined);
      };
    });
  },

  async set(text: string): Promise<void> {
    const db = await openDB();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(CONSENSUS_STORE, 'readwrite');
      const store = tx.objectStore(CONSENSUS_STORE);
      store.put(text, CONSENSUS_KEY);
      tx.oncomplete = () => {
        db.close();
        resolve();
      };
      tx.onerror = () => reject(tx.error);
    });
  },
};

// ---------------------------------------------------------------------------
// Microdescriptors
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Debug log
// ---------------------------------------------------------------------------
//
// The service worker's debug-log ring buffer is in-memory, and the browser is
// free to kill an idle SW at any time — which is exactly the failure mode the
// log exists to diagnose. Persisting it means a freshly restarted SW can still
// hand the page the history from the instance that died.

export const debugLogIDB = {
  async load(): Promise<string[]> {
    const db = await openDB();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(DEBUG_LOG_STORE, 'readonly');
      const req = tx.objectStore(DEBUG_LOG_STORE).get(DEBUG_LOG_KEY);
      req.onerror = () => reject(req.error);
      req.onsuccess = () => {
        db.close();
        const value = req.result as unknown;
        resolve(Array.isArray(value) ? (value as string[]) : []);
      };
    });
  },

  async save(entries: string[]): Promise<void> {
    const db = await openDB();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(DEBUG_LOG_STORE, 'readwrite');
      tx.objectStore(DEBUG_LOG_STORE).put(entries, DEBUG_LOG_KEY);
      tx.oncomplete = () => {
        db.close();
        resolve();
      };
      tx.onerror = () => reject(tx.error);
    });
  },

  async clear(): Promise<void> {
    const db = await openDB();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(DEBUG_LOG_STORE, 'readwrite');
      tx.objectStore(DEBUG_LOG_STORE).clear();
      tx.oncomplete = () => {
        db.close();
        resolve();
      };
      tx.onerror = () => reject(tx.error);
    });
  },
};

export const microdescIDB = {
  async loadAll(): Promise<Map<string, CachedMicrodesc>> {
    const db = await openDB();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(MICRODESCS_STORE, 'readonly');
      const store = tx.objectStore(MICRODESCS_STORE);
      const req = store.openCursor();
      const result = new Map<string, CachedMicrodesc>();
      req.onerror = () => reject(req.error);
      req.onsuccess = () => {
        const cursor = req.result;
        if (cursor) {
          try {
            const entry = fromStored(cursor.value as StoredMicrodesc);
            result.set(cursor.key as string, entry);
          } catch {
            // Skip invalid entries
          }
          cursor.continue();
        } else {
          db.close();
          resolve(result);
        }
      };
    });
  },

  async saveAll(entries: Map<string, CachedMicrodesc>): Promise<void> {
    const db = await openDB();
    const tx = db.transaction(MICRODESCS_STORE, 'readwrite');
    const store = tx.objectStore(MICRODESCS_STORE);
    for (const [digest, entry] of entries) {
      store.put(toStored(entry), digest);
    }
    return new Promise((resolve, reject) => {
      tx.oncomplete = () => {
        db.close();
        resolve();
      };
      tx.onerror = () => reject(tx.error);
    });
  },

  async clear(): Promise<void> {
    const db = await openDB();
    const tx = db.transaction(MICRODESCS_STORE, 'readwrite');
    tx.objectStore(MICRODESCS_STORE).clear();
    return new Promise((resolve, reject) => {
      tx.oncomplete = () => {
        db.close();
        resolve();
      };
      tx.onerror = () => reject(tx.error);
    });
  },
};
