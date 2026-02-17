/**
 * IndexedDB persistence for Tor consensus and microdescriptors.
 * Used by the service worker (no sessionStorage/localStorage).
 */

import type { CachedMicrodesc } from 'browser';

const DB_NAME = 'tor-cache';
const DB_VERSION = 1;
const CONSENSUS_STORE = 'consensus';
const MICRODESCS_STORE = 'microdescs';
const CONSENSUS_KEY = 'current';

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
    };
  });
}

function toStored(entry: CachedMicrodesc): StoredMicrodesc {
  const md = entry.microdesc;
  return {
    lastReferenced: entry.lastReferenced,
    microdesc: {
      ntorOnionKeyB64: md.ntorOnionKey?.length
        ? Buffer.from(md.ntorOnionKey).toString('base64')
        : undefined,
      ed25519IdentityB64: md.ed25519Identity?.length
        ? Buffer.from(md.ed25519Identity).toString('base64')
        : undefined,
      exitPolicy: md.exitPolicy,
    },
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
