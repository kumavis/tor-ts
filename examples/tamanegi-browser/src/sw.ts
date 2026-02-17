/**
 * Service worker: runs the Tor client (Snowflake, circuits, fetch).
 * Communicates with the main page via postMessage.
 */
/// <reference lib="webworker" />

declare const self: ServiceWorkerGlobalScope;

import { makeBrowserTorClient } from 'browser';
import type { BrowserTorClient, CachedMicrodesc, MicrodescStorage } from 'browser';
import type { MainToSW, SWToMain } from './sw-messages.ts';
import { consensusIDB, microdescIDB } from './idb-cache.ts';

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

let client: BrowserTorClient | null = null;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async function broadcast(msg: SWToMain): Promise<void> {
  const clients = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
  for (const c of clients) {
    c.postMessage(msg);
  }
}

/** In-memory microdesc storage that flushes to IndexedDB on set (fire-and-forget). */
function createIdbBackedMicrodescStorage(initial: Map<string, CachedMicrodesc>): MicrodescStorage {
  const cache = new Map<string, CachedMicrodesc>(initial);

  const flush = (): void => {
    microdescIDB.saveAll(cache).catch((err) => {
      console.warn('[sw] microdescIDB.saveAll failed:', err);
    });
  };

  return {
    get(digests: string[]): Map<string, CachedMicrodesc> {
      const result = new Map<string, CachedMicrodesc>();
      for (const digest of digests) {
        const entry = cache.get(digest);
        if (entry) result.set(digest, entry);
      }
      return result;
    },
    set(entries: Map<string, CachedMicrodesc>): void {
      for (const [digest, entry] of entries) {
        cache.set(digest, entry);
      }
      flush();
    },
    updateLastReferenced(digests: string[], timestamp: number): void {
      for (const digest of digests) {
        const entry = cache.get(digest);
        if (entry) entry.lastReferenced = timestamp;
      }
      flush();
    },
    removeExpired(before: number): number {
      let removed = 0;
      for (const [digest, entry] of cache) {
        if (entry.lastReferenced < before) {
          cache.delete(digest);
          removed++;
        }
      }
      if (removed > 0) flush();
      return removed;
    },
    getAllDigests(): string[] {
      return Array.from(cache.keys());
    },
    clear(): void {
      cache.clear();
      microdescIDB.clear().catch(() => {});
    },
  };
}

// ---------------------------------------------------------------------------
// Install / Activate
// ---------------------------------------------------------------------------

self.addEventListener('install', (e: ExtendableEvent) => {
  e.waitUntil(self.skipWaiting());
});

self.addEventListener('activate', (e: ExtendableEvent) => {
  e.waitUntil(self.clients.claim());
});

// ---------------------------------------------------------------------------
// Message handling
// ---------------------------------------------------------------------------

type ConnectOptions = { relayUrl?: string; skipConsensusCache?: boolean };

async function handleConnect(options?: ConnectOptions): Promise<void> {
  if (client) {
    await broadcast({ type: 'state', state: 'connected' });
    return;
  }

  try {
    await broadcast({ type: 'state', state: 'connecting' });

    const [cachedConsensus, microdescMap] = await Promise.all([
      consensusIDB.get(),
      microdescIDB.loadAll(),
    ]);

    const microdescStorage = createIdbBackedMicrodescStorage(microdescMap);

    const { client: c, channel: ch } = await makeBrowserTorClient({
      relayUrl: options?.relayUrl,
      skipConsensusCache: options?.skipConsensusCache ?? false,
      cachedConsensusText: cachedConsensus,
      microdescStorage,
      onConsensusUpdate: (raw) => {
        consensusIDB.set(raw).catch((err) => console.warn('[sw] consensusIDB.set failed:', err));
      },
      onStatus: (message) => {
        broadcast({ type: 'status', message });
      },
      onConsensusProgress: (progress) => {
        broadcast({ type: 'consensusProgress', progress });
      },
      onMicrodescProgress: (progress) => {
        broadcast({
          type: 'microdescProgress',
          progress: {
            fetched: progress.fetched,
            total: progress.total,
            cached: progress.cached,
          },
        });
      },
    });

    client = c;

    // Teardown detection: when channel is destroyed, notify clients
    const origDestroy = ch.destroy.bind(ch);
    ch.destroy = () => {
      origDestroy();
      broadcast({ type: 'disconnected', reason: 'channel destroyed' });
      client = null;
    };

    await broadcast({ type: 'connected' });
    await broadcast({ type: 'state', state: 'connected' });
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    await broadcast({ type: 'error', error: message });
    await broadcast({ type: 'state', state: 'disconnected' });
    client = null;
  }
}

async function handleFetch(requestId: string, url: string, timeout?: number): Promise<void> {
  if (!client) {
    await broadcast({ type: 'fetchError', requestId, error: 'Tor client not connected' });
    return;
  }
  try {
    const response = await client.fetch(url, { timeout });
    await broadcast({
      type: 'fetchResult',
      requestId,
      status: response.status,
      statusText: response.statusText,
      body: response.body,
    });
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    await broadcast({ type: 'fetchError', requestId, error: message });
    // If the client/channel died during fetch, broadcast disconnected
    if (!client) {
      await broadcast({ type: 'disconnected', reason: 'connection lost during fetch' });
    }
  }
}

function handleDestroy(): void {
  if (client) {
    try {
      client.destroy();
    } catch {
      // ignore
    }
    client = null;
    void broadcast({ type: 'disconnected', reason: 'destroyed' });
    void broadcast({ type: 'state', state: 'disconnected' });
  }
}

function handleGetState(): void {
  const state: 'idle' | 'connecting' | 'connected' | 'disconnected' = client ? 'connected' : 'idle';
  void broadcast({ type: 'state', state });
}

self.addEventListener('message', (e: ExtendableMessageEvent) => {
  const msg = e.data as MainToSW;
  if (!msg || typeof msg !== 'object' || !('type' in msg)) return;

  try {
    switch (msg.type) {
      case 'connect':
        void handleConnect(msg.options);
        break;
      case 'fetch':
        void handleFetch(msg.requestId, msg.url, msg.timeout);
        break;
      case 'refreshConsensus':
        if (client) {
          client.refreshConsensus().catch((err) => {
            broadcast({
              type: 'error',
              error: err instanceof Error ? err.message : String(err),
            });
          });
        }
        break;
      case 'destroy':
        handleDestroy();
        break;
      case 'getState':
        void handleGetState();
        break;
      default:
        break;
    }
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    void broadcast({ type: 'error', error: message });
  }
});
