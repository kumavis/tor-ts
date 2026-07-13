/**
 * Service worker: runs the Tor client (Snowflake, circuits, fetch).
 * Communicates with the main page via postMessage.
 */
/// <reference lib="webworker" />

declare const self: ServiceWorkerGlobalScope;

import { makeBrowserTorClient } from 'browser';
import type { BrowserTorClient, CachedMicrodesc, MicrodescStorage } from 'browser';
import { type MainToSW, type SWToMain, TOR_PROXY_PATH_SEGMENT } from './sw-messages.ts';
import { consensusIDB, debugLogIDB, microdescIDB } from './idb-cache.ts';

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

let client: BrowserTorClient | null = null;

// ---------------------------------------------------------------------------
// Debug log capture
// ---------------------------------------------------------------------------
//
// The Tor client runs here in the service worker, whose console is awkward to
// reach from devtools and impossible to hand off for analysis. So we tee every
// status/error line into an in-memory ring buffer that the page can pull via
// the `getLogs` message and offer as a download. Verbose HS diagnostics (SRV /
// time-period / HSDir-ring / per-intro-point detail) are enabled by passing
// `debug: true` to the browser client on connect, so they land here too.

const MAX_LOG_ENTRIES = 10_000;
let logBuffer: string[] = [];
let logFlushTimer: ReturnType<typeof setTimeout> | undefined;

/**
 * Persist the buffer to IndexedDB (debounced). The buffer alone dies with the
 * SW instance — and the browser killing the SW is precisely the event we most
 * need the log to survive.
 */
function scheduleLogFlush(): void {
  if (logFlushTimer !== undefined) return;
  logFlushTimer = setTimeout(() => {
    logFlushTimer = undefined;
    debugLogIDB.save([...logBuffer]).catch(() => {});
  }, 1000);
}

function captureLog(line: string): void {
  const ts = new Date().toISOString();
  logBuffer.push(`${ts} ${line}`);
  if (logBuffer.length > MAX_LOG_ENTRIES) {
    logBuffer.splice(0, logBuffer.length - MAX_LOG_ENTRIES);
  }
  scheduleLogFlush();
}

// Restore the log persisted by any previous SW instance, so an exported log
// includes history from before a restart instead of coming back empty.
const logsRestored: Promise<void> = debugLogIDB
  .load()
  .then((persisted) => {
    if (persisted.length > 0) {
      logBuffer = [...persisted, ...logBuffer].slice(-MAX_LOG_ENTRIES);
    }
  })
  .catch(() => {});

// Startup marker: a restart mid-session means the browser killed the previous
// instance (taking the Tor client with it) — make that visible in the log and
// tell any open pages so they can reset instead of waiting forever.
captureLog('[sw] service worker instance started');
void broadcast({ type: 'swStarted' });

/**
 * Full proxy path prefix derived from the SW scope so it works under any
 * deployment base path (e.g. "/" locally, "/tor-ts/" on GitHub Pages).
 */
function getProxyPathPrefix(): string {
  const scopePath = new URL(self.registration.scope).pathname;
  return `${scopePath}${TOR_PROXY_PATH_SEGMENT}`;
}

/**
 * Extract the target URL from a request path like /tor-ts/tor/https%3A%2F%2Fexample.com%2Fstyle.css
 */
function getTargetUrlFromProxyPath(pathname: string): string | null {
  const prefix = getProxyPathPrefix();
  if (!pathname.startsWith(prefix)) return null;
  const encoded = pathname.slice(prefix.length);
  if (!encoded) return null;
  try {
    return decodeURIComponent(encoded);
  } catch {
    return null;
  }
}

/**
 * Convert a Map of headers to a Headers instance for Response.
 */
function mapToHeaders(map: Map<string, string>): Headers {
  const h = new Headers();
  for (const [k, v] of map) {
    h.set(k, v);
  }
  return h;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async function broadcast(msg: SWToMain): Promise<void> {
  // Tee human-readable messages into the debug-log buffer. Progress spam
  // (consensus/microdesc byte counts) and the log dump itself are skipped.
  switch (msg.type) {
    case 'status':
      captureLog(`[status] ${msg.message}`);
      break;
    case 'error':
      captureLog(`[error] ${msg.error}`);
      break;
    case 'fetchError':
      captureLog(`[fetchError:${msg.requestId}] ${msg.error}`);
      break;
    case 'connected':
      captureLog('[connected]');
      break;
    case 'disconnected':
      captureLog(`[disconnected] ${msg.reason}`);
      break;
    default:
      break;
  }

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

type ConnectOptions = { relayUrl?: string; skipConsensusCache?: boolean; debug?: boolean };

async function handleConnect(options?: ConnectOptions): Promise<void> {
  if (client) {
    await broadcast({ type: 'state', state: 'connected' });
    return;
  }

  // Default debug on: this is a diagnostic tool and the verbose HS logs are the
  // whole point of the log capture. Callers can pass debug: false to quiet it.
  const debug = options?.debug ?? true;

  try {
    captureLog(`[connect] starting (debug=${debug}, relayUrl=${options?.relayUrl ?? 'default'})`);
    await broadcast({ type: 'state', state: 'connecting' });

    const [cachedConsensus, microdescMap] = await Promise.all([
      consensusIDB.get(),
      microdescIDB.loadAll(),
    ]);

    const microdescStorage = createIdbBackedMicrodescStorage(microdescMap);

    const { client: c, channel: ch } = await makeBrowserTorClient({
      ...(options?.relayUrl !== undefined ? { relayUrl: options.relayUrl } : {}),
      debug,
      skipConsensusCache: options?.skipConsensusCache ?? false,
      ...(cachedConsensus !== undefined ? { cachedConsensusText: cachedConsensus } : {}),
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
  captureLog(`[fetch:${requestId}] ${url} (timeout=${timeout ?? 'default'})`);
  try {
    const response = await client.fetch(url, timeout !== undefined ? { timeout } : {});
    captureLog(`[fetch:${requestId}] ${response.status} ${response.statusText}`);
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

async function handleGetLogs(): Promise<void> {
  // Make sure any log persisted by a previous SW instance has been merged in
  // before answering, then snapshot the buffer so the page gets a stable copy.
  await logsRestored;
  await broadcast({ type: 'logs', entries: [...logBuffer] });
}

// ---------------------------------------------------------------------------
// Fetch: intercept /tor/<encoded-url> and fulfill over Tor
// ---------------------------------------------------------------------------

const TOR_PROXY_TIMEOUT_MS = 30_000;

async function handleProxyFetch(request: Request): Promise<Response> {
  const url = new URL(request.url);
  const targetUrl = getTargetUrlFromProxyPath(url.pathname);

  if (!targetUrl) {
    return new Response('Invalid Tor proxy path', { status: 400 });
  }
  if (!client) {
    return new Response('Tor not connected', { status: 503 });
  }

  try {
    const headers: Record<string, string> = {};
    const accept = request.headers.get('Accept');
    if (accept) headers['Accept'] = accept;

    const result = await client.fetch(targetUrl, {
      method: request.method || 'GET',
      ...(Object.keys(headers).length > 0 ? { headers } : {}),
      timeout: TOR_PROXY_TIMEOUT_MS,
    });

    return new Response(result.body as BodyInit, {
      status: result.status,
      statusText: result.statusText,
      headers: mapToHeaders(result.headers),
    });
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return new Response(message, { status: 502, statusText: 'Bad Gateway' });
  }
}

self.addEventListener('fetch', (e: FetchEvent) => {
  const url = new URL(e.request.url);
  if (url.origin !== self.location.origin) return;
  if (!url.pathname.startsWith(getProxyPathPrefix())) return;
  e.respondWith(handleProxyFetch(e.request));
});

// ---------------------------------------------------------------------------
// Message (from main page)
// ---------------------------------------------------------------------------

self.addEventListener('message', (e: ExtendableMessageEvent) => {
  const msg = e.data as MainToSW;
  if (!msg || typeof msg !== 'object' || !('type' in msg)) return;

  try {
    // Long-running work goes through e.waitUntil: without it the handler
    // returns immediately and the browser is free to terminate the SW ~30s
    // later, killing the Tor client mid-connect/fetch (the page then hangs on
    // a reply that will never come, and the in-memory log dies with us).
    switch (msg.type) {
      case 'connect':
        e.waitUntil(handleConnect(msg.options));
        break;
      case 'fetch':
        e.waitUntil(handleFetch(msg.requestId, msg.url, msg.timeout));
        break;
      case 'refreshConsensus':
        if (client) {
          e.waitUntil(
            client.refreshConsensus().catch((err) => {
              return broadcast({
                type: 'error',
                error: err instanceof Error ? err.message : String(err),
              });
            })
          );
        }
        break;
      case 'destroy':
        handleDestroy();
        break;
      case 'getState':
        void handleGetState();
        break;
      case 'getLogs':
        e.waitUntil(handleGetLogs());
        break;
      case 'ping':
        // Keepalive from the page: the event itself resets the SW idle timer.
        e.waitUntil(broadcast({ type: 'pong' }));
        break;
      default:
        break;
    }
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    void broadcast({ type: 'error', error: message });
  }
});
