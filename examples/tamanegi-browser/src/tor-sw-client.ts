/**
 * Main-thread proxy for the Tor service worker.
 * Sends commands via postMessage and exposes callbacks for SW events.
 */

import type { MainToSW, MicrodescProgressPayload, SWToMain } from './sw-messages.ts';
import type { DownloadProgress } from 'browser';

export type FetchResult = {
  status: number;
  statusText: string;
  body: Uint8Array;
};

export class TorServiceWorkerClient {
  private controller: ServiceWorker | null;
  private pendingFetch = new Map<
    string,
    { resolve: (r: FetchResult) => void; reject: (e: Error) => void }
  >();
  private pendingLogs: Array<(entries: string[]) => void> = [];
  private messageHandler: (e: MessageEvent) => void;

  constructor(sw: ServiceWorker | null) {
    this.controller = sw;
    this.messageHandler = (e: MessageEvent) => this.onMessage(e);
    if (typeof navigator !== 'undefined' && navigator.serviceWorker) {
      navigator.serviceWorker.addEventListener('message', this.messageHandler);
    }
  }

  /** Send a message to the service worker. */
  private post(msg: MainToSW): void {
    if (this.controller) {
      this.controller.postMessage(msg);
    }
  }

  private onMessage(e: MessageEvent): void {
    const msg = e.data as SWToMain;
    if (!msg || typeof msg !== 'object' || !('type' in msg)) return;

    switch (msg.type) {
      case 'status':
        this.onStatus?.(msg.message);
        break;
      case 'consensusProgress':
        this.onConsensusProgress?.(msg.progress);
        break;
      case 'microdescProgress':
        this.onMicrodescProgress?.(msg.progress);
        break;
      case 'connected':
        this.onConnected?.();
        break;
      case 'disconnected':
        this.onDisconnected?.(msg.reason);
        break;
      case 'fetchResult': {
        const pending = this.pendingFetch.get(msg.requestId);
        if (pending) {
          this.pendingFetch.delete(msg.requestId);
          pending.resolve({
            status: msg.status,
            statusText: msg.statusText,
            body: msg.body,
          });
        }
        break;
      }
      case 'fetchError': {
        const pending = this.pendingFetch.get(msg.requestId);
        if (pending) {
          this.pendingFetch.delete(msg.requestId);
          pending.reject(new Error(msg.error));
        }
        break;
      }
      case 'error':
        this.onError?.(msg.error);
        break;
      case 'state':
        // Optional: could expose state for UI
        break;
      case 'logs': {
        const waiters = this.pendingLogs.splice(0);
        for (const resolve of waiters) {
          resolve(msg.entries);
        }
        break;
      }
      default:
        break;
    }
  }

  connect(options?: { relayUrl?: string; skipConsensusCache?: boolean; debug?: boolean }): void {
    this.post({ type: 'connect', ...(options !== undefined ? { options } : {}) });
  }

  /**
   * Pull the full captured debug-log buffer from the service worker. Resolves
   * with an empty array if the SW never responds within the timeout (e.g. no
   * active controller).
   */
  getLogs(timeoutMs = 5000): Promise<string[]> {
    return new Promise((resolve) => {
      const timer = setTimeout(() => {
        const idx = this.pendingLogs.indexOf(settle);
        if (idx !== -1) this.pendingLogs.splice(idx, 1);
        resolve([]);
      }, timeoutMs);
      const settle = (entries: string[]): void => {
        clearTimeout(timer);
        resolve(entries);
      };
      this.pendingLogs.push(settle);
      this.post({ type: 'getLogs' });
    });
  }

  fetch(url: string, opts?: { timeout?: number }): Promise<FetchResult> {
    return new Promise((resolve, reject) => {
      const requestId = crypto.randomUUID();
      this.pendingFetch.set(requestId, { resolve, reject });
      this.post({
        type: 'fetch',
        requestId,
        url,
        ...(opts?.timeout !== undefined ? { timeout: opts.timeout } : {}),
      });
    });
  }

  refreshConsensus(): void {
    this.post({ type: 'refreshConsensus' });
  }

  destroy(): void {
    if (typeof navigator !== 'undefined' && navigator.serviceWorker) {
      navigator.serviceWorker.removeEventListener('message', this.messageHandler);
    }
    this.post({ type: 'destroy' });
    for (const [, { reject }] of this.pendingFetch) {
      reject(new Error('Tor client destroyed'));
    }
    this.pendingFetch.clear();
    for (const resolve of this.pendingLogs.splice(0)) {
      resolve([]);
    }
    this.controller = null;
  }

  /** Update the service worker reference (e.g. after registration). */
  setController(sw: ServiceWorker | null): void {
    this.controller = sw;
  }

  // Callbacks – set by main.ts
  onStatus?: (message: string) => void;
  onConsensusProgress?: (progress: DownloadProgress) => void;
  onMicrodescProgress?: (progress: MicrodescProgressPayload) => void;
  onConnected?: () => void;
  onDisconnected?: (reason: string) => void;
  onError?: (error: string) => void;
}
