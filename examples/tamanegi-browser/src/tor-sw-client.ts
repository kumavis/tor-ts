/**
 * Main-thread proxy for the Tor service worker.
 * Sends commands via postMessage and exposes callbacks for SW events.
 */

import type { MainToSW, MicrodescProgressPayload, SWToMain } from './sw-messages.ts';
import type { DownloadProgress } from 'browser';

export type FetchResult = { status: number; statusText: string; html: string };

export class TorServiceWorkerClient {
  private controller: ServiceWorker | null;
  private pendingFetch = new Map<
    string,
    { resolve: (r: FetchResult) => void; reject: (e: Error) => void }
  >();
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
            html: msg.html,
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
      default:
        break;
    }
  }

  connect(options?: { relayUrl?: string; skipConsensusCache?: boolean }): void {
    this.post({ type: 'connect', options });
  }

  fetch(url: string, opts?: { timeout?: number }): Promise<FetchResult> {
    return new Promise((resolve, reject) => {
      const requestId = crypto.randomUUID();
      this.pendingFetch.set(requestId, { resolve, reject });
      this.post({ type: 'fetch', requestId, url, timeout: opts?.timeout });
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
