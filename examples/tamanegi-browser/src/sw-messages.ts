/**
 * Typed message protocol between main page and service worker.
 * Used by both main.ts (via TorServiceWorkerClient) and sw.ts.
 */

import type { DownloadProgress } from 'browser';

/** Path segment for Tor proxy – combined with the deployment base path to form the full prefix. */
export const TOR_PROXY_PATH_SEGMENT = 'tor/';

// ---------------------------------------------------------------------------
// Main page -> Service worker
// ---------------------------------------------------------------------------

export type MainToSW =
  | {
      type: 'connect';
      options?: { relayUrl?: string; skipConsensusCache?: boolean };
    }
  | { type: 'fetch'; requestId: string; url: string; timeout?: number }
  | { type: 'refreshConsensus' }
  | { type: 'destroy' }
  | { type: 'getState' };

// ---------------------------------------------------------------------------
// Service worker -> Main page
// ---------------------------------------------------------------------------

export type MicrodescProgressPayload = {
  fetched: number;
  total: number;
  cached: number;
};

export type SWToMain =
  | { type: 'status'; message: string }
  | { type: 'consensusProgress'; progress: DownloadProgress }
  | { type: 'microdescProgress'; progress: MicrodescProgressPayload }
  | { type: 'connected' }
  | { type: 'disconnected'; reason: string }
  | {
      type: 'fetchResult';
      requestId: string;
      status: number;
      statusText: string;
      body: Uint8Array;
    }
  | { type: 'fetchError'; requestId: string; error: string }
  | { type: 'error'; error: string }
  | { type: 'state'; state: 'idle' | 'connecting' | 'connected' | 'disconnected' };
