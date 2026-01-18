/**
 * Browser-compatible Tor client using Snowflake transport.
 *
 * Primary API: makeBrowserTorClient()
 *
 * BOOTSTRAP FLOW:
 * 1. Connect to Snowflake via WebSocket → get relay identity from TLS handshake
 * 2. Build 1-hop bootstrap circuit using CREATE_FAST (no onion key needed)
 * 3. Fetch directory consensus over encrypted bootstrap circuit (or use cached)
 * 4. Return a long-lived client for Tor operations
 *
 * This is safe because all directory lookups happen over an encrypted Tor circuit,
 * not via plain HTTP or CORS proxies.
 *
 * CONSENSUS CACHING:
 * The consensus document (~3.5MB) is cached in sessionStorage following Tor spec:
 * - Cached consensus is used while it's "fresh" (before fresh-until timestamp)
 * - Expired consensus is automatically re-fetched
 * - Cache can be manually cleared via clearCachedConsensus()
 */

// Snowflake channel (low-level, for advanced use)
export { SnowflakeBrowserChannel } from './snowflake-channel.ts';

// Consensus caching utilities for sessionStorage
export {
  getCachedConsensusText as getCachedConsensusRaw,
  cacheConsensusText as cacheConsensusRaw,
  clearCachedConsensus,
  hasCachedConsensus,
  getConsensusCacheStatus,
} from './consensus-cache.ts';
export type { ConsensusCacheStatus } from './consensus-cache.ts';

// Microdescriptor caching utilities for localStorage
export { LocalStorageMicrodescStorage } from './microdesc-cache.ts';

// Hidden service (.onion) support
export { isOnionAddress } from 'tor/hidden-service';

// Browser Tor Client - primary API
export {
  makeBrowserTorClient,
  createSnowflakeChannelManager,
  fetchHtml,
  type BrowserTorClient,
  type BrowserTorClientResult,
  type BrowserTorClientOptions,
  type FetchHtmlOptions,
} from './client.ts';

// Re-export shared client types from tor package
export {
  TorClient,
  MicrodescManager,
  InMemoryMicrodescStorage,
  type HsConnectionResult,
  type CircuitResult,
  type FetchOptions,
  type FetchResponse,
  type MicrodescProgressCallback,
  type MicrodescStorage,
} from 'tor';

// Re-export types for convenience
export type { PeerInfo, Circuit } from 'tor/circuit';
export type { DownloadProgress } from 'tor/directory-client';
