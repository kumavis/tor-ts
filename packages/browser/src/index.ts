/**
 * Browser-compatible Tor client using Snowflake transport.
 * Provides high-level API for connecting to Tor and fetching web content.
 *
 * BOOTSTRAP FLOW:
 * 1. Connect to Snowflake via WebSocket → get relay identity from TLS handshake
 * 2. Build 1-hop bootstrap circuit using CREATE_FAST (no onion key needed)
 * 3. Fetch directory consensus over encrypted bootstrap circuit (or use cached)
 * 4. Build full 3-hop circuit using relay info from consensus
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

import { Circuit } from 'tor/circuit';
import { lookupPeerInfo } from 'tor/directory-client';
import { pickRelayWithFlags } from 'tor/build-circuit/util';
import { SnowflakeBrowserChannel } from './snowflake-channel.ts';
import { fetchHtml } from './http-fetch.ts';
import { performBootstrap, type BrowserBootstrapOptions } from './bootstrap.ts';

export { SnowflakeBrowserChannel } from './snowflake-channel.ts';
export { fetchViaTor, fetchHtml } from './http-fetch.ts';
export type { TorFetchResponse } from './http-fetch.ts';
export { pickRelayWithFlags } from 'tor/build-circuit/util';
export type { MicroDescNodeInfo } from 'tor/build-circuit/directory';
export type { DownloadProgress } from 'tor/directory-client';

// Consensus caching utilities for sessionStorage
export {
  getCachedConsensusText as getCachedConsensusRaw,
  cacheConsensusText as cacheConsensusRaw,
  clearCachedConsensus,
  hasCachedConsensus,
  getConsensusCacheStatus,
} from './consensus-cache.ts';
export type { ConsensusCacheStatus } from './consensus-cache.ts';

// Re-export bootstrap utilities
export { performBootstrap } from './bootstrap.ts';
export type { BrowserBootstrapOptions, BootstrapResult } from './bootstrap.ts';

// Hidden service (.onion) support
export {
  connectToHiddenService,
  parseOnionV3Address,
  isOnionAddress,
  computeTimePeriod,
  deriveBlindedPublicKey,
  deriveSubcredential,
} from './hidden-service.ts';
export type {
  HiddenServiceConnection,
  HiddenServiceConnectionOptions,
  HiddenServiceDescriptor,
  IntroPoint,
} from './hidden-service.ts';

export type BrowserCircuitOptions = BrowserBootstrapOptions;

export type BrowserCircuit = {
  circuit: Circuit;
  channel: SnowflakeBrowserChannel;
  destroy: () => void;
};

/**
 * Connect to the Tor network via Snowflake and build a 3-hop circuit.
 * Uses safe bootstrap: directory lookups happen over an encrypted circuit.
 * Caches consensus in sessionStorage following Tor spec validity periods.
 * Returns a circuit that can be used to fetch content anonymously.
 */
export async function connectBrowserCircuit(
  options: BrowserCircuitOptions = {}
): Promise<BrowserCircuit> {
  const { onStatus } = options;

  const log = (msg: string) => {
    console.log(`[tor-browser] ${msg}`);
    onStatus?.(msg);
  };

  // Perform common bootstrap (connect, build bootstrap circuit, get consensus)
  const { channel, bootstrapCircuit, dirClient, consensus, entryPeerInfo } = await performBootstrap(
    {
      ...options,
      logPrefix: 'tor-browser',
    }
  );

  // Select middle and exit nodes
  const middleNode = pickRelayWithFlags(consensus.relays, [], []);
  const exitNode = pickRelayWithFlags(consensus.relays, ['Exit'], [middleNode]);

  log(`Selected middle node: ${middleNode.nickname}`);
  log(`Selected exit node: ${exitNode.nickname}`);

  // Look up relay info over encrypted circuit
  log('Looking up relay descriptors (via Tor circuit)...');
  const middlePeerInfo = await lookupPeerInfo(dirClient, middleNode);
  const exitPeerInfo = await lookupPeerInfo(dirClient, exitNode);

  // Build full 3-hop circuit on the same channel
  log('Building full 3-hop circuit...');
  const fullCircuit = new Circuit({
    path: [entryPeerInfo, middlePeerInfo, exitPeerInfo],
    channel,
  });
  await fullCircuit.connect();

  // Clean up bootstrap circuit state (preserve channel for fullCircuit)
  bootstrapCircuit.destroy({ preserveChannel: true });

  log('Circuit established!');

  return {
    circuit: fullCircuit,
    channel,
    destroy: () => {
      fullCircuit.destroy();
    },
  };
}

/**
 * High-level helper to fetch a webpage through Tor.
 * Automatically connects, fetches, and cleans up.
 */
export async function fetchPageViaTor(
  url: string,
  options: BrowserCircuitOptions = {}
): Promise<string> {
  const { circuit, destroy } = await connectBrowserCircuit(options);
  try {
    return await fetchHtml(circuit, url);
  } finally {
    destroy();
  }
}

/**
 * Re-export types for convenience.
 */
export type { PeerInfo } from 'tor/circuit';
export type { Circuit } from 'tor/circuit';
