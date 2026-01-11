/**
 * Browser-compatible Tor client using Snowflake transport.
 * Provides high-level API for connecting to Tor and fetching web content.
 *
 * BOOTSTRAP FLOW:
 * 1. Connect to Snowflake via WebSocket → get relay identity from TLS handshake
 * 2. Build 1-hop bootstrap circuit using CREATE_FAST (no onion key needed)
 * 3. Fetch directory consensus over encrypted bootstrap circuit
 * 4. Build full 3-hop circuit using relay info from consensus
 *
 * This is safe because all directory lookups happen over an encrypted Tor circuit,
 * not via plain HTTP or CORS proxies.
 */

import { Circuit } from 'tor/circuit';
import type { PeerInfo } from 'tor/circuit';
import { DirectoryClient, parseMicroDescConsensus, lookupPeerInfo } from 'tor/directory-client';
import { pickRelayWithFlags } from 'tor/build-circuit/util';
import { SnowflakeBrowserChannel } from './snowflake-channel.ts';
import { fetchHtml } from './http-fetch.ts';

export { SnowflakeBrowserChannel } from './snowflake-channel.ts';
export { fetchViaTor, fetchHtml } from './http-fetch.ts';
export type { TorFetchResponse } from './http-fetch.ts';
export { pickRelayWithFlags } from 'tor/build-circuit/util';
export type { MicroDescNodeInfo } from 'tor/build-circuit/directory';

export type BrowserCircuitOptions = {
  relayUrl?: string;
  onStatus?: (status: string) => void;
};

export type BrowserCircuit = {
  circuit: Circuit;
  channel: SnowflakeBrowserChannel;
  destroy: () => void;
};

/**
 * Connect to the Tor network via Snowflake and build a 3-hop circuit.
 * Uses safe bootstrap: directory lookups happen over an encrypted circuit.
 * Returns a circuit that can be used to fetch content anonymously.
 */
export async function connectBrowserCircuit(
  options: BrowserCircuitOptions = {}
): Promise<BrowserCircuit> {
  const { relayUrl = 'wss://snowflake.torproject.net/', onStatus } = options;

  const log = (msg: string) => {
    console.log(`[tor-browser] ${msg}`);
    onStatus?.(msg);
  };

  // Step 1: Connect to Snowflake relay
  log('Connecting to Snowflake relay...');
  const channel = new SnowflakeBrowserChannel();
  await channel.connect({ relayUrl });

  const entryRsaIdDigest = channel.peerIdentity?.rsaIdDigest;
  if (!entryRsaIdDigest) {
    channel.destroy();
    throw new Error('Snowflake channel has no peer identity');
  }

  // Step 2: Build 1-hop bootstrap circuit using CREATE_FAST
  log('Building bootstrap circuit...');
  const entryPeerInfo: PeerInfo = {
    onionKey: Buffer.alloc(0), // Empty triggers CREATE_FAST
    rsaIdDigest: entryRsaIdDigest,
    linkSpecifiers: [],
  };

  const bootstrapCircuit = new Circuit({ path: [entryPeerInfo], channel });
  await bootstrapCircuit.connect();

  // Step 3: Fetch directory consensus over encrypted bootstrap circuit
  log('Downloading network consensus (via Tor circuit)...');
  const dirClient = new DirectoryClient(bootstrapCircuit);
  const microDescContent = await dirClient.downloadMicrodescConsensus();
  const consensus = parseMicroDescConsensus(microDescContent);

  if (consensus.relays.length === 0) {
    bootstrapCircuit.destroy();
    throw new Error('No relays found in consensus');
  }

  // Step 4: Select middle and exit nodes
  const middleNode = pickRelayWithFlags(consensus.relays, [], []);
  const exitNode = pickRelayWithFlags(consensus.relays, ['Exit'], [middleNode]);

  log(`Selected middle node: ${middleNode.nickname}`);
  log(`Selected exit node: ${exitNode.nickname}`);

  // Step 5: Look up relay info over encrypted circuit
  log('Looking up relay descriptors (via Tor circuit)...');
  const middlePeerInfo = await lookupPeerInfo(dirClient, middleNode);
  const exitPeerInfo = await lookupPeerInfo(dirClient, exitNode);

  // Step 6: Extend bootstrap circuit to full 3-hop circuit
  log('Extending circuit to 3 hops...');
  const fullCircuit = new Circuit({
    path: [entryPeerInfo, middlePeerInfo, exitPeerInfo],
    channel,
  });
  await fullCircuit.connect();

  // Clean up bootstrap circuit (we now have the full circuit)
  bootstrapCircuit.destroy();

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
