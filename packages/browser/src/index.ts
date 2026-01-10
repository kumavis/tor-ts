/**
 * Browser-compatible Tor client using Snowflake transport.
 * Provides high-level API for connecting to Tor and fetching web content.
 */

import { Circuit } from 'tor/circuit';
import type { PeerInfo } from 'tor/circuit';
import {
  getRandomDirectoryAuthorityBrowser,
  downloadMicrodescBrowser,
  lookupPeerInfoBrowser,
  parseRelaysFromMicroDesc,
  pickRelayWithFlags,
} from './directory-browser.ts';
import { SnowflakeBrowserChannel } from './snowflake-channel.ts';
import { fetchHtml } from './http-fetch.ts';

export { SnowflakeBrowserChannel } from './snowflake-channel.ts';
export { fetchViaTor, fetchHtml } from './http-fetch.ts';
export type { TorFetchResponse } from './http-fetch.ts';
export {
  getRandomDirectoryAuthorityBrowser,
  downloadMicrodescBrowser,
  lookupPeerInfoBrowser,
  parseRelaysFromMicroDesc,
  pickRelayWithFlags,
} from './directory-browser.ts';
export type { MicroDescNodeInfo, BrowserDirectoryOptions } from './directory-browser.ts';

export type BrowserCircuitOptions = {
  relayUrl?: string;
  corsProxy?: string;
  onStatus?: (status: string) => void;
};

export type BrowserCircuit = {
  circuit: Circuit;
  channel: SnowflakeBrowserChannel;
  destroy: () => void;
};

/**
 * Connect to the Tor network via Snowflake and build a 3-hop circuit.
 * Returns a circuit that can be used to fetch content anonymously.
 */
export async function connectBrowserCircuit(
  options: BrowserCircuitOptions = {}
): Promise<BrowserCircuit> {
  const { relayUrl = 'wss://snowflake.torproject.net/', corsProxy, onStatus } = options;

  const log = (msg: string) => {
    console.log(`[tor-browser] ${msg}`);
    onStatus?.(msg);
  };

  log('Fetching directory information...');
  const directoryAuthority = await getRandomDirectoryAuthorityBrowser();
  const directoryServer = directoryAuthority.dir_address;

  log('Downloading network consensus (via CORS proxy)...');
  const microDescContent = await downloadMicrodescBrowser(directoryServer, { corsProxy });
  const microDescNodeInfos = parseRelaysFromMicroDesc(microDescContent);

  log('Connecting to Snowflake relay...');
  const channel = new SnowflakeBrowserChannel();
  await channel.connect({ relayUrl });

  const entryRsaIdDigest = channel.peerIdentity?.rsaIdDigest;
  if (!entryRsaIdDigest) {
    channel.destroy();
    throw new Error('Snowflake channel has no peer identity');
  }

  log('Building circuit...');

  // The Snowflake entry may not appear in the public consensus. For the first hop only,
  // we use CREATE_FAST (no descriptor keys required). Subsequent hops are extended with ntor.
  const entryPeerInfo: PeerInfo = {
    onionKey: Buffer.alloc(0),
    rsaIdDigest: entryRsaIdDigest,
    linkSpecifiers: [],
  };

  const middleNode = pickRelayWithFlags(microDescNodeInfos, [], []);
  const exitNode = pickRelayWithFlags(microDescNodeInfos, ['Exit'], [middleNode]);

  log(`Selected middle node: ${middleNode.nickname}`);
  log(`Selected exit node: ${exitNode.nickname}`);

  const middlePeerInfo = await lookupPeerInfoBrowser(directoryServer, middleNode, { corsProxy });
  const exitPeerInfo = await lookupPeerInfoBrowser(directoryServer, exitNode, { corsProxy });

  const circuitPeerInfos: Array<PeerInfo> = [entryPeerInfo, middlePeerInfo, exitPeerInfo];

  const circuit = new Circuit({ path: circuitPeerInfos, channel });
  await circuit.connect();

  log('Circuit established!');

  return {
    circuit,
    channel,
    destroy: () => {
      circuit.destroy();
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
