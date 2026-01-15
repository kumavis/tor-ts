/**
 * Snowflake Chutney testing utilities.
 *
 * ## Bootstrap Context
 *
 * This module uses direct HTTP requests for directory lookups, which is
 * acceptable in the Snowflake bootstrap context because:
 *
 * 1. Snowflake is specifically designed for users who can't directly connect
 *    to Tor relays (e.g., censored networks). The user's first circuit is
 *    established through Snowflake proxies.
 *
 * 2. By definition, we don't have an existing circuit to use for safe
 *    directory lookups - that's what we're trying to establish.
 *
 * 3. The direct HTTP requests are to a local Chutney test network, not
 *    the public Tor network. In production Snowflake, directory information
 *    would be fetched through the Snowflake connection itself.
 *
 * After the initial Snowflake circuit is established, callers can use
 * the safe `DirectoryClient` from the tor package for subsequent lookups.
 */

import { Circuit } from 'tor/circuit';
import type { PeerInfo } from 'tor/circuit';
import { LinkSpecifierTypes } from 'tor/messaging';

// Import from tor package to avoid duplication
import { chutney } from 'tor';
import {
  dangerouslyLookupOnionKey,
  dangerouslyLookupPeerInfo,
  type MicroDescNodeInfo,
} from 'tor/build-circuit/directory';
import { pickRelayWithFlags } from 'tor/build-circuit/util';

import { SnowflakeTlsChannelConnection } from './tor-channel.ts';

// Re-export for convenience
export { discoverChutneyDirectoryServer } from 'tor/build-circuit/chutney';

export async function connectSnowflakeChutneyCircuit(opts: {
  relayUrl: string;
  expectedEntryOrPort?: number;
}): Promise<Circuit> {
  const directoryServer = await chutney.discoverChutneyDirectoryServer();
  const { consensus } = await chutney.getChutneyMicrodescConsensus();
  const microDescNodeInfos = consensus.relays;

  const channel = new SnowflakeTlsChannelConnection();
  await channel.connect({ relayUrl: opts.relayUrl });

  const entryRsaIdDigest = channel.peerIdentity?.rsaIdDigest;
  if (!entryRsaIdDigest) throw new Error('snowflake channel has no peer identity');

  const entryOnionKey = await dangerouslyLookupOnionKey(directoryServer, entryRsaIdDigest);
  const entryPeerInfo: PeerInfo = {
    onionKey: entryOnionKey,
    rsaIdDigest: entryRsaIdDigest,
    linkSpecifiers: [{ type: LinkSpecifierTypes.LegacyId, data: entryRsaIdDigest }],
  };

  if (opts.expectedEntryOrPort) {
    const match = microDescNodeInfos.find((n) => n.rsaIdDigest.equals(entryRsaIdDigest));
    if (match && match.onion_router_port !== opts.expectedEntryOrPort) {
      throw new Error(
        `snowflake entry ORPort mismatch: expected ${opts.expectedEntryOrPort} got ${match.onion_router_port}`
      );
    }
  }

  const ignoreEntry = [{ rsaIdDigest: entryRsaIdDigest } as MicroDescNodeInfo];

  const forcedExitRsaIdDigestHex = process.env.TOR_TS_CHUTNEY_EXIT_RSA_ID_DIGEST_HEX?.toLowerCase();
  const exitNode = forcedExitRsaIdDigestHex
    ? (() => {
        const forcedExit = microDescNodeInfos.find((n) => {
          const digestHex = n.rsaIdDigest.toString('hex');
          return digestHex === forcedExitRsaIdDigestHex;
        });
        if (!forcedExit) {
          throw new Error(
            `TOR_TS_CHUTNEY_EXIT_RSA_ID_DIGEST_HEX=${forcedExitRsaIdDigestHex} not found in microdesc`
          );
        }
        return forcedExit;
      })()
    : pickRelayWithFlags(microDescNodeInfos, ['Exit'], ignoreEntry);

  const middleNode = pickRelayWithFlags(microDescNodeInfos, [], [exitNode, ...ignoreEntry]);
  const middlePeerInfo = await dangerouslyLookupPeerInfo(directoryServer, middleNode);
  const exitPeerInfo = await dangerouslyLookupPeerInfo(directoryServer, exitNode);

  const pathInfos: PeerInfo[] = [entryPeerInfo, middlePeerInfo, exitPeerInfo];
  const circuit = new Circuit({ path: pathInfos, channel });
  await circuit.connect();
  return circuit;
}
