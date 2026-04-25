/**
 * Snowflake Chutney testing utilities.
 *
 * Builds a 3-hop chutney circuit whose entry hop is the snowflake relay we
 * connected to. Bootstrap goes:
 *
 *   1. Open snowflake channel; the channel's TLS handshake verifies the
 *      entry relay's identity.
 *   2. Build a 1-hop bootstrap circuit through that channel using
 *      CREATE_FAST (no onion key needed — identity is already verified by
 *      TLS in step 1).
 *   3. Use the 1-hop circuit as a directory pivot: fetch the chutney
 *      consensus over BEGIN_DIR, look up middle/exit peers safely.
 *   4. Build the full 3-hop circuit reusing the snowflake channel.
 *
 * This is the same pattern the tamanegi browser bootstrap runs — no plain
 * HTTP, no `dangerouslyLookup*`.
 */

import { Circuit } from 'tor/circuit';
import type { PeerInfo } from 'tor/circuit';
import { LinkSpecifierTypes } from 'tor/messaging';

import { DirectoryClient, lookupPeerInfo } from 'tor/directory-client';
import { pickRelayWithFlags } from 'tor/build-circuit/util';
import { fetchChutneyConsensusOverCircuit } from 'tor/build-circuit/chutney';
import type { MicroDescNodeInfo } from 'tor/build-circuit/directory';

import { SnowflakeTlsChannelConnection } from './tor-channel.ts';

// Re-export for convenience (used by ci-chutney-snowflake.sh and tests).
export { discoverChutneyBootstrapPeer } from 'tor/build-circuit/chutney';

export async function connectSnowflakeChutneyCircuit(opts: {
  relayUrl: string;
  expectedEntryOrPort?: number;
}): Promise<Circuit> {
  const channel = new SnowflakeTlsChannelConnection();
  await channel.connect({ relayUrl: opts.relayUrl });

  const entryRsaIdDigest = channel.peerIdentity?.rsaIdDigest;
  if (!entryRsaIdDigest) throw new Error('snowflake channel has no peer identity');

  // 1-hop bootstrap circuit through the snowflake channel. Empty onionKey
  // → CREATE_FAST; the relay's identity was already verified by the TLS
  // handshake the snowflake channel just completed.
  const entryPeerInfo: PeerInfo = {
    onionKey: Buffer.alloc(0),
    rsaIdDigest: entryRsaIdDigest,
    linkSpecifiers: [{ type: LinkSpecifierTypes.LegacyId, data: entryRsaIdDigest }],
  };
  const bootstrapCircuit = new Circuit({ path: [entryPeerInfo], channel });
  await bootstrapCircuit.connect();

  try {
    const consensus = await fetchChutneyConsensusOverCircuit(bootstrapCircuit);
    const microDescNodeInfos = consensus.relays;

    if (opts.expectedEntryOrPort) {
      const match = microDescNodeInfos.find((n) => n.rsaIdDigest.equals(entryRsaIdDigest));
      if (match && match.onion_router_port !== opts.expectedEntryOrPort) {
        throw new Error(
          `snowflake entry ORPort mismatch: expected ${opts.expectedEntryOrPort} got ${match.onion_router_port}`
        );
      }
    }

    const ignoreEntry = [{ rsaIdDigest: entryRsaIdDigest } as MicroDescNodeInfo];

    const forcedExitRsaIdDigestHex =
      process.env.TOR_TS_CHUTNEY_EXIT_RSA_ID_DIGEST_HEX?.toLowerCase();
    const exitNode = forcedExitRsaIdDigestHex
      ? (() => {
          const forcedExit = microDescNodeInfos.find(
            (n) => n.rsaIdDigest.toString('hex') === forcedExitRsaIdDigestHex
          );
          if (!forcedExit) {
            throw new Error(
              `TOR_TS_CHUTNEY_EXIT_RSA_ID_DIGEST_HEX=${forcedExitRsaIdDigestHex} not found in microdesc`
            );
          }
          return forcedExit;
        })()
      : pickRelayWithFlags(microDescNodeInfos, ['Exit'], ignoreEntry);

    const middleNode = pickRelayWithFlags(microDescNodeInfos, [], [exitNode, ...ignoreEntry]);

    const dirClient = new DirectoryClient(bootstrapCircuit);
    const middlePeerInfo = await lookupPeerInfo(dirClient, middleNode);
    const exitPeerInfo = await lookupPeerInfo(dirClient, exitNode);

    const pathInfos: PeerInfo[] = [entryPeerInfo, middlePeerInfo, exitPeerInfo];
    const circuit = new Circuit({ path: pathInfos, channel });
    await circuit.connect();
    bootstrapCircuit.destroy({ preserveChannel: true });
    return circuit;
  } catch (err) {
    bootstrapCircuit.destroy({ preserveChannel: true });
    throw err;
  }
}
