import { Circuit } from '../circuit.ts';
import type { PeerInfo } from '../circuit.ts';
import { TlsChannelConnection } from '../channel.ts';
import {
  DirectoryClient,
  lookupPeerInfo,
  parseMicroDescConsensus,
} from '../directory-client.ts';
import {
  getRandomDirectoryAuthority,
  dangerouslyLookupPeerInfo,
  dangerouslyDownloadMicrodescFromDirectory,
  parseRelaysFromMicroDesc,
} from './directory.ts';
import type { MicroDescNodeInfo } from './directory.ts';
import { pickRelayWithFlags } from './util.ts';

/**
 * Bootstrap: Download consensus via direct (dangerous) fetch.
 *
 * This is the only unavoidable direct request - we need initial directory
 * information to build our first circuit. After this, use safe methods.
 *
 * @returns The consensus content and directory server used
 */
async function bootstrapConsensus(): Promise<{
  directoryServer: string;
  microDescContent: string;
}> {
  let directoryServer: string | undefined;
  let microDescContent: string | undefined;
  while (!microDescContent) {
    const directoryServerInfo = await getRandomDirectoryAuthority();
    directoryServer = directoryServerInfo.dir_address;
    if (!directoryServer) continue;
    try {
      microDescContent = await dangerouslyDownloadMicrodescFromDirectory(directoryServer);
    } catch {
      // ignore error and attempt again
    }
  }
  if (!directoryServer) {
    throw new Error('Failed to select a directory authority');
  }
  return { directoryServer, microDescContent };
}

/**
 * Build a circuit path using safe directory lookups over an existing circuit.
 *
 * This is the privacy-preserving way to look up relay information.
 * Requires an existing circuit to a relay that serves directory information.
 */
export async function getRandomCircuitPathSafe(directoryCircuit: Circuit): Promise<PeerInfo[]> {
  const client = new DirectoryClient(directoryCircuit);
  const microDescContent = await client.downloadMicrodescConsensus();
  const consensus = parseMicroDescConsensus(microDescContent);

  if (consensus.relays.length === 0) {
    throw new Error('No relays parsed from consensus');
  }

  const circuitPlan: Array<MicroDescNodeInfo> = [];
  circuitPlan.push(pickRelayWithFlags(consensus.relays, ['Exit'], circuitPlan));
  circuitPlan.push(pickRelayWithFlags(consensus.relays, [], circuitPlan));
  circuitPlan.push(pickRelayWithFlags(consensus.relays, ['Guard'], circuitPlan));

  // Look up PeerInfo safely through the circuit
  const circuitPeerInfos: Array<PeerInfo> = await Promise.all(
    circuitPlan.map((relayInfo) => lookupPeerInfo(client, relayInfo))
  );

  // Reverse so that guard is first and exit is last
  circuitPeerInfos.reverse();
  return circuitPeerInfos;
}

/**
 * Build a random circuit path using bootstrap (dangerous) methods.
 *
 * WARNING: This function makes direct HTTP requests to directory servers,
 * which leaks the client's IP address. Use only for initial bootstrap when
 * no circuit exists yet. For subsequent circuits, use `getRandomCircuitPathSafe`.
 *
 * @deprecated Use getRandomCircuitPathSafe with an existing circuit when possible
 */
export async function getRandomCircuitPath() {
  const { directoryServer, microDescContent } = await bootstrapConsensus();

  const microDescNodeInfos = parseRelaysFromMicroDesc(microDescContent);
  if (microDescNodeInfos.length === 0) {
    console.warn('microdesc content:', microDescContent);
    throw new Error(
      `Failed to parse relays from directory server (${directoryServer}). No relays parsed from microdesc.`
    );
  }

  const circuitPlan: Array<MicroDescNodeInfo> = [];
  circuitPlan.push(pickRelayWithFlags(microDescNodeInfos, ['Exit'], circuitPlan));
  circuitPlan.push(pickRelayWithFlags(microDescNodeInfos, [], circuitPlan));
  circuitPlan.push(pickRelayWithFlags(microDescNodeInfos, ['Guard'], circuitPlan));

  // NOTE: This uses dangerous direct fetches. Once you have a circuit,
  // use getRandomCircuitPathSafe instead for privacy.
  const circuitPeerInfos: Array<PeerInfo> = await Promise.all(
    circuitPlan.map(async (relayInfo) => {
      return await dangerouslyLookupPeerInfo(directoryServer, relayInfo);
    })
  );

  // reverse so that gateway is first and exit is last
  circuitPeerInfos.reverse();

  return circuitPeerInfos;
}

/**
 * Connect a random circuit using bootstrap (dangerous) methods.
 *
 * WARNING: This function makes direct HTTP requests for initial directory
 * lookups. Use for initial bootstrap only.
 *
 * @deprecated Build an initial circuit, then use getRandomCircuitPathSafe for subsequent circuits
 */
export async function connectRandomCircuit() {
  const circuitPeerInfos = await getRandomCircuitPath();
  const gatewayPeerInfo = circuitPeerInfos[0];
  if (!gatewayPeerInfo) {
    throw new Error('Failed to build circuit path (no gateway peer)');
  }
  const channel = new TlsChannelConnection();
  await channel.connectPeerInfo(gatewayPeerInfo);
  const circuit = new Circuit({
    path: circuitPeerInfos,
    channel,
  });
  await circuit.connect();
  return circuit;
}

/**
 * Build a new circuit using safe directory lookups over an existing circuit.
 *
 * This is the recommended way to build circuits after initial bootstrap.
 * The existing circuit is used only for directory lookups - the new circuit
 * is completely independent.
 */
export async function connectRandomCircuitSafe(directoryCircuit: Circuit): Promise<Circuit> {
  const circuitPeerInfos = await getRandomCircuitPathSafe(directoryCircuit);
  const gatewayPeerInfo = circuitPeerInfos[0];
  if (!gatewayPeerInfo) {
    throw new Error('Failed to build circuit path (no gateway peer)');
  }
  const channel = new TlsChannelConnection();
  await channel.connectPeerInfo(gatewayPeerInfo);
  const circuit = new Circuit({
    path: circuitPeerInfos,
    channel,
  });
  await circuit.connect();
  return circuit;
}
