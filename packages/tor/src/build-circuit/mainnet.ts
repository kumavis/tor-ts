import { Circuit } from '../circuit.ts';
import type { PeerInfo } from '../circuit.ts';
import { TlsChannelConnection } from '../channel.ts';
import { AddressTypes, LinkSpecifierTypes, addressAndPortToLinkSpecifier } from '../messaging.ts';
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
import {
  getRandomFallbackDirectory,
  type FallbackDirectory,
} from '../fallback-dirs.ts';

// =============================================================================
// Safe Bootstrap Using Fallback Directories (Tor Spec Compliant)
// =============================================================================

/**
 * Convert a FallbackDirectory to PeerInfo for circuit building.
 */
function fallbackToPeerInfo(fallback: FallbackDirectory): PeerInfo {
  return {
    onionKey: fallback.ntorOnionKey,
    rsaIdDigest: fallback.rsaIdDigest,
    linkSpecifiers: [
      addressAndPortToLinkSpecifier({
        type: AddressTypes.IPv4,
        ip: fallback.ip,
        port: fallback.orPort,
      }),
      {
        type: LinkSpecifierTypes.LegacyId,
        data: fallback.rsaIdDigest,
      },
      {
        type: LinkSpecifierTypes.Ed25519Id,
        data: fallback.ed25519Id,
      },
    ],
  };
}

/**
 * Bootstrap safely using hardcoded fallback directories.
 *
 * This is the Tor-spec-compliant way to bootstrap:
 * 1. Connect via TLS to a fallback directory's OR port
 * 2. Verify the relay's identity during TLS handshake
 * 3. Build a single-hop circuit using ntor handshake
 * 4. Use RELAY_BEGIN_DIR to fetch directory info over encrypted channel
 *
 * This is SAFER than plain HTTP because:
 * - Connection is encrypted (TLS + Tor encryption)
 * - Relay identity is cryptographically verified
 * - Traffic looks like normal Tor (not HTTP)
 * - Directory request content is hidden from network observers
 *
 * While the client's IP is visible to the fallback relay (unavoidable for
 * first-hop), this is the same exposure as any Tor circuit's entry node.
 *
 * @returns A single-hop bootstrap circuit to the fallback directory
 */
export async function bootstrapWithFallbackDirectory(): Promise<Circuit> {
  const fallback = getRandomFallbackDirectory();
  const peerInfo = fallbackToPeerInfo(fallback);

  const channel = new TlsChannelConnection();
  await channel.connectPeerInfo(peerInfo);

  // Build a single-hop circuit to the fallback directory
  const circuit = new Circuit({
    path: [peerInfo],
    channel,
  });
  await circuit.connect();

  return circuit;
}

/**
 * Build a full 3-hop circuit using safe bootstrap.
 *
 * This is the recommended way to connect to Tor:
 * 1. Bootstrap safely using a fallback directory (single-hop, encrypted)
 * 2. Fetch directory info over the encrypted bootstrap circuit
 * 3. Build a full 3-hop circuit using safe directory lookups
 * 4. Close the bootstrap circuit
 *
 * The returned circuit is a full 3-hop circuit (Guard → Middle → Exit).
 */
export async function connectRandomCircuitWithSafeBootstrap(): Promise<Circuit> {
  // Step 1: Bootstrap safely using fallback directory
  const bootstrapCircuit = await bootstrapWithFallbackDirectory();

  try {
    // Step 2: Build a full 3-hop circuit using safe lookups
    const circuit = await connectRandomCircuitSafe(bootstrapCircuit);

    // Step 3: Clean up bootstrap circuit
    bootstrapCircuit.destroy();

    return circuit;
  } catch (err) {
    bootstrapCircuit.destroy();
    throw err;
  }
}

// =============================================================================
// Legacy Bootstrap (uses plain HTTP - less safe)
// =============================================================================

/**
 * Bootstrap: Download consensus via direct (dangerous) fetch.
 *
 * ⚠️ DEPRECATED: Use `bootstrapWithFallbackDirectory()` instead.
 *
 * This makes plain HTTP requests which leak client IP and request patterns.
 * The safe alternative uses TLS to fallback directories with RELAY_BEGIN_DIR.
 *
 * @deprecated Use bootstrapWithFallbackDirectory() for safe bootstrap
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
