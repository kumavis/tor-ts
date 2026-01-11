import { Circuit } from '../circuit.ts';
import type { PeerInfo } from '../circuit.ts';
import { TlsChannelConnection } from '../channel.ts';
import { DirectoryClient, lookupPeerInfo, parseMicroDescConsensus } from '../directory-client.ts';
import type { MicroDescNodeInfo } from './directory.ts';
import { pickRelayWithFlags } from './util.ts';
import { getRandomFallbackDirectory, fallbackToPeerInfo } from '../fallback-dirs.ts';

/**
 * Bootstrap safely using hardcoded fallback directories.
 *
 * This is the Tor-spec-compliant way to bootstrap:
 * 1. Connect via TLS to a fallback directory's OR port
 * 2. Verify the relay's identity during TLS handshake
 * 3. Build a single-hop circuit using CREATE_FAST (no onion key needed)
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
