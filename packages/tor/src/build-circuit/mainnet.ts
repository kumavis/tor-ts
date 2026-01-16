import { Circuit } from '../circuit.ts';
import type { PeerInfo } from '../circuit.ts';
import { TlsChannelConnection } from '../channel.ts';
import {
  DirectoryClient,
  lookupPeerInfo,
  fetchExitPolicies,
  fetchAndVerifyConsensus,
} from '../directory-client.ts';
import type { MicroDescNodeInfo, VerifiedMicroDescConsensus } from './directory.ts';
import {
  pickRelayWithFlags,
  filterRelaysByFlags,
  pickExitRelay,
  pickGuardRelay,
  pickMiddleRelay,
} from './util.ts';
import { getRandomFallbackDirectory, fallbackToPeerInfo } from '../fallback-dirs.ts';
import { DEFAULT_TARGET_PORTS } from '../exit-policy.ts';

/**
 * Options for circuit building.
 */
export type CircuitBuildOptions = {
  /**
   * Target ports the exit relay must support.
   * Default: [80, 443] (HTTP and HTTPS)
   *
   * The circuit builder will select an exit relay whose exit policy
   * allows connections to all specified ports.
   */
  targetPorts?: number[];

  /**
   * Whether to use bandwidth-weighted relay selection.
   * Default: true
   *
   * When enabled, relays are selected with probability proportional
   * to their bandwidth, following the Tor specification.
   */
  useBandwidthWeighting?: boolean;

  /**
   * Whether to fetch exit policies before selecting exits.
   * Default: true
   *
   * When enabled, downloads microdescriptors for exit candidates
   * to check their exit policies before selection.
   */
  fetchExitPoliciesBeforeSelection?: boolean;
};

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
 *
 * @param directoryCircuit - Existing circuit for directory lookups
 * @param options - Circuit building options
 * @returns Array of PeerInfo for the circuit path (Guard → Middle → Exit)
 */
export async function getRandomCircuitPathSafe(
  directoryCircuit: Circuit,
  options: CircuitBuildOptions = {}
): Promise<PeerInfo[]> {
  const {
    targetPorts = DEFAULT_TARGET_PORTS,
    useBandwidthWeighting = true,
    fetchExitPoliciesBeforeSelection = true,
  } = options;

  // Fetch and verify consensus using the standard flow
  const { consensus, dirClient: client } = await fetchAndVerifyConsensus(directoryCircuit);

  // Select relays based on options
  const circuitPlan = useBandwidthWeighting
    ? await selectRelaysWithBandwidthWeighting(
        client,
        consensus,
        targetPorts,
        fetchExitPoliciesBeforeSelection
      )
    : selectRelaysUniform(consensus.relays);

  // Look up PeerInfo safely through the circuit
  const circuitPeerInfos: Array<PeerInfo> = await Promise.all(
    circuitPlan.map((relayInfo) => lookupPeerInfo(client, relayInfo))
  );

  // Reverse so that guard is first and exit is last
  circuitPeerInfos.reverse();
  return circuitPeerInfos;
}

/**
 * Select relays using bandwidth-weighted selection with exit policy checking.
 */
async function selectRelaysWithBandwidthWeighting(
  client: DirectoryClient,
  consensus: VerifiedMicroDescConsensus,
  targetPorts: number[],
  fetchPolicies: boolean
): Promise<MicroDescNodeInfo[]> {
  const relays = consensus.relays;
  const circuitPlan: MicroDescNodeInfo[] = [];

  // Get exit candidates
  const exitCandidates = filterRelaysByFlags(relays, ['Exit'], []);

  // Fetch exit policies if requested
  if (fetchPolicies && exitCandidates.length > 0) {
    await fetchExitPolicies(client, exitCandidates);
  }

  // Pick exit with bandwidth weighting and policy filtering
  const exit = pickExitRelay(relays, targetPorts, consensus, circuitPlan);
  circuitPlan.push(exit);

  // Pick middle relay (any relay not already selected)
  const middle = pickMiddleRelay(relays, consensus, circuitPlan);
  circuitPlan.push(middle);

  // Pick guard relay
  const guard = pickGuardRelay(relays, consensus, circuitPlan);
  circuitPlan.push(guard);

  return circuitPlan;
}

/**
 * Select relays using uniform random selection (legacy behavior).
 */
function selectRelaysUniform(relays: MicroDescNodeInfo[]): MicroDescNodeInfo[] {
  const circuitPlan: MicroDescNodeInfo[] = [];
  circuitPlan.push(pickRelayWithFlags(relays, ['Exit'], circuitPlan));
  circuitPlan.push(pickRelayWithFlags(relays, [], circuitPlan));
  circuitPlan.push(pickRelayWithFlags(relays, ['Guard'], circuitPlan));
  return circuitPlan;
}

/**
 * Build a new circuit using safe directory lookups over an existing circuit.
 *
 * This is the recommended way to build circuits after initial bootstrap.
 * The existing circuit is used only for directory lookups - the new circuit
 * is completely independent.
 *
 * @param directoryCircuit - Existing circuit for directory lookups
 * @param options - Circuit building options
 * @returns New 3-hop circuit
 */
export async function connectRandomCircuitSafe(
  directoryCircuit: Circuit,
  options: CircuitBuildOptions = {}
): Promise<Circuit> {
  const circuitPeerInfos = await getRandomCircuitPathSafe(directoryCircuit, options);
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
 *
 * @param options - Circuit building options
 * @returns New 3-hop circuit
 */
export async function connectRandomCircuitWithSafeBootstrap(
  options: CircuitBuildOptions = {}
): Promise<Circuit> {
  // Step 1: Bootstrap safely using fallback directory
  const bootstrapCircuit = await bootstrapWithFallbackDirectory();

  try {
    // Step 2: Build a full 3-hop circuit using safe lookups
    const circuit = await connectRandomCircuitSafe(bootstrapCircuit, options);

    // Step 3: Clean up bootstrap circuit
    bootstrapCircuit.destroy();

    return circuit;
  } catch (err) {
    bootstrapCircuit.destroy();
    throw err;
  }
}

// Re-export for convenience
export { DEFAULT_TARGET_PORTS };
export type { CircuitBuildOptions as BuildCircuitOptions };
