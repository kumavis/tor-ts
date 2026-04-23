import { Circuit } from '../circuit.ts';
import type { PeerInfo } from '../circuit.ts';
import { TlsChannelConnection } from '../channel.ts';
import { lookupPeerInfo, fetchExitPolicies, fetchAndVerifyConsensus } from '../directory-client.ts';
import { MicrodescManager, InMemoryMicrodescStorage } from '../microdesc-manager.ts';
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

  // Create microdescriptor manager for exit policy lookups
  const microdescManager = new MicrodescManager({
    storage: new InMemoryMicrodescStorage(),
    dirClient: client,
  });

  // Select relays based on options
  const circuitPlan = useBandwidthWeighting
    ? await selectRelaysWithBandwidthWeighting(
        microdescManager,
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
  microdescManager: MicrodescManager,
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
    await fetchExitPolicies(microdescManager, exitCandidates);
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

// ---------------------------------------------------------------------------
// Retry helper
//
// Building a circuit and doing anything over it on the live Tor network is
// inherently flaky: relays hibernate, exit policies change, the guard's
// upstream OR-to-OR link can die mid-EXTEND, the chosen exit can fail to
// connect to the target, or any hop can be overloaded. None of those are
// bugs in client code — they're the cost of being a client of a volunteer
// relay network — so application callers need to retry.
// ---------------------------------------------------------------------------

/**
 * DESTROY reasons that indicate a transient network/relay failure rather than
 * a protocol mistake on our side. A fresh circuit through a different path
 * may well succeed.
 *
 * Per tor-spec.txt §5.4:
 *   4 HIBERNATING, 5 RESOURCELIMIT, 6 CONNECTFAILED, 7 OR_IDENTITY,
 *   8 CHANNEL_CLOSED, 10 TIMEOUT, 11 DESTROYED
 *
 * Non-retryable:
 *   0 NONE, 1 PROTOCOL, 2 INTERNAL, 3 REQUESTED, 9 FINISHED, 12 NOSUCHSERVICE
 */
const RETRYABLE_DESTROY_REASONS = new Set([4, 5, 6, 7, 8, 10, 11]);
const RETRYABLE_DESTROY_NAMES = new Set([
  'HIBERNATING',
  'RESOURCELIMIT',
  'CONNECTFAILED',
  'OR_IDENTITY',
  'CHANNEL_CLOSED',
  'TIMEOUT',
  'DESTROYED',
]);

/**
 * Whether this error is worth retrying with a fresh circuit. Matches both the
 * structured "circuit destroyed: REASON (N)" messages produced by Circuit
 * and common transport-level hang-ups (ECONNRESET, ETIMEDOUT, socket hang up).
 */
export function isRetryableTorError(err: unknown): boolean {
  if (!(err instanceof Error)) return false;
  const msg = err.message;

  // Structured circuit-destroy messages from Circuit.receiveMessage.
  const m = msg.match(/circuit destroyed: (\w+) \((\d+)\)/);
  if (m) {
    const name = m[1]!;
    const code = Number.parseInt(m[2]!, 10);
    return RETRYABLE_DESTROY_NAMES.has(name) || RETRYABLE_DESTROY_REASONS.has(code);
  }

  // Transport-level transients — guard/middle/exit TCP flakiness, stalled
  // reads surfacing as socket timeouts, etc.
  if (/ECONNRESET|ETIMEDOUT|ENETUNREACH|EHOSTUNREACH|socket hang up|timed out|timeout/i.test(msg)) {
    return true;
  }
  return false;
}

export type WithCircuitRetryOptions = CircuitBuildOptions & {
  /** Maximum number of bootstrap+run attempts. Defaults to 3. */
  maxAttempts?: number;
  /**
   * Called before each retry with the failure that triggered it. Useful for
   * surfacing transient-failure telemetry without coupling to a logger.
   */
  onRetry?: (attempt: number, err: Error) => void;
  /**
   * Override for the retry predicate. Defaults to {@link isRetryableTorError}.
   */
  shouldRetry?: (err: unknown) => boolean;
};

/**
 * Build a fresh random 3-hop circuit, run `fn` over it, and destroy the
 * circuit when `fn` returns. If `fn` or the bootstrap throws a retryable Tor
 * error, discard the (possibly half-dead) circuit and try again with a new
 * one up to `maxAttempts` times.
 *
 * Non-retryable errors propagate immediately so caller bugs don't get masked
 * behind a multi-minute retry loop.
 *
 * @example
 * const html = await withRetryingCircuit(async (circuit) => {
 *   const agent = getTorAgentForUrl(circuit, 'http://example.com');
 *   const r = await fetch('http://example.com', { agent });
 *   return r.text();
 * });
 */
export async function withRetryingCircuit<T>(
  fn: (circuit: Circuit) => Promise<T>,
  options: WithCircuitRetryOptions = {}
): Promise<T> {
  const { maxAttempts, onRetry, shouldRetry, ...buildOpts } = options;
  return retryWithCircuit(fn, {
    connect: () => connectRandomCircuitWithSafeBootstrap(buildOpts),
    ...(maxAttempts !== undefined ? { maxAttempts } : {}),
    ...(onRetry !== undefined ? { onRetry } : {}),
    ...(shouldRetry !== undefined ? { shouldRetry } : {}),
  });
}

/**
 * Testable core of {@link withRetryingCircuit}: identical behavior, but lets
 * callers inject the circuit-build step so unit tests can exercise the retry
 * policy without touching the live Tor network.
 */
export async function retryWithCircuit<T>(
  fn: (circuit: Circuit) => Promise<T>,
  options: {
    connect: () => Promise<Circuit>;
    maxAttempts?: number;
    onRetry?: (attempt: number, err: Error) => void;
    shouldRetry?: (err: unknown) => boolean;
  }
): Promise<T> {
  const { connect, maxAttempts = 3, onRetry, shouldRetry = isRetryableTorError } = options;
  if (maxAttempts < 1) throw new Error('maxAttempts must be >= 1');

  let lastError: unknown;
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    let circuit: Circuit | undefined;
    try {
      circuit = await connect();
      return await fn(circuit);
    } catch (err) {
      lastError = err;
      const shouldTryAgain = attempt < maxAttempts && shouldRetry(err);
      if (shouldTryAgain) {
        if (onRetry) onRetry(attempt, err instanceof Error ? err : new Error(String(err)));
        continue;
      }
      throw err;
    } finally {
      if (circuit) {
        try {
          circuit.destroy();
        } catch {
          // Circuit may already be destroyed by the DESTROY cell we caught.
        }
      }
    }
  }

  throw lastError ?? new Error('retryWithCircuit: exhausted without a result or error');
}
