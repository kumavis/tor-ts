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
  // reads surfacing as socket timeouts, connection refused from an unhealthy
  // fallback directory, etc. Covers every Node system errno we realistically
  // expect to see when a Tor relay is down, restarting, or firewalled.
  if (
    /\b(ECONNREFUSED|ECONNRESET|ECONNABORTED|ETIMEDOUT|ENETUNREACH|EHOSTUNREACH|ENETDOWN|ENETRESET|ENOTCONN|EPIPE|EPROTO)\b/.test(
      msg
    )
  ) {
    return true;
  }
  if (/socket hang up|timed out|timeout/i.test(msg)) {
    return true;
  }
  return false;
}

export type RetryOptions = {
  /** Maximum number of attempts. Defaults to 3. Must be >= 1. */
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
  /**
   * Milliseconds to wait before attempt N+1 when attempt N fails. Called
   * with the 1-based attempt number that just failed. Default: no delay.
   * A small linear/exponential backoff helps avoid correlated failures when
   * a guard relay is in the middle of restarting.
   */
  backoffMs?: number | ((failedAttempt: number) => number);
};

/**
 * Generic retry loop for a function that may throw transient Tor errors.
 *
 * Exposed publicly so callers can apply the same classifier+loop to their
 * own custom attempt unit — for example, retrying a single stream open on a
 * long-lived circuit without rebuilding the circuit, or composing bootstrap
 * and per-request retries with independent budgets.
 *
 * The default `shouldRetry` matches both the structured circuit-destroy
 * messages produced by {@link Circuit.receiveMessage} and common transport-
 * level hang-ups (ECONNREFUSED, ECONNRESET, ETIMEDOUT, ...). Non-retryable
 * errors propagate on the first attempt, so caller bugs aren't hidden by a
 * multi-minute retry loop.
 */
export async function retryTransient<T>(
  attempt: () => Promise<T>,
  options: RetryOptions = {}
): Promise<T> {
  const { maxAttempts = 3, onRetry, shouldRetry = isRetryableTorError, backoffMs } = options;
  if (maxAttempts < 1) throw new Error('maxAttempts must be >= 1');

  const computeDelay = (failedAttempt: number): number => {
    if (backoffMs === undefined) return 0;
    return typeof backoffMs === 'function' ? backoffMs(failedAttempt) : backoffMs;
  };

  let lastError: unknown;
  for (let i = 1; i <= maxAttempts; i++) {
    try {
      return await attempt();
    } catch (err) {
      lastError = err;
      if (i < maxAttempts && shouldRetry(err)) {
        if (onRetry) onRetry(i, err instanceof Error ? err : new Error(String(err)));
        const delay = computeDelay(i);
        if (delay > 0) await new Promise<void>((resolve) => setTimeout(resolve, delay));
        continue;
      }
      throw err;
    }
  }
  throw lastError ?? new Error('retryTransient: exhausted without a result or error');
}

// ---------------------------------------------------------------------------
// Layered retry primitives
//
// Two distinct concerns, two distinct helpers:
//
//  1. Building a usable circuit — retrying on transient bootstrap failures
//     (ECONNREFUSED to the fallback directory, DESTROY mid-EXTEND, ...).
//     See: buildCircuitWithRetry.
//
//  2. Running an operation against *some* working circuit, tolerating a
//     circuit that dies mid-operation by building a fresh one and running
//     the operation again. See: withTorOperation.
//
// The circuits built by each attempt of withTorOperation are *different*
// circuits, because a circuit is a specific path of relays. If you want to
// run several operations over the same circuit and only rebuild when it
// actually dies, call buildCircuitWithRetry yourself, reuse the circuit,
// and wrap each operation with retryTransient.
// ---------------------------------------------------------------------------

export type BuildCircuitWithRetryOptions = CircuitBuildOptions & RetryOptions;

/**
 * Build a fresh random 3-hop circuit, retrying on transient bootstrap
 * failures. Returns a circuit that was alive at the moment it was returned;
 * the caller owns it and is responsible for destroying it.
 *
 * Retry unit: one full bootstrap+circuit-build.
 *
 * @example
 * const circuit = await buildCircuitWithRetry();
 * try {
 *   // ... use circuit.openStream(...) as many times as you like ...
 * } finally {
 *   circuit.destroy();
 * }
 */
export async function buildCircuitWithRetry(
  options: BuildCircuitWithRetryOptions = {}
): Promise<Circuit> {
  const { maxAttempts, onRetry, shouldRetry, backoffMs, ...buildOpts } = options;
  return retryTransient(() => connectRandomCircuitWithSafeBootstrap(buildOpts), {
    ...(maxAttempts !== undefined ? { maxAttempts } : {}),
    ...(onRetry !== undefined ? { onRetry } : {}),
    ...(shouldRetry !== undefined ? { shouldRetry } : {}),
    ...(backoffMs !== undefined ? { backoffMs } : {}),
  });
}

export type WithTorOperationOptions = CircuitBuildOptions & RetryOptions;

/**
 * Run `fn` against a fresh Tor circuit, tolerating a circuit that dies
 * mid-operation by building a new one and running `fn` again from scratch.
 *
 * Retry unit: one full (build circuit + run fn + destroy circuit) cycle.
 *
 * Useful when `fn` is a single side-effect-free request (e.g. a GET) — every
 * attempt will re-run it in full, so do NOT use this for operations that
 * have observable side effects on the first attempt. For batch workloads
 * that should survive mid-batch circuit death, call {@link buildCircuitWithRetry}
 * yourself and wrap each sub-request with {@link retryTransient} so only the
 * failed request re-runs.
 *
 * @example
 * const html = await withTorOperation(async (circuit) => {
 *   const agent = getTorAgentForUrl(circuit, 'http://example.com');
 *   const r = await fetch('http://example.com', { agent });
 *   return r.text();
 * });
 */
export async function withTorOperation<T>(
  fn: (circuit: Circuit) => Promise<T>,
  options: WithTorOperationOptions = {}
): Promise<T> {
  const { maxAttempts, onRetry, shouldRetry, backoffMs, ...buildOpts } = options;
  return retryTransient(
    async () => {
      // Build a fresh circuit per attempt. We intentionally do NOT call
      // buildCircuitWithRetry here: this helper has a single retry budget
      // that covers both bootstrap and fn failures, so a caller with
      // maxAttempts=3 gets exactly 3 full tries — not 3 * 3.
      const circuit = await connectRandomCircuitWithSafeBootstrap(buildOpts);
      try {
        return await fn(circuit);
      } finally {
        try {
          circuit.destroy();
        } catch {
          // Circuit may already have been destroyed by a DESTROY cell.
        }
      }
    },
    {
      ...(maxAttempts !== undefined ? { maxAttempts } : {}),
      ...(onRetry !== undefined ? { onRetry } : {}),
      ...(shouldRetry !== undefined ? { shouldRetry } : {}),
      ...(backoffMs !== undefined ? { backoffMs } : {}),
    }
  );
}
