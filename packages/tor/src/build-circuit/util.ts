import type { MicroDescNodeInfo, VerifiedMicroDescConsensus } from './directory.ts';
import { policyAllowsAllPorts, policyRejectsAll } from '../exit-policy.ts';

/**
 * Position in the circuit path, used for bandwidth weight calculation.
 */
export type RelayPosition = 'guard' | 'middle' | 'exit';

/**
 * Filter relays by required flags.
 */
export function filterRelaysByFlags(
  relays: MicroDescNodeInfo[],
  flags: string[],
  ignoreList: MicroDescNodeInfo[] = []
): MicroDescNodeInfo[] {
  const matchingRelays = relays.filter((relayInfo) => {
    const relayFlags = relayInfo.flags ?? [];
    const flagMatches = flags.every((flag) => relayFlags.includes(flag));
    if (!flagMatches) return false;
    const isIgnored = ignoreList.find((ignoredNodeInfo) => {
      return (
        ignoredNodeInfo === relayInfo || ignoredNodeInfo.rsaIdDigest.equals(relayInfo.rsaIdDigest)
      );
    });
    if (isIgnored) return false;
    return true;
  });
  return matchingRelays;
}

/**
 * Filter exit relays by exit policy for target ports.
 *
 * @param relays - Relays to filter (should have Exit flag)
 * @param targetPorts - Ports the exit must support
 * @returns Relays whose exit policy allows all target ports
 */
export function filterExitsByPolicy(
  relays: MicroDescNodeInfo[],
  targetPorts: number[]
): MicroDescNodeInfo[] {
  if (targetPorts.length === 0) {
    // No port requirements - just filter out exits that reject everything
    return relays.filter((r) => !policyRejectsAll(r.exitPolicy));
  }

  return relays.filter((relayInfo) => {
    // If no policy info, be permissive (will get REASON_EXITPOLICY if wrong)
    if (!relayInfo.exitPolicy) {
      return true;
    }
    return policyAllowsAllPorts(relayInfo.exitPolicy, targetPorts);
  });
}

/**
 * Pick a relay using uniform random selection (legacy behavior).
 */
export function pickRelayWithFlags(
  relays: MicroDescNodeInfo[],
  flags: string[],
  ignoreList: MicroDescNodeInfo[] = []
) {
  const matchingRelays = filterRelaysByFlags(relays, flags, ignoreList);
  if (matchingRelays.length === 0) {
    throw new Error(
      `Failed to find any matching relays for [${flags}] from ${relays.length} relays`
    );
  }
  // console.log(`matching`, flags, matchingRelays)
  const randomIndex = Math.floor(Math.random() * matchingRelays.length);
  const picked = matchingRelays[randomIndex];
  if (!picked) {
    throw new Error(
      `Failed to pick a relay (index=${randomIndex} length=${matchingRelays.length})`
    );
  }
  return picked;
}

/**
 * Default bandwidth weight scale (from Tor spec).
 */
const DEFAULT_WEIGHT_SCALE = 10000;

/**
 * Get the bandwidth weight multiplier for a relay at a given position.
 *
 * The consensus contains weight parameters like:
 * - Wgg: Weight for Guard in guard position
 * - Wgd: Weight for Guard+Exit in guard position
 * - Wmg: Weight for Guard in middle position
 * - Wmd: Weight for Guard+Exit in middle position
 * - Wme: Weight for Exit in middle position
 * - Wee: Weight for Exit in exit position
 * - Wed: Weight for Guard+Exit in exit position
 *
 * @param relay - The relay to get weight for
 * @param position - Position in the circuit
 * @param bandwidthWeights - Weights from consensus
 * @returns Weight multiplier (0-1 range after dividing by scale)
 */
export function getBandwidthWeightMultiplier(
  relay: MicroDescNodeInfo,
  position: RelayPosition,
  bandwidthWeights: Record<string, number>
): number {
  const scale = bandwidthWeights['bwweightscale'] ?? DEFAULT_WEIGHT_SCALE;
  const flags = relay.flags ?? [];
  const isGuard = flags.includes('Guard');
  const isExit = flags.includes('Exit');

  let weightKey: string;

  if (position === 'guard') {
    if (isGuard && isExit) {
      weightKey = 'Wgd'; // Guard+Exit in guard position
    } else if (isGuard) {
      weightKey = 'Wgg'; // Guard in guard position
    } else {
      weightKey = 'Wgm'; // Middle-only in guard position (shouldn't happen normally)
    }
  } else if (position === 'middle') {
    if (isGuard && isExit) {
      weightKey = 'Wmd'; // Guard+Exit in middle position
    } else if (isGuard) {
      weightKey = 'Wmg'; // Guard in middle position
    } else if (isExit) {
      weightKey = 'Wme'; // Exit in middle position
    } else {
      weightKey = 'Wmm'; // Middle-only in middle position
    }
  } else {
    // exit position
    if (isGuard && isExit) {
      weightKey = 'Wed'; // Guard+Exit in exit position
    } else if (isExit) {
      weightKey = 'Wee'; // Exit in exit position
    } else {
      weightKey = 'Wem'; // Middle-only in exit position (shouldn't happen normally)
    }
  }

  const weight = bandwidthWeights[weightKey] ?? scale;
  return weight / scale;
}

/**
 * Compute bandwidth weights for a list of relays at a given position.
 *
 * @param relays - Relays to compute weights for
 * @param position - Position in the circuit
 * @param bandwidthWeights - Weights from consensus
 * @returns Array of weights (same order as relays)
 */
export function computeRelayWeights(
  relays: MicroDescNodeInfo[],
  position: RelayPosition,
  bandwidthWeights: Record<string, number>
): number[] {
  return relays.map((relay) => {
    // Get base bandwidth from relay stats
    const baseBandwidth = relay.bandwidthStats?.Bandwidth ?? 1;
    // Apply position-specific weight multiplier
    const multiplier = getBandwidthWeightMultiplier(relay, position, bandwidthWeights);
    return baseBandwidth * multiplier;
  });
}

/**
 * Pick a relay using bandwidth-weighted random selection.
 *
 * @param relays - Candidate relays
 * @param weights - Bandwidth weights (same order as relays)
 * @param random - Random value in [0, 1) range (default: Math.random())
 * @returns Selected relay
 */
export function pickRelayWeighted(
  relays: MicroDescNodeInfo[],
  weights: number[],
  random: number = Math.random()
): MicroDescNodeInfo {
  if (relays.length === 0) {
    throw new Error('No relays to pick from');
  }
  if (relays.length !== weights.length) {
    throw new Error('Relays and weights arrays must have the same length');
  }

  // Calculate total weight
  const totalWeight = weights.reduce((sum, w) => sum + w, 0);
  if (totalWeight <= 0) {
    // Fall back to uniform random if no valid weights
    return relays[Math.floor(random * relays.length)]!;
  }

  // Pick a random point in [0, totalWeight)
  let target = random * totalWeight;

  // Find the relay at that point
  for (let i = 0; i < relays.length; i++) {
    target -= weights[i]!;
    if (target <= 0) {
      return relays[i]!;
    }
  }

  // Should not reach here, but return last relay as fallback
  return relays[relays.length - 1]!;
}

/**
 * Pick a relay with bandwidth weighting for a specific circuit position.
 *
 * @param relays - Candidate relays (should already be filtered by flags)
 * @param position - Position in the circuit
 * @param consensus - Parsed consensus containing bandwidth weights
 * @param ignoreList - Relays to exclude (already in circuit)
 * @returns Selected relay
 */
export function pickRelayWeightedForPosition(
  relays: MicroDescNodeInfo[],
  position: RelayPosition,
  consensus: VerifiedMicroDescConsensus,
  ignoreList: MicroDescNodeInfo[] = []
): MicroDescNodeInfo {
  // Filter out ignored relays
  const candidates = relays.filter((relay) => {
    return !ignoreList.some(
      (ignored) => ignored === relay || ignored.rsaIdDigest.equals(relay.rsaIdDigest)
    );
  });

  if (candidates.length === 0) {
    throw new Error(`No candidate relays for ${position} position`);
  }

  const weights = computeRelayWeights(candidates, position, consensus.bandwidthWeights);
  return pickRelayWeighted(candidates, weights);
}

/**
 * Pick an exit relay with bandwidth weighting and exit policy filtering.
 *
 * @param relays - All relays from consensus
 * @param targetPorts - Ports the exit must support
 * @param consensus - Parsed consensus containing bandwidth weights
 * @param ignoreList - Relays to exclude
 * @returns Selected exit relay
 */
export function pickExitRelay(
  relays: MicroDescNodeInfo[],
  targetPorts: number[],
  consensus: VerifiedMicroDescConsensus,
  ignoreList: MicroDescNodeInfo[] = []
): MicroDescNodeInfo {
  // Filter to exits only
  const exits = filterRelaysByFlags(relays, ['Exit'], ignoreList);
  if (exits.length === 0) {
    throw new Error('No exit relays available');
  }

  // Filter by exit policy
  const validExits = filterExitsByPolicy(exits, targetPorts);
  if (validExits.length === 0) {
    throw new Error(`No exit relays support target ports [${targetPorts.join(', ')}]`);
  }

  // Pick with bandwidth weighting
  const weights = computeRelayWeights(validExits, 'exit', consensus.bandwidthWeights);
  return pickRelayWeighted(validExits, weights);
}

/**
 * Pick a guard relay with bandwidth weighting.
 *
 * @param relays - All relays from consensus
 * @param consensus - Parsed consensus containing bandwidth weights
 * @param ignoreList - Relays to exclude
 * @returns Selected guard relay
 */
export function pickGuardRelay(
  relays: MicroDescNodeInfo[],
  consensus: VerifiedMicroDescConsensus,
  ignoreList: MicroDescNodeInfo[] = []
): MicroDescNodeInfo {
  const guards = filterRelaysByFlags(relays, ['Guard'], ignoreList);
  if (guards.length === 0) {
    throw new Error('No guard relays available');
  }

  const weights = computeRelayWeights(guards, 'guard', consensus.bandwidthWeights);
  return pickRelayWeighted(guards, weights);
}

/**
 * Pick a middle relay with bandwidth weighting.
 *
 * @param relays - All relays from consensus
 * @param consensus - Parsed consensus containing bandwidth weights
 * @param ignoreList - Relays to exclude
 * @returns Selected middle relay
 */
export function pickMiddleRelay(
  relays: MicroDescNodeInfo[],
  consensus: VerifiedMicroDescConsensus,
  ignoreList: MicroDescNodeInfo[] = []
): MicroDescNodeInfo {
  // Middle relays don't need special flags, just exclude already-selected relays
  const candidates = relays.filter((relay) => {
    return !ignoreList.some(
      (ignored) => ignored === relay || ignored.rsaIdDigest.equals(relay.rsaIdDigest)
    );
  });

  if (candidates.length === 0) {
    throw new Error('No middle relays available');
  }

  const weights = computeRelayWeights(candidates, 'middle', consensus.bandwidthWeights);
  return pickRelayWeighted(candidates, weights);
}
