import {
  x25519,
  ed25519,
  makeAes256CtrKey,
  randomBytes,
  aes256CtrXor,
  ed25519VerifySync,
  // rend-spec-v3 helpers (same impl shared by hidden-service-host.ts):
  sha3,
  kdfShake256,
  u64be,
  mac,
  dMac,
  bytesToBigIntLE,
  createSha3_256Hash,
  // rend-spec-v3 hidden-service proof-of-work (proposal 327 / hspow-spec):
  solveHsPow,
} from 'tor-crypto';
import { BytesReader, shuffleInPlace } from './util.ts';
import { type LinkSpecifier, LinkSpecifierTypes, RELAY_PAYLOAD_LEN } from './messaging.ts';
import { RelayCell } from './relay-cell.ts';
import { parseEd25519Certificate, CertTypes } from './cert.ts';
import { Circuit, type CircuitCipherPair, type PeerInfo } from './circuit.ts';
import { pickRelayWithFlags } from './build-circuit/util.ts';
import { DirectoryClient, lookupPeerInfo } from './directory-client.ts';
import {
  type VerifiedMicroDescConsensus,
  type MicroDescNodeInfo,
  microDescNodeInfoToPeerInfo,
} from './build-circuit/directory.ts';
import type { MicrodescManager, MicrodescProgressCallback } from './microdesc-manager.ts';

const HASH_LEN = 32; // SHA3-256
const MAC_KEY_LEN = 32;
const S_KEY_LEN = 32; // AES-256 key
const S_IV_LEN = 16; // AES block/iv length

/**
 * Target length for the INTRODUCE1 encrypted section (CLIENT_PK + ciphertext + MAC) per the spec.
 * The spec recommends 490 octets for v3; the relay cell payload limit is RELAY_PAYLOAD_LEN (498),
 * so we cap the encrypted section at (498 - header length) so the full INTRODUCE1 fits in one cell.
 */
const INTRO1_ENCRYPTED_SECTION_RECOMMENDED = 490;
const INTRO1_HEADER_LEN = 20 + 1 + 2 + 32 + 1; // legacy_key_id + auth_key_type + auth_key_len + AUTH_KEY + N_EXT
const INTRO1_ENCRYPTED_SECTION_MAX = RELAY_PAYLOAD_LEN - INTRO1_HEADER_LEN; // 498 - 56 = 442
const INTRO1_TARGET_LEN = Math.min(
  INTRO1_ENCRYPTED_SECTION_RECOMMENDED,
  INTRO1_ENCRYPTED_SECTION_MAX
);

/**
 * Verbose HS-flow diagnostics (HSDir selection, SRV/period candidates, blinded
 * keys, replica indices, etc.) are gated behind TOR_TS_HS_DEBUG. Set the env
 * var to `1`/`true` to surface them through the existing `log` callback.
 *
 * The default log callback is a no-op for the production path; this gate is
 * for the case where the caller *did* wire a log sink and we want to keep
 * routine flows quiet there too.
 */
/**
 * Whether verbose HS diagnostics are currently enabled.
 *
 * Evaluated per-call (not cached at module load) so it can be toggled at
 * runtime. This matters in the browser / service-worker, where there is no
 * `process.env`: the browser Tor client sets `globalThis.__TOR_TS_HS_DEBUG__`
 * when created with `{ debug: true }`, which turns these logs on without a
 * rebuild.
 *
 * Enabled when either:
 *   - Node:    `process.env.TOR_TS_HS_DEBUG` is `'1'` or `'true'`, or
 *   - Browser: `globalThis.__TOR_TS_HS_DEBUG__ === true`.
 */
export function isHsDebugEnabled(): boolean {
  const g = globalThis as { __TOR_TS_HS_DEBUG__?: boolean };
  if (g.__TOR_TS_HS_DEBUG__ === true) return true;
  const v =
    typeof process !== 'undefined' && process?.env ? process.env.TOR_TS_HS_DEBUG : undefined;
  if (v === undefined) return false;
  return v === '1' || v.toLowerCase() === 'true';
}

function makeHsDebugLog(log: (msg: string) => void): (msg: string) => void {
  return (msg: string) => {
    if (isHsDebugEnabled()) log(msg);
  };
}

// ============================================================================
// Protocol Version Parsing Utilities
// ============================================================================

/**
 * Parse a protocol version string (e.g., "1-2,4,6-10") into an array of version numbers.
 *
 * The format is a comma-separated list of ranges. Each range can be:
 * - A single number: "2"
 * - A range: "1-5"
 *
 * @param protoStr - The protocol version string (e.g., "1-2,4" or "2")
 * @returns Array of version numbers
 */
export function parseProtocolVersions(protoStr: string): number[] {
  const versions: number[] = [];
  for (const part of protoStr.split(',')) {
    const trimmed = part.trim();
    if (!trimmed) continue;
    if (trimmed.includes('-')) {
      const [startStr, endStr] = trimmed.split('-');
      const start = Number(startStr);
      const end = Number(endStr);
      if (Number.isFinite(start) && Number.isFinite(end) && start <= end) {
        for (let v = start; v <= end; v++) {
          versions.push(v);
        }
      }
    } else {
      const v = Number(trimmed);
      if (Number.isFinite(v)) {
        versions.push(v);
      }
    }
  }
  return versions;
}

/**
 * Check if a protocol version string contains a specific version.
 *
 * This properly handles the Tor protocol version format (e.g., "1-2,4,6-10")
 * instead of using naive string matching like `.includes('2')` which would
 * incorrectly match "12", "20", etc.
 *
 * @param protoStr - The protocol version string
 * @param version - The version to check for
 * @returns true if the version is supported
 */
export function supportsProtocolVersion(protoStr: string, version: number): boolean {
  return parseProtocolVersions(protoStr).includes(version);
}

/**
 * Time period information derived from a consensus, used for HS descriptor location.
 */
export interface TimePeriodInfo {
  periodLengthMinutes: bigint;
  periodCandidates: bigint[];
  nReplicas: number;
  spreadFetch: number;
}

// ============================================================================
// Generic Hidden Service Connection Types
// ============================================================================

/**
 * Function type for building circuits to a target relay.
 * This abstracts the platform-specific circuit building (browser vs Node.js).
 *
 * @param target - The target relay (final hop)
 * @param options.avoid - Relays to avoid in path selection
 * @returns A connected circuit
 */
export type BuildCircuitFn = (
  target: PeerInfo,
  options?: { avoid?: PeerInfo[] }
) => Promise<Circuit>;

/**
 * Client authorization credentials for accessing a restricted onion service.
 *
 * When a service has restricted discovery enabled, clients must possess
 * a pre-shared x25519 keypair to decrypt the descriptor cookie.
 */
export interface HsClientAuthCredentials {
  /**
   * The client's x25519 private key (32 bytes).
   * This is the secret key (KS_hsc_desc_enc) used to derive the descriptor cookie.
   */
  privateKey: Buffer;
  /**
   * The client's x25519 public key (32 bytes).
   * This is KP_hsc_desc_enc, which was shared with the hidden service.
   */
  publicKey: Buffer;
}

/**
 * Outcome of an introduction point attempt.
 */
export type IptOutcome =
  | { type: 'success'; durationMs: number }
  | { type: 'failure'; durationMs: number; retryAfterMs?: number };

/**
 * Tracks experience with introduction points across connection attempts.
 * This allows smarter ordering of intro points on retry (favoring those that worked).
 */
export class IptExperienceTracker {
  private experiences = new Map<string, IptOutcome[]>();

  /**
   * Get the relay ID key for an intro point.
   */
  private getRelayId(intro: IntroPoint): string {
    const legacyId = intro.linkSpecifiers.find((ls) => ls.type === LinkSpecifierTypes.LegacyId);
    if (legacyId) {
      return legacyId.data.toString('hex');
    }
    // Fallback to auth key
    return intro.authKeyEd25519.toString('hex');
  }

  /**
   * Record the outcome of an introduction attempt.
   */
  record(intro: IntroPoint, outcome: IptOutcome): void {
    const key = this.getRelayId(intro);
    const existing = this.experiences.get(key) ?? [];
    existing.push(outcome);
    // Keep only the last 5 experiences per relay
    if (existing.length > 5) {
      existing.shift();
    }
    this.experiences.set(key, existing);
  }

  /**
   * Get a score for an intro point based on past experience.
   * Higher scores are better (more successful, faster).
   */
  private getScore(intro: IntroPoint): number {
    const key = this.getRelayId(intro);
    const experiences = this.experiences.get(key);
    if (!experiences || experiences.length === 0) {
      return 0; // Neutral for unknown
    }

    let score = 0;
    for (const exp of experiences) {
      if (exp.type === 'success') {
        // Reward success, prefer faster connections
        score += 100 - Math.min(exp.durationMs / 100, 50);
      } else {
        // Penalize failures
        score -= 50;
        if (exp.retryAfterMs && exp.retryAfterMs > Date.now()) {
          // Extra penalty if we're still in a retry backoff period
          score -= 100;
        }
      }
    }
    return score;
  }

  /**
   * Sort intro points by experience, with best performers first.
   * Unknown intro points are shuffled randomly among themselves.
   */
  sortByExperience(introPoints: IntroPoint[]): IntroPoint[] {
    return introPoints.sort((a, b) => {
      const scoreA = this.getScore(a);
      const scoreB = this.getScore(b);
      // Higher score = better = should come first
      if (scoreA !== scoreB) {
        return scoreB - scoreA;
      }
      // For same score (including unknowns), maintain random order
      return 0;
    });
  }
}

/**
 * Options for the core hidden service connection flow.
 */
export interface HsConnectionOptions {
  /** Overall timeout in milliseconds (default: 120000) */
  overallTimeoutMs?: number;
  /** Timeout per handshake operation (default: min of overallTimeoutMs, 120000) */
  perHandshakeTimeoutMs?: number;
  /** Timeout for waiting for RENDEZVOUS2 after successful introduction (default: 60000) */
  rendezvousTimeoutMs?: number;
  /** Max introduction attempts (default: 6) */
  maxIntroAttempts?: number;
  /** Logging function for status updates */
  log?: (message: string) => void;
  /** Progress callback for microdescriptor downloads (called when fetching HSDir Ed25519 keys) */
  onMicrodescProgress?: MicrodescProgressCallback;
  /** Generate random bytes (default: uses tor-crypto randomBytes) */
  randomBytes?: (length: number) => Uint8Array;
  /**
   * Client authorization credentials for restricted discovery.
   * If provided, these will be used to decrypt the descriptor cookie
   * for services with client authorization enabled.
   */
  clientAuth?: HsClientAuthCredentials;
  /**
   * Experience tracker for introduction points.
   * If provided, past experiences will be used to order intro points
   * and failed/successful attempts will be recorded for future connections.
   */
  iptExperienceTracker?: IptExperienceTracker;
  /**
   * Descriptor cache for avoiding repeated HSDir lookups.
   * If provided, descriptors will be cached and reused across connection attempts.
   */
  descriptorCache?: HsDescriptorCache;
  /**
   * Disable the proof-of-work client. When a service advertises `pow-params`
   * with a non-zero suggested effort, the client solves an Equi-X puzzle
   * (proposal 327) and attaches it to INTRODUCE1. Set this to skip that — the
   * introduction is then sent without a PoW token (likely dropped by a service
   * actively enforcing PoW).
   */
  disablePow?: boolean;
  /**
   * Upper bound on the PoW effort to attempt, regardless of the service's
   * suggested effort. Solving cost scales roughly linearly with effort, so this
   * caps worst-case CPU time. Default: the descriptor's suggested effort.
   */
  maxPowEffort?: number;
  /**
   * Wall-clock budget for solving the PoW, in ms (default 60000). If exceeded,
   * the introduction is sent without a PoW token rather than blocking forever.
   */
  powTimeoutMs?: number;
}

/**
 * Result of a successful hidden service connection.
 */
export interface HsConnectionResult {
  /** The rendezvous circuit with virtual hop to the hidden service */
  circuit: Circuit;
  /** The parsed descriptor (contains intro points for reference) */
  descriptor: HiddenServiceDescriptor;
}

// ============================================================================
// Descriptor Caching
// ============================================================================

/**
 * A cached hidden service descriptor entry.
 */
interface CachedDescriptor {
  /** The parsed descriptor */
  descriptor: HiddenServiceDescriptor;
  /** The blinded public key (determines cache key along with identity) */
  blindedPublicKey: Buffer;
  /** The subcredential for this descriptor */
  subcred: Buffer;
  /** When this descriptor was fetched (ms since epoch) */
  fetchedAt: number;
  /** When this descriptor expires (ms since epoch, based on validity period) */
  expiresAt: number;
}

/**
 * Cache for hidden service descriptors.
 *
 * Caches descriptors by onion address (public identity key) to avoid
 * re-fetching from HSDirs on every connection attempt.
 *
 * Per the spec, descriptors are valid for their declared lifetime
 * (typically 3 hours / 180 minutes).
 */
export class HsDescriptorCache {
  private cache = new Map<string, CachedDescriptor>();

  /** Default descriptor validity period in ms (3 hours) */
  private static DEFAULT_VALIDITY_MS = 3 * 60 * 60 * 1000;

  /**
   * Get a cached descriptor for an onion address.
   *
   * @param publicIdentityKey - The HS identity public key (32 bytes)
   * @returns The cached entry if valid, or undefined if not cached or expired
   */
  get(publicIdentityKey: Buffer): CachedDescriptor | undefined {
    const key = publicIdentityKey.toString('hex');
    const entry = this.cache.get(key);

    if (!entry) {
      return undefined;
    }

    // Check if expired
    if (Date.now() > entry.expiresAt) {
      this.cache.delete(key);
      return undefined;
    }

    return entry;
  }

  /**
   * Store a descriptor in the cache.
   *
   * @param publicIdentityKey - The HS identity public key (32 bytes)
   * @param descriptor - The parsed descriptor
   * @param blindedPublicKey - The blinded key used to fetch it
   * @param subcred - The subcredential
   * @param validityMs - How long the descriptor is valid (default: 3 hours)
   */
  set(
    publicIdentityKey: Buffer,
    descriptor: HiddenServiceDescriptor,
    blindedPublicKey: Buffer,
    subcred: Buffer,
    validityMs: number = HsDescriptorCache.DEFAULT_VALIDITY_MS
  ): void {
    const key = publicIdentityKey.toString('hex');
    const now = Date.now();

    this.cache.set(key, {
      descriptor,
      blindedPublicKey,
      subcred,
      fetchedAt: now,
      expiresAt: now + validityMs,
    });
  }

  /**
   * Invalidate a cached descriptor (e.g., after connection failures suggest it's stale).
   *
   * @param publicIdentityKey - The HS identity public key
   */
  invalidate(publicIdentityKey: Buffer): void {
    const key = publicIdentityKey.toString('hex');
    this.cache.delete(key);
  }

  /**
   * Clear all cached descriptors.
   */
  clear(): void {
    this.cache.clear();
  }

  /**
   * Remove expired entries from the cache.
   */
  prune(): void {
    const now = Date.now();
    for (const [key, entry] of this.cache.entries()) {
      if (now > entry.expiresAt) {
        this.cache.delete(key);
      }
    }
  }

  /**
   * Get the number of cached descriptors.
   */
  get size(): number {
    return this.cache.size;
  }
}

/**
 * Context for hidden service connection.
 * Contains bootstrap resources and platform-specific circuit builder.
 */
export interface HsConnectionContext {
  /** Verified consensus */
  consensus: VerifiedMicroDescConsensus;
  /** Bootstrap circuit for directory lookups */
  bootstrapCircuit: Circuit;
  /** Directory client for relay info lookups */
  dirClient: DirectoryClient;
  /** Microdescriptor manager for Ed25519 key lookups */
  microdescManager: MicrodescManager;
  /** Function to build circuits to a target relay */
  buildCircuit: BuildCircuitFn;
}

/**
 * Computes time period information from a consensus for HS descriptor location.
 *
 * IMPORTANT: The time period is computed from the CURRENT time, not the consensus time.
 * The consensus is used only to derive the period length and voting parameters.
 * This matches C Tor's hs_get_time_period_num(time(NULL)) behavior.
 *
 * @param consensus - The consensus document (used for period length derivation)
 * @param currentTime - The current time (defaults to Date.now())
 * @returns Time period info needed for HS operations
 */
export function computeTimePeriodInfo(
  consensus: VerifiedMicroDescConsensus,
  currentTime: Date = new Date()
): TimePeriodInfo {
  if (!consensus.validAfter) {
    throw new Error('Consensus missing valid-after; cannot compute HS time period');
  }

  // Consensus params use underscores (`hsdir_interval`), matching C Tor's
  // networkstatus param names. An earlier hyphenated lookup (`hsdir-interval`)
  // always missed and silently fell back to 1440 — harmless while authorities
  // never voted a non-default value, but a latent correctness bug that would
  // pick the wrong time period (and thus the wrong blinded key / HSDirs) the
  // moment they did.
  const hsdirInterval = consensus.params['hsdir_interval'] ?? 1440;

  // Use CURRENT time for period calculation, but consensus for voting interval derivation
  const timeArgs: Parameters<typeof computeTimePeriod>[0] = { validAfter: currentTime };
  if (consensus.freshUntil && consensus.validAfter) {
    // Preserve the voting interval from the consensus
    const votingIntervalMs = consensus.freshUntil.getTime() - consensus.validAfter.getTime();
    timeArgs.freshUntil = new Date(currentTime.getTime() + votingIntervalMs);
  }

  // On mainnet, hsdir_interval == derived (votingIntervalSec * 24)/60 because the voting interval is 1h.
  // On testing networks (including Chutney), Tor ignores hsdir_interval and derives the period length from
  // the voting interval, which is typically much shorter than 1h. To match Tor behavior across both cases,
  // only pass hsdir_interval when it matches the derived value; otherwise let computeTimePeriod derive it.
  const votingIntervalSec = consensus.freshUntil
    ? Math.floor((consensus.freshUntil.getTime() - consensus.validAfter.getTime()) / 1000)
    : 3600;
  const derivedPeriodMinutes = Math.max(1, Math.floor((votingIntervalSec * 24) / 60));
  if (hsdirInterval === derivedPeriodMinutes) {
    timeArgs.hsdirIntervalMinutes = hsdirInterval;
  }

  const { periodNum: basePeriodNum, periodLengthMinutes } = computeTimePeriod(timeArgs);
  const periodCandidates = [basePeriodNum, basePeriodNum - 1n, basePeriodNum + 1n].filter(
    (n) => n >= 0n
  );
  const nReplicas = Math.min(16, Math.max(1, consensus.params['hsdir_n_replicas'] ?? 2));
  const spreadFetch = Math.min(128, Math.max(1, consensus.params['hsdir_spread_fetch'] ?? 3));

  return { periodLengthMinutes, periodCandidates, nReplicas, spreadFetch };
}

/**
 * Returns SRV values from a consensus for HS hash ring computation, with disaster SRV fallbacks.
 *
 * @param consensus - The consensus document
 * @param periodLengthMinutes - The period length in minutes
 * @param periodNum - The period number
 * @returns Array of SRV values to try (current and previous, with disaster fallbacks)
 */
export function getSrvValues(
  consensus: VerifiedMicroDescConsensus,
  periodLengthMinutes: bigint,
  periodNum: bigint
): Buffer[] {
  const disasterSrv = computeDisasterSrv({ periodLengthMinutes, periodNum });
  return [
    consensus.sharedRandCurrentValue ?? disasterSrv,
    consensus.sharedRandPreviousValue ?? disasterSrv,
  ];
}

/** Number of rounds in a full SR protocol run (C Tor: SHARED_RANDOM_N_ROUNDS * SHARED_RANDOM_N_PHASES). */
const SR_PROTOCOL_TOTAL_ROUNDS = 24;

/**
 * Returns true if valid_after falls in the time segment between a new time period and the next SRV
 * (on mainnet: 12:00–00:00 UTC). When true, clients use current SRV for fetching; when false (00:00–12:00),
 * they use previous SRV. Mirrors C Tor's hs_in_period_between_tp_and_srv().
 */
export function isInPeriodBetweenTpAndSrv(
  validAfter: Date,
  votingIntervalSeconds: number,
  periodLengthMinutes: number
): boolean {
  const validAfterSec = Math.floor(validAfter.getTime() / 1000);
  // Start of current SR protocol run (24 rounds)
  const currRoundSlot =
    Math.floor(validAfterSec / votingIntervalSeconds) % SR_PROTOCOL_TOTAL_ROUNDS;
  const timeElapsedSinceRunStart = currRoundSlot * votingIntervalSeconds;
  const srvStartTimeSec = validAfterSec - timeElapsedSinceRunStart;
  // Start of next time period (from srv_start; C Tor: hs_get_start_time_of_next_time_period)
  const rotationOffsetSec = 12 * votingIntervalSeconds;
  const rotationOffsetMin = rotationOffsetSec / 60;
  const minutesSinceEpoch = Math.floor(srvStartTimeSec / 60);
  const periodNum = Math.floor((minutesSinceEpoch - rotationOffsetMin) / periodLengthMinutes);
  const nextPeriodStartMin = (periodNum + 1) * periodLengthMinutes;
  const tpStartTimeSec = nextPeriodStartMin * 60 + rotationOffsetSec;
  // C Tor: return 1 if NOT in [srv_start, tp_start)
  if (validAfterSec >= srvStartTimeSec && validAfterSec < tpStartTimeSec) {
    return false;
  }
  return true;
}

/**
 * Returns the single SRV clients should use for HSDir fetch in the current time window.
 * In SRV-to-TP window (00:00–12:00 UTC) uses previous SRV; in TP-to-SRV (12:00–00:00) uses current SRV.
 * Matches C Tor's node_set_hsdir_index() fetch_srv choice.
 */
export function getFetchSrv(
  consensus: VerifiedMicroDescConsensus,
  periodLengthMinutes: bigint,
  periodNum: bigint
): Buffer {
  const disasterSrv = computeDisasterSrv({ periodLengthMinutes, periodNum });
  if (!consensus.validAfter) {
    return disasterSrv;
  }
  const votingIntervalSec = consensus.freshUntil
    ? Math.floor((consensus.freshUntil.getTime() - consensus.validAfter.getTime()) / 1000)
    : 3600;
  if (votingIntervalSec < 1) {
    throw new Error(
      `Invalid consensus: voting interval is ${votingIntervalSec} (validAfter and freshUntil must differ)`
    );
  }
  const periodLenMin = Number(periodLengthMinutes);
  const useCurrent = isInPeriodBetweenTpAndSrv(
    consensus.validAfter,
    votingIntervalSec,
    periodLenMin
  );
  if (useCurrent) {
    return consensus.sharedRandCurrentValue ?? disasterSrv;
  }
  return consensus.sharedRandPreviousValue ?? disasterSrv;
}

export function toBase64UrlNoPad(buf: Buffer): string {
  return buf.toString('base64').replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
}

/**
 * Standard base64 encoding without padding.
 *
 * The Tor directory protocol uses standard base64 (with `+` and `/`)
 * WITHOUT padding for blinded public keys in HSDir descriptor fetch URLs.
 * This matches the C Tor client's `digest256_to_base64()` / `base64_encode_nopad()`.
 *
 * IMPORTANT: Do NOT use base64url here. The HSDir's `base64_decode()` rejects
 * `-` and `_` characters, returning 404.
 */
export function toBase64NoPad(buf: Buffer): string {
  return buf.toString('base64').replaceAll('=', '');
}

export function computeDisasterSrv(params: {
  periodLengthMinutes: bigint;
  periodNum: bigint;
}): Buffer {
  // Tor-compatible disaster SRV (see tor hs_common.c compute_disaster_srv()):
  // SHA3-256("shared-random-disaster" | INT_8(period_length) | INT_8(period_num))
  const prefix = Buffer.from('shared-random-disaster', 'ascii');
  return sha3(prefix, u64be(params.periodLengthMinutes), u64be(params.periodNum));
}

export function hsBuildHsIndex(params: {
  blindedPublicKey: Buffer;
  replicanum: bigint;
  periodLengthMinutes: bigint;
  periodNum: bigint;
}): Buffer {
  // SHA3-256("store-at-idx" | blinded_public_key |
  //          INT_8(replicanum) | INT_8(period_length) | INT_8(period_num))
  const prefix = Buffer.from('store-at-idx', 'ascii');
  return sha3(
    prefix,
    params.blindedPublicKey,
    u64be(params.replicanum),
    u64be(params.periodLengthMinutes),
    u64be(params.periodNum)
  );
}

export function hsBuildHsdirIndex(params: {
  ed25519IdentityKey: Buffer;
  sharedRandomValue: Buffer;
  periodLengthMinutes: bigint;
  periodNum: bigint;
}): Buffer {
  // SHA3-256("node-idx" | node_identity |
  //          shared_random_value | INT_8(period_num) | INT_8(period_length))
  // Note order matches tor hs_build_hsdir_index().
  const prefix = Buffer.from('node-idx', 'ascii');
  return sha3(
    prefix,
    params.ed25519IdentityKey,
    params.sharedRandomValue,
    u64be(params.periodNum),
    u64be(params.periodLengthMinutes)
  );
}

export type HsdirCandidate = {
  peerInfo: PeerInfo;
  ed25519IdentityKey: Buffer;
};

/**
 * Build HSDir candidates with Ed25519 identity keys using cached microdescriptors.
 *
 * This uses the MicrodescManager to efficiently look up Ed25519 keys
 * from cached microdescriptors. The manager handles caching and deduplication.
 *
 * @param manager - MicrodescManager with cached microdescriptors
 * @param hsdirNodes - Array of HSDir nodes from the consensus
 * @param onProgress - Optional progress callback
 * @returns Array of HSDir candidates with PeerInfo and Ed25519 identity keys
 */
export async function fetchHsdirCandidates(
  manager: MicrodescManager,
  hsdirNodes: MicroDescNodeInfo[],
  onProgress?: MicrodescProgressCallback
): Promise<HsdirCandidate[]> {
  // Filter to nodes with mKey (microdescriptor digest)
  const nodesWithMKey = hsdirNodes.filter((n) => n.mKey);
  if (nodesWithMKey.length === 0) {
    return [];
  }

  // Convert mKey buffers to base64 (without padding, as used in directory requests)
  const digestsBase64 = nodesWithMKey.map((n) => n.mKey!.toString('base64').replace(/=+$/, ''));

  // Build a map from digest to node for quick lookup
  const digestToNode = new Map<string, MicroDescNodeInfo>();
  for (let i = 0; i < nodesWithMKey.length; i++) {
    digestToNode.set(digestsBase64[i]!, nodesWithMKey[i]!);
  }

  // Fetch microdescriptors via the manager (uses cache + deduplication)
  const microdescriptors = await manager.get(digestsBase64, onProgress);

  const candidates: HsdirCandidate[] = [];
  for (const [digest, microdesc] of microdescriptors) {
    const node = digestToNode.get(digest);
    if (node && microdesc.ntorOnionKey && microdesc.ed25519Identity) {
      const peerInfo = microDescNodeInfoToPeerInfo(
        node,
        microdesc.ntorOnionKey,
        microdesc.ed25519Identity
      );
      candidates.push({
        peerInfo,
        ed25519IdentityKey: microdesc.ed25519Identity,
      });
    }
  }

  return candidates;
}

export function selectHsdirsForFetch(params: {
  hsdirs: HsdirCandidate[];
  sharedRandomValue: Buffer;
  blindedPublicKey: Buffer;
  periodLengthMinutes: bigint;
  periodNum: bigint;
  nReplicas: number;
  spreadFetch: number;
  log?: (msg: string) => void;
}): PeerInfo[] {
  const dlog = makeHsDebugLog(params.log ?? (() => {}));

  const ring = params.hsdirs
    .map((h) => {
      const idx = hsBuildHsdirIndex({
        ed25519IdentityKey: h.ed25519IdentityKey,
        sharedRandomValue: params.sharedRandomValue,
        periodLengthMinutes: params.periodLengthMinutes,
        periodNum: params.periodNum,
      });
      return { ...h, idx };
    })
    .sort((a, b) => Buffer.compare(a.idx, b.idx));

  if (ring.length === 0) return [];

  const selected = new Set<string>();
  const out: PeerInfo[] = [];

  for (let replica = 1; replica <= params.nReplicas; replica++) {
    const hsIdx = hsBuildHsIndex({
      blindedPublicKey: params.blindedPublicKey,
      replicanum: BigInt(replica),
      periodLengthMinutes: params.periodLengthMinutes,
      periodNum: params.periodNum,
    });

    dlog(`Replica ${replica} hs_index: ${hsIdx.toString('hex').slice(0, 16)}...`);

    let start = ring.findIndex((x) => Buffer.compare(x.idx, hsIdx) > 0);
    if (start === -1) start = 0;

    let added = 0;
    for (let step = 0; step < ring.length && added < params.spreadFetch; step++) {
      const entry = ring[(start + step) % ring.length]!;
      const key = entry.peerInfo.rsaIdDigest.toString('hex');
      if (selected.has(key)) continue;
      selected.add(key);
      out.push(entry.peerInfo);
      added++;

      if (added === 1) {
        dlog(
          `Replica ${replica} first HSDir: ${key.slice(0, 8)} at hsdir_index: ${entry.idx.toString('hex').slice(0, 16)}...`
        );
      }
    }
  }

  return shuffleInPlace(out);
}

function base32DecodeLowerNoPad(s: string): Buffer {
  // RFC4648 base32 alphabet, accepting lowercase or uppercase.
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const clean = s.toUpperCase().replaceAll('=', '');
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const ch of clean) {
    const idx = alphabet.indexOf(ch);
    if (idx === -1) throw new Error(`Invalid base32 char: ${ch}`);
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out.push((value >>> bits) & 0xff);
    }
  }
  return Buffer.from(out);
}

export function parseOnionV3Address(onion: string): { publicIdentityKey: Buffer } {
  // Strip .onion suffix and any subdomain prefix (per address-spec.md: [ignored].[onion_address].onion)
  const withoutSuffix = onion.toLowerCase().endsWith('.onion')
    ? onion.slice(0, -'.onion'.length)
    : onion;
  // The actual onion address is the last dot-separated component (subdomains are for vhosting)
  const parts = withoutSuffix.split('.');
  const host = parts[parts.length - 1] ?? '';
  if (host.length !== 56) {
    throw new Error(`Expected v3 onion address host length 56, got ${host.length}`);
  }
  const raw = base32DecodeLowerNoPad(host);
  if (raw.length !== 35) {
    throw new Error(`Expected v3 onion decoded length 35, got ${raw.length}`);
  }
  const pub = raw.subarray(0, 32);
  const checksum = raw.subarray(32, 34);
  const version = raw[34];
  if (version !== 3) {
    throw new Error(`Unsupported onion version: ${version}`);
  }
  const checksumExpected = sha3(
    Buffer.from('.onion checksum', 'ascii'),
    pub,
    Buffer.from([version])
  ).subarray(0, 2);
  if (!checksum.equals(checksumExpected)) {
    throw new Error('Invalid v3 onion checksum');
  }
  return { publicIdentityKey: Buffer.from(pub) };
}

/**
 * Check if a hostname is a .onion address.
 */
export function isOnionAddress(hostname: string): boolean {
  return hostname.toLowerCase().endsWith('.onion');
}

export function computeTimePeriod(params: {
  validAfter: Date;
  freshUntil?: Date;
  hsdirIntervalMinutes?: number;
}): { periodNum: bigint; periodLengthMinutes: bigint } {
  // Tor's HS time period math (see tor src/feature/hs/hs_common.c):
  // - period_length (minutes): consensus param hsdir_interval in normal networks.
  // - testing networks: period_length is derived from SRV protocol run duration
  //   (24 rounds of the voting interval), i.e. (voting_interval_seconds*24)/60.
  // - rotation offset (minutes): sr_state_get_phase_duration()/60 which is
  //   effectively (voting_interval_seconds*12)/60 in common configurations.

  const minutesSinceEpoch = BigInt(Math.floor(params.validAfter.getTime() / 60_000));

  let votingIntervalSeconds = 3600; // default 1 hour
  if (params.freshUntil) {
    const deltaSec = Math.floor((params.freshUntil.getTime() - params.validAfter.getTime()) / 1000);
    if (Number.isFinite(deltaSec) && deltaSec > 0) votingIntervalSeconds = deltaSec;
  }

  let periodLengthMinutes: bigint;
  if (params.hsdirIntervalMinutes !== undefined) {
    periodLengthMinutes = BigInt(params.hsdirIntervalMinutes);
  } else {
    const derived = Math.floor((votingIntervalSeconds * 24) / 60);
    periodLengthMinutes = BigInt(Math.max(1, derived));
  }

  const rotationOffsetMinutes = BigInt(Math.floor((12 * votingIntervalSeconds) / 60));
  const adjusted = minutesSinceEpoch - rotationOffsetMinutes;
  const periodNum = adjusted / periodLengthMinutes;
  return { periodNum, periodLengthMinutes };
}

export function deriveBlindedPublicKey(params: {
  publicIdentityKey: Buffer;
  periodNum: bigint;
  periodLengthMinutes: bigint;
}): Buffer {
  // Tor-compatible blinding parameter construction (see tor hs_common.c):
  // h = SHA3_256("Derive temporary signing key\\0" | A | [secret] | str_ed25519_basepoint | N)
  const blindStr = Buffer.from('Derive temporary signing key\0', 'ascii');
  const basepointStr = Buffer.from(
    '(15112221349535400772501151409588531511454012693041857206046113283949847762202, ' +
      '46316835694926478169428394003475163141307993866256225615783033603165251855960)',
    'ascii'
  );
  const N = Buffer.concat([
    Buffer.from('key-blind', 'ascii'),
    u64be(params.periodNum),
    u64be(params.periodLengthMinutes),
  ]);
  const hRaw = sha3(blindStr, params.publicIdentityKey, basepointStr, N);
  const h = Buffer.from(hRaw);
  // clamp per ed25519
  h[0] = (h[0] ?? 0) & 248;
  h[31] = (h[31] ?? 0) & 63;
  h[31] = (h[31] ?? 0) | 64;
  const scalar = bytesToBigIntLE(h) % ed25519.CURVE.n;
  const A = ed25519.ExtendedPoint.fromHex(params.publicIdentityKey);
  const APrime = A.multiply(scalar).toRawBytes();
  return Buffer.from(APrime);
}

export function deriveSubcredential(params: {
  publicIdentityKey: Buffer;
  blindedPublicKey: Buffer;
}): Buffer {
  const cred = sha3(Buffer.from('credential', 'ascii'), params.publicIdentityKey);
  return sha3(Buffer.from('subcredential', 'ascii'), cred, params.blindedPublicKey);
}

/**
 * Pick a rendezvous point from the consensus, applying the canonical tor
 * filters for RP selection. Exposed so a test can verify the filter without
 * running the full HS flow.
 *
 * Filters (canonical tor, hs_client.c `pick_rendezvous_node`):
 *   1. Must advertise HSRend protocol version 2 (v3 onion service rendezvous).
 *      Relays whose consensus entry lacks any HSRend protocol-version field at
 *      all are accepted as a permissive fallback — chutney consensuses
 *      occasionally omit the field for testing relays. A relay that *does*
 *      advertise an HSRend version but not v2 is still rejected.
 *   2. Must NOT be an authority (those are heavily loaded and not for relay).
 *   3. Must NOT be an Exit (canonical tor avoids Exits for RP so non-exit
 *      load stays balanced).
 *
 * If no relay matches all three filters we degrade gracefully: first drop
 * the Exit filter, then drop the Authority filter too. This keeps the
 * client functional on pathologically small or malformed consensuses while
 * still preferring the canonical choice when the consensus has it.
 *
 * Returns the chosen node plus the count of fully-qualified candidates — the
 * caller logs that count so we can tell at a glance whether we had to fall
 * back.
 */
export function pickRendezvousPoint(consensus: VerifiedMicroDescConsensus): {
  node: MicroDescNodeInfo;
  qualifiedCount: number;
} {
  const supportsHsRend2 = (r: MicroDescNodeInfo): boolean => {
    const versions = r.protocols?.HSRend;
    if (!versions) return true; // accept relays without explicit version info
    return supportsProtocolVersion(versions, 2);
  };
  const qualified = consensus.relays.filter((r) => {
    if (!supportsHsRend2(r)) return false;
    const flags = r.flags ?? [];
    if (flags.includes('Authority')) return false;
    if (flags.includes('Exit')) return false;
    return true;
  });
  if (qualified.length > 0) {
    return {
      node: pickRelayWithFlags(qualified, [], []),
      qualifiedCount: qualified.length,
    };
  }
  // Degrade step 1: allow Exits.
  const nonAuth = consensus.relays.filter(
    (r) => !(r.flags ?? []).includes('Authority') && supportsHsRend2(r)
  );
  if (nonAuth.length > 0) {
    return {
      node: pickRelayWithFlags(nonAuth, [], []),
      qualifiedCount: 0,
    };
  }
  // Degrade step 2: any relay.
  return {
    node: pickRelayWithFlags(consensus.relays, [], []),
    qualifiedCount: 0,
  };
}

function extractArmoredMessage(text: string, begin: string, end: string): Buffer {
  const start = text.indexOf(begin);
  if (start === -1) throw new Error(`Missing ${begin} armor`);
  const endIdx = text.indexOf(end, start);
  if (endIdx === -1) throw new Error(`Missing ${end} armor`);
  const body = text
    .slice(start + begin.length, endIdx)
    .replaceAll('\r', '')
    .split('\n')
    .map((l) => l.trim())
    .filter((l) => l.length > 0)
    .join('');
  return Buffer.from(body, 'base64');
}

type HsOuter = {
  revisionCounter: bigint;
  superencrypted: Buffer;
  descriptorSigningKeyCert: Buffer;
  signature: Buffer;
  signedPortion: Buffer;
};

const HS_DESC_SIG_PREFIX = Buffer.from('Tor onion service descriptor sig v3', 'ascii');

function parseHsDescriptorOuter(text: string): HsOuter {
  // Parse revision-counter
  const revMatch = text.match(/^revision-counter\s+(\d+)\s*$/m);
  if (!revMatch?.[1]) throw new Error('Missing revision-counter');
  const revisionCounter = BigInt(revMatch[1]);

  // Parse superencrypted blob
  const superencrypted = extractArmoredMessage(
    text,
    '-----BEGIN MESSAGE-----',
    '-----END MESSAGE-----'
  );

  // Parse descriptor-signing-key-cert
  const certBegin = '-----BEGIN ED25519 CERT-----';
  const certEnd = '-----END ED25519 CERT-----';
  const certStartIdx = text.indexOf(certBegin);
  if (certStartIdx === -1) throw new Error('Missing descriptor-signing-key-cert');
  const certEndIdx = text.indexOf(certEnd, certStartIdx);
  if (certEndIdx === -1) throw new Error('Missing descriptor-signing-key-cert end');
  const descriptorSigningKeyCert = extractArmoredMessage(
    text.slice(certStartIdx, certEndIdx + certEnd.length),
    certBegin,
    certEnd
  );

  // Parse signature - it's the last line after "signature "
  const sigMatch = text.match(/^signature\s+([A-Za-z0-9+/=]+)\s*$/m);
  if (!sigMatch?.[1]) throw new Error('Missing signature');
  const signature = Buffer.from(sigMatch[1], 'base64');

  // The signed portion is everything up to (but not including) the "signature " line
  const sigLineIdx = text.indexOf('\nsignature ');
  if (sigLineIdx === -1) throw new Error('Could not find signature line position');
  // Include the newline before signature in the signed portion
  const signedPortion = Buffer.from(text.slice(0, sigLineIdx + 1), 'utf8');

  return { revisionCounter, superencrypted, descriptorSigningKeyCert, signature, signedPortion };
}

/**
 * Verify the cryptographic signatures on a hidden service descriptor.
 *
 * This verifies:
 * 1. The certificate chain: blinded_id -> descriptor_signing_key
 * 2. The descriptor body signature using the descriptor signing key
 *
 * @param outer - The parsed outer descriptor
 * @param expectedBlindedPubKey - The expected blinded public key (derived from onion address + time period)
 * @throws Error if verification fails
 */
export function verifyHsDescriptor(outer: HsOuter, expectedBlindedPubKey: Buffer): void {
  // Parse the descriptor signing key certificate
  const cert = parseEd25519Certificate(outer.descriptorSigningKeyCert);

  // Certificate type must be 0x08 (HS_BLINDED_ID_V_SIGNING)
  if (cert.type !== CertTypes.HS_BLINDED_ID_V_SIGNING) {
    throw new Error(
      `Invalid descriptor signing key cert type: expected ${CertTypes.HS_BLINDED_ID_V_SIGNING}, got ${cert.type}`
    );
  }

  // The blinded public key should be in the signedWith extension
  if (!cert.signedWith) {
    throw new Error('Descriptor signing key cert missing signing key extension (blinded ID)');
  }

  // Verify the blinded key matches what we expect
  if (!cert.signedWith.equals(expectedBlindedPubKey)) {
    throw new Error('Descriptor blinded public key does not match expected value');
  }

  // Verify the certificate signature (blinded key signs the cert)
  const certValid = ed25519VerifySync(cert.signature, cert.text, cert.signedWith);
  if (!certValid) {
    throw new Error('Descriptor signing key certificate signature verification failed');
  }

  // Check certificate expiration
  const nowHours = Math.floor(Date.now() / (1000 * 60 * 60));
  if (cert.expirationHours < nowHours) {
    throw new Error(
      `Descriptor signing key certificate expired: ${cert.expirationHours} < ${nowHours}`
    );
  }

  // The descriptor signing key is the certified key in the certificate
  const descriptorSigningKey = cert.key;

  // Verify the descriptor body signature
  // Per spec: signature is over (prefix | signedPortion)
  const signedData = Buffer.concat([HS_DESC_SIG_PREFIX, outer.signedPortion]);
  const sigValid = ed25519VerifySync(outer.signature, signedData, descriptorSigningKey);
  if (!sigValid) {
    throw new Error('Descriptor body signature verification failed');
  }
}

/**
 * Decrypt a hidden service descriptor layer using AES-256-CTR.
 * Uses WebCrypto for browser compatibility.
 */
async function decryptHsLayer(params: {
  ciphertext: Buffer;
  secretData: Buffer;
  subcred: Buffer;
  revisionCounter: bigint;
  stringConstant: string;
}): Promise<Buffer> {
  const { ciphertext, secretData, subcred, revisionCounter, stringConstant } = params;
  if (ciphertext.length < 16 + 32) throw new Error('Encrypted layer too short');
  const salt = ciphertext.subarray(0, 16);
  const macIn = ciphertext.subarray(ciphertext.length - 32);
  const encrypted = ciphertext.subarray(16, ciphertext.length - 32);

  const secretInput = Buffer.concat([secretData, subcred, u64be(revisionCounter)]);
  const keys = kdfShake256(
    Buffer.concat([secretInput, salt, Buffer.from(stringConstant, 'ascii')]),
    S_KEY_LEN + S_IV_LEN + MAC_KEY_LEN
  );
  const secretKey = keys.subarray(0, S_KEY_LEN);
  const secretIv = keys.subarray(S_KEY_LEN, S_KEY_LEN + S_IV_LEN);
  const macKey = keys.subarray(S_KEY_LEN + S_IV_LEN);
  const macExpected = dMac(macKey, salt, encrypted);
  if (!macIn.equals(macExpected)) {
    throw new Error('Descriptor layer MAC check failed');
  }
  return await aes256CtrXor(secretKey, secretIv, encrypted);
}

function trimTrailingNuls(b: Buffer): Buffer {
  let end = b.length;
  while (end > 0 && b[end - 1] === 0x00) end--;
  return b.subarray(0, end);
}

// ============================================================================
// First Layer Parsing (Client Authorization / Restricted Discovery)
// ============================================================================

/**
 * Represents a parsed auth-client entry from the first layer plaintext.
 *
 * When restricted discovery is enabled, each entry contains an encrypted
 * descriptor cookie that can be decrypted by the authorized client.
 */
export type AuthClientEntry = {
  /** CLIENT-ID: first 8 bytes of SHAKE256_KDF(N_hs_subcred | SECRET_SEED, 40) */
  clientId: Buffer;
  /** Random 16-byte IV for AES-256-CTR decryption of the cookie */
  iv: Buffer;
  /** Encrypted descriptor cookie (16 bytes) */
  encryptedCookie: Buffer;
};

/**
 * Parsed first layer plaintext with optional client authorization fields.
 */
export type FirstLayerParsed = {
  /** The encrypted second layer blob */
  innerEncrypted: Buffer;
  /**
   * Type of authorization. Currently only "x25519" is recognized.
   * If absent or unrecognized, client authorization may not be supported.
   */
  authType?: string;
  /**
   * Ephemeral x25519 public key (32 bytes, base64-decoded from desc-auth-ephemeral-key).
   * This is used to derive the decryption key for the descriptor cookie.
   */
  ephemeralKey?: Buffer;
  /**
   * List of auth-client entries. Even when restricted discovery is disabled,
   * the service includes fake entries to hide whether auth is enabled.
   */
  authClients: AuthClientEntry[];
};

/**
 * Parse the first layer plaintext of a hidden service descriptor.
 *
 * This extracts:
 * - desc-auth-type: The authorization type (e.g., "x25519")
 * - desc-auth-ephemeral-key: The service's ephemeral x25519 public key
 * - auth-client entries: Encrypted descriptor cookies for authorized clients
 * - encrypted: The second layer ciphertext
 *
 * @param text - The decrypted first layer plaintext
 * @returns Parsed fields including auth client entries
 */
function parseFirstLayerPlaintext(text: string): FirstLayerParsed {
  const result: FirstLayerParsed = {
    innerEncrypted: Buffer.alloc(0),
    authClients: [],
  };

  // Parse desc-auth-type (optional)
  const authTypeMatch = text.match(/^desc-auth-type\s+(\S+)\s*$/m);
  if (authTypeMatch?.[1]) {
    result.authType = authTypeMatch[1];
  }

  // Parse desc-auth-ephemeral-key (optional)
  const ephemeralKeyMatch = text.match(/^desc-auth-ephemeral-key\s+(\S+)\s*$/m);
  if (ephemeralKeyMatch?.[1]) {
    result.ephemeralKey = Buffer.from(ephemeralKeyMatch[1], 'base64');
  }

  // Parse all auth-client lines
  // Format: auth-client SP client-id SP iv SP encrypted-cookie
  const authClientRegex = /^auth-client\s+(\S+)\s+(\S+)\s+(\S+)\s*$/gm;
  let match;
  while ((match = authClientRegex.exec(text)) !== null) {
    const clientId = Buffer.from(match[1]!, 'base64');
    const iv = Buffer.from(match[2]!, 'base64');
    const encryptedCookie = Buffer.from(match[3]!, 'base64');
    result.authClients.push({ clientId, iv, encryptedCookie });
  }

  // Parse the encrypted blob (required)
  const encryptedIdx = text.indexOf('\nencrypted');
  if (encryptedIdx === -1 && !text.startsWith('encrypted')) {
    throw new Error('Missing encrypted field in first layer plaintext');
  }
  const begin = '-----BEGIN MESSAGE-----';
  const end = '-----END MESSAGE-----';
  const start = text.indexOf(begin);
  if (start === -1) throw new Error('Missing encrypted MESSAGE armor in first layer');
  const endIdx = text.indexOf(end, start);
  if (endIdx === -1) throw new Error('Missing encrypted MESSAGE end armor in first layer');
  const armored = text.slice(start, endIdx + end.length);
  result.innerEncrypted = extractArmoredMessage(armored, begin, end);

  return result;
}

// ============================================================================
// Client Authorization (Restricted Discovery) - Cookie Decryption
// ============================================================================

/**
 * Decrypt the descriptor cookie using client authorization credentials.
 *
 * When restricted discovery is enabled, the hidden service encrypts a
 * descriptor_cookie for each authorized client. The client uses their
 * private x25519 key along with the service's ephemeral key to derive
 * the decryption key.
 *
 * The algorithm:
 * 1. SECRET_SEED = x25519(client_private_key, ephemeral_public_key)
 * 2. KEYS = SHAKE256_KDF(N_hs_subcred | SECRET_SEED, 40)
 * 3. CLIENT-ID = first 8 bytes of KEYS
 * 4. COOKIE-KEY = last 32 bytes of KEYS
 * 5. Find the auth-client entry with matching CLIENT-ID
 * 6. descriptor_cookie = AES256-CTR(COOKIE-KEY, iv) XOR encrypted_cookie
 *
 * @param firstLayer - Parsed first layer with auth entries
 * @param subcred - The service subcredential (N_hs_subcred)
 * @param clientAuth - The client's x25519 keypair
 * @returns The 32-byte descriptor cookie, or undefined if auth is disabled or no matching entry
 */
export async function decryptDescriptorCookie(
  firstLayer: FirstLayerParsed,
  subcred: Buffer,
  clientAuth: HsClientAuthCredentials
): Promise<Buffer | undefined> {
  // If no auth type or ephemeral key, auth is not set up
  if (!firstLayer.authType || !firstLayer.ephemeralKey) {
    return undefined;
  }

  // Only x25519 is supported
  if (firstLayer.authType !== 'x25519') {
    throw new Error(`Unsupported descriptor auth type: ${firstLayer.authType}`);
  }

  // Compute SECRET_SEED = x25519(client_private, ephemeral_public)
  const secretSeed = x25519.getSharedSecret(clientAuth.privateKey, firstLayer.ephemeralKey);

  // Compute KEYS = SHAKE256_KDF(N_hs_subcred | SECRET_SEED, 40)
  const keys = kdfShake256(Buffer.concat([subcred, Buffer.from(secretSeed)]), 40);
  const clientId = keys.subarray(0, 8);
  const cookieKey = keys.subarray(8, 40); // Last 32 bytes

  // Find matching auth-client entry by CLIENT-ID
  const matchingEntry = firstLayer.authClients.find((entry) => entry.clientId.equals(clientId));

  if (!matchingEntry) {
    // No matching entry - client is not authorized
    return undefined;
  }

  // Decrypt the cookie: descriptor_cookie = AES256-CTR(COOKIE-KEY, iv) XOR encrypted_cookie
  // Since AES-CTR is XOR-based, we just run the encryption function to decrypt
  const descriptorCookie = await aes256CtrXor(
    cookieKey,
    matchingEntry.iv,
    matchingEntry.encryptedCookie
  );

  return descriptorCookie;
}

export type IntroPoint = {
  linkSpecifiers: LinkSpecifier[];
  introPointOnionKey: Buffer; // curve25519 pubkey for ntor to intro point
  authKeyEd25519: Buffer; // KP_hs_ipt_sid
  serviceEncKey: Buffer; // KP_hss_ntor (curve25519 pubkey for hs-ntor)
};

/**
 * Proof-of-work parameters from the descriptor.
 * Used when the service is under DoS protection.
 */
export interface PowParams {
  /** The PoW scheme (e.g., "v1" for Equix) */
  scheme: string;
  /** The random seed for the PoW hash function (32 bytes) */
  seed: Buffer;
  /** Suggested effort value for clients */
  suggestedEffort: number;
  /** When this seed expires (ISO 8601 format) */
  expirationTime: Date;
}

/**
 * Parsed hidden service descriptor.
 */
export type HiddenServiceDescriptor = {
  /** List of introduction points */
  introPoints: IntroPoint[];
  /**
   * Flow control protocol versions supported by this service.
   * Parsed from the "flow-ctrl" line. If version 2 is present,
   * the client can request congestion control in INTRODUCE1.
   */
  flowCtrlVersions?: number[];
  /**
   * Proof-of-work parameters for DoS mitigation.
   * If present with a non-zero suggested effort, clients should
   * include a PoW solution in their INTRODUCE1 message.
   */
  powParams?: PowParams;
  /**
   * Create2 handshake formats supported by the service.
   * Parsed from "create2-formats" line.
   */
  create2Formats?: number[];
  /**
   * Whether this is a single-onion service (non-anonymous on service side).
   */
  singleOnionService?: boolean;
};

function parseLinkSpecifiersBlock(block: Buffer): LinkSpecifier[] {
  const r = new BytesReader(block);
  const n = r.readUIntBE(1);
  const out: LinkSpecifier[] = [];
  for (let i = 0; i < n; i++) {
    const type = r.readUIntBE(1);
    const len = r.readUIntBE(1);
    const data = r.readBytes(len);
    out.push({ type, data });
  }
  return out;
}

function parseSecondLayerPlaintext(text: string): HiddenServiceDescriptor {
  const lines = text.replaceAll('\r', '').split('\n');
  const introPoints: IntroPoint[] = [];

  // Parse top-level descriptor fields
  let flowCtrlVersions: number[] | undefined;
  let powParams: PowParams | undefined;
  let create2Formats: number[] | undefined;
  let singleOnionService = false;

  let current: Partial<IntroPoint> | undefined;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i] ?? '';

    // Parse flow-ctrl line (before intro points)
    // Format: flow-ctrl SP versions (e.g., "flow-ctrl 1-2")
    if (line.startsWith('flow-ctrl ')) {
      const versionStr = line.slice('flow-ctrl '.length).trim();
      flowCtrlVersions = parseProtocolVersions(versionStr);
      continue;
    }

    // Parse create2-formats line
    // Format: create2-formats SP format1 SP format2 ...
    if (line.startsWith('create2-formats ')) {
      const formatsStr = line.slice('create2-formats '.length).trim();
      create2Formats = formatsStr
        .split(/\s+/)
        .map((s) => parseInt(s, 10))
        .filter(Number.isFinite);
      continue;
    }

    // Parse single-onion-service flag
    if (line === 'single-onion-service') {
      singleOnionService = true;
      continue;
    }

    // Parse pow-params line
    // Format: pow-params SP scheme SP seed-b64 SP suggested-effort SP expiration-time
    if (line.startsWith('pow-params ')) {
      const parts = line.slice('pow-params '.length).trim().split(/\s+/);
      if (parts.length >= 4) {
        const [scheme, seedB64, effortStr, expirationStr] = parts;
        if (scheme && seedB64 && effortStr && expirationStr) {
          try {
            powParams = {
              scheme,
              seed: Buffer.from(seedB64, 'base64'),
              suggestedEffort: parseInt(effortStr, 10),
              expirationTime: new Date(expirationStr),
            };
          } catch {
            // Ignore malformed pow-params
          }
        }
      }
      continue;
    }

    if (line.startsWith('introduction-point ')) {
      if (current) {
        // finalize previous if complete
        if (
          current.linkSpecifiers &&
          current.introPointOnionKey &&
          current.authKeyEd25519 &&
          current.serviceEncKey
        ) {
          introPoints.push(current as IntroPoint);
        }
      }
      const b64 = line.slice('introduction-point '.length).trim();
      const block = Buffer.from(b64, 'base64');
      current = { linkSpecifiers: parseLinkSpecifiersBlock(block) };
      continue;
    }
    if (!current) continue;
    if (line.startsWith('onion-key ntor ')) {
      current.introPointOnionKey = Buffer.from(
        line.slice('onion-key ntor '.length).trim(),
        'base64'
      );
      continue;
    }
    if (line === 'auth-key') {
      // Next lines include BEGIN/END ED25519 CERT armor
      const certBegin = '-----BEGIN ED25519 CERT-----';
      const certEnd = '-----END ED25519 CERT-----';
      const rest = lines.slice(i + 1).join('\n');
      const certBody = extractArmoredMessage(rest, certBegin, certEnd);
      const cert = parseEd25519Certificate(certBody);
      current.authKeyEd25519 = Buffer.from(cert.key);
      // Move index to end of cert
      const endLineIdx = lines.findIndex((l, idx) => idx > i && l.includes(certEnd));
      if (endLineIdx !== -1) i = endLineIdx;
      continue;
    }
    if (line.startsWith('enc-key ntor ')) {
      current.serviceEncKey = Buffer.from(line.slice('enc-key ntor '.length).trim(), 'base64');
      continue;
    }
  }

  if (
    current &&
    current.linkSpecifiers &&
    current.introPointOnionKey &&
    current.authKeyEd25519 &&
    current.serviceEncKey
  ) {
    introPoints.push(current as IntroPoint);
  }

  const descriptor: HiddenServiceDescriptor = { introPoints };

  if (flowCtrlVersions && flowCtrlVersions.length > 0) {
    descriptor.flowCtrlVersions = flowCtrlVersions;
  }
  if (powParams) {
    descriptor.powParams = powParams;
  }
  if (create2Formats && create2Formats.length > 0) {
    descriptor.create2Formats = create2Formats;
  }
  if (singleOnionService) {
    descriptor.singleOnionService = true;
  }

  return descriptor;
}

/**
 * Fetch and decrypt a hidden service descriptor via a directory stream.
 * This is the browser-compatible version that uses async Web Crypto.
 *
 * @param circuit - An existing circuit to use for the directory stream
 * @param hsdirPeer - The HSDir peer info (used for logging, not for connection)
 * @param blindedPublicKey - The blinded public key for the HS
 * @param subcred - The subcredential for decryption
 * @param timeoutMs - Timeout for the request
 * @param log - Logging function
 * @param clientAuth - Optional client authorization credentials for restricted services
 */
export async function fetchHsDescriptorOverDirectoryStream(
  circuit: Circuit,
  _hsdirPeer: PeerInfo,
  blindedPublicKey: Buffer,
  subcred: Buffer,
  timeoutMs: number,
  log: (msg: string) => void = () => {},
  clientAuth?: HsClientAuthCredentials
): Promise<HiddenServiceDescriptor | undefined> {
  // Use standard base64 (no padding) — NOT base64url.
  // Tor HSDirs use C Tor's base64_decode() which rejects '-' and '_'.
  const z = toBase64NoPad(blindedPublicKey);

  try {
    const stream = await circuit.openDirectoryStream();

    const requestText =
      `GET /tor/hs/3/${z} HTTP/1.0\r\n` + `Host: hsdir\r\n` + `Connection: close\r\n` + `\r\n`;

    const chunks: Buffer[] = [];
    stream.on('data', (d: Buffer) => chunks.push(Buffer.from(d)));

    const endedP = new Promise<void>((resolve, reject) => {
      stream.once('end', (err?: Error) => {
        if (err) reject(err);
        else resolve();
      });
    });

    await Promise.race([
      stream.write(Buffer.from(requestText, 'ascii')),
      new Promise<never>((_r, rej) =>
        setTimeout(() => rej(new Error('dir request write timeout')), timeoutMs)
      ),
    ]);

    await Promise.race([
      endedP,
      new Promise<never>((_r, rej) =>
        setTimeout(() => rej(new Error('dir request read timeout')), timeoutMs)
      ),
    ]);

    const resp = Buffer.concat(chunks).toString('utf8');
    if (!resp.startsWith('HTTP/')) {
      log(`HSDir response invalid (not HTTP): ${resp.slice(0, 100)}`);
      return undefined;
    }

    // Extract status code for logging
    const statusLine = resp.split('\r\n')[0] || '';
    if (!resp.includes(' 200 ')) {
      log(`HSDir returned non-200: ${statusLine}`);
      return undefined;
    }

    const split = resp.split('\r\n\r\n');
    if (split.length < 2) {
      log(`HSDir response missing body`);
      return undefined;
    }
    const outerText = split.slice(1).join('\r\n\r\n');

    // Parse and verify the descriptor
    const outer = parseHsDescriptorOuter(outerText);

    // Verify descriptor signatures before trusting the content
    verifyHsDescriptor(outer, blindedPublicKey);
    log('Descriptor signature verified');

    const firstPlain = trimTrailingNuls(
      await decryptHsLayer({
        ciphertext: outer.superencrypted,
        secretData: blindedPublicKey,
        subcred,
        revisionCounter: outer.revisionCounter,
        stringConstant: 'hsdir-superencrypted-data',
      })
    );
    const firstText = firstPlain.toString('utf8');
    const firstLayer = parseFirstLayerPlaintext(firstText);

    // All v3 descriptors include auth fields; only use cookie when client provided credentials and we get a match.
    // Otherwise try with blinded key only; decryptHsLayer MAC check will fail if auth was actually required.
    let secondLayerSecretData = blindedPublicKey;
    if (firstLayer.authType === 'x25519' && firstLayer.ephemeralKey && clientAuth) {
      const descriptorCookie = await decryptDescriptorCookie(firstLayer, subcred, clientAuth);
      if (descriptorCookie) {
        log('Client authorization successful');
        secondLayerSecretData = Buffer.concat([blindedPublicKey, descriptorCookie]);
      }
    }

    try {
      const secondPlain = trimTrailingNuls(
        await decryptHsLayer({
          ciphertext: firstLayer.innerEncrypted,
          secretData: secondLayerSecretData,
          subcred,
          revisionCounter: outer.revisionCounter,
          stringConstant: 'hsdir-encrypted-data',
        })
      );
      return parseSecondLayerPlaintext(secondPlain.toString('utf8'));
    } catch (innerErr) {
      const msg = innerErr instanceof Error ? innerErr.message : String(innerErr);
      if (msg.includes('MAC check failed') && !clientAuth && firstLayer.authType === 'x25519') {
        throw new Error(
          'Descriptor decryption failed — service likely requires client authorization'
        );
      }
      throw innerErr;
    }
  } catch (err) {
    log(`HSDir fetch error: ${err instanceof Error ? err.message : String(err)}`);
    return undefined;
  }
}

export type HsNtorClientState = {
  x: Buffer;
  X: Buffer;
  B: Buffer;
  AUTH_KEY: Buffer;
  N_hs_subcred: Buffer;
};

export function hsNtorDeriveEncAndMac(params: {
  x: Buffer;
  X: Buffer;
  B: Buffer;
  AUTH_KEY: Buffer;
  N_hs_subcred: Buffer;
}): { ENC_KEY: Buffer; MAC_KEY: Buffer } {
  const PROTOID = Buffer.from('tor-hs-ntor-curve25519-sha3-256-1', 'ascii');
  const t_hsenc = Buffer.from(`${PROTOID.toString('ascii')}:hs_key_extract`, 'ascii');
  const m_hsexpand = Buffer.from(`${PROTOID.toString('ascii')}:hs_key_expand`, 'ascii');

  const expBx = Buffer.from(x25519.scalarMult(params.x, params.B));
  const introSecret = Buffer.concat([expBx, params.AUTH_KEY, params.X, params.B, PROTOID]);
  const info = Buffer.concat([m_hsexpand, params.N_hs_subcred]);
  const hsKeys = kdfShake256(Buffer.concat([introSecret, t_hsenc, info]), S_KEY_LEN + MAC_KEY_LEN);
  const ENC_KEY = hsKeys.subarray(0, S_KEY_LEN);
  const MAC_KEY = hsKeys.subarray(S_KEY_LEN);
  return { ENC_KEY, MAC_KEY };
}

export function hsNtorComplete(params: { state: HsNtorClientState; Y: Buffer; auth: Buffer }): {
  NTOR_KEY_SEED: Buffer;
} {
  const PROTOID = Buffer.from('tor-hs-ntor-curve25519-sha3-256-1', 'ascii');
  const t_hsenc = Buffer.from(`${PROTOID.toString('ascii')}:hs_key_extract`, 'ascii');
  const t_hsverify = Buffer.from(`${PROTOID.toString('ascii')}:hs_verify`, 'ascii');
  const t_hsmac = Buffer.from(`${PROTOID.toString('ascii')}:hs_mac`, 'ascii');

  const { x, X, B, AUTH_KEY } = params.state;
  const expYx = Buffer.from(x25519.scalarMult(x, params.Y));
  const expBx = Buffer.from(x25519.scalarMult(x, B));
  const rendSecret = Buffer.concat([expYx, expBx, AUTH_KEY, B, X, params.Y, PROTOID]);
  const NTOR_KEY_SEED = mac(rendSecret, t_hsenc);
  const verify = mac(rendSecret, t_hsverify);
  const authInput = Buffer.concat([
    verify,
    AUTH_KEY,
    B,
    params.Y,
    X,
    PROTOID,
    Buffer.from('Server', 'ascii'),
  ]);
  const AUTH_INPUT_MAC = mac(authInput, t_hsmac);
  if (!AUTH_INPUT_MAC.equals(params.auth)) {
    throw new Error('hs-ntor AUTH_INPUT_MAC verification failed');
  }
  return { NTOR_KEY_SEED };
}

export function makeHsRendezvousCipherPairFromKeySeed(NTOR_KEY_SEED: Buffer) {
  const PROTOID = Buffer.from('tor-hs-ntor-curve25519-sha3-256-1', 'ascii');
  const m_hsexpand = Buffer.from(`${PROTOID.toString('ascii')}:hs_key_expand`, 'ascii');
  const K = kdfShake256(Buffer.concat([NTOR_KEY_SEED, m_hsexpand]), HASH_LEN * 2 + S_KEY_LEN * 2);
  const r = new BytesReader(K);
  const fSeed = r.readBytes(HASH_LEN);
  const bSeed = r.readBytes(HASH_LEN);
  const Kf = r.readBytes(S_KEY_LEN);
  const Kb = r.readBytes(S_KEY_LEN);

  // Use browser-compatible SHA3-256 implementation
  const forwardDigest = createSha3_256Hash();
  const backwardDigest = createSha3_256Hash();
  forwardDigest.update(fSeed);
  backwardDigest.update(bSeed);

  const forwardKey = makeAes256CtrKey(Kf);
  const backwardKey = makeAes256CtrKey(Kb);

  const cipherPair: CircuitCipherPair = {
    forward: { key: forwardKey, digest: forwardDigest },
    backward: { key: backwardKey, digest: backwardDigest },
  };
  return cipherPair;
}

export function peerInfoFromIntroPoint(intro: IntroPoint): PeerInfo {
  const legacyId = intro.linkSpecifiers.find((ls) => ls.type === LinkSpecifierTypes.LegacyId);
  const ed25519Id = intro.linkSpecifiers.find((ls) => ls.type === LinkSpecifierTypes.Ed25519Id);

  if (!legacyId) {
    throw new Error('Introduction point link specifiers missing legacy identity');
  }
  // Ed25519 identity is strongly recommended but not strictly required for compatibility
  // with older intro points. Log a warning if missing but continue.

  const peerInfo: PeerInfo = {
    onionKey: intro.introPointOnionKey,
    rsaIdDigest: Buffer.from(legacyId.data),
    linkSpecifiers: intro.linkSpecifiers,
  };

  if (ed25519Id) {
    peerInfo.ed25519Id = Buffer.from(ed25519Id.data);
  }

  return peerInfo;
}

/**
 * Extension types for the ENCRYPTED section of INTRODUCE1/INTRODUCE2.
 * These share a namespace with circuit creation extensions.
 */
export const Introduce1ExtensionType = {
  /** Request congestion control on the rendezvous circuit */
  CC_FIELD_REQUEST: 0x01,
  /** Proof-of-work to raise priority */
  PROOF_OF_WORK: 0x02,
  /** Subprotocol request (reserved) */
  SUBPROTOCOL_REQUEST: 0x03,
} as const;

/**
 * Parameters for building an INTRODUCE1 payload.
 */
export interface BuildIntroduce1Params {
  introAuthKeyEd25519: Buffer;
  serviceEncKey: Buffer;
  N_hs_subcred: Buffer;
  rendezvousCookie: Buffer;
  rendezvousPoint: PeerInfo;
  /**
   * Request congestion control on the rendezvous circuit.
   * Only set this if the service supports FlowCtrl=2 in its descriptor.
   */
  requestCongestionControl?: boolean;
  /**
   * Proof-of-work solution for DoS mitigation.
   * Only needed for services that advertise pow-params.
   */
  proofOfWork?: {
    /** PoW scheme (1 = v1/Equix) */
    scheme: number;
    /** Client-chosen nonce (16 bytes) */
    nonce: Buffer;
    /** Client-chosen effort (32-bit unsigned) */
    effort: number;
    /** First 4 bytes of the seed from pow-params */
    seed: Buffer;
    /** Solution from the Equix solver (16 bytes) */
    solution: Buffer;
  };
}

export async function buildIntroduce1Payload(
  params: BuildIntroduce1Params
): Promise<{ payload: Buffer; state: HsNtorClientState }> {
  const AUTH_KEY = params.introAuthKeyEd25519;
  const legacyKeyId = Buffer.alloc(20, 0);
  const AUTH_KEY_TYPE = Buffer.from([0x02]); // ed25519
  const AUTH_KEY_LEN = Buffer.from([0x00, 0x20]); // 32
  const N_EXT = Buffer.from([0x00]);
  const header = Buffer.concat([legacyKeyId, AUTH_KEY_TYPE, AUTH_KEY_LEN, AUTH_KEY, N_EXT]);

  // Plaintext body (decrypted payload) for INTRODUCE2 [PROCESS_INTRO2]
  const ONION_KEY_TYPE = Buffer.from([0x01]); // ntor
  const ONION_KEY_LEN = Buffer.from([0x00, 0x20]); // 32
  const ONION_KEY = params.rendezvousPoint.onionKey;
  const linkSpecifiersBlock = Buffer.concat([
    Buffer.from([params.rendezvousPoint.linkSpecifiers.length]),
    ...params.rendezvousPoint.linkSpecifiers.map((ls) =>
      Buffer.concat([Buffer.from([ls.type]), Buffer.from([ls.data.length]), ls.data])
    ),
  ]);

  // Build encrypted extensions (appears in ENCRYPTED section after RENDEZVOUS_COOKIE)
  // Format: N_EXTENSIONS [1 byte], then N_EXTENSIONS times: EXT_FIELD_TYPE [1], EXT_FIELD_LEN [1], EXT_FIELD [len]
  const extensionBuffers: Buffer[] = [];
  let extensionCount = 0;

  // Congestion control request (type 0x01, zero-length body)
  if (params.requestCongestionControl) {
    extensionBuffers.push(
      Buffer.from([
        Introduce1ExtensionType.CC_FIELD_REQUEST, // EXT_FIELD_TYPE
        0x00, // EXT_FIELD_LEN (zero bytes)
      ])
    );
    extensionCount++;
  }

  // Proof-of-work extension (type 0x02)
  if (params.proofOfWork) {
    const pow = params.proofOfWork;
    if (pow.nonce.length !== 16) throw new Error('PoW nonce must be 16 bytes');
    if (pow.seed.length !== 4) throw new Error('PoW seed must be 4 bytes');
    if (pow.solution.length !== 16) throw new Error('PoW solution must be 16 bytes');

    const effortBuf = Buffer.alloc(4);
    effortBuf.writeUInt32BE(pow.effort);

    const powBody = Buffer.concat([
      Buffer.from([pow.scheme]), // POW_SCHEME (1 byte)
      pow.nonce, // POW_NONCE (16 bytes)
      effortBuf, // POW_EFFORT (4 bytes)
      pow.seed, // POW_SEED (4 bytes)
      pow.solution, // POW_SOLUTION (16 bytes)
    ]);

    extensionBuffers.push(
      Buffer.from([
        Introduce1ExtensionType.PROOF_OF_WORK, // EXT_FIELD_TYPE
        powBody.length, // EXT_FIELD_LEN
      ])
    );
    extensionBuffers.push(powBody);
    extensionCount++;
  }

  const extensionsBlock = Buffer.concat([Buffer.from([extensionCount]), ...extensionBuffers]);

  const plaintext = Buffer.concat([
    params.rendezvousCookie,
    extensionsBlock,
    ONION_KEY_TYPE,
    ONION_KEY_LEN,
    ONION_KEY,
    linkSpecifiersBlock,
  ]);

  // Pad plaintext for INTRODUCE1 (see [FMT_INTRO1]).
  // Per spec, the encrypted data section SHOULD be 490 bytes to avoid fingerprinting
  // and for proposal 340 compatibility.
  //
  // Structure: header | CLIENT_PK (32) | encrypted_data | MAC (32)
  // The target is to make the entire payload (header + encrypted section) fit well.
  //
  // For proposal 340 compatibility, we use 490 bytes as the target for the encrypted section
  // (CLIENT_PK + ciphertext + MAC).
  const encryptedSectionTargetLen = INTRO1_TARGET_LEN;
  const encryptedDataLen = encryptedSectionTargetLen - 32 /* CLIENT_PK */ - 32; /* MAC */
  if (encryptedDataLen <= plaintext.length) {
    throw new Error(
      `INTRODUCE1 plaintext too large (need <= ${encryptedDataLen}, got ${plaintext.length})`
    );
  }
  const paddedPlaintext = Buffer.concat([
    plaintext,
    Buffer.alloc(encryptedDataLen - plaintext.length),
  ]);

  // hs-ntor client keypair
  const x = Buffer.from(x25519.utils.randomPrivateKey());
  const X = Buffer.from(x25519.getPublicKey(x));
  const B = params.serviceEncKey;

  const { ENC_KEY, MAC_KEY } = hsNtorDeriveEncAndMac({
    x,
    X,
    B,
    AUTH_KEY,
    N_hs_subcred: params.N_hs_subcred,
  });
  const iv0 = Buffer.alloc(16, 0);
  // Use async Web Crypto version for browser compatibility
  const C = await aes256CtrXor(ENC_KEY, iv0, paddedPlaintext);
  const macInput = Buffer.concat([header, X, C]);
  const M = mac(MAC_KEY, macInput);

  const payload = Buffer.concat([header, X, C, M]);
  // The encrypted section should be exactly INTRO1_TARGET_LEN (490 bytes)
  const encryptedSectionLen = X.length + C.length + M.length;
  if (encryptedSectionLen !== INTRO1_TARGET_LEN) {
    throw new Error(
      `INTRODUCE1 encrypted section length mismatch: ${encryptedSectionLen} != ${INTRO1_TARGET_LEN}`
    );
  }
  return {
    payload,
    state: { x, X, B, AUTH_KEY, N_hs_subcred: params.N_hs_subcred },
  };
}

/**
 * Wait for a specific relay command on a circuit.
 * Useful for hidden service protocol handshakes (RENDEZVOUS, INTRODUCE_ACK, etc).
 *
 * @param circuit - The circuit to listen on
 * @param relayCommand - The relay command to wait for
 * @param timeoutMs - Timeout in milliseconds
 * @returns The relay event data
 */
export async function waitForRelayCommand(
  circuit: Circuit,
  relayCommand: number,
  timeoutMs: number
): Promise<{ streamId: number; relayCommand: number; data: Buffer }> {
  return await new Promise((resolve, reject) => {
    const onRelay = (evt: { streamId: number; relayCommand: number; data: Buffer }) => {
      if (evt.relayCommand !== relayCommand) return;
      cleanup();
      resolve(evt);
    };
    const t = setTimeout(() => {
      cleanup();
      reject(new Error(`Timed out waiting for relayCommand=${relayCommand}`));
    }, timeoutMs);
    const cleanup = () => {
      clearTimeout(t);
      circuit.off('relay', onRelay);
    };
    circuit.on('relay', onRelay);
  });
}

// ============================================================================
// Core Hidden Service Connection (Platform-Agnostic)
// ============================================================================

/**
 * Core hidden service connection flow.
 *
 * This implements the full HSv3 client protocol:
 * 1. Find HSDir nodes and fetch descriptor
 * 2. Build rendezvous circuit and establish rendezvous point
 * 3. Build intro circuit and send INTRODUCE1
 * 4. Complete hs-ntor handshake on RENDEZVOUS2
 *
 * Platform-specific concerns (channel creation, path selection) are abstracted
 * via the `buildCircuit` function in the context.
 *
 * @param ctx - Connection context with consensus, circuits, and circuit builder
 * @param onionAddress - The .onion address to connect to
 * @param options - Connection options
 * @returns The rendezvous circuit with virtual hop to the hidden service
 */
export async function connectToHiddenServiceCore(
  ctx: HsConnectionContext,
  onionAddress: string,
  options: HsConnectionOptions = {}
): Promise<HsConnectionResult> {
  const {
    overallTimeoutMs = 120_000,
    perHandshakeTimeoutMs = Math.min(overallTimeoutMs, 120_000),
    rendezvousTimeoutMs = 60_000,
    maxIntroAttempts = 6,
    log = () => {},
    onMicrodescProgress,
    randomBytes: randomBytesOpt = randomBytes,
    iptExperienceTracker,
    descriptorCache,
    disablePow = false,
    maxPowEffort,
    powTimeoutMs = 60_000,
  } = options;
  const dlog = makeHsDebugLog(log);

  const { consensus, dirClient, microdescManager, buildCircuit } = ctx;

  if (!consensus.validAfter) {
    throw new Error('Consensus missing valid-after');
  }

  // Step 1: Parse onion address
  log('Parsing onion address...');
  const { publicIdentityKey } = parseOnionV3Address(onionAddress);

  // Step 2: Find HSDir nodes
  log('Locating hidden service directory nodes...');
  const hsdirNodes = (consensus.relays ?? []).filter((r) => {
    if (!(r.flags ?? []).includes('HSDir')) return false;
    const hsdirProto = r.protocols?.HSDir;
    if (!hsdirProto) return false;
    return supportsProtocolVersion(hsdirProto, 2);
  });

  if (hsdirNodes.length === 0) {
    throw new Error('No HSDir candidates found in consensus');
  }

  // Build HSDir candidates with Ed25519 identity keys via cached microdescriptors
  log(`Looking up Ed25519 keys for ${hsdirNodes.length} HSDir nodes...`);
  const hsdirCandidates = await fetchHsdirCandidates(
    microdescManager,
    hsdirNodes,
    onMicrodescProgress
  );
  log(`Got ${hsdirCandidates.length} HSDir candidates with Ed25519 keys`);

  if (hsdirCandidates.length === 0) {
    throw new Error('Failed to build any HSDir candidates');
  }

  // Step 3: Check cache or compute time period info and fetch descriptor
  // We can parallelize descriptor fetch with rendezvous setup for better performance
  const { periodLengthMinutes, periodCandidates, nReplicas, spreadFetch } =
    computeTimePeriodInfo(consensus);

  // Start rendezvous setup in parallel with descriptor fetch
  // This saves time since rendezvous doesn't depend on the descriptor
  log('Selecting rendezvous point...');
  const { node: rendNodeInfo, qualifiedCount } = pickRendezvousPoint(consensus);
  log(
    `Rendezvous point picked: ${rendNodeInfo.nickname} (rsaId=${rendNodeInfo.rsaIdDigest
      .toString('hex')
      .slice(0, 16)}…, flags=${(rendNodeInfo.flags ?? []).join(',') || 'none'}) ` +
      `from ${qualifiedCount} qualified candidate(s) / ${consensus.relays.length} total`
  );

  // Start building rendezvous circuit in parallel
  const rendezvousPointPromise = lookupPeerInfo(dirClient, rendNodeInfo);

  let subcred: Buffer | undefined;
  let blindedPublicKey: Buffer | undefined;
  let descriptor: HiddenServiceDescriptor | undefined;
  let usedCachedDescriptor = false;

  // Check descriptor cache first
  if (descriptorCache) {
    const cached = descriptorCache.get(publicIdentityKey);
    if (cached) {
      log('Using cached descriptor');
      descriptor = cached.descriptor;
      subcred = cached.subcred;
      blindedPublicKey = cached.blindedPublicKey;
      usedCachedDescriptor = true;
    }
  }

  // If not in cache, fetch from HSDirs
  if (!descriptor) {
    log('Fetching hidden service descriptor...');
    const descriptorDeadline = Date.now() + Math.min(overallTimeoutMs, 180_000);

    // Verbose HSDir-lookup diagnostics — gated on TOR_TS_HS_DEBUG.
    const now = new Date();
    dlog(`Current time: ${now.toISOString()}`);
    dlog(`Consensus valid-after: ${consensus.validAfter?.toISOString()}`);
    dlog(`Period candidates: [${periodCandidates.join(', ')}]`);
    dlog(`Period length (minutes): ${periodLengthMinutes}`);
    dlog(
      `SRV current: ${consensus.sharedRandCurrentValue?.toString('hex').slice(0, 16) ?? 'MISSING'}...`
    );
    dlog(
      `SRV previous: ${consensus.sharedRandPreviousValue?.toString('hex').slice(0, 16) ?? 'MISSING'}...`
    );
    dlog(`nReplicas=${nReplicas}, spreadFetch=${spreadFetch}`);

    for (const periodNum of periodCandidates) {
      if (descriptor) break;
      if (Date.now() > descriptorDeadline) break;

      blindedPublicKey = deriveBlindedPublicKey({
        publicIdentityKey,
        periodNum,
        periodLengthMinutes,
      });
      subcred = deriveSubcredential({ publicIdentityKey, blindedPublicKey });

      dlog(`Trying period ${periodNum}, blinded key: ${toBase64UrlNoPad(blindedPublicKey)}`);

      const fetchSrv = getFetchSrv(consensus, periodLengthMinutes, periodNum);
      const srvValues = getSrvValues(consensus, periodLengthMinutes, periodNum);
      const disasterSrv = computeDisasterSrv({ periodLengthMinutes, periodNum });
      // Try correct SRV for time window first, then fallback to the other
      const srvOrder = fetchSrv.equals(srvValues[0]!)
        ? [srvValues[0]!, srvValues[1]!]
        : [srvValues[1]!, srvValues[0]!];

      for (let srvIdx = 0; srvIdx < srvOrder.length; srvIdx++) {
        const srv = srvOrder[srvIdx]!;
        if (descriptor) break;

        const isDisasterSrv = srv.equals(disasterSrv);
        const srvLabel = srv.equals(consensus.sharedRandCurrentValue ?? Buffer.alloc(0))
          ? 'current'
          : 'previous';
        if (isDisasterSrv) {
          dlog(
            `Using DISASTER SRV for ${srvLabel} (consensus missing shared-rand-${srvLabel}-value)`
          );
        } else {
          dlog(`Using real ${srvLabel} SRV: ${srv.toString('hex').slice(0, 16)}...`);
        }

        const hsdirPeersThisRound = selectHsdirsForFetch({
          hsdirs: hsdirCandidates,
          sharedRandomValue: srv,
          blindedPublicKey,
          periodLengthMinutes,
          periodNum,
          nReplicas,
          spreadFetch,
          log,
        });

        for (const hsdirPeer of hsdirPeersThisRound) {
          if (Date.now() > descriptorDeadline) break;

          let hsdirCircuit: Circuit | undefined;
          try {
            // Build a circuit TO the HSDir - the descriptor is stored there
            log(
              `Building circuit to HSDir ${hsdirPeer.rsaIdDigest.toString('hex').slice(0, 8)}...`
            );
            hsdirCircuit = await buildCircuit(hsdirPeer, { avoid: [] });
            const got = await fetchHsDescriptorOverDirectoryStream(
              hsdirCircuit,
              hsdirPeer,
              blindedPublicKey,
              subcred,
              perHandshakeTimeoutMs,
              log,
              options.clientAuth
            );
            if (got) {
              descriptor = got;
              hsdirCircuit.destroy({ preserveChannel: true });

              // Cache the descriptor for future connections
              if (descriptorCache && blindedPublicKey && subcred) {
                descriptorCache.set(publicIdentityKey, descriptor, blindedPublicKey, subcred);
                log('Descriptor cached');
              }

              break;
            }
          } catch {
            // Continue to next HSDir
          } finally {
            // Clean up circuit if we didn't find descriptor
            if (!descriptor) {
              hsdirCircuit?.destroy({ preserveChannel: true });
            }
          }
        }
      }
    }
  }

  if (!descriptor || !subcred || !blindedPublicKey) {
    throw new Error('Failed to download hidden service descriptor');
  }

  // Wait for rendezvous point lookup to complete (started earlier in parallel)
  const rendezvousPoint = await rendezvousPointPromise;

  log(`Found ${descriptor.introPoints.length} introduction point(s)`);

  // Proof-of-work gate (proposal 327 / hspow-spec v1). When a service is under
  // DoS defense it advertises `pow-params` with a non-zero suggested effort and
  // its intro points prioritise the pending-rendezvous queue by the client's
  // PoW effort. We solve the Equi-X puzzle (below, per intro attempt) and attach
  // it to INTRODUCE1. A request arriving with no PoW token — or too little
  // effort — is deprioritised and, under real load, dropped, surfacing as a
  // RENDEZVOUS2 timeout. See https://spec.torproject.org/hspow-spec.
  const powRequired =
    !disablePow && descriptor.powParams !== undefined && descriptor.powParams.suggestedEffort > 0;
  if (descriptor.powParams && descriptor.powParams.suggestedEffort > 0 && disablePow) {
    log(
      `Hidden service requests proof-of-work (suggested-effort=` +
        `${descriptor.powParams.suggestedEffort}) but PoW is disabled; sending introduction ` +
        `without a PoW token (may be dropped by a service enforcing PoW).`
    );
  } else if (powRequired) {
    log(
      `Hidden service requests proof-of-work (scheme=${descriptor.powParams!.scheme}, ` +
        `suggested-effort=${descriptor.powParams!.suggestedEffort}); will solve an Equi-X puzzle ` +
        `for each introduction attempt.`
    );
  }

  // Step 4: Order intro points (by experience if available, otherwise shuffled)
  let introPoints = shuffleInPlace([...descriptor.introPoints]);
  if (introPoints.length === 0) {
    throw new Error('Descriptor contained no introduction points');
  }

  // If we have an experience tracker, use it to prioritize intro points
  if (iptExperienceTracker) {
    introPoints = iptExperienceTracker.sortByExperience(introPoints);
    log(`Intro points sorted by experience (${introPoints.length} available)`);
  }

  // Step 5: Build rendezvous circuit and establish rendezvous
  // (rendezvous point was already selected and looked up in parallel with descriptor fetch)
  log('Building rendezvous circuit...');
  const rendCircuit = await buildCircuit(rendezvousPoint, { avoid: [] });

  const rendezvousCookie = Buffer.from(randomBytesOpt(20));
  log('Establishing rendezvous point...');
  await rendCircuit.sendRelayMessage({
    streamId: 0,
    relayCommand: RelayCell.ESTABLISH_RENDEZVOUS,
    data: rendezvousCookie,
  });
  await waitForRelayCommand(rendCircuit, RelayCell.RENDEZVOUS_ESTABLISHED, perHandshakeTimeoutMs);

  // Step 6a: Arm the RENDEZVOUS2 listener BEFORE sending INTRODUCE1.
  //
  // On fast networks (chutney localhost, LAN, etc.) the HS can receive our
  // INTRODUCE2, extend a circuit back to the RP, and have RENDEZVOUS1 reach
  // the RP — which then forwards it to our client as RENDEZVOUS2 — in under
  // 10 ms. If we attach the listener *after* introduction returns, the cell
  // has already come and gone by the time we care. That's the bug that made
  // the chutney HS test look like it was silently failing: the diagnostic
  // we added showed RENDEZVOUS2 arriving BEFORE "Waiting for rendezvous
  // completion" was logged.
  //
  // The observer helper also runs from here so "0 cells received" in the
  // error path means the cell truly never arrived, not that we missed it.
  const rendezvousObserver = rendCircuit.observeRelayTraffic();
  const rendezvous2Promise = waitForRelayCommand(
    rendCircuit,
    RelayCell.RENDEZVOUS2,
    rendezvousTimeoutMs
  );
  // Swallow any unhandled rejection on the promise until we await it below;
  // the final try/catch in step 7 is what surfaces the failure.
  rendezvous2Promise.catch(() => {});

  // Step 6: Try intro points until one succeeds
  const introErrors: Error[] = [];
  let successfulIntro:
    | { intro: IntroPoint; introCircuit: Circuit; state: HsNtorClientState }
    | undefined;

  for (let attempt = 0; attempt < maxIntroAttempts; attempt++) {
    const intro = introPoints[attempt % introPoints.length]!;

    let introCircuit: Circuit | undefined;
    const attemptStartTime = Date.now();
    try {
      log(`Building introduction circuit (attempt ${attempt + 1}/${maxIntroAttempts})...`);
      const introPeer = peerInfoFromIntroPoint(intro);
      introCircuit = await buildCircuit(introPeer, { avoid: [rendezvousPoint] });

      // Solve proof-of-work for this attempt (fresh nonce each time, so a retry
      // to another intro point is never rejected as a replay by the service).
      let proofOfWork: BuildIntroduce1Params['proofOfWork'] | undefined;
      if (powRequired && descriptor.powParams) {
        const effort =
          maxPowEffort !== undefined
            ? Math.min(descriptor.powParams.suggestedEffort, maxPowEffort)
            : descriptor.powParams.suggestedEffort;
        const powStart = Date.now();
        log(`Solving proof-of-work (effort=${effort})...`);
        const solved = await solveHsPow({
          seed: descriptor.powParams.seed,
          blindedId: blindedPublicKey,
          effort,
          randomBytes: randomBytesOpt,
          timeoutMs: powTimeoutMs,
        });
        if (solved) {
          log(`Proof-of-work solved in ${Date.now() - powStart}ms (effort=${solved.effort})`);
          proofOfWork = {
            scheme: 1, // v1 (Equi-X)
            nonce: solved.nonce,
            effort: solved.effort,
            seed: solved.seedHead,
            solution: solved.solution,
          };
        } else {
          log(
            `Proof-of-work not solved within ${powTimeoutMs}ms; sending introduction without a ` +
              `PoW token (may be dropped by a service enforcing PoW).`
          );
        }
      }

      log(`Sending introduction (attempt ${attempt + 1}/${maxIntroAttempts})...`);
      const { payload: introducePayload, state } = await buildIntroduce1Payload({
        introAuthKeyEd25519: intro.authKeyEd25519,
        serviceEncKey: intro.serviceEncKey,
        N_hs_subcred: subcred,
        rendezvousCookie,
        rendezvousPoint,
        ...(proofOfWork && { proofOfWork }),
      });

      await introCircuit.sendRelayMessage({
        streamId: 0,
        relayCommand: RelayCell.INTRODUCE1,
        data: introducePayload,
      });

      const ack = await waitForRelayCommand(
        introCircuit,
        RelayCell.INTRODUCE_ACK,
        perHandshakeTimeoutMs
      );
      if (ack.data.length < 2) throw new Error('INTRODUCE_ACK too short');
      const status = ack.data.readUInt16BE(0);
      if (status !== 0) {
        throw new Error(`INTRODUCE_ACK status=${status}`);
      }

      // Record successful experience
      const durationMs = Date.now() - attemptStartTime;
      iptExperienceTracker?.record(intro, { type: 'success', durationMs });

      successfulIntro = { intro, introCircuit, state };
      log(`Introduction succeeded on attempt ${attempt + 1}`);
      break;
    } catch (err) {
      const error = err instanceof Error ? err : new Error(String(err));
      introErrors.push(error);
      log(`Introduction attempt ${attempt + 1}/${maxIntroAttempts} failed: ${error.message}`);

      // Record failed experience
      const durationMs = Date.now() - attemptStartTime;
      const failureOutcome: IptOutcome = { type: 'failure', durationMs };
      // If we got an ACK with rate-limit status (status=2), apply a backoff
      if (error.message.includes('status=2')) {
        failureOutcome.retryAfterMs = Date.now() + 30_000;
      }
      iptExperienceTracker?.record(intro, failureOutcome);

      introCircuit?.destroy();
    }
  }

  // Wrap everything between observer-attach and rendezvous-completion in a
  // try/finally so the 'relay' listener is always removed from rendCircuit,
  // even on early throws (no successful intro, RENDEZVOUS2 timeout, malformed
  // RENDEZVOUS2 body). The success path falls through to the same detach().
  try {
    if (!successfulIntro) {
      rendCircuit.destroy();

      // If we used a cached descriptor and all intros failed, invalidate the cache
      // The descriptor might be stale (intro points changed)
      if (usedCachedDescriptor && descriptorCache) {
        log('All intro points failed with cached descriptor; invalidating cache');
        descriptorCache.invalidate(publicIdentityKey);
      }

      const errorSummary = introErrors.map((e) => e.message).join('; ');
      throw new Error(`All ${maxIntroAttempts} introduction attempts failed: ${errorSummary}`);
    }

    const { introCircuit, state } = successfulIntro;

    // Give the intro point a moment to fully relay the message before closing.
    // The intro point needs to forward INTRODUCE2 to the service over its circuit.
    await new Promise((resolve) => setTimeout(resolve, 100));
    introCircuit.destroy({ preserveChannel: true });

    // Step 7: Await RENDEZVOUS2 (listener was armed before introduction in 6a).
    // Use a dedicated rendezvous timeout (default 60s) rather than the overall timeout.
    // If the hidden service received our introduction, it should respond within this window.
    log(`Waiting for rendezvous completion (timeout: ${rendezvousTimeoutMs}ms)...`);
    let r2: { streamId: number; relayCommand: number; data: Buffer };
    try {
      r2 = await rendezvous2Promise;
    } catch (err) {
      const observed = rendezvousObserver.snapshot();
      rendCircuit.destroy();
      const msg = err instanceof Error ? err.message : String(err);
      throw new Error(
        `Rendezvous failed: timed out waiting for hidden service response ` +
          `(${rendezvousTimeoutMs}ms). The service may be offline, overloaded, ` +
          `or unable to decrypt the introduction. ` +
          `Cells received on rendezvous circuit during the wait: ` +
          `${observed.totalCells} (${observed.commandSummary || 'none'}). ` +
          `Original error: ${msg}`
      );
    }
    if (r2.data.length < 64) {
      rendCircuit.destroy();
      throw new Error('RENDEZVOUS2 too short');
    }

    const Y = r2.data.subarray(0, 32);
    const auth = r2.data.subarray(32, 64);
    const { NTOR_KEY_SEED } = hsNtorComplete({ state, Y, auth });
    const cipherPair = makeHsRendezvousCipherPairFromKeySeed(NTOR_KEY_SEED);
    rendCircuit.addVirtualHop(cipherPair);

    log('Connected to hidden service!');

    return { circuit: rendCircuit, descriptor };
  } finally {
    rendezvousObserver.detach();
  }
}
