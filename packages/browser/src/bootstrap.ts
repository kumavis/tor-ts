/**
 * Shared bootstrap utilities for browser Tor connections.
 *
 * This module provides the common bootstrap flow used by both regular circuits
 * and hidden service connections:
 * 1. Connect to Snowflake via WebSocket → get relay identity from TLS handshake
 * 2. Build 1-hop bootstrap circuit using CREATE_FAST (no onion key needed)
 * 3. Fetch directory consensus over encrypted bootstrap circuit (or use cached)
 * 4. Parse and verify consensus signatures
 */

import { Circuit } from 'tor/circuit';
import type { PeerInfo } from 'tor/circuit';
import { DirectoryClient } from 'tor/directory-client';
import type { DownloadProgress } from 'tor/directory-client';
import type { VerifiedMicroDescConsensus } from 'tor/build-circuit/directory';
import { ConsensusManager, MicrodescManager } from 'tor';
import { SnowflakeBrowserChannel } from './snowflake-channel.ts';
import { getCachedConsensusText, cacheConsensusText } from './consensus-cache.ts';
import { LocalStorageMicrodescStorage } from './microdesc-cache.ts';

/**
 * Common options for browser bootstrap operations.
 */
export type BrowserBootstrapOptions = {
  /** Snowflake relay URL */
  relayUrl?: string;
  /** Callback for status updates */
  onStatus?: (status: string) => void;
  /** Callback for consensus download progress */
  onConsensusProgress?: (progress: DownloadProgress) => void;
  /**
   * **DANGEROUS**: Skip consensus signature verification entirely.
   *
   * WARNING: This disables a critical security check. The consensus document
   * could be forged by an attacker to direct you to malicious relays.
   *
   * Only use this option if:
   * - You're in a test environment
   * - You're debugging/developing and understand the risks
   * - The crypto implementation for your platform is not yet complete
   *
   * Default: false
   */
  dangerouslySkipSignatureVerification?: boolean;
  /**
   * Skip using cached consensus from sessionStorage.
   * Forces a fresh download even if a valid cached consensus exists.
   *
   * Default: false
   */
  skipConsensusCache?: boolean;
  /** Log prefix for status messages */
  logPrefix?: string;
};

/**
 * Result of the bootstrap process.
 */
export type BootstrapResult = {
  /** The Snowflake channel connection */
  channel: SnowflakeBrowserChannel;
  /** The 1-hop bootstrap circuit for directory lookups */
  bootstrapCircuit: Circuit;
  /** Directory client for fetching relay info */
  dirClient: DirectoryClient;
  /** Consensus manager for accessing and refreshing consensus */
  consensusManager: ConsensusManager;
  /** Microdescriptor manager for relay info caching */
  microdescManager: MicrodescManager;
  /** Parsed and verified consensus */
  consensus: VerifiedMicroDescConsensus;
  /** PeerInfo for the entry relay (for building additional circuits) */
  entryPeerInfo: PeerInfo;
};

/**
 * Perform the common bootstrap flow for browser Tor connections.
 *
 * This establishes a 1-hop circuit via Snowflake and fetches/parses the consensus.
 * The caller is responsible for:
 * - Building additional circuits as needed
 * - Cleaning up the bootstrap circuit when done (use `bootstrapCircuit.destroy({ preserveChannel: true })`)
 * - Cleaning up the channel when completely done
 *
 * @param options - Bootstrap options
 * @returns Bootstrap result containing channel, circuit, consensus, etc.
 */
export async function performBootstrap(
  options: BrowserBootstrapOptions = {}
): Promise<BootstrapResult> {
  const {
    relayUrl = 'wss://snowflake.torproject.net/',
    onStatus,
    onConsensusProgress,
    dangerouslySkipSignatureVerification = false,
    skipConsensusCache = false,
    logPrefix = 'tor-browser',
  } = options;

  const log = (msg: string) => {
    console.log(`[${logPrefix}] ${msg}`);
    onStatus?.(msg);
  };

  // Step 1: Connect to Snowflake relay
  log('Connecting to Snowflake relay...');
  const channel = new SnowflakeBrowserChannel();
  await channel.connect({ relayUrl });

  const entryRsaIdDigest = channel.peerIdentity?.rsaIdDigest;
  if (!entryRsaIdDigest) {
    channel.destroy();
    throw new Error('Snowflake channel has no peer identity');
  }

  // Step 2: Build 1-hop bootstrap circuit using CREATE_FAST
  log('Building bootstrap circuit...');
  const entryPeerInfo: PeerInfo = {
    onionKey: Buffer.alloc(0), // Empty triggers CREATE_FAST
    rsaIdDigest: entryRsaIdDigest,
    linkSpecifiers: [],
  };

  const bootstrapCircuit = new Circuit({ path: [entryPeerInfo], channel });
  await bootstrapCircuit.connect();

  // Step 3: Get consensus via ConsensusManager
  const cachedRaw = skipConsensusCache ? undefined : getCachedConsensusText();

  if (cachedRaw) {
    log('Found cached consensus');
  }

  // Create consensus manager (will parse cached raw content if provided)
  const consensusManager = new ConsensusManager(bootstrapCircuit, {
    initialRawContent: cachedRaw,
    defaultRefreshOptions: {
      timeoutMs: 600_000, // Longer timeout for browser environment
      dangerouslySkipSignatureVerification,
      onProgress: onConsensusProgress,
      onStatus: log,
    },
  });

  // Subscribe to cache new consensus on updates
  consensusManager.subscribe((_consensus, rawContent) => {
    cacheConsensusText(rawContent);
  });

  // Get consensus (uses initial if available, otherwise fetches)
  const consensus = await consensusManager.getConsensus();

  if (consensus.relays.length === 0) {
    bootstrapCircuit.destroy();
    channel.destroy();
    throw new Error('No relays found in consensus');
  }

  // Create directory client for relay lookups
  const dirClient = new DirectoryClient(bootstrapCircuit, { timeoutMs: 600_000 });

  // Create microdescriptor manager with localStorage-backed storage
  // Microdescriptors are fetched lazily when needed (e.g., for hidden service connections)
  const microdescManager = new MicrodescManager({
    storage: new LocalStorageMicrodescStorage(),
    dirClient,
  });

  return {
    channel,
    bootstrapCircuit,
    dirClient,
    consensusManager,
    microdescManager,
    consensus,
    entryPeerInfo,
  };
}
