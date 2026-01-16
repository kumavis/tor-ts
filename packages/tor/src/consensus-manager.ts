/**
 * ConsensusManager - Unified consensus management for Tor networks.
 *
 * This module provides consensus management that works across different
 * environments (Node.js, Browser) and networks (mainnet, Chutney).
 *
 * Key concepts:
 * - **Fresh**: Consensus is fresh if current time < freshUntil. A fresh consensus
 *   is the preferred state and indicates no refresh is needed.
 * - **Valid**: Consensus is valid if current time < validUntil. A valid consensus
 *   can still be used even if not fresh, but a refresh may be beneficial.
 * - **Stale**: Consensus is stale if current time >= validUntil. Must refresh.
 */

import type { Circuit } from './circuit.ts';
import type { VerifiedMicroDescConsensus } from './build-circuit/directory.ts';
import {
  dangerouslyTrustUnverifiedConsensus,
  parseMicroDescConsensus,
} from './build-circuit/directory.ts';
import type { DownloadProgressCallback } from './directory-client.ts';
import { fetchAndVerifyConsensus } from './directory-client.ts';

/**
 * Consensus validity status.
 */
export type ConsensusStatus = {
  /** Whether a consensus is currently held */
  hasConsensus: boolean;
  /** Whether the consensus is fresh (current time < freshUntil) */
  isFresh: boolean;
  /** Whether the consensus is valid (current time < validUntil) */
  isValid: boolean;
  /** When the consensus becomes stale (no longer fresh) */
  freshUntil?: Date;
  /** When the consensus expires (must not use after) */
  validUntil?: Date;
  /** When the consensus became valid */
  validAfter?: Date;
};

/**
 * Options for consensus refresh operations.
 */
export type ConsensusRefreshOptions = {
  /** Callback for download progress */
  onProgress?: DownloadProgressCallback;
  /** Callback for status messages */
  onStatus?: (message: string) => void;
  /** Skip signature verification (dangerous, for testing only) */
  dangerouslySkipSignatureVerification?: boolean;
  /** Timeout in milliseconds */
  timeoutMs?: number;
};

/**
 * Listener callback for consensus updates.
 */
export type ConsensusUpdateListener = (
  consensus: VerifiedMicroDescConsensus,
  rawContent: string
) => void;

/**
 * Check if a consensus is fresh (current time < freshUntil).
 *
 * @param consensus - The consensus to check
 * @param now - Current time in milliseconds (defaults to Date.now())
 */
export function isConsensusFresh(
  consensus: VerifiedMicroDescConsensus,
  now: number = Date.now()
): boolean {
  if (consensus.freshUntil) {
    return now < consensus.freshUntil.getTime();
  }
  // If freshUntil is missing, estimate based on validAfter + 1 voting interval.
  // On mainnet this is 1 hour; on Chutney it's typically 20 seconds.
  if (consensus.validAfter) {
    const votingIntervalMs = 3600 * 1000; // Default 1 hour
    return now < consensus.validAfter.getTime() + votingIntervalMs;
  }
  // No timing info available; consider stale to be safe
  return false;
}

/**
 * Check if a consensus is still valid (current time < validUntil).
 *
 * @param consensus - The consensus to check
 * @param now - Current time in milliseconds (defaults to Date.now())
 */
export function isConsensusTtlValid(
  consensus: VerifiedMicroDescConsensus,
  now: number = Date.now()
): boolean {
  if (!consensus.validUntil) {
    // If no validUntil, fall back to freshUntil + buffer or assume invalid
    if (consensus.freshUntil) {
      // Allow 2 hours past freshUntil as a rough estimate
      return now < consensus.freshUntil.getTime() + 2 * 3600 * 1000;
    }
    return false;
  }
  return now < consensus.validUntil.getTime();
}

/**
 * Options for ConsensusManager constructor.
 */
export type ConsensusManagerOptions = {
  /**
   * Initial verified consensus (skips initial fetch if still valid).
   * Expired consensus will be ignored.
   */
  initialVerifiedConsensus?: VerifiedMicroDescConsensus;
  /**
   * Raw content of initial consensus (will be parsed).
   * The raw content was verified when originally cached, so we trust it.
   * Expired consensus will be ignored after parsing.
   */
  initialRawContent?: string;
  /** Default options for refresh operations */
  defaultRefreshOptions?: ConsensusRefreshOptions;
};

/**
 * Unified consensus manager for Tor networks.
 *
 * Features:
 * - Deduplicates concurrent refresh requests (returns in-flight promise)
 * - Subscription support for consensus updates (use for external caching)
 * - Works across Node.js and browser environments
 *
 * For caching, load from your cache and pass `initialRawContent`,
 * then subscribe to updates to save new consensus to your cache.
 */
export class ConsensusManager {
  private refreshInFlight: Promise<VerifiedMicroDescConsensus> | undefined;
  protected circuit: Circuit;
  protected consensus: VerifiedMicroDescConsensus | undefined;
  private readonly defaultOptions: ConsensusRefreshOptions;
  private readonly listeners = new Set<ConsensusUpdateListener>();

  constructor(circuit: Circuit, options: ConsensusManagerOptions = {}) {
    // Validate: cannot provide both initialVerifiedConsensus and initialRawContent
    if (options.initialVerifiedConsensus && options.initialRawContent) {
      throw new Error(
        'Cannot provide both initialVerifiedConsensus and initialRawContent. ' +
          'Use initialRawContent for cached content or initialVerifiedConsensus for pre-parsed.'
      );
    }

    this.circuit = circuit;
    this.defaultOptions = options.defaultRefreshOptions ?? {};

    // Handle initial consensus
    if (options.initialVerifiedConsensus) {
      // Only store if still valid (not expired)
      if (isConsensusTtlValid(options.initialVerifiedConsensus)) {
        this.consensus = options.initialVerifiedConsensus;
      }
    } else if (options.initialRawContent) {
      // Parse raw content synchronously (parseMicroDescConsensus is now sync)
      this.parseInitialRawContent(options.initialRawContent);
    }
  }

  /**
   * Parse raw content for initial consensus (called from constructor).
   */
  private parseInitialRawContent(rawContent: string): void {
    try {
      // Parse without verification
      const unverified = parseMicroDescConsensus(rawContent);

      // SKIP VERIFICATION: This raw content was loaded from cache. The consensus
      // was verified when it was originally fetched and cached.
      const consensus = dangerouslyTrustUnverifiedConsensus(
        unverified,
        'loaded from cache (was verified when originally fetched)'
      );

      // Only store if still valid
      if (isConsensusTtlValid(consensus)) {
        this.consensus = consensus;
      }
    } catch (err) {
      console.error('Failed to parse initial raw consensus:', err);
    }
  }

  /**
   * Subscribe to consensus updates.
   * The listener is called whenever a new consensus is fetched.
   *
   * @param listener - Callback function
   * @returns Unsubscribe function
   */
  subscribe(listener: ConsensusUpdateListener): () => void {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  /**
   * Get the current consensus, refreshing if stale.
   */
  async getConsensus(): Promise<VerifiedMicroDescConsensus> {
    if (this.consensus && isConsensusFresh(this.consensus)) {
      return this.consensus;
    }
    return this.refresh();
  }

  /**
   * Get the current consensus synchronously.
   * Returns undefined if no consensus or if expired.
   */
  getCurrentConsensus(): VerifiedMicroDescConsensus | undefined {
    if (!this.consensus) {
      return undefined;
    }
    // Don't return expired consensus
    if (!isConsensusTtlValid(this.consensus)) {
      return undefined;
    }
    return this.consensus;
  }

  /**
   * Get the current consensus status.
   */
  getStatus(): ConsensusStatus {
    if (!this.consensus) {
      return { hasConsensus: false, isFresh: false, isValid: false };
    }

    const status: ConsensusStatus = {
      hasConsensus: true,
      isFresh: isConsensusFresh(this.consensus),
      isValid: isConsensusTtlValid(this.consensus),
    };

    if (this.consensus.freshUntil) status.freshUntil = this.consensus.freshUntil;
    if (this.consensus.validUntil) status.validUntil = this.consensus.validUntil;
    if (this.consensus.validAfter) status.validAfter = this.consensus.validAfter;

    return status;
  }

  /**
   * Force a refresh of the consensus.
   * If a refresh is already in flight, returns that promise.
   */
  refresh(options: ConsensusRefreshOptions = {}): Promise<VerifiedMicroDescConsensus> {
    // If a refresh is already in flight, return the existing promise
    if (this.refreshInFlight) {
      return this.refreshInFlight;
    }

    // Start the refresh and track the promise
    this.refreshInFlight = this.doRefresh(options).finally(() => {
      this.refreshInFlight = undefined;
    });

    return this.refreshInFlight;
  }

  /**
   * Internal method that performs the actual refresh.
   */
  private async doRefresh(options: ConsensusRefreshOptions): Promise<VerifiedMicroDescConsensus> {
    const mergedOptions = { ...this.defaultOptions, ...options };
    const onStatus = mergedOptions.onStatus;

    onStatus?.('Refreshing consensus...');
    const result = await fetchAndVerifyConsensus(this.circuit, {
      ...(mergedOptions.timeoutMs !== undefined && { timeoutMs: mergedOptions.timeoutMs }),
      ...(mergedOptions.dangerouslySkipSignatureVerification !== undefined && {
        dangerouslySkipSignatureVerification: mergedOptions.dangerouslySkipSignatureVerification,
      }),
      ...(mergedOptions.onProgress && { onProgress: mergedOptions.onProgress }),
      ...(onStatus && { onStatus }),
    });

    this.consensus = result.consensus;

    // Notify listeners (with raw content for their caching needs)
    for (const listener of this.listeners) {
      try {
        listener(result.consensus, result.rawContent);
      } catch (err) {
        console.error('Consensus update listener error:', err);
      }
    }

    onStatus?.(
      `Consensus refreshed (valid-after=${result.consensus.validAfter?.toISOString() ?? 'unknown'})`
    );

    return result.consensus;
  }

  /**
   * Clear in-memory consensus.
   */
  clear(): void {
    this.consensus = undefined;
  }
}
