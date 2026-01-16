/**
 * Consensus caching for browser environments.
 *
 * This module provides simple sessionStorage-based caching for raw consensus
 * documents. It's a dumb cache that just stores and retrieves text.
 *
 * All freshness/validity checking is handled by ConsensusManager - the cache
 * doesn't need to understand consensus semantics.
 *
 * The consensus is ~3.5MB but compresses well. We store it as-is since
 * sessionStorage has a 5-10MB limit per origin in most browsers.
 */

const CONSENSUS_STORAGE_KEY = 'tor-consensus-cache';

/**
 * Check if sessionStorage is available.
 */
function isStorageAvailable(): boolean {
  try {
    const test = '__storage_test__';
    sessionStorage.setItem(test, test);
    sessionStorage.removeItem(test);
    return true;
  } catch {
    return false;
  }
}

/**
 * Get cached consensus raw text if available.
 * Returns undefined if no cache exists.
 */
export function getCachedConsensusText(): string | undefined {
  if (!isStorageAvailable()) {
    return undefined;
  }

  try {
    const cached = sessionStorage.getItem(CONSENSUS_STORAGE_KEY);
    if (!cached) {
      return undefined;
    }

    console.log('[consensus-cache] Found cached consensus');
    return cached;
  } catch (error) {
    console.warn('[consensus-cache] Error reading cache:', error);
    return undefined;
  }
}

/**
 * Cache a raw consensus document.
 */
export function cacheConsensusText(content: string): boolean {
  if (!isStorageAvailable()) {
    console.warn('[consensus-cache] sessionStorage not available');
    return false;
  }

  try {
    sessionStorage.setItem(CONSENSUS_STORAGE_KEY, content);
    console.log(`[consensus-cache] Cached consensus (${Math.round(content.length / 1024)} KB)`);
    return true;
  } catch (error) {
    // sessionStorage might be full or quota exceeded
    console.warn('[consensus-cache] Failed to cache consensus:', error);
    return false;
  }
}

/**
 * Clear the cached consensus.
 */
export function clearCachedConsensus(): void {
  if (!isStorageAvailable()) {
    return;
  }

  try {
    sessionStorage.removeItem(CONSENSUS_STORAGE_KEY);
    console.log('[consensus-cache] Cleared cached consensus');
  } catch {
    // Ignore errors
  }
}

/**
 * Check if a cached consensus exists.
 */
export function hasCachedConsensus(): boolean {
  if (!isStorageAvailable()) {
    return false;
  }

  try {
    return sessionStorage.getItem(CONSENSUS_STORAGE_KEY) !== null;
  } catch {
    return false;
  }
}

/**
 * Cache status information.
 */
export interface ConsensusCacheStatus {
  /** Whether a consensus is cached */
  cached: boolean;
  /** Size of cached consensus in bytes (if cached) */
  sizeBytes?: number;
  /** Fresh-until date parsed from consensus (if cached) */
  freshUntil?: Date;
  /** Valid-until date parsed from consensus (if cached) */
  validUntil?: Date;
  /** Whether the cached consensus is still fresh (before fresh-until) */
  isFresh?: boolean;
  /** Whether the cached consensus is still valid (before valid-until) */
  isValid?: boolean;
}

/**
 * Get detailed status of the cached consensus.
 * Parses the consensus to extract validity information.
 */
export function getConsensusCacheStatus(): ConsensusCacheStatus {
  const text = getCachedConsensusText();
  if (!text) {
    return { cached: false };
  }

  const now = new Date();

  // Parse fresh-until from consensus
  const freshUntilMatch = text.match(/^fresh-until (\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})$/m);
  let freshUntil: Date | undefined;
  let isFresh: boolean | undefined;

  if (freshUntilMatch?.[1]) {
    freshUntil = new Date(freshUntilMatch[1].replace(' ', 'T') + 'Z');
    isFresh = freshUntil > now;
  }

  // Parse valid-until from consensus
  const validUntilMatch = text.match(/^valid-until (\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})$/m);
  let validUntil: Date | undefined;
  let isValid: boolean | undefined;

  if (validUntilMatch?.[1]) {
    validUntil = new Date(validUntilMatch[1].replace(' ', 'T') + 'Z');
    isValid = validUntil > now;
  }

  return {
    cached: true,
    sizeBytes: text.length,
    freshUntil,
    validUntil,
    isFresh,
    isValid,
  };
}
