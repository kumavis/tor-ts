/**
 * Consensus caching for browser environments.
 *
 * Stores the raw consensus document in sessionStorage with validity timestamps
 * following the Tor specification:
 * - fresh-until: Time until which this consensus is considered "fresh" (~1 hour)
 * - valid-until: Time after which this consensus should not be used (~3 hours)
 *
 * Caching strategy:
 * - If current time < validUntil: Use cached consensus (still valid)
 * - If current time >= validUntil: Must fetch new consensus
 *
 * Note: We use valid-until (not fresh-until) because:
 * 1. Browser downloads are slow and expensive (~3.5MB over Tor)
 * 2. The consensus data doesn't change that frequently
 * 3. Tor spec allows using consensus until valid-until
 *
 * The consensus is ~3.5MB but compresses well. We store it as-is since
 * sessionStorage has a 5-10MB limit per origin in most browsers.
 */

const CONSENSUS_STORAGE_KEY = 'tor-consensus-cache';

export type CachedConsensus = {
  /** Raw consensus document text */
  content: string;
  /** When this consensus becomes stale (should fetch new one) */
  freshUntil: number;
  /** When this consensus expires (must not use after this) */
  validUntil: number;
  /** When this was cached */
  cachedAt: number;
};

/**
 * Parse the validity timestamps from a raw consensus document.
 * Returns undefined if parsing fails.
 */
export function parseConsensusValidity(
  content: string
): { freshUntil: Date; validUntil: Date } | undefined {
  let freshUntil: Date | undefined;
  let validUntil: Date | undefined;

  // Parse line by line, looking for the header fields
  // These appear early in the document, so we can stop after finding them
  const lines = content.split('\n');
  for (const line of lines) {
    if (line.startsWith('fresh-until ')) {
      // Format: "fresh-until YYYY-MM-DD HH:MM:SS"
      const dateStr = line.slice('fresh-until '.length).trim();
      freshUntil = new Date(dateStr.replace(' ', 'T') + 'Z');
    } else if (line.startsWith('valid-until ')) {
      // Format: "valid-until YYYY-MM-DD HH:MM:SS"
      const dateStr = line.slice('valid-until '.length).trim();
      validUntil = new Date(dateStr.replace(' ', 'T') + 'Z');
    }

    // Once we have both, we can stop parsing
    if (freshUntil && validUntil) {
      break;
    }

    // These fields appear in the header, before any relay entries
    // If we hit a relay entry ('r '), we've gone too far
    if (line.startsWith('r ')) {
      break;
    }
  }

  if (freshUntil && validUntil && !isNaN(freshUntil.getTime()) && !isNaN(validUntil.getTime())) {
    return { freshUntil, validUntil };
  }

  return undefined;
}

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
 * Get cached consensus if available and still fresh.
 * Returns undefined if no valid cache exists.
 */
export function getCachedConsensus(): CachedConsensus | undefined {
  if (!isStorageAvailable()) {
    return undefined;
  }

  try {
    const cached = sessionStorage.getItem(CONSENSUS_STORAGE_KEY);
    if (!cached) {
      return undefined;
    }

    const data = JSON.parse(cached) as CachedConsensus;

    // Validate structure
    if (
      typeof data.content !== 'string' ||
      typeof data.freshUntil !== 'number' ||
      typeof data.validUntil !== 'number'
    ) {
      console.warn('[consensus-cache] Invalid cache structure, clearing');
      sessionStorage.removeItem(CONSENSUS_STORAGE_KEY);
      return undefined;
    }

    const now = Date.now();

    // Check if consensus is still valid (not expired)
    if (now >= data.validUntil) {
      console.log('[consensus-cache] Cached consensus has expired (past valid-until)');
      sessionStorage.removeItem(CONSENSUS_STORAGE_KEY);
      return undefined;
    }

    // Use the consensus as long as it's valid (until valid-until)
    // Note: fresh-until is just a hint for when a new consensus might be available,
    // but the current one is still perfectly usable until valid-until
    const remainingMinutes = Math.round((data.validUntil - now) / 1000 / 60);
    const isFresh = now < data.freshUntil;
    console.log(
      `[consensus-cache] Using cached consensus (${isFresh ? 'fresh' : 'valid'}, expires in ${remainingMinutes} minutes)`
    );
    return data;
  } catch (error) {
    console.warn('[consensus-cache] Error reading cache:', error);
    try {
      sessionStorage.removeItem(CONSENSUS_STORAGE_KEY);
    } catch {
      // Ignore cleanup errors
    }
    return undefined;
  }
}

/**
 * Cache a consensus document.
 * Parses the validity timestamps from the document content.
 */
export function cacheConsensus(content: string): boolean {
  if (!isStorageAvailable()) {
    console.warn('[consensus-cache] sessionStorage not available');
    return false;
  }

  const validity = parseConsensusValidity(content);
  if (!validity) {
    console.warn('[consensus-cache] Could not parse validity timestamps from consensus');
    return false;
  }

  const data: CachedConsensus = {
    content,
    freshUntil: validity.freshUntil.getTime(),
    validUntil: validity.validUntil.getTime(),
    cachedAt: Date.now(),
  };

  try {
    sessionStorage.setItem(CONSENSUS_STORAGE_KEY, JSON.stringify(data));
    console.log(
      `[consensus-cache] Cached consensus (fresh until ${validity.freshUntil.toISOString()}, valid until ${validity.validUntil.toISOString()})`
    );
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
 * Get cache status information.
 */
export function getConsensusCacheStatus(): {
  cached: boolean;
  isFresh?: boolean;
  isValid?: boolean;
  freshUntil?: Date;
  validUntil?: Date;
  cachedAt?: Date;
  sizeBytes?: number;
} {
  if (!isStorageAvailable()) {
    return { cached: false };
  }

  try {
    const cached = sessionStorage.getItem(CONSENSUS_STORAGE_KEY);
    if (!cached) {
      return { cached: false };
    }

    const data = JSON.parse(cached) as CachedConsensus;
    const now = Date.now();
    const isFresh = now < data.freshUntil;
    const isValid = now < data.validUntil;

    // If not valid, don't report as cached
    if (!isValid) {
      return { cached: false };
    }

    return {
      cached: true,
      isFresh,
      isValid,
      freshUntil: new Date(data.freshUntil),
      validUntil: new Date(data.validUntil),
      cachedAt: new Date(data.cachedAt),
      sizeBytes: cached.length,
    };
  } catch {
    return { cached: false };
  }
}
