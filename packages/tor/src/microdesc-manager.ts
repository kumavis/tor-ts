/**
 * MicrodescManager - Manages microdescriptor fetching and caching.
 *
 * Microdescriptors contain:
 * - ntor-onion-key: curve25519 key for ntor handshake
 * - id ed25519: Ed25519 identity key (required for HSDir hash ring)
 * - p/p6: exit policy summary
 * - family: relay family info
 *
 * Key concepts:
 * - Microdescriptors are identified by their SHA256 digest (from consensus `m` line)
 * - They are cached with a "last-referenced" timestamp
 * - Evicted after 1 week of not being referenced by any consensus (per spec)
 * - Multiple requests for the same digest are deduplicated
 */

import type { DirectoryClient, ParsedMicrodescriptor } from './directory-client.ts';
import { parseMicrodescriptorBatch } from './directory-client.ts';
import type { MicroDescNodeInfo, VerifiedMicroDescConsensus } from './build-circuit/directory.ts';

/** How long to keep unreferenced microdescriptors (1 week per spec) */
const MICRODESC_EXPIRY_MS = 7 * 24 * 60 * 60 * 1000;

/** Batch size for fetching microdescriptors */
const FETCH_BATCH_SIZE = 92;

// ============================================================================
// Types
// ============================================================================

/**
 * Cached microdescriptor entry with metadata.
 */
export type CachedMicrodesc = {
  /** Parsed microdescriptor data */
  microdesc: ParsedMicrodescriptor;
  /** When this was last referenced by a consensus */
  lastReferenced: number;
};

/**
 * Progress callback for microdescriptor downloads.
 */
export type MicrodescProgressCallback = (progress: {
  /** Number of microdescriptors fetched so far */
  fetched: number;
  /** Total number of microdescriptors to fetch */
  total: number;
  /** Number already cached (not needing fetch) */
  cached: number;
}) => void;

/**
 * Storage interface for microdescriptors.
 * Implement this for different storage backends (memory, localStorage, etc.)
 */
export interface MicrodescStorage {
  /**
   * Get cached microdescriptors by digest.
   * Returns a map from digest to cached entry (only for those found).
   */
  get(digests: string[]): Map<string, CachedMicrodesc>;

  /**
   * Store microdescriptors with their last-referenced timestamp.
   */
  set(entries: Map<string, CachedMicrodesc>): void;

  /**
   * Update the last-referenced timestamp for existing entries.
   * Only updates entries that exist; doesn't create new ones.
   */
  updateLastReferenced(digests: string[], timestamp: number): void;

  /**
   * Remove entries that haven't been referenced since `before` timestamp.
   * Returns the number of entries removed.
   */
  removeExpired(before: number): number;

  /**
   * Get all cached digests (for debugging/stats).
   */
  getAllDigests(): string[];

  /**
   * Clear all cached entries.
   */
  clear(): void;
}

/**
 * Options for MicrodescManager constructor.
 */
export type MicrodescManagerOptions = {
  /** Storage backend for microdescriptors */
  storage: MicrodescStorage;
  /** Directory client for fetching */
  dirClient: DirectoryClient;
};

/**
 * Options for updateFromConsensus.
 */
export type UpdateFromConsensusOptions = {
  /** Progress callback for fetch operations */
  onProgress?: MicrodescProgressCallback;
  /** Status message callback */
  onStatus?: (message: string) => void;
  /** Only fetch microdescriptors for nodes matching this filter */
  filter?: (node: MicroDescNodeInfo) => boolean;
};

// ============================================================================
// In-Memory Storage Implementation
// ============================================================================

/**
 * Simple in-memory storage for microdescriptors.
 * Suitable for Node.js and testing.
 */
export class InMemoryMicrodescStorage implements MicrodescStorage {
  private cache = new Map<string, CachedMicrodesc>();

  get(digests: string[]): Map<string, CachedMicrodesc> {
    const result = new Map<string, CachedMicrodesc>();
    for (const digest of digests) {
      const entry = this.cache.get(digest);
      if (entry) {
        result.set(digest, entry);
      }
    }
    return result;
  }

  set(entries: Map<string, CachedMicrodesc>): void {
    for (const [digest, entry] of entries) {
      this.cache.set(digest, entry);
    }
  }

  updateLastReferenced(digests: string[], timestamp: number): void {
    for (const digest of digests) {
      const entry = this.cache.get(digest);
      if (entry) {
        entry.lastReferenced = timestamp;
      }
    }
  }

  removeExpired(before: number): number {
    let removed = 0;
    for (const [digest, entry] of this.cache) {
      if (entry.lastReferenced < before) {
        this.cache.delete(digest);
        removed++;
      }
    }
    return removed;
  }

  getAllDigests(): string[] {
    return Array.from(this.cache.keys());
  }

  clear(): void {
    this.cache.clear();
  }

  /** Get cache size (for debugging) */
  get size(): number {
    return this.cache.size;
  }
}

// ============================================================================
// MicrodescManager
// ============================================================================

/**
 * Manages microdescriptor fetching and caching.
 *
 * Features:
 * - Deduplicates concurrent requests for the same digests
 * - Flexible storage backend (memory, localStorage, etc.)
 * - Automatic cleanup of expired entries
 * - Progress callbacks for UI feedback
 */
export class MicrodescManager {
  private readonly storage: MicrodescStorage;
  private readonly dirClient: DirectoryClient;

  /** In-flight fetch promises, keyed by digest */
  private readonly inFlight = new Map<string, Promise<ParsedMicrodescriptor | undefined>>();

  constructor(options: MicrodescManagerOptions) {
    this.storage = options.storage;
    this.dirClient = options.dirClient;
  }

  /**
   * Get microdescriptors for the given digests.
   * Returns cached entries and fetches missing ones.
   *
   * @param digestsBase64 - Base64-encoded SHA256 digests (without padding)
   * @param onProgress - Optional progress callback
   * @returns Map from digest to parsed microdescriptor
   */
  async get(
    digestsBase64: string[],
    onProgress?: MicrodescProgressCallback
  ): Promise<Map<string, ParsedMicrodescriptor>> {
    if (digestsBase64.length === 0) {
      return new Map();
    }

    const now = Date.now();
    const result = new Map<string, ParsedMicrodescriptor>();

    // Check cache first
    const cached = this.storage.get(digestsBase64);
    const missing: string[] = [];

    for (const digest of digestsBase64) {
      const entry = cached.get(digest);
      if (entry) {
        result.set(digest, entry.microdesc);
      } else if (!this.inFlight.has(digest)) {
        // Only add to missing if not already being fetched
        missing.push(digest);
      }
    }

    // Log cache hit rate for debugging
    console.log(
      `[MicrodescManager] get(${digestsBase64.length}): cached=${cached.size}, missing=${missing.length}, inFlight=${digestsBase64.length - cached.size - missing.length}`
    );

    // Update last-referenced for cached entries
    if (cached.size > 0) {
      this.storage.updateLastReferenced(Array.from(cached.keys()), now);
    }

    // Wait for any in-flight requests
    const inFlightDigests = digestsBase64.filter((d) => this.inFlight.has(d));
    if (inFlightDigests.length > 0) {
      const inFlightResults = await Promise.all(
        inFlightDigests.map(async (d) => {
          const md = await this.inFlight.get(d);
          return [d, md] as const;
        })
      );
      for (const [digest, md] of inFlightResults) {
        if (md) {
          result.set(digest, md);
        }
      }
    }

    // Report initial progress
    onProgress?.({
      fetched: 0,
      total: missing.length,
      cached: cached.size,
    });

    // Fetch missing in batches
    if (missing.length > 0) {
      await this.fetchAndStore(missing, now, (fetched) => {
        onProgress?.({
          fetched,
          total: missing.length,
          cached: cached.size,
        });
      });

      // Get the newly fetched entries
      const newlyCached = this.storage.get(missing);
      for (const [digest, entry] of newlyCached) {
        result.set(digest, entry.microdesc);
      }
    }

    return result;
  }

  /**
   * Get a single microdescriptor by digest.
   */
  async getOne(digestBase64: string): Promise<ParsedMicrodescriptor | undefined> {
    const result = await this.get([digestBase64]);
    return result.get(digestBase64);
  }

  /**
   * Update from a new consensus: fetch missing microdescriptors and clean expired.
   *
   * @param consensus - The new consensus
   * @param options - Update options
   * @returns Stats about the update
   */
  async updateFromConsensus(
    consensus: VerifiedMicroDescConsensus,
    options: UpdateFromConsensusOptions = {}
  ): Promise<{
    fetched: number;
    cached: number;
    expired: number;
    total: number;
  }> {
    const { onProgress, onStatus, filter } = options;
    const now = Date.now();

    // Get all relays with microdescriptor digests
    let relays = consensus.relays.filter((r) => r.mKey);
    if (filter) {
      relays = relays.filter(filter);
    }

    const digests = relays.map((r) => r.mKey!.toString('base64').replace(/=+$/, ''));

    onStatus?.(`Checking ${digests.length} microdescriptors...`);

    // Check cache
    const cached = this.storage.get(digests);
    const cachedDigests = Array.from(cached.keys());
    const missing = digests.filter((d) => !cached.has(d));

    // Update last-referenced for all digests in this consensus
    this.storage.updateLastReferenced(cachedDigests, now);

    onStatus?.(`Found ${cached.size} cached, need to fetch ${missing.length}`);

    // Fetch missing
    let fetched = 0;
    if (missing.length > 0) {
      fetched = await this.fetchAndStore(missing, now, (count) => {
        onProgress?.({
          fetched: count,
          total: missing.length,
          cached: cached.size,
        });
      });
    }

    // Clean up expired entries (not referenced in this or recent consensuses)
    const expiryThreshold = now - MICRODESC_EXPIRY_MS;
    const expired = this.storage.removeExpired(expiryThreshold);

    if (expired > 0) {
      onStatus?.(`Removed ${expired} expired microdescriptors`);
    }

    return {
      fetched,
      cached: cached.size,
      expired,
      total: digests.length,
    };
  }

  /**
   * Fetch microdescriptors and store them incrementally.
   * Caches each batch as it's downloaded (doesn't wait for full download).
   * Handles batching and in-flight deduplication.
   */
  private async fetchAndStore(
    digests: string[],
    timestamp: number,
    onProgress?: (fetched: number) => void
  ): Promise<number> {
    let fetchedCount = 0;
    const allFetched = new Set<string>();

    // Create promises for in-flight tracking
    const digestPromises = new Map<
      string,
      { resolve: (md: ParsedMicrodescriptor | undefined) => void }
    >();
    for (const digest of digests) {
      const promise = new Promise<ParsedMicrodescriptor | undefined>((resolve) => {
        digestPromises.set(digest, { resolve });
      });
      this.inFlight.set(digest, promise);
    }

    try {
      // Fetch in batches - cache each batch immediately as it's downloaded
      for (let i = 0; i < digests.length; i += FETCH_BATCH_SIZE) {
        const batchDigests = digests.slice(i, i + FETCH_BATCH_SIZE);

        try {
          const content = await this.dirClient.downloadMicrodescriptors(batchDigests);
          const parsed = parseMicrodescriptorBatch(content, batchDigests);

          // Log batch match rate
          console.log(
            `[MicrodescManager] batch ${Math.floor(i / FETCH_BATCH_SIZE) + 1}: requested=${batchDigests.length}, matched=${parsed.size}, content=${content.length} bytes`
          );

          // Build batch entries for immediate caching
          const batchEntries = new Map<string, CachedMicrodesc>();

          for (const [digest, microdesc] of parsed) {
            batchEntries.set(digest, {
              microdesc,
              lastReferenced: timestamp,
            });
            allFetched.add(digest);
            fetchedCount++;

            // Resolve in-flight promise immediately
            digestPromises.get(digest)?.resolve(microdesc);
          }

          // Cache this batch immediately - don't wait for full download
          if (batchEntries.size > 0) {
            this.storage.set(batchEntries);
          }
        } catch (err) {
          // Log batch errors
          console.warn(
            `[MicrodescManager] batch ${Math.floor(i / FETCH_BATCH_SIZE) + 1} failed:`,
            err
          );
        }

        onProgress?.(fetchedCount);
      }

      // Resolve any unresolved promises (not found)
      for (const [digest, { resolve }] of digestPromises) {
        if (!allFetched.has(digest)) {
          resolve(undefined);
        }
      }
    } finally {
      // Clean up in-flight tracking
      for (const digest of digests) {
        this.inFlight.delete(digest);
      }
    }

    return fetchedCount;
  }

  /**
   * Get cached microdescriptor data for relay nodes.
   * Useful for HSDir lookups where we need Ed25519 identity.
   *
   * @param nodes - Relay nodes from consensus
   * @returns Map from RSA ID hex to microdescriptor
   */
  getCachedForNodes(nodes: MicroDescNodeInfo[]): Map<string, ParsedMicrodescriptor> {
    const nodesWithMKey = nodes.filter((n) => n.mKey);
    const digests = nodesWithMKey.map((n) => n.mKey!.toString('base64').replace(/=+$/, ''));

    const cached = this.storage.get(digests);
    const result = new Map<string, ParsedMicrodescriptor>();

    for (let i = 0; i < nodesWithMKey.length; i++) {
      const node = nodesWithMKey[i]!;
      const digest = digests[i]!;
      const entry = cached.get(digest);
      if (entry) {
        const rsaIdHex = node.rsaIdDigest.toString('hex');
        result.set(rsaIdHex, entry.microdesc);
      }
    }

    return result;
  }

  /**
   * Get stats about the cache.
   */
  getStats(): { size: number; digests: string[] } {
    const digests = this.storage.getAllDigests();
    return { size: digests.length, digests };
  }

  /**
   * Clear all cached microdescriptors.
   */
  clear(): void {
    this.storage.clear();
  }
}
