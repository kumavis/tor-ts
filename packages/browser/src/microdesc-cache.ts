/**
 * Microdescriptor caching for browser environments.
 *
 * This module provides localStorage-based caching for microdescriptors.
 * Unlike consensus (sessionStorage), we use localStorage so microdescriptors
 * persist across browser sessions.
 *
 * Storage format:
 * - Key: `tor-md-{digest}` for each microdescriptor
 * - Value: compact format `timestamp|ntorKey|ed25519Key|policy`
 * - Key: `tor-md-idx` for the index of all digests (for enumeration)
 *
 * Compact encoding (~80 bytes per entry vs ~300 with JSON):
 * - timestamp: base36 encoded unix ms
 * - ntorKey: base64 (no padding), 43 chars for 32 bytes
 * - ed25519Key: base64 (no padding), 43 chars for 32 bytes
 * - policy: "a:80,443" or "r:*" (a=accept, r=reject)
 */

import type { MicrodescStorage, CachedMicrodesc } from 'tor/microdesc-manager';
import type { ParsedMicrodescriptor } from 'tor/directory-client';
import type { ExitPolicy, PortRange } from 'tor/exit-policy';

const MD_KEY_PREFIX = 'tor-md-';
const MD_INDEX_KEY = 'tor-md-idx';
const MD_VERSION_KEY = 'tor-md-ver';
const CACHE_VERSION = 2; // Increment to clear stale caches

function encodePolicy(policy: ExitPolicy | undefined): string {
  if (!policy) return '';
  const prefix = policy.type === 'accept' ? 'a:' : 'r:';
  if (policy.ports.length === 0) return '';
  const ranges = policy.ports.map((r: PortRange) =>
    r.start === r.end ? String(r.start) : `${r.start}-${r.end}`
  );
  return prefix + ranges.join(',');
}

function decodePolicy(str: string): ExitPolicy | undefined {
  if (!str) return undefined;
  const type = str[0] === 'a' ? 'accept' : 'reject';
  const portsStr = str.slice(2);
  if (!portsStr || portsStr === '*') {
    return { type, ports: [{ start: 1, end: 65535 }] };
  }
  const ports: PortRange[] = portsStr.split(',').map((p) => {
    const dash = p.indexOf('-');
    if (dash === -1) {
      const n = parseInt(p, 10);
      return { start: n, end: n };
    }
    return {
      start: parseInt(p.slice(0, dash), 10),
      end: parseInt(p.slice(dash + 1), 10),
    };
  });
  return { type, ports };
}

function encodeEntry(entry: CachedMicrodesc): string {
  const md = entry.microdesc;
  const parts = [
    entry.lastReferenced.toString(36), // Base36 for compact timestamp (~8 chars)
    md.ntorOnionKey?.toString('base64').replace(/=+$/, '') ?? '',
    md.ed25519Identity?.toString('base64').replace(/=+$/, '') ?? '',
    encodePolicy(md.exitPolicy),
  ];
  return parts.join('|');
}

function decodeEntry(value: string): CachedMicrodesc | null {
  try {
    const parts = value.split('|');
    if (parts.length < 3) return null;

    const [timestampB36, ntorB64, ed25519B64, policyStr] = parts;

    const lastReferenced = parseInt(timestampB36!, 36);
    if (isNaN(lastReferenced)) return null;

    const microdesc: ParsedMicrodescriptor = {};

    if (ntorB64) {
      const key = Buffer.from(ntorB64, 'base64');
      // ntor onion key must be exactly 32 bytes (curve25519 public key)
      if (key.length !== 32) {
        console.warn(`[microdesc-cache] Invalid ntor key length: ${key.length}`);
        return null;
      }
      microdesc.ntorOnionKey = key;
    }
    if (ed25519B64) {
      const key = Buffer.from(ed25519B64, 'base64');
      // Ed25519 identity must be exactly 32 bytes
      if (key.length !== 32) {
        console.warn(`[microdesc-cache] Invalid ed25519 key length: ${key.length}`);
        return null;
      }
      microdesc.ed25519Identity = key;
    }
    if (policyStr) {
      const policy = decodePolicy(policyStr);
      if (policy) {
        microdesc.exitPolicy = policy;
      }
    }

    return { microdesc, lastReferenced };
  } catch {
    return null;
  }
}

/**
 * Check if localStorage is available.
 */
function isStorageAvailable(): boolean {
  try {
    const test = '__storage_test__';
    localStorage.setItem(test, test);
    localStorage.removeItem(test);
    return true;
  } catch {
    return false;
  }
}

/**
 * localStorage-based storage for microdescriptors.
 *
 * Implements the MicrodescStorage interface for browser environments.
 * Uses localStorage for persistence across browser sessions.
 *
 * Uses compact encoding (~80 bytes per entry vs ~300 with JSON).
 */
export class LocalStorageMicrodescStorage implements MicrodescStorage {
  private index: Set<string>;
  private available: boolean;

  constructor() {
    this.available = isStorageAvailable();

    // Check cache version - clear if format changed
    if (this.available) {
      const storedVersion = localStorage.getItem(MD_VERSION_KEY);
      if (storedVersion !== String(CACHE_VERSION)) {
        console.log(
          `[microdesc-cache] Cache version mismatch (${storedVersion} vs ${CACHE_VERSION}), clearing`
        );
        this.clearAllEntries();
        localStorage.setItem(MD_VERSION_KEY, String(CACHE_VERSION));
      }
    }

    this.index = this.loadIndex();

    if (this.index.size > 0) {
      console.log(`[microdesc-cache] Found ${this.index.size} cached microdescriptors`);
    }
  }

  /**
   * Clear all microdesc entries from localStorage (used for version migration).
   */
  private clearAllEntries(): void {
    if (!this.available) return;

    // Find and remove all tor-md-* keys
    const keysToRemove: string[] = [];
    for (let i = 0; i < localStorage.length; i++) {
      const key = localStorage.key(i);
      if (key?.startsWith(MD_KEY_PREFIX)) {
        keysToRemove.push(key);
      }
    }
    for (const key of keysToRemove) {
      localStorage.removeItem(key);
    }
    localStorage.removeItem(MD_INDEX_KEY);
  }

  private loadIndex(): Set<string> {
    if (!this.available) return new Set();

    try {
      const raw = localStorage.getItem(MD_INDEX_KEY);
      if (!raw) return new Set();
      // Index is just comma-separated digests
      return new Set(raw.split(',').filter(Boolean));
    } catch {
      return new Set();
    }
  }

  private saveIndex(): void {
    if (!this.available) return;

    try {
      localStorage.setItem(MD_INDEX_KEY, Array.from(this.index).join(','));
    } catch (error) {
      console.warn('[microdesc-cache] Failed to save index:', error);
    }
  }

  get(digests: string[]): Map<string, CachedMicrodesc> {
    const result = new Map<string, CachedMicrodesc>();

    if (!this.available) return result;

    let inIndex = 0;
    let notInStorage = 0;
    let decodeFailed = 0;

    for (const digest of digests) {
      if (!this.index.has(digest)) continue;
      inIndex++;

      try {
        const raw = localStorage.getItem(MD_KEY_PREFIX + digest);
        if (!raw) {
          // Entry in index but not in storage - clean up
          this.index.delete(digest);
          notInStorage++;
          continue;
        }

        const entry = decodeEntry(raw);
        if (entry) {
          result.set(digest, entry);
        } else {
          // Failed to decode - remove
          this.index.delete(digest);
          localStorage.removeItem(MD_KEY_PREFIX + digest);
          decodeFailed++;
        }
      } catch {
        this.index.delete(digest);
      }
    }

    // Log cache behavior for debugging
    if (digests.length > 10 && (notInStorage > 0 || decodeFailed > 0)) {
      console.warn(
        `[microdesc-cache] get(${digests.length}): index=${this.index.size}, inIndex=${inIndex}, found=${result.size}, notInStorage=${notInStorage}, decodeFailed=${decodeFailed}`
      );
    }

    return result;
  }

  set(entries: Map<string, CachedMicrodesc>): void {
    if (!this.available) return;

    let saved = 0;
    let failed = 0;

    for (const [digest, entry] of entries) {
      try {
        const encoded = encodeEntry(entry);
        localStorage.setItem(MD_KEY_PREFIX + digest, encoded);
        this.index.add(digest);
        saved++;
      } catch (error) {
        failed++;
        if (failed <= 3) {
          console.warn(`[microdesc-cache] Failed to cache ${digest}:`, error);
        } else if (failed === 4) {
          console.warn('[microdesc-cache] (suppressing further errors...)');
        }
      }
    }

    if (saved > 0) {
      this.saveIndex();
      // Log cache state after saving
      console.log(
        `[microdesc-cache] Saved ${saved} entries, index now has ${this.index.size} entries`
      );
    }

    if (failed > 0) {
      console.warn(
        `[microdesc-cache] Failed to cache ${failed}/${entries.size} entries (quota likely exceeded)`
      );
    }
  }

  updateLastReferenced(digests: string[], timestamp: number): void {
    if (!this.available) return;

    // Batch update - only update entries that exist
    for (const digest of digests) {
      if (!this.index.has(digest)) continue;

      try {
        const raw = localStorage.getItem(MD_KEY_PREFIX + digest);
        if (!raw) continue;

        const entry = decodeEntry(raw);
        if (entry) {
          entry.lastReferenced = timestamp;
          localStorage.setItem(MD_KEY_PREFIX + digest, encodeEntry(entry));
        }
      } catch {
        // Ignore update failures
      }
    }
  }

  removeExpired(before: number): number {
    if (!this.available) return 0;

    let removed = 0;
    const toRemove: string[] = [];

    for (const digest of this.index) {
      try {
        const raw = localStorage.getItem(MD_KEY_PREFIX + digest);
        if (!raw) {
          toRemove.push(digest);
          continue;
        }

        const entry = decodeEntry(raw);
        if (!entry || entry.lastReferenced < before) {
          toRemove.push(digest);
          localStorage.removeItem(MD_KEY_PREFIX + digest);
          removed++;
        }
      } catch {
        toRemove.push(digest);
      }
    }

    for (const digest of toRemove) {
      this.index.delete(digest);
    }

    if (removed > 0) {
      this.saveIndex();
      console.log(`[microdesc-cache] Removed ${removed} expired entries`);
    }

    return removed;
  }

  getAllDigests(): string[] {
    return Array.from(this.index);
  }

  clear(): void {
    if (this.available) {
      for (const digest of this.index) {
        try {
          localStorage.removeItem(MD_KEY_PREFIX + digest);
        } catch {
          // Ignore
        }
      }
      try {
        localStorage.removeItem(MD_INDEX_KEY);
      } catch {
        // Ignore
      }
    }

    this.index.clear();
    console.log('[microdesc-cache] Cleared all cached microdescriptors');
  }

  /**
   * Get cache statistics.
   */
  getStats(): { count: number; estimatedSizeBytes: number } {
    // ~80 bytes per entry + ~50 bytes key overhead
    const estimatedSizeBytes = this.index.size * 130;
    return { count: this.index.size, estimatedSizeBytes };
  }
}
