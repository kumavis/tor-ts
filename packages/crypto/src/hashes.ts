/**
 * Hash functions shared between Node.js and browser implementations.
 *
 * Uses @noble/hashes which works identically in both environments.
 */

import { sha1 as nobleSha1 } from '@noble/hashes/legacy';
import { sha256 as nobleSha256, sha512 as nobleSha512 } from '@noble/hashes/sha2';
import { sha3_256 as nobleSha3_256 } from '@noble/hashes/sha3';
import { hmac as nobleHmac } from '@noble/hashes/hmac';
import { blake2b as nobleBlake2b } from '@noble/hashes/blake2b';

// Re-export shake256 directly from @noble/hashes for XOF functionality
export { shake256 } from '@noble/hashes/sha3';

// Re-export the raw noble hash constructors for use with hmac
export { sha256 as sha256Hash } from '@noble/hashes/sha2';

// ============================================================================
// Helper to combine multiple inputs
// ============================================================================

function combineInputs(data: (Buffer | Uint8Array)[]): Uint8Array {
  const totalLength = data.reduce((sum, d) => sum + d.length, 0);
  const combined = new Uint8Array(totalLength);
  let offset = 0;
  for (const d of data) {
    combined.set(d, offset);
    offset += d.length;
  }
  return combined;
}

// ============================================================================
// Hash functions
// ============================================================================

/**
 * Compute SHA-1 hash of the input data.
 */
export function sha1(...data: (Buffer | Uint8Array)[]): Buffer {
  return Buffer.from(nobleSha1(combineInputs(data)));
}

/**
 * Compute SHA-256 hash of the input data.
 */
export function sha256(...data: (Buffer | Uint8Array)[]): Buffer {
  return Buffer.from(nobleSha256(combineInputs(data)));
}

/**
 * Compute a BLAKE2b hash.
 *
 * Supports the full parameter block (digest length, salt, personalization,
 * key) so it can produce Argon2/HashX-compatible keyed and salted digests as
 * well as plain digests. Used by the hidden-service proof-of-work client
 * (HashX seed expansion + the Equi-X effort hash).
 *
 * @param data   - Message to hash.
 * @param options - Optional BLAKE2b parameters:
 *   - `dkLen` output length in bytes (default 64, the BLAKE2b maximum)
 *   - `salt` 16-byte salt (mixed into the parameter block)
 *   - `personalization` 16-byte personalization string
 *   - `key` up to 64-byte key for keyed hashing
 */
export function blake2b(
  data: Buffer | Uint8Array,
  options?: {
    dkLen?: number;
    salt?: Buffer | Uint8Array;
    personalization?: Buffer | Uint8Array;
    key?: Buffer | Uint8Array;
  }
): Buffer {
  const opts: Record<string, unknown> = {};
  if (options?.dkLen !== undefined) opts.dkLen = options.dkLen;
  if (options?.salt !== undefined) opts.salt = options.salt;
  if (options?.personalization !== undefined) opts.personalization = options.personalization;
  if (options?.key !== undefined) opts.key = options.key;
  return Buffer.from(nobleBlake2b(data, opts));
}

/**
 * Compute SHA-512 hash of the input data.
 */
export function sha512(...data: (Buffer | Uint8Array)[]): Buffer {
  return Buffer.from(nobleSha512(combineInputs(data)));
}

/**
 * Compute SHA3-256 hash of the input data.
 */
export function sha3_256(...data: (Buffer | Uint8Array)[]): Buffer {
  return Buffer.from(nobleSha3_256(combineInputs(data)));
}

/**
 * Compute HMAC using the specified hash function.
 *
 * @param hash - The hash function to use (e.g., sha256Hash)
 * @param key - The HMAC key
 * @param message - The message to authenticate
 * @returns The HMAC result
 */
export const hmac: typeof nobleHmac = nobleHmac;
