/**
 * Hash functions shared between Node.js and browser implementations.
 *
 * Uses @noble/hashes which works identically in both environments.
 */

import { sha1 as nobleSha1 } from '@noble/hashes/legacy';
import { sha256 as nobleSha256, sha512 as nobleSha512 } from '@noble/hashes/sha2';
import { sha3_256 as nobleSha3_256 } from '@noble/hashes/sha3';
import { hmac as nobleHmac } from '@noble/hashes/hmac';

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
