/**
 * Browser crypto shim for Node.js dependencies.
 *
 * This shim provides compatibility for external packages that import from 'node:crypto'.
 * It does NOT provide Tor-specific crypto operations - those are in packages/tor/src/crypto/browser.ts.
 *
 * Exports:
 * 1. `webcrypto` with `subtle` - for @reclaimprotocol/tls/webcrypto
 * 2. `randomBytes` - for snowflake package and other Node.js crypto usage
 * 3. `getRandomValues` - for direct crypto usage
 * 4. `createHash` - synchronous hashing using @noble/hashes
 *
 * This allows code that imports from 'crypto' to work in browsers.
 */

import { sha1 as nobleSha1 } from '@noble/hashes/sha1';
import { sha256 as nobleSha256 } from '@noble/hashes/sha256';
import { sha384 as nobleSha384, sha512 as nobleSha512 } from '@noble/hashes/sha512';

// Export browser's native crypto as webcrypto for Node.js compatibility
// This matches: import { webcrypto } from 'crypto';
export const webcrypto = globalThis.crypto;

// randomBytes function for Node.js compatibility
// This matches: import { randomBytes } from 'crypto';
export function randomBytes(size: number): Buffer {
  const buffer = new Uint8Array(size);
  globalThis.crypto.getRandomValues(buffer);
  return Buffer.from(buffer);
}

// getRandomValues for direct crypto usage
export function getRandomValues<T extends ArrayBufferView>(array: T): T {
  return globalThis.crypto.getRandomValues(array);
}

// Map algorithm names to @noble/hashes functions
type HashFunction = (data: Uint8Array) => Uint8Array;
const HASH_FUNCTIONS: Record<string, HashFunction> = {
  sha1: nobleSha1,
  'sha-1': nobleSha1,
  sha256: nobleSha256,
  'sha-256': nobleSha256,
  sha384: nobleSha384,
  'sha-384': nobleSha384,
  sha512: nobleSha512,
  'sha-512': nobleSha512,
};

// createHash - synchronous implementation using @noble/hashes
// This is required for dependencies that expect synchronous hash operations
export function createHash(algorithm: string) {
  const data: Uint8Array[] = [];
  const hashFn = HASH_FUNCTIONS[algorithm.toLowerCase()];
  if (!hashFn) {
    throw new Error(`Unsupported hash algorithm: ${algorithm}`);
  }

  return {
    update(chunk: Uint8Array | Buffer | string) {
      if (typeof chunk === 'string') {
        data.push(new TextEncoder().encode(chunk));
      } else if (chunk instanceof Uint8Array) {
        data.push(chunk);
      } else {
        // Buffer case
        data.push(new Uint8Array(chunk));
      }
      return this;
    },
    digest(encoding?: string): Buffer | string {
      const totalLength = data.reduce((sum, arr) => sum + arr.length, 0);
      const combined = new Uint8Array(totalLength);
      let offset = 0;
      for (const arr of data) {
        combined.set(arr, offset);
        offset += arr.length;
      }

      const result = hashFn(combined);

      if (encoding === 'hex') {
        return Array.from(result)
          .map((b) => b.toString(16).padStart(2, '0'))
          .join('');
      }
      return Buffer.from(result);
    },
  };
}

// Default export for: import crypto from 'crypto';
export default {
  webcrypto,
  randomBytes,
  getRandomValues,
  createHash,
};
