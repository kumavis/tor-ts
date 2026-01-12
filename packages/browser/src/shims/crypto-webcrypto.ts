/**
 * Browser crypto shim.
 *
 * This shim provides both:
 * 1. `webcrypto` export with `subtle` - for @reclaimprotocol/tls/webcrypto
 * 2. `randomBytes` function - for snowflake package and other Node.js crypto usage
 * 3. `createHash` - synchronous hashing using @noble/hashes (required by tor package)
 * 4. `createPublicKey` / `createVerify` - RSA signature verification for consensus
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
// This is required because the Tor package expects synchronous hash operations
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

// ============================================================================
// RSA Public Key Operations
// ============================================================================

/**
 * Parse a PEM-encoded RSA public key and extract the DER bytes.
 */
function pemToDer(pem: string): Uint8Array {
  const lines = pem.split('\n');
  const base64Lines = lines.filter((line) => !line.startsWith('-----') && line.trim().length > 0);
  const base64 = base64Lines.join('');
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

/**
 * Browser implementation of crypto.createPublicKey.
 * Returns an object that can be used with createVerify.
 */
export function createPublicKey(
  input: string | { key: string; format?: string }
): BrowserPublicKey {
  const pem = typeof input === 'string' ? input : input.key;
  return new BrowserPublicKey(pem);
}

/**
 * Browser RSA public key wrapper.
 * Caches the imported CryptoKey for reuse, keyed by hash algorithm.
 */
class BrowserPublicKey {
  private pem: string;
  private der: Uint8Array;
  // Cache keys per hash algorithm since Web Crypto binds keys to hash at import time
  private cachedKeys: Map<string, CryptoKey> = new Map();
  private importPromises: Map<string, Promise<CryptoKey>> = new Map();

  constructor(pem: string) {
    this.pem = pem;
    this.der = pemToDer(pem);
  }

  /**
   * Import the key for Web Crypto operations.
   * Uses SPKI format for RSA public keys.
   * Keys are cached per hash algorithm since Web Crypto binds keys to hash at import time.
   */
  async importKey(algorithm: RsaHashedImportParams): Promise<CryptoKey> {
    const hashName = typeof algorithm.hash === 'string' ? algorithm.hash : algorithm.hash.name;

    // Check cache first
    const cached = this.cachedKeys.get(hashName);
    if (cached) {
      return cached;
    }

    // Check if import is in progress
    const existingPromise = this.importPromises.get(hashName);
    if (existingPromise) {
      return existingPromise;
    }

    // Try SPKI format first (standard), then PKCS#1 if that fails
    const importPromise = this.tryImportSpki(algorithm).catch(() => this.tryImportPkcs1(algorithm));
    this.importPromises.set(hashName, importPromise);

    const key = await importPromise;
    this.cachedKeys.set(hashName, key);
    return key;
  }

  private async tryImportSpki(algorithm: RsaHashedImportParams): Promise<CryptoKey> {
    // If the PEM says "RSA PUBLIC KEY", it's PKCS#1 format and needs conversion
    if (this.pem.includes('RSA PUBLIC KEY')) {
      // Convert PKCS#1 to SPKI format
      const spkiDer = this.pkcs1ToSpki(this.der);
      return crypto.subtle.importKey('spki', spkiDer as BufferSource, algorithm, true, ['verify']);
    }

    // Otherwise try as SPKI directly
    return crypto.subtle.importKey('spki', this.der as BufferSource, algorithm, true, ['verify']);
  }

  private async tryImportPkcs1(algorithm: RsaHashedImportParams): Promise<CryptoKey> {
    // Convert PKCS#1 to SPKI and import
    const spkiDer = this.pkcs1ToSpki(this.der);
    return crypto.subtle.importKey('spki', spkiDer as BufferSource, algorithm, true, ['verify']);
  }

  /**
   * Convert PKCS#1 RSA public key format to SPKI format.
   * PKCS#1: RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }
   * SPKI: SubjectPublicKeyInfo ::= SEQUENCE { algorithm AlgorithmIdentifier, subjectPublicKey BIT STRING }
   */
  private pkcs1ToSpki(pkcs1Der: Uint8Array): Uint8Array {
    // RSA algorithm identifier (OID 1.2.840.113549.1.1.1 with NULL parameters)
    const rsaAlgorithmId = new Uint8Array([
      0x30,
      0x0d, // SEQUENCE, 13 bytes
      0x06,
      0x09, // OID, 9 bytes
      0x2a,
      0x86,
      0x48,
      0x86,
      0xf7,
      0x0d,
      0x01,
      0x01,
      0x01, // 1.2.840.113549.1.1.1
      0x05,
      0x00, // NULL
    ]);

    // BIT STRING wrapper for the PKCS#1 key
    // First byte is 0x00 (no unused bits)
    const bitStringContent = new Uint8Array(pkcs1Der.length + 1);
    bitStringContent[0] = 0x00;
    bitStringContent.set(pkcs1Der, 1);

    const bitStringHeader = this.encodeDerLength(0x03, bitStringContent.length);

    // Outer SEQUENCE
    const innerLength = rsaAlgorithmId.length + bitStringHeader.length + bitStringContent.length;
    const outerSequence = this.encodeDerLength(0x30, innerLength);

    // Combine all parts
    const result = new Uint8Array(
      outerSequence.length +
        rsaAlgorithmId.length +
        bitStringHeader.length +
        bitStringContent.length
    );
    let offset = 0;
    result.set(outerSequence, offset);
    offset += outerSequence.length;
    result.set(rsaAlgorithmId, offset);
    offset += rsaAlgorithmId.length;
    result.set(bitStringHeader, offset);
    offset += bitStringHeader.length;
    result.set(bitStringContent, offset);

    return result;
  }

  private encodeDerLength(tag: number, length: number): Uint8Array {
    if (length < 128) {
      return new Uint8Array([tag, length]);
    } else if (length < 256) {
      return new Uint8Array([tag, 0x81, length]);
    } else if (length < 65536) {
      return new Uint8Array([tag, 0x82, (length >> 8) & 0xff, length & 0xff]);
    } else {
      return new Uint8Array([
        tag,
        0x83,
        (length >> 16) & 0xff,
        (length >> 8) & 0xff,
        length & 0xff,
      ]);
    }
  }

  /**
   * Export the key in DER format (for fingerprint computation).
   */
  export(options: { type: string; format: string }): Uint8Array {
    if (options.type === 'pkcs1' && options.format === 'der') {
      return this.der;
    }
    throw new Error(`Unsupported export format: ${options.type}/${options.format}`);
  }
}

/**
 * Browser implementation of crypto.createVerify.
 * Returns a verifier that uses Web Crypto for RSA signature verification.
 */
export function createVerify(algorithm: string): BrowserVerifier {
  return new BrowserVerifier(algorithm);
}

/**
 * Browser RSA signature verifier.
 * Collects data and verifies using Web Crypto.
 */
class BrowserVerifier {
  private algorithm: string;
  private data: Uint8Array[] = [];
  private _verifyPromise: Promise<boolean> | null = null;

  constructor(algorithm: string) {
    this.algorithm = algorithm.toUpperCase();
  }

  update(data: string | Uint8Array | Buffer): this {
    if (typeof data === 'string') {
      this.data.push(new TextEncoder().encode(data));
    } else {
      this.data.push(new Uint8Array(data));
    }
    return this;
  }

  /**
   * Verify the signature.
   * In browser, this starts async verification and throws AsyncVerificationRequired.
   * The caller should catch this and await the promise.
   */
  verify(publicKey: BrowserPublicKey, signature: Uint8Array | Buffer): never {
    // Start async verification
    this._verifyPromise = this.verifyAsync(publicKey, signature);

    // Throw to indicate async handling is required
    throw new AsyncVerificationRequired(this._verifyPromise);
  }

  async verifyAsync(publicKey: BrowserPublicKey, signature: Uint8Array | Buffer): Promise<boolean> {
    try {
      // Combine all data
      const totalLength = this.data.reduce((sum, arr) => sum + arr.length, 0);
      const combined = new Uint8Array(totalLength);
      let offset = 0;
      for (const arr of this.data) {
        combined.set(arr, offset);
        offset += arr.length;
      }

      // Map algorithm name to Web Crypto hash
      let hashAlg: string;
      if (this.algorithm === 'SHA256' || this.algorithm === 'RSA-SHA256') {
        hashAlg = 'SHA-256';
      } else if (this.algorithm === 'SHA1' || this.algorithm === 'RSA-SHA1') {
        hashAlg = 'SHA-1';
      } else {
        return false;
      }

      // Import the public key
      const cryptoKey = await publicKey.importKey({
        name: 'RSASSA-PKCS1-v1_5',
        hash: { name: hashAlg },
      });

      // Verify the signature
      const result = await crypto.subtle.verify(
        'RSASSA-PKCS1-v1_5',
        cryptoKey,
        signature as BufferSource,
        combined
      );
      return result;
    } catch {
      return false;
    }
  }
}

/**
 * Custom error to indicate async verification is required.
 * The caller should catch this and await the promise.
 */
export class AsyncVerificationRequired extends Error {
  public readonly promise: Promise<boolean>;

  constructor(promise: Promise<boolean>) {
    super('RSA verification requires async handling in browser');
    this.name = 'AsyncVerificationRequired';
    this.promise = promise;
  }
}

// RSA constants for Node.js crypto compatibility
export const constants = {
  RSA_PKCS1_PADDING: 1,
  RSA_PKCS1_OAEP_PADDING: 4,
};

/**
 * Custom error for async publicDecrypt operations.
 */
export class AsyncPublicDecryptRequired extends Error {
  public readonly promise: Promise<Uint8Array>;

  constructor(promise: Promise<Uint8Array>) {
    super('publicDecrypt requires async handling in browser');
    this.name = 'AsyncPublicDecryptRequired';
    this.promise = promise;
  }
}

/**
 * Browser implementation of crypto.publicDecrypt using raw RSA operations.
 *
 * This is needed for Tor's unprefixed PKCS#1 v1.5 signature verification.
 * Web Crypto doesn't support this directly, so we use a pure JS approach.
 *
 * Throws AsyncPublicDecryptRequired with a promise that resolves to the decrypted bytes.
 */
export function publicDecrypt(
  options: { key: BrowserPublicKey; padding: number },
  data: Uint8Array
): never {
  // Start async RSA operation
  const promise = publicDecryptAsync(options, data);
  throw new AsyncPublicDecryptRequired(promise);
}

/**
 * Async implementation of publicDecrypt using Web Crypto for raw RSA.
 *
 * This performs RSA public key operation and manually verifies PKCS#1 v1.5 padding.
 */
async function publicDecryptAsync(
  options: { key: BrowserPublicKey; padding: number },
  signature: Uint8Array
): Promise<Uint8Array> {
  const { key, padding } = options;

  if (padding !== constants.RSA_PKCS1_PADDING) {
    throw new Error(`Unsupported padding: ${padding}`);
  }

  // Import key for RSA-OAEP (we'll use it for raw modular exponentiation)
  // Actually, Web Crypto can't do raw RSA. We need to parse the key and do it manually.
  // For now, we'll use a simple modular exponentiation approach.

  // Parse the RSA key to get n and e
  const keyData = key.export({ type: 'pkcs1', format: 'der' });
  const { n, e } = parseRsaPublicKey(keyData);

  // Convert signature to BigInt
  const sigBigInt = bytesToBigInt(signature);

  // RSA public key operation: m = s^e mod n
  const decrypted = modPow(sigBigInt, e, n);

  // Convert back to bytes (same length as modulus)
  const modulusBytes = (n.toString(16).length + 1) >> 1;
  const decryptedBytes = bigIntToBytes(decrypted, modulusBytes);

  // Verify PKCS#1 v1.5 padding: 0x00 0x01 [0xFF...] 0x00 [data]
  if (decryptedBytes[0] !== 0x00 || decryptedBytes[1] !== 0x01) {
    throw new Error('Invalid PKCS#1 v1.5 padding');
  }

  // Find the 0x00 separator
  let i = 2;
  while (i < decryptedBytes.length && decryptedBytes[i] === 0xff) {
    i++;
  }

  if (i >= decryptedBytes.length || decryptedBytes[i] !== 0x00) {
    throw new Error('Invalid PKCS#1 v1.5 padding: missing separator');
  }

  // Return the data after the separator
  return decryptedBytes.slice(i + 1);
}

/**
 * Parse an RSA public key from PKCS#1 DER format.
 * Returns { n: BigInt, e: BigInt }
 */
function parseRsaPublicKey(der: Uint8Array): { n: bigint; e: bigint } {
  // PKCS#1 RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }
  // Simple ASN.1 DER parser for this specific case

  let offset = 0;

  // Skip outer SEQUENCE tag and length
  if (der[offset++] !== 0x30) throw new Error('Expected SEQUENCE');
  const seqLen = parseAsn1Length(der, offset);
  offset = seqLen.offset;

  // Parse modulus INTEGER
  if (der[offset++] !== 0x02) throw new Error('Expected INTEGER for modulus');
  const nLen = parseAsn1Length(der, offset);
  offset = nLen.offset;
  const nBytes = der.slice(offset, offset + nLen.length);
  offset += nLen.length;
  const n = bytesToBigInt(nBytes);

  // Parse publicExponent INTEGER
  if (der[offset++] !== 0x02) throw new Error('Expected INTEGER for exponent');
  const eLen = parseAsn1Length(der, offset);
  offset = eLen.offset;
  const eBytes = der.slice(offset, offset + eLen.length);
  const e = bytesToBigInt(eBytes);

  return { n, e };
}

/**
 * Parse ASN.1 DER length encoding.
 */
function parseAsn1Length(data: Uint8Array, offset: number): { length: number; offset: number } {
  const firstByte = data[offset++]!;
  if (firstByte < 0x80) {
    return { length: firstByte, offset };
  }
  const numBytes = firstByte & 0x7f;
  let length = 0;
  for (let i = 0; i < numBytes; i++) {
    length = (length << 8) | data[offset++]!;
  }
  return { length, offset };
}

/**
 * Convert bytes to BigInt (big-endian).
 */
function bytesToBigInt(bytes: Uint8Array): bigint {
  let result = 0n;
  for (const byte of bytes) {
    result = (result << 8n) | BigInt(byte);
  }
  return result;
}

/**
 * Convert BigInt to bytes (big-endian, with specified length).
 */
function bigIntToBytes(num: bigint, length: number): Uint8Array {
  const result = new Uint8Array(length);
  let temp = num;
  for (let i = length - 1; i >= 0; i--) {
    result[i] = Number(temp & 0xffn);
    temp = temp >> 8n;
  }
  return result;
}

/**
 * Modular exponentiation: base^exp mod mod
 */
function modPow(base: bigint, exp: bigint, mod: bigint): bigint {
  let result = 1n;
  base = base % mod;
  while (exp > 0n) {
    if (exp % 2n === 1n) {
      result = (result * base) % mod;
    }
    exp = exp >> 1n;
    base = (base * base) % mod;
  }
  return result;
}

// Default export for: import crypto from 'crypto';
export default {
  webcrypto,
  randomBytes,
  getRandomValues,
  createHash,
  createPublicKey,
  createVerify,
  publicDecrypt,
  constants,
};
