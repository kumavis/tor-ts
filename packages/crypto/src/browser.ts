/**
 * Browser crypto implementation.
 *
 * This module provides cryptographic functions using Web Crypto API and pure JS.
 * It is selected via the package.json "exports" conditional for browser builds.
 */

// Re-export all hash functions from the shared hashes module
export * from './hashes.ts';

// Re-export elliptic curve primitives (same implementation for Node.js and browser)
export * from './curves.ts';

// Import sha1 for use in computeRsaKeyFingerprint
import { sha1 } from './hashes.ts';

// ============================================================================
// Browser specific: randomBytes
// ============================================================================

/**
 * Generate cryptographically secure random bytes.
 */
export function randomBytes(size: number): Buffer {
  const buffer = new Uint8Array(size);
  globalThis.crypto.getRandomValues(buffer);
  return Buffer.from(buffer);
}

// ============================================================================
// Browser specific: RSA operations (pure JS implementation)
// ============================================================================

/**
 * Verify a Tor "unprefixed PKCS#1 v1.5" signature.
 *
 * Tor uses PKCS#1 v1.5 signatures WITHOUT the DigestInfo ASN.1 prefix.
 * The signature directly embeds the raw hash, not the DigestInfo structure.
 *
 * Web Crypto doesn't support this directly, so we use pure JS modular exponentiation.
 *
 * @param digest - The hash that was signed
 * @param signature - The signature bytes
 * @param publicKeyPem - The RSA public key in PEM format
 * @returns true if the signature is valid
 */
export async function verifyUnprefixedPkcs1Signature(
  digest: Buffer,
  signature: Buffer,
  publicKeyPem: string
): Promise<boolean> {
  try {
    // Parse the PEM key to get n and e
    const der = pemToDer(publicKeyPem);
    const { n, e } = parseRsaPublicKey(der, publicKeyPem);

    // RSA public key operation: m = s^e mod n
    const sigBigInt = bytesToBigInt(signature);
    const decrypted = modPow(sigBigInt, e, n);

    // Convert back to bytes (same length as modulus)
    const modulusBytes = (n.toString(16).length + 1) >> 1;
    const decryptedBytes = bigIntToBytes(decrypted, modulusBytes);

    // Verify PKCS#1 v1.5 padding: 0x00 0x01 [0xFF...] 0x00 [data]
    if (decryptedBytes[0] !== 0x00 || decryptedBytes[1] !== 0x01) {
      return false;
    }

    // Find the 0x00 separator
    let i = 2;
    while (i < decryptedBytes.length && decryptedBytes[i] === 0xff) {
      i++;
    }

    if (i >= decryptedBytes.length || decryptedBytes[i] !== 0x00) {
      return false;
    }

    // Compare the data after the separator with the digest
    const extractedDigest = decryptedBytes.slice(i + 1);
    if (extractedDigest.length !== digest.length) {
      return false;
    }

    // Constant-time comparison
    let diff = 0;
    for (let j = 0; j < digest.length; j++) {
      diff |= extractedDigest[j]! ^ digest[j]!;
    }
    return diff === 0;
  } catch {
    return false;
  }
}

/**
 * Compute the SHA-1 fingerprint of an RSA public key.
 *
 * The fingerprint is the SHA-1 hash of the DER-encoded PKCS#1 key.
 *
 * @param keyPem - The RSA public key in PEM format
 * @returns The fingerprint as an uppercase hex string
 */
export function computeRsaKeyFingerprint(keyPem: string): string {
  const der = pemToDer(keyPem);
  // If it's SPKI format, we need to extract the PKCS#1 key
  // For now, assume it's already PKCS#1 (RSA PUBLIC KEY) format
  return sha1(der).toString('hex').toUpperCase();
}

// ============================================================================
// Helper functions for RSA
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
 * Parse an RSA public key from DER format.
 * Handles both PKCS#1 and SPKI formats.
 */
function parseRsaPublicKey(der: Uint8Array, pem: string): { n: bigint; e: bigint } {
  // Check if this is PKCS#1 format (RSA PUBLIC KEY) or SPKI format (PUBLIC KEY)
  if (pem.includes('RSA PUBLIC KEY')) {
    return parsePkcs1RsaPublicKey(der);
  } else {
    // SPKI format - extract the PKCS#1 key from inside
    return parseSpkiRsaPublicKey(der);
  }
}

/**
 * Parse a PKCS#1 RSA public key.
 * PKCS#1: RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }
 */
function parsePkcs1RsaPublicKey(der: Uint8Array): { n: bigint; e: bigint } {
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
 * Parse an SPKI-wrapped RSA public key.
 * SPKI: SubjectPublicKeyInfo ::= SEQUENCE { algorithm AlgorithmIdentifier, subjectPublicKey BIT STRING }
 */
function parseSpkiRsaPublicKey(der: Uint8Array): { n: bigint; e: bigint } {
  let offset = 0;

  // Outer SEQUENCE
  if (der[offset++] !== 0x30) throw new Error('Expected SEQUENCE');
  const outerLen = parseAsn1Length(der, offset);
  offset = outerLen.offset;

  // AlgorithmIdentifier SEQUENCE (skip it)
  if (der[offset++] !== 0x30) throw new Error('Expected AlgorithmIdentifier SEQUENCE');
  const algLen = parseAsn1Length(der, offset);
  offset = algLen.offset + algLen.length;

  // BIT STRING containing the PKCS#1 key
  if (der[offset++] !== 0x03) throw new Error('Expected BIT STRING');
  const bitLen = parseAsn1Length(der, offset);
  offset = bitLen.offset;

  // Skip the unused bits byte (should be 0x00)
  offset++;

  // The rest is the PKCS#1 key
  const pkcs1Der = der.slice(offset, offset + bitLen.length - 1);
  return parsePkcs1RsaPublicKey(pkcs1Der);
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
 * Uses square-and-multiply algorithm.
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
