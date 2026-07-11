/**
 * Node.js crypto implementation.
 *
 * This module provides cryptographic functions using Node.js native crypto.
 * For browser environments, the bundler should swap this for browser.ts via
 * the package.json "exports" conditional.
 */

import * as nodeCrypto from 'node:crypto';

// Re-export all hash functions from the shared hashes module
export * from './hashes.ts';

// Re-export elliptic curve primitives (same implementation for Node.js and browser)
export * from './curves.ts';

// Re-export AES stream ciphers (same implementation for Node.js and browser)
export * from './aes.ts';

// Re-export rend-spec-v3 hidden-service crypto helpers (same impl for both
// platforms; consumed by the `tor` package's hidden-service client + host).
export * from './hs-crypto.ts';

// Re-export the hidden-service proof-of-work primitives (HashX + Equi-X +
// hspow client, proposal 327). Pure computation, identical on both platforms.
export * from './pow/index.ts';

// Import sha1 for use in computeRsaKeyFingerprint
import { sha1 } from './hashes.ts';

// ============================================================================
// Node.js specific: randomBytes
// ============================================================================

/**
 * Generate cryptographically secure random bytes.
 */
export function randomBytes(size: number): Buffer {
  return nodeCrypto.randomBytes(size);
}

// ============================================================================
// Node.js specific: RSA operations
// ============================================================================

/**
 * Verify a Tor "unprefixed PKCS#1 v1.5" signature.
 *
 * Tor uses PKCS#1 v1.5 signatures WITHOUT the DigestInfo ASN.1 prefix.
 * The signature directly embeds the raw hash, not the DigestInfo structure.
 *
 * This function decrypts the signature with the public key and compares
 * the result directly to the provided digest.
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
    const publicKey = nodeCrypto.createPublicKey(publicKeyPem);

    // Use publicDecrypt to "decrypt" the signature and compare with raw digest
    const paddingOptions = {
      key: publicKey,
      padding: nodeCrypto.constants.RSA_PKCS1_PADDING,
    };

    const decrypted = nodeCrypto.publicDecrypt(paddingOptions, signature);
    return Buffer.from(decrypted).equals(digest);
  } catch (err: unknown) {
    // publicDecrypt throws on invalid padding or malformed signatures
    if (
      err instanceof Error &&
      (err.message.includes('padding') ||
        err.message.includes('decrypt') ||
        (err as NodeJS.ErrnoException).code?.includes('RSA'))
    ) {
      return false;
    }
    // Re-throw unexpected errors (e.g., invalid key format)
    throw err;
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
  const keyObject = nodeCrypto.createPublicKey(keyPem);
  const derKey = keyObject.export({ type: 'pkcs1', format: 'der' });
  return sha1(derKey).toString('hex').toUpperCase();
}
