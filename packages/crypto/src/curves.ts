/**
 * Elliptic curve cryptography exports.
 *
 * Re-exports from @noble/curves and @noble/ed25519 for use by tor package.
 * These work identically in Node.js and browser environments.
 */

import * as ed from '@noble/ed25519';
import { sha512 } from './hashes.ts';

// X25519 key exchange and Ed25519 signatures from @noble/curves
export { x25519, ed25519 } from '@noble/curves/ed25519';

// Configure @noble/ed25519 for synchronous operation
ed.etc.sha512Sync = (...m) => sha512(ed.etc.concatBytes(...m));

/**
 * Synchronously verify an Ed25519 signature.
 *
 * This is pre-configured with sha512Sync for synchronous operation.
 *
 * @param signature - The 64-byte Ed25519 signature
 * @param message - The message that was signed
 * @param publicKey - The 32-byte Ed25519 public key
 * @returns true if the signature is valid
 */
export function ed25519VerifySync(
  signature: Uint8Array,
  message: Uint8Array,
  publicKey: Uint8Array
): boolean {
  return ed.verify(signature, message, publicKey);
}
