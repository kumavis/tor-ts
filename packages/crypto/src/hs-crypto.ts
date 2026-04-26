/**
 * Crypto helpers used by the rend-spec-v3 hidden-service client + server
 * implementations in the `tor` package. Kept here in `tor-crypto` so the
 * exact same primitives are available to Node.js and browser consumers
 * (the host needs them server-side, the client needs them everywhere).
 *
 * Everything is a thin Buffer-shaped wrapper over `sha3_256` / `shake256`
 * so it works identically across platforms.
 */

import { sha3_256, shake256 } from './hashes.ts';

/** SHA3-256 of the concatenation of `parts`. */
export function sha3(...parts: Buffer[]): Buffer {
  return Buffer.from(sha3_256(Buffer.concat(parts)));
}

/** SHAKE256-based KDF emitting `length` bytes. */
export function kdfShake256(input: Buffer, length: number): Buffer {
  return Buffer.from(shake256(input, { dkLen: length }));
}

/** Encode a bigint as 8 big-endian bytes (`htonll`). */
export function u64be(n: bigint): Buffer {
  const b = Buffer.alloc(8);
  b.writeBigUInt64BE(n);
  return b;
}

/**
 * SHA3-256 MAC per rend-spec-v3 §0.3:
 * `SHA3_256(htonll(len(k)) || k || m)`.
 */
export function mac(key: Buffer, message: Buffer): Buffer {
  return sha3(u64be(BigInt(key.length)), key, message);
}

/**
 * Domain-separated MAC for descriptor layers (rend-spec-v3 §2.5.1.1):
 * `SHA3_256(htonll(len(macKey)) || macKey || htonll(len(salt)) || salt || encrypted)`.
 */
export function dMac(macKey: Buffer, salt: Buffer, encrypted: Buffer): Buffer {
  return sha3(u64be(BigInt(macKey.length)), macKey, u64be(BigInt(salt.length)), salt, encrypted);
}

/** Decode a little-endian byte buffer as a non-negative bigint. */
export function bytesToBigIntLE(bytes: Uint8Array): bigint {
  let n = 0n;
  for (let i = bytes.length - 1; i >= 0; i--) {
    n = (n << 8n) | BigInt(bytes[i] ?? 0);
  }
  return n;
}

/** Encode a non-negative bigint as `length` little-endian bytes. */
export function bigIntToBytesLE(n: bigint, length: number): Buffer {
  const out = Buffer.alloc(length);
  let temp = n;
  for (let i = 0; i < length; i++) {
    out[i] = Number(temp & 0xffn);
    temp >>= 8n;
  }
  return out;
}

/**
 * Modular inverse `a^-1 mod p` via Fermat's little theorem.
 * `p` must be prime; used for the curve25519→ed25519 conversion.
 */
export function modInverse(a: bigint, p: bigint): bigint {
  let result = 1n;
  let base = ((a % p) + p) % p;
  let exp = p - 2n;
  while (exp > 0n) {
    if (exp & 1n) result = (result * base) % p;
    base = (base * base) % p;
    exp >>= 1n;
  }
  return result;
}

/**
 * Streaming SHA3-256 hash with copy semantics, structurally compatible with
 * the `CopyableHash` interface in the `tor` package's circuit module
 * (`{ update(); copy(); digest(); }`). Browser-compatible — no `node:crypto`.
 *
 * IMPORTANT: `update()` copies its input — relay-cell digest computation
 * sets the integrity field after updating, so the original Buffer would
 * otherwise mutate under the digest.
 */
export class Sha3_256Hash {
  private accumulated: Uint8Array[] = [];

  update(data: Buffer | Uint8Array): this {
    this.accumulated.push(Uint8Array.from(data));
    return this;
  }

  copy(): Sha3_256Hash {
    const cloned = new Sha3_256Hash();
    cloned.accumulated = [...this.accumulated];
    return cloned;
  }

  digest(): Buffer {
    const totalLength = this.accumulated.reduce((sum, arr) => sum + arr.length, 0);
    const combined = new Uint8Array(totalLength);
    let offset = 0;
    for (const arr of this.accumulated) {
      combined.set(arr, offset);
      offset += arr.length;
    }
    return Buffer.from(sha3_256(combined));
  }
}

export function createSha3_256Hash(): Sha3_256Hash {
  return new Sha3_256Hash();
}

/** RFC4648 base32 alphabet, lowercase, unpadded. */
export function base32EncodeLowerNoPad(buf: Buffer): string {
  const alphabet = 'abcdefghijklmnopqrstuvwxyz234567';
  let bits = 0;
  let value = 0;
  let out = '';
  for (let i = 0; i < buf.length; i++) {
    value = (value << 8) | (buf[i] ?? 0);
    bits += 8;
    while (bits >= 5) {
      out += alphabet[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += alphabet[(value << (5 - bits)) & 31];
  return out;
}
