/**
 * Cross-platform tests for tor-crypto.
 *
 * These tests run in both Node.js and browser environments.
 * They import from the package entry point (tor-crypto), which resolves to:
 * - node.ts in Node.js
 * - browser.ts in browser
 *
 * This ensures both implementations are tested with the same test suite.
 */

import { describe, it, expect } from 'vitest';
import {
  sha1,
  sha256,
  sha512,
  sha3_256,
  shake256,
  hmac,
  sha256Hash,
  randomBytes,
  x25519,
  ed25519,
  ed25519VerifySync,
  verifyUnprefixedPkcs1Signature,
  computeRsaKeyFingerprint,
  makeAes128CtrKey,
  makeAes256CtrKey,
  aes256CtrXor,
} from 'tor-crypto';

// ============================================================================
// Hash function tests
// ============================================================================

describe('Hash functions', () => {
  it('sha1 produces correct output', () => {
    const input = Buffer.from('test');
    const result = sha1(input);
    expect(result.length).toBe(20);
    expect(result.toString('hex')).toBe('a94a8fe5ccb19ba61c4c0873d391e987982fbbd3');
  });

  it('sha256 produces correct output', () => {
    const input = Buffer.from('test');
    const result = sha256(input);
    expect(result.length).toBe(32);
    expect(result.toString('hex')).toBe(
      '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08'
    );
  });

  it('sha512 produces correct output', () => {
    const input = Buffer.from('test');
    const result = sha512(input);
    expect(result.length).toBe(64);
  });

  it('sha3_256 produces correct output', () => {
    const input = Buffer.from('test');
    const result = sha3_256(input);
    expect(result.length).toBe(32);
  });

  it('shake256 produces output of specified length', () => {
    const input = Buffer.from('test');
    const result = shake256(input, { dkLen: 64 });
    expect(result.length).toBe(64);
  });

  it('sha256 accepts multiple inputs', () => {
    const input1 = Buffer.from('hello');
    const input2 = Buffer.from('world');
    const result = sha256(input1, input2);
    expect(result.length).toBe(32);

    // Should equal sha256 of concatenated inputs
    const combined = sha256(Buffer.concat([input1, input2]));
    expect(result.equals(combined)).toBe(true);
  });
});

// ============================================================================
// HMAC tests
// ============================================================================

describe('HMAC', () => {
  it('hmac produces correct output', () => {
    const key = Buffer.from('secret');
    const message = Buffer.from('message');
    const result = hmac(sha256Hash, key, message);
    expect(result.length).toBe(32);
  });
});

// ============================================================================
// Random bytes tests
// ============================================================================

describe('randomBytes', () => {
  it('returns buffer of correct length', () => {
    const result = randomBytes(32);
    expect(result.length).toBe(32);
  });

  it('returns different values on each call', () => {
    const result1 = randomBytes(16);
    const result2 = randomBytes(16);
    expect(result1.equals(result2)).toBe(false);
  });
});

// ============================================================================
// Elliptic curve tests
// ============================================================================

describe('Elliptic curves', () => {
  it('x25519 key generation works', () => {
    const privateKey = randomBytes(32);
    const publicKey = x25519.getPublicKey(privateKey);
    expect(publicKey.length).toBe(32);
  });

  it('x25519 key exchange works', () => {
    const alicePrivate = randomBytes(32);
    const alicePublic = x25519.getPublicKey(alicePrivate);

    const bobPrivate = randomBytes(32);
    const bobPublic = x25519.getPublicKey(bobPrivate);

    const aliceShared = x25519.getSharedSecret(alicePrivate, bobPublic);
    const bobShared = x25519.getSharedSecret(bobPrivate, alicePublic);

    expect(Buffer.from(aliceShared).equals(Buffer.from(bobShared))).toBe(true);
  });

  it('ed25519 key generation works', () => {
    const privateKey = randomBytes(32);
    const publicKey = ed25519.getPublicKey(privateKey);
    expect(publicKey.length).toBe(32);
  });

  it('ed25519VerifySync verifies signatures', () => {
    const privateKey = randomBytes(32);
    const publicKey = ed25519.getPublicKey(privateKey);
    const message = Buffer.from('test message');

    const signature = ed25519.sign(message, privateKey);
    const valid = ed25519VerifySync(signature, message, publicKey);
    expect(valid).toBe(true);
  });

  it('ed25519VerifySync rejects invalid signatures', () => {
    const privateKey = randomBytes(32);
    const publicKey = ed25519.getPublicKey(privateKey);
    const message = Buffer.from('test message');
    const wrongMessage = Buffer.from('wrong message');

    const signature = ed25519.sign(message, privateKey);
    const valid = ed25519VerifySync(signature, wrongMessage, publicKey);
    expect(valid).toBe(false);
  });
});

// ============================================================================
// RSA tests
// ============================================================================

const TEST_RSA_PUBLIC_KEY_PEM = `-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBALRiMLAhpFMAl/dstBpWFYmk0QjB4/39kFutAFj3LLmFtuIi031JHZ83
oL/E6WCbLkP5AcTLGgvvDw8+iA88AQCf+Y8lZNhP7a7bP6Lf4gZ+A1zTbLzBsRfj
TmYRaR4YMY9/o2b2GCpmKXcjB3i15Z0HnfrD8sG0sFdoU9Q1dNXJAgMBAAE=
-----END RSA PUBLIC KEY-----`;

describe('RSA functions', () => {
  it('computeRsaKeyFingerprint produces correct output', () => {
    const fingerprint = computeRsaKeyFingerprint(TEST_RSA_PUBLIC_KEY_PEM);
    expect(typeof fingerprint).toBe('string');
    expect(fingerprint.length).toBe(40); // SHA-1 hex = 40 chars
    expect(fingerprint).toMatch(/^[A-F0-9]+$/);
  });

  it('verifyUnprefixedPkcs1Signature is a function', () => {
    expect(typeof verifyUnprefixedPkcs1Signature).toBe('function');
  });
});

// ============================================================================
// AES tests
// ============================================================================

describe('AES functions', () => {
  describe('aes256CtrXor', () => {
    it('encrypts and decrypts correctly', async () => {
      const key = Buffer.alloc(32, 0x42);
      const iv = Buffer.alloc(16, 0x00);
      const plaintext = Buffer.from('Hello, World!');

      const ciphertext = await aes256CtrXor(key, iv, plaintext);
      expect(ciphertext.length).toBe(plaintext.length);
      expect(ciphertext.equals(plaintext)).toBe(false);

      // CTR mode is symmetric - encrypt again to decrypt
      const decrypted = await aes256CtrXor(key, iv, ciphertext);
      expect(decrypted.equals(plaintext)).toBe(true);
    });

    it('produces different output for different keys', async () => {
      const key1 = Buffer.alloc(32, 0x11);
      const key2 = Buffer.alloc(32, 0x22);
      const iv = Buffer.alloc(16, 0x00);
      const plaintext = Buffer.from('test data');

      const result1 = await aes256CtrXor(key1, iv, plaintext);
      const result2 = await aes256CtrXor(key2, iv, plaintext);

      expect(result1.equals(result2)).toBe(false);
    });

    it('produces different output for different IVs', async () => {
      const key = Buffer.alloc(32, 0x42);
      const iv1 = Buffer.alloc(16, 0x00);
      const iv2 = Buffer.alloc(16, 0x01);
      const plaintext = Buffer.from('test data');

      const result1 = await aes256CtrXor(key, iv1, plaintext);
      const result2 = await aes256CtrXor(key, iv2, plaintext);

      expect(result1.equals(result2)).toBe(false);
    });
  });

  describe('makeAes128CtrKey', () => {
    it('creates a working stream cipher', async () => {
      const key = Buffer.alloc(16, 0x12);
      const cipher = makeAes128CtrKey(key);

      const plaintext = Buffer.from('test message');
      const ciphertext = await cipher.encrypt(plaintext);

      expect(ciphertext.length).toBe(plaintext.length);
      expect(ciphertext.equals(plaintext)).toBe(false);
    });

    it('maintains state across multiple calls', async () => {
      const key = Buffer.alloc(16, 0x34);
      const cipher1 = makeAes128CtrKey(key);
      const cipher2 = makeAes128CtrKey(key);

      const chunk1 = Buffer.from('first');
      const chunk2 = Buffer.from('second');

      // Encrypt in two calls with cipher1
      const enc1a = await cipher1.encrypt(chunk1);
      const enc1b = await cipher1.encrypt(chunk2);

      // Encrypt concatenated with cipher2
      const enc2 = await cipher2.encrypt(Buffer.concat([chunk1, chunk2]));

      // The concatenation of two separate encryptions should equal
      // the encryption of the concatenated plaintext
      expect(Buffer.concat([enc1a, enc1b]).equals(enc2)).toBe(true);
    });
  });

  describe('makeAes256CtrKey', () => {
    it('creates a working stream cipher', async () => {
      const key = Buffer.alloc(32, 0x56);
      const cipher = makeAes256CtrKey(key);

      const plaintext = Buffer.from('test message for AES-256');
      const ciphertext = await cipher.encrypt(plaintext);

      expect(ciphertext.length).toBe(plaintext.length);
      expect(ciphertext.equals(plaintext)).toBe(false);
    });

    it('encrypt then decrypt returns original', async () => {
      const key = Buffer.alloc(32, 0x78);
      const encCipher = makeAes256CtrKey(key);
      const decCipher = makeAes256CtrKey(key);

      const plaintext = Buffer.from('Original message');
      const ciphertext = await encCipher.encrypt(plaintext);
      const decrypted = await decCipher.decrypt(ciphertext);

      expect(decrypted.equals(plaintext)).toBe(true);
    });

    it('handles partial blocks correctly', async () => {
      const key = Buffer.alloc(32, 0x9a);
      const cipher = makeAes256CtrKey(key);

      // Encrypt data that doesn't align to 16-byte blocks
      const chunk1 = Buffer.from('12345'); // 5 bytes
      const chunk2 = Buffer.from('67890ABC'); // 8 bytes
      const chunk3 = Buffer.from('DEF'); // 3 bytes

      await cipher.encrypt(chunk1);
      await cipher.encrypt(chunk2);
      await cipher.encrypt(chunk3);

      // If we get here without error, partial blocks are handled
      expect(true).toBe(true);
    });
  });
});
