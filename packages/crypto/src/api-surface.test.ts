/**
 * Test that node.ts and browser.ts export the same API surface.
 *
 * This ensures that the two implementations are interchangeable.
 * This test runs in Node.js only (not browser) because it imports both
 * implementations and compares their outputs.
 */

import { describe, it, expect } from 'vitest';
import * as nodeExports from './node.ts';
import * as browserExports from './browser.ts';

describe('API Surface', () => {
  it('node and browser exports have the same function names', () => {
    const nodeKeys = Object.keys(nodeExports).sort();
    const browserKeys = Object.keys(browserExports).sort();
    expect(nodeKeys).toEqual(browserKeys);
  });

  it('node and browser exports have the same types for each export', () => {
    const nodeKeys = Object.keys(nodeExports) as (keyof typeof nodeExports)[];

    for (const key of nodeKeys) {
      const nodeType = typeof nodeExports[key];
      const browserType = typeof browserExports[key as keyof typeof browserExports];
      expect(nodeType).toBe(browserType);
    }
  });
});

describe('Export types', () => {
  it('sha1 is exported as a function', () => {
    expect(typeof nodeExports.sha1).toBe('function');
    expect(typeof browserExports.sha1).toBe('function');
  });

  it('sha256 is exported as a function', () => {
    expect(typeof nodeExports.sha256).toBe('function');
    expect(typeof browserExports.sha256).toBe('function');
  });

  it('sha512 is exported as a function', () => {
    expect(typeof nodeExports.sha512).toBe('function');
    expect(typeof browserExports.sha512).toBe('function');
  });

  it('sha3_256 is exported as a function', () => {
    expect(typeof nodeExports.sha3_256).toBe('function');
    expect(typeof browserExports.sha3_256).toBe('function');
  });

  it('shake256 is exported as a function', () => {
    expect(typeof nodeExports.shake256).toBe('function');
    expect(typeof browserExports.shake256).toBe('function');
  });

  it('hmac is exported as a function', () => {
    expect(typeof nodeExports.hmac).toBe('function');
    expect(typeof browserExports.hmac).toBe('function');
  });

  it('sha256Hash is exported', () => {
    expect(nodeExports.sha256Hash).toBeTruthy();
    expect(browserExports.sha256Hash).toBeTruthy();
  });

  it('randomBytes is exported as a function', () => {
    expect(typeof nodeExports.randomBytes).toBe('function');
    expect(typeof browserExports.randomBytes).toBe('function');
  });

  it('verifyUnprefixedPkcs1Signature is exported as a function', () => {
    expect(typeof nodeExports.verifyUnprefixedPkcs1Signature).toBe('function');
    expect(typeof browserExports.verifyUnprefixedPkcs1Signature).toBe('function');
  });

  it('computeRsaKeyFingerprint is exported as a function', () => {
    expect(typeof nodeExports.computeRsaKeyFingerprint).toBe('function');
    expect(typeof browserExports.computeRsaKeyFingerprint).toBe('function');
  });

  it('x25519 is exported', () => {
    expect(nodeExports.x25519).toBeTruthy();
    expect(browserExports.x25519).toBeTruthy();
  });

  it('ed25519 is exported', () => {
    expect(nodeExports.ed25519).toBeTruthy();
    expect(browserExports.ed25519).toBeTruthy();
  });

  it('ed25519VerifySync is exported as a function', () => {
    expect(typeof nodeExports.ed25519VerifySync).toBe('function');
    expect(typeof browserExports.ed25519VerifySync).toBe('function');
  });

  it('makeAes128CtrKey is exported as a function', () => {
    expect(typeof nodeExports.makeAes128CtrKey).toBe('function');
    expect(typeof browserExports.makeAes128CtrKey).toBe('function');
  });

  it('makeAes256CtrKey is exported as a function', () => {
    expect(typeof nodeExports.makeAes256CtrKey).toBe('function');
    expect(typeof browserExports.makeAes256CtrKey).toBe('function');
  });

  it('aes256CtrXor is exported as a function', () => {
    expect(typeof nodeExports.aes256CtrXor).toBe('function');
    expect(typeof browserExports.aes256CtrXor).toBe('function');
  });
});

describe('Hash function outputs match', () => {
  it('sha1 produces same output in both implementations', () => {
    const input = Buffer.from('test data');
    const nodeResult = nodeExports.sha1(input);
    const browserResult = browserExports.sha1(input);
    expect(nodeResult.equals(browserResult)).toBe(true);
  });

  it('sha256 produces same output in both implementations', () => {
    const input = Buffer.from('test data');
    const nodeResult = nodeExports.sha256(input);
    const browserResult = browserExports.sha256(input);
    expect(nodeResult.equals(browserResult)).toBe(true);
  });

  it('sha512 produces same output in both implementations', () => {
    const input = Buffer.from('test data');
    const nodeResult = nodeExports.sha512(input);
    const browserResult = browserExports.sha512(input);
    expect(nodeResult.equals(browserResult)).toBe(true);
  });

  it('sha3_256 produces same output in both implementations', () => {
    const input = Buffer.from('test data');
    const nodeResult = nodeExports.sha3_256(input);
    const browserResult = browserExports.sha3_256(input);
    expect(nodeResult.equals(browserResult)).toBe(true);
  });

  it('shake256 produces same output in both implementations', () => {
    const input = Buffer.from('test data');
    const outputLength = 32;

    const nodeResult = nodeExports.shake256(input, { dkLen: outputLength });
    const browserResult = browserExports.shake256(input, { dkLen: outputLength });

    expect(nodeResult).toEqual(browserResult);
  });

  it('hmac produces same output in both implementations', () => {
    const key = Buffer.from('secret key');
    const message = Buffer.from('test message');

    const nodeResult = nodeExports.hmac(nodeExports.sha256Hash, key, message);
    const browserResult = browserExports.hmac(browserExports.sha256Hash, key, message);

    expect(nodeResult).toEqual(browserResult);
  });

  it('sha256 with multiple inputs produces same output', () => {
    const input1 = Buffer.from('hello');
    const input2 = Buffer.from('world');

    const nodeResult = nodeExports.sha256(input1, input2);
    const browserResult = browserExports.sha256(input1, input2);

    expect(nodeResult.equals(browserResult)).toBe(true);
  });
});

describe('randomBytes', () => {
  it('returns correct length in both implementations', () => {
    const size = 32;
    const nodeResult = nodeExports.randomBytes(size);
    const browserResult = browserExports.randomBytes(size);

    expect(nodeResult.length).toBe(size);
    expect(browserResult.length).toBe(size);
  });
});

describe('RSA functions', () => {
  const TEST_RSA_PUBLIC_KEY_PEM = `-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBALRiMLAhpFMAl/dstBpWFYmk0QjB4/39kFutAFj3LLmFtuIi031JHZ83
oL/E6WCbLkP5AcTLGgvvDw8+iA88AQCf+Y8lZNhP7a7bP6Lf4gZ+A1zTbLzBsRfj
TmYRaR4YMY9/o2b2GCpmKXcjB3i15Z0HnfrD8sG0sFdoU9Q1dNXJAgMBAAE=
-----END RSA PUBLIC KEY-----`;

  it('computeRsaKeyFingerprint produces same output in both implementations', () => {
    const nodeResult = nodeExports.computeRsaKeyFingerprint(TEST_RSA_PUBLIC_KEY_PEM);
    const browserResult = browserExports.computeRsaKeyFingerprint(TEST_RSA_PUBLIC_KEY_PEM);
    expect(nodeResult).toBe(browserResult);
  });
});

describe('Elliptic curves', () => {
  it('x25519 key generation works in both implementations', () => {
    const privateKey = nodeExports.randomBytes(32);
    const nodePublic = nodeExports.x25519.getPublicKey(privateKey);
    const browserPublic = browserExports.x25519.getPublicKey(privateKey);
    expect(nodePublic).toEqual(browserPublic);
  });
});

describe('AES cross-implementation', () => {
  it('aes256CtrXor encrypts and decrypts correctly', async () => {
    const key = Buffer.alloc(32, 0x42);
    const iv = Buffer.alloc(16, 0x00);
    const plaintext = Buffer.from('Hello, World! This is a test message.');

    // Encrypt with node implementation
    const ciphertext = await nodeExports.aes256CtrXor(key, iv, plaintext);

    // Decrypt with browser implementation (CTR mode is symmetric)
    const decrypted = await browserExports.aes256CtrXor(key, iv, ciphertext);

    expect(plaintext.equals(decrypted)).toBe(true);
  });

  it('aes256CtrXor produces same output in both implementations', async () => {
    const key = Buffer.alloc(32, 0xab);
    const iv = Buffer.alloc(16, 0xcd);
    const data = Buffer.from('Test data for AES encryption');

    const nodeResult = await nodeExports.aes256CtrXor(key, iv, data);
    const browserResult = await browserExports.aes256CtrXor(key, iv, data);

    expect(nodeResult.equals(browserResult)).toBe(true);
  });

  it('makeAes128CtrKey stream cipher works correctly', async () => {
    const key = Buffer.alloc(16, 0x12);

    const nodeCipher = nodeExports.makeAes128CtrKey(key);
    const browserCipher = browserExports.makeAes128CtrKey(key);

    const plaintext1 = Buffer.from('First chunk');
    const plaintext2 = Buffer.from('Second chunk');

    const nodeCt1 = await nodeCipher.encrypt(plaintext1);
    const browserCt1 = await browserCipher.encrypt(plaintext1);

    expect(nodeCt1.equals(browserCt1)).toBe(true);

    const nodeCt2 = await nodeCipher.encrypt(plaintext2);
    const browserCt2 = await browserCipher.encrypt(plaintext2);

    expect(nodeCt2.equals(browserCt2)).toBe(true);
  });

  it('makeAes256CtrKey stream cipher works correctly', async () => {
    const key = Buffer.alloc(32, 0x34);

    const nodeCipher = nodeExports.makeAes256CtrKey(key);
    const browserCipher = browserExports.makeAes256CtrKey(key);

    const plaintext = Buffer.from('Test message for AES-256-CTR stream cipher');

    const nodeEncrypted = await nodeCipher.encrypt(plaintext);
    const browserEncrypted = await browserCipher.encrypt(plaintext);

    expect(nodeEncrypted.equals(browserEncrypted)).toBe(true);
  });

  it('makeAes256CtrKey encrypt then decrypt returns original', async () => {
    const key = Buffer.alloc(32, 0x56);
    const plaintext = Buffer.from('Original message to encrypt and decrypt');

    const encryptCipher = nodeExports.makeAes256CtrKey(key);
    const decryptCipher = nodeExports.makeAes256CtrKey(key);

    const ciphertext = await encryptCipher.encrypt(plaintext);
    const decrypted = await decryptCipher.decrypt(ciphertext);

    expect(plaintext.equals(decrypted)).toBe(true);
  });
});
