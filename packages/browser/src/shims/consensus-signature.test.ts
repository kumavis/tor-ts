/**
 * Browser unit tests for consensus signature verification.
 *
 * These tests verify that the browser crypto shim correctly implements
 * RSA signature verification for Tor consensus documents.
 *
 * Tor uses "unprefixed" PKCS#1 v1.5 signatures where the signature
 * directly contains the raw hash (without DigestInfo ASN.1 wrapper).
 * This is different from standard RSASSA-PKCS1-v1_5 and requires
 * manual RSA operations (modular exponentiation).
 */

import { describe, it, expect } from 'vitest';
import crypto, { publicDecrypt, constants, createPublicKey } from './crypto-webcrypto.ts';

// Pre-computed test data from a real Tor consensus document
// This is the SHA-256 hash of the signed portion of the consensus
const EXPECTED_HASH_HEX = 'b012bbf546016eb68d094558e3d668f3dd72360590bcf87e4aaacdf5b60ca430';

// The signing key PEM for directory authority "dannenberg"
// (identity fingerprint: 0232AF901C31A04EE9848595AF9BB7620D4C5B2E)
const SIGNING_KEY_PEM = `-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEAoUlOIijVazsyQ8Ou44IBtJUQigiosmyzXEawNiegdA5UyC5YLRV3
9eKkw0A0AzXOxpmpUIw2woJFQaXjP/gNroRtpXUDX7RR6JEEvK34DnH1eI5LUX9E
pyjEI5tr2NeB3EOUN4pcFcbmG4EPihTS9vOvdgSWNgwAQ12AotBRjezUSefCMhSs
vauvo5UcRuN/8AQtWgt4RkB9AlvP9jvxzR2G/dZ/C8z6FvwrLiCmpsox8Rc6xF39
BZahQb4o67/jUiudFMqzpe7n2IUePWs8lRxnWaA60vyw1X9vmJuwZofj3PuELSk5
aCtI5/nzQqXtEakGj5nenxghEZuuFoZMXwIDAQAB
-----END RSA PUBLIC KEY-----`;

// The signature from dannenberg on the consensus
const SIGNATURE_BASE64 =
  'ZFUi6N1XpvMWqUXfRG1xWHVGaSyI4Ya1S2X4YFj3KnLWKkWc3LfRRCpeYKY/hsWj' +
  'iAVE0JqgRQBrIdrpa1zXT58Ur8byZTzdUsJ39mFeaT3ZYnpA6jAVAIk3vbpUeum2' +
  '2qsVLXf45SVDF924CTXXffFP0mlhAFJSJc8SnIpY0f5ZS+ezuLrTjiGnkH/jCv20' +
  '4Z+QA+GJNi/LmYDuGW23oK4wllKWrSJgm41T2RzoAFkUhuX7EavIL3rEKJBjMJQ2' +
  'Rvm24ZCD4NulntUN9HjpfN7oETUuLZtfUiUAWfnkjilBtStzo9NcgJhZFkFfMxsj' +
  'AAm9DWALJEgYjgMq9qSnng==';

describe('Browser consensus signature verification', () => {
  it('crypto shim exports required functions', () => {
    expect(typeof publicDecrypt).toBe('function');
    expect(typeof createPublicKey).toBe('function');
    expect(constants.RSA_PKCS1_PADDING).toBe(1);
  });

  it('createPublicKey creates key from PEM', () => {
    const key = createPublicKey(SIGNING_KEY_PEM);
    expect(key).toBeDefined();
    // Verify export works
    const der = key.export({ type: 'pkcs1', format: 'der' });
    expect(der).toBeInstanceOf(Uint8Array);
    expect(der.length).toBeGreaterThan(0);
  });

  it('publicDecrypt throws AsyncPublicDecryptRequired', async () => {
    const key = createPublicKey(SIGNING_KEY_PEM);
    const signature = Uint8Array.from(atob(SIGNATURE_BASE64), (c) => c.charCodeAt(0));

    let asyncError: unknown = null;

    try {
      publicDecrypt({ key, padding: constants.RSA_PKCS1_PADDING }, signature);
    } catch (err) {
      asyncError = err;
    }

    // In browser, publicDecrypt throws AsyncPublicDecryptRequired
    expect(asyncError).not.toBeNull();
    expect((asyncError as Error).name).toBe('AsyncPublicDecryptRequired');
    expect((asyncError as { promise: Promise<Uint8Array> }).promise).toBeInstanceOf(Promise);
  });

  it('publicDecrypt recovers correct hash from signature', async () => {
    const key = createPublicKey(SIGNING_KEY_PEM);
    const signature = Uint8Array.from(atob(SIGNATURE_BASE64), (c) => c.charCodeAt(0));

    let decryptedHash: Uint8Array | undefined;

    try {
      publicDecrypt({ key, padding: constants.RSA_PKCS1_PADDING }, signature);
    } catch (err: unknown) {
      if (
        err &&
        typeof err === 'object' &&
        'name' in err &&
        err.name === 'AsyncPublicDecryptRequired'
      ) {
        // Await the async result
        decryptedHash = await (err as { promise: Promise<Uint8Array> }).promise;
      } else {
        throw err;
      }
    }

    expect(decryptedHash).toBeDefined();
    expect(decryptedHash!.length).toBe(32); // SHA-256 is 32 bytes

    // Convert to hex and compare
    const decryptedHex = Array.from(decryptedHash!)
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('');

    expect(decryptedHex).toBe(EXPECTED_HASH_HEX);
  });

  it('publicDecrypt fails gracefully with wrong signature', async () => {
    const key = createPublicKey(SIGNING_KEY_PEM);
    // Corrupt the signature
    const corruptedSig = Uint8Array.from(atob(SIGNATURE_BASE64), (c) => c.charCodeAt(0));
    corruptedSig[0] ^= 0xff;

    let error: Error | undefined;

    try {
      publicDecrypt({ key, padding: constants.RSA_PKCS1_PADDING }, corruptedSig);
    } catch (err: unknown) {
      if (
        err &&
        typeof err === 'object' &&
        'name' in err &&
        err.name === 'AsyncPublicDecryptRequired'
      ) {
        try {
          await (err as { promise: Promise<Uint8Array> }).promise;
        } catch (e) {
          error = e as Error;
        }
      }
    }

    // Should fail with padding error
    expect(error).toBeDefined();
  });

  it('createHash computes correct SHA-256', () => {
    // Test that our hash function works correctly
    const testData = 'Hello, World!';
    const hash = crypto.createHash('sha256').update(testData).digest();

    // Known SHA-256 of "Hello, World!"
    const expectedHex = 'dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f';
    const actualHex = Array.from(new Uint8Array(hash))
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('');

    expect(actualHex).toBe(expectedHex);
  });

  it('createHash computes correct SHA-1', () => {
    const testData = 'Hello, World!';
    const hash = crypto.createHash('sha1').update(testData).digest();

    // Known SHA-1 of "Hello, World!"
    const expectedHex = '0a0a9f2a6772942557ab5355d76af442f8f65e01';
    const actualHex = Array.from(new Uint8Array(hash))
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('');

    expect(actualHex).toBe(expectedHex);
  });
});

describe('Tor consensus signature verification integration', () => {
  /**
   * This test simulates the full consensus signature verification flow
   * as it would happen in the browser, using pre-computed digest.
   */
  it('verifies signature with pre-computed digest', async () => {
    const key = createPublicKey(SIGNING_KEY_PEM);
    const signature = Uint8Array.from(atob(SIGNATURE_BASE64), (c) => c.charCodeAt(0));

    // The expected digest (pre-computed hash of consensus signed portion)
    const expectedDigest = Uint8Array.from(
      EXPECTED_HASH_HEX.match(/.{2}/g)!.map((byte) => parseInt(byte, 16))
    );

    let decryptedHash: Uint8Array | undefined;

    try {
      publicDecrypt({ key, padding: constants.RSA_PKCS1_PADDING }, signature);
    } catch (err: unknown) {
      if (
        err &&
        typeof err === 'object' &&
        'name' in err &&
        err.name === 'AsyncPublicDecryptRequired'
      ) {
        decryptedHash = await (err as { promise: Promise<Uint8Array> }).promise;
      } else {
        throw err;
      }
    }

    // Verify the decrypted hash matches the expected digest
    expect(decryptedHash).toBeDefined();
    expect(decryptedHash!.length).toBe(expectedDigest.length);

    // Compare byte by byte
    for (let i = 0; i < expectedDigest.length; i++) {
      expect(decryptedHash![i]).toBe(expectedDigest[i]);
    }
  });

  /**
   * Additional test with a different authority to ensure the verification
   * is not specific to one key/signature combination.
   */
  it('verifies signature from different authority (longclaw)', async () => {
    // Signing key for longclaw (23D15D965BC35114467363C165C4F724B64B4F66)
    const longclawKeyPem = `-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEAq/DVJAbGZivOFEtzRaeGD4VxAO6dVIkTeS0YTNSUw0pttlAcFgFU
+owfKTg/eH8ecI7ugABiX0cosuI1S8Za7qLKnqnuQUbLSUrIRqyx+l6CnYiW4MrG
oac97wOg9kQ8b3UEbeGgfl4qmL6OfRxdXlLmafM6p0q65m9lJOr3TATSuIUqga1z
J1GdXXzRIO19QnY6QtW9TvMoo0BgjqfAyHAs9focGO7mru4qr21ySkoZyfIk2/Jb
ijIc0evuvD5kmJ/XukhYYzW7mDdT2J6r97tOK8xLAX7l8eFm4N73MCscq8DOAVO0
4ssMBDf5sKlQ0JkOz6xoJ+4ayuSDlwsXYQIDAQAB
-----END RSA PUBLIC KEY-----`;

    // Signature from longclaw on the same consensus
    const longclawSigBase64 =
      'TofqXjLMRIHkeALfypvT4SjDeMAQtcSVAvMonE2i8RlReg/LcddRPLNFGgAKhUwF' +
      'xHk8jT8MnkwRRgg3FAy3g76Org8HbctDZ2Lo2BTZOWGbPGbKwywai4V4Ti4zT4qH' +
      'sTddo5JHWO0BzqiariL6cT3puu9+ffoTxYoL1rRyWy6VN+GBmQGuNb2y1v3PGTSQ' +
      'pzrhYimjroUUboDxZIP7B1J8FNHfSzjfuKDNc+Mi8fQhvs/Yf27iOeiUdSxqZRtg' +
      'nRGqHIUNZnIu4vhuIVlsa9LcubijEc21qE7LNgY/KfhRyEU40U9VYFJbIFpgFYoQ' +
      'Sb4zO4080iq6fsMmPn9/Bw==';

    const key = createPublicKey(longclawKeyPem);
    const signature = Uint8Array.from(atob(longclawSigBase64), (c) => c.charCodeAt(0));

    let decryptedHash: Uint8Array | undefined;

    try {
      publicDecrypt({ key, padding: constants.RSA_PKCS1_PADDING }, signature);
    } catch (err: unknown) {
      if (
        err &&
        typeof err === 'object' &&
        'name' in err &&
        err.name === 'AsyncPublicDecryptRequired'
      ) {
        decryptedHash = await (err as { promise: Promise<Uint8Array> }).promise;
      } else {
        throw err;
      }
    }

    expect(decryptedHash).toBeDefined();
    expect(decryptedHash!.length).toBe(32);

    // Should produce the same hash (both signatures are for the same consensus)
    const decryptedHex = Array.from(decryptedHash!)
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('');

    expect(decryptedHex).toBe(EXPECTED_HASH_HEX);
  });
});
