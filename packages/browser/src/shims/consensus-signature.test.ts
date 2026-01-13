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

// Import fixture data using Vite's ?raw suffix
import consensusText from '../../../tor/src/fixtures/consensus-microdesc.txt?raw';
import authorityKeysText from '../../../tor/src/fixtures/authority-keys.txt?raw';

// Import the consensus signature verification functions from the tor package
import {
  parseConsensusSignatures,
  getConsensusSignedPortion,
  parseAllKeyCertificates,
  findAuthorityByFingerprint,
  verifyConsensusSignaturesAsync,
  type AuthorityKeyCertificate,
} from '../../../tor/src/consensus-signature.ts';

describe('Browser consensus signature verification', () => {
  describe('Crypto shim basics', () => {
    it('exports required functions', () => {
      expect(typeof publicDecrypt).toBe('function');
      expect(typeof createPublicKey).toBe('function');
      expect(constants.RSA_PKCS1_PADDING).toBe(1);
    });

    it('createHash computes correct SHA-256', () => {
      const testData = 'Hello, World!';
      const hash = crypto.createHash('sha256').update(testData).digest();

      const expectedHex = 'dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f';
      const hashBuffer = hash as Buffer;
      const actualHex = Array.from(new Uint8Array(hashBuffer))
        .map((b) => b.toString(16).padStart(2, '0'))
        .join('');

      expect(actualHex).toBe(expectedHex);
    });

    it('createHash computes correct SHA-1', () => {
      const testData = 'Hello, World!';
      const hash = crypto.createHash('sha1').update(testData).digest();

      const expectedHex = '0a0a9f2a6772942557ab5355d76af442f8f65e01';
      const hashBuffer = hash as Buffer;
      const actualHex = Array.from(new Uint8Array(hashBuffer))
        .map((b) => b.toString(16).padStart(2, '0'))
        .join('');

      expect(actualHex).toBe(expectedHex);
    });
  });

  describe('Fixture data loading', () => {
    it('loads consensus fixture', () => {
      expect(consensusText).toBeDefined();
      expect(consensusText.length).toBeGreaterThan(0);
      expect(consensusText).toContain('network-status-version');
    });

    it('loads authority keys fixture', () => {
      expect(authorityKeysText).toBeDefined();
      expect(authorityKeysText.length).toBeGreaterThan(0);
      expect(authorityKeysText).toContain('dir-key-certificate-version');
    });

    it('parses consensus signatures', () => {
      const signatures = parseConsensusSignatures(consensusText);
      expect(signatures.length).toBeGreaterThanOrEqual(8);

      for (const sig of signatures) {
        expect(sig.algorithm).toBe('sha256');
        expect(sig.identityFingerprint.length).toBe(40);
        expect(sig.signingKeyFingerprint.length).toBe(40);
        expect(sig.signature.length).toBeGreaterThan(0);
      }
    });

    it('parses authority key certificates', () => {
      const certificates = parseAllKeyCertificates(authorityKeysText);
      expect(certificates.length).toBeGreaterThanOrEqual(8);

      for (const cert of certificates) {
        expect(cert.identityFingerprint.length).toBe(40);
        expect(cert.signingKeyFingerprint.length).toBe(40);
        expect(cert.signingKeyPem).toContain('-----BEGIN RSA PUBLIC KEY-----');
      }
    });

    it('certificates match consensus signatures', () => {
      const signatures = parseConsensusSignatures(consensusText);
      const certificates = parseAllKeyCertificates(authorityKeysText);

      let matchCount = 0;
      for (const sig of signatures) {
        const cert = certificates.find(
          (c) =>
            c.identityFingerprint.toUpperCase() === sig.identityFingerprint.toUpperCase() &&
            c.signingKeyFingerprint.toUpperCase() === sig.signingKeyFingerprint.toUpperCase()
        );
        if (cert) {
          matchCount++;
        }
      }

      // All 9 signatures should have matching certificates
      expect(matchCount).toBe(signatures.length);
    });
  });

  describe('Full consensus verification with all authorities', () => {
    let keyCertificates: AuthorityKeyCertificate[];

    // Parse certificates once for all tests
    keyCertificates = parseAllKeyCertificates(authorityKeysText);

    it('verifies all consensus signatures using browser crypto', async () => {
      // Use a fixed time that's within the certificate validity period
      // The certificates have various expiry dates, we use a time when most are valid
      const testTime = new Date('2026-01-13T00:00:00Z').getTime();

      const result = await verifyConsensusSignaturesAsync(consensusText, {
        keyCertificates,
        requiredSignatures: 5,
        now: testTime,
      });

      // Log the results for debugging
      console.log(`Verification result: valid=${result.valid}`);
      console.log(
        `Valid signatures: ${result.validSignatureCount}/${result.requiredSignatureCount} required`
      );

      for (const sig of result.signatures) {
        const status = sig.valid ? '✓' : '✗';
        const name = sig.nickname ?? sig.identityFingerprint.slice(0, 8);
        console.log(`  ${status} ${name}: ${sig.valid ? 'OK' : sig.error}`);
      }

      // The consensus should be valid with at least 5 valid signatures
      expect(result.valid).toBe(true);
      expect(result.validSignatureCount).toBeGreaterThanOrEqual(5);
    });

    it('verifies each authority signature individually', async () => {
      const signatures = parseConsensusSignatures(consensusText);
      const signedPortion = getConsensusSignedPortion(consensusText);

      // Compute expected hash
      const hashObj = crypto.createHash('sha256').update(signedPortion).digest();
      const expectedHash = new Uint8Array(hashObj as Buffer);
      const expectedHashHex = Array.from(expectedHash)
        .map((b) => b.toString(16).padStart(2, '0'))
        .join('');

      console.log(`Signed portion length: ${signedPortion.length}`);
      console.log(`Expected hash: ${expectedHashHex.slice(0, 32)}...`);

      let validCount = 0;

      for (const sig of signatures) {
        const cert = keyCertificates.find(
          (c) =>
            c.identityFingerprint.toUpperCase() === sig.identityFingerprint.toUpperCase() &&
            c.signingKeyFingerprint.toUpperCase() === sig.signingKeyFingerprint.toUpperCase()
        );

        if (!cert) {
          console.log(`No certificate for ${sig.identityFingerprint.slice(0, 8)}`);
          continue;
        }

        const authority = findAuthorityByFingerprint(sig.identityFingerprint);
        const name = authority?.nickname ?? sig.identityFingerprint.slice(0, 8);

        // Verify using browser crypto shim's publicDecrypt
        const key = createPublicKey(cert.signingKeyPem);
        const signatureBytes = new Uint8Array(sig.signature);

        let decryptedHash: Uint8Array | undefined;
        let error: string | undefined;

        try {
          publicDecrypt({ key, padding: constants.RSA_PKCS1_PADDING }, signatureBytes);
        } catch (err: unknown) {
          if (
            err &&
            typeof err === 'object' &&
            'name' in err &&
            err.name === 'AsyncPublicDecryptRequired' &&
            'promise' in err
          ) {
            try {
              decryptedHash = await (err as unknown as { promise: Promise<Uint8Array> }).promise;
            } catch (e) {
              error = (e as Error).message;
            }
          } else {
            error = (err as Error).message;
          }
        }

        if (decryptedHash) {
          const decryptedHex = Array.from(decryptedHash)
            .map((b) => b.toString(16).padStart(2, '0'))
            .join('');

          const isValid = decryptedHex === expectedHashHex;
          console.log(`${name}: ${isValid ? 'VALID' : 'INVALID'}`);

          if (isValid) {
            validCount++;
          }
        } else {
          console.log(`${name}: ERROR - ${error}`);
        }
      }

      // At least 5 signatures should be valid
      expect(validCount).toBeGreaterThanOrEqual(5);
    });

    it('fails verification with corrupted consensus', async () => {
      // Corrupt the consensus by modifying some content
      const corruptedConsensus = consensusText.replace(
        'network-status-version',
        'corrupted-header'
      );

      const testTime = new Date('2026-01-13T00:00:00Z').getTime();

      const result = await verifyConsensusSignaturesAsync(corruptedConsensus, {
        keyCertificates,
        requiredSignatures: 5,
        now: testTime,
      });

      // Corrupted consensus should fail verification
      expect(result.valid).toBe(false);
      expect(result.validSignatureCount).toBe(0);
    });

    it('requires minimum number of valid signatures', async () => {
      const testTime = new Date('2026-01-13T00:00:00Z').getTime();

      // Require more signatures than available
      const result = await verifyConsensusSignaturesAsync(consensusText, {
        keyCertificates,
        requiredSignatures: 100,
        now: testTime,
      });

      expect(result.valid).toBe(false);
      expect(result.requiredSignatureCount).toBe(100);
    });
  });
});
