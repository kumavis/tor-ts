/**
 * Test consensus signature verification using different crypto implementations.
 *
 * This test uses fixture data (downloaded consensus and authority certificates)
 * to verify that both Node.js crypto and the browser shim work correctly.
 */

import test from 'ava';
import * as nodeCrypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  parseConsensusSignatures,
  getConsensusSignedPortion,
  parseAllKeyCertificates,
  findAuthorityByFingerprint,
  verifySignatureWithData,
  verifyConsensusSignatures,
  verifyConsensusSignaturesAsync,
} from './consensus-signature.ts';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// Load fixture data
const fixtureDir = path.join(__dirname, 'fixtures');
const consensusPath = path.join(fixtureDir, 'consensus-microdesc.txt');
const authKeysPath = path.join(fixtureDir, 'authority-keys.txt');

const hasFixtures = fs.existsSync(consensusPath) && fs.existsSync(authKeysPath);

// Skip reading if files don't exist
const consensusText = hasFixtures ? fs.readFileSync(consensusPath, 'utf-8') : '';
const authKeysText = hasFixtures ? fs.readFileSync(authKeysPath, 'utf-8') : '';

// Parse authority certificates
const keyCertificates = hasFixtures ? parseAllKeyCertificates(authKeysText) : [];

test('fixtures are available', (t) => {
  if (!hasFixtures) {
    t.fail(
      'Missing fixture files. Run: curl to download consensus and authority keys to packages/tor/src/fixtures/'
    );
  }
  t.true(consensusText.length > 0, 'Consensus text is not empty');
  t.true(authKeysText.length > 0, 'Authority keys text is not empty');
  t.true(keyCertificates.length > 0, `Parsed ${keyCertificates.length} key certificates`);
});

test('parseConsensusSignatures - parses fixture consensus', (t) => {
  if (!hasFixtures) {
    t.pass('Skipping: no fixtures');
    return;
  }

  const signatures = parseConsensusSignatures(consensusText);
  t.true(signatures.length >= 8, `Found ${signatures.length} signatures`);

  // All should use sha256
  for (const sig of signatures) {
    t.is(sig.algorithm, 'sha256');
    t.is(sig.identityFingerprint.length, 40);
    t.is(sig.signingKeyFingerprint.length, 40);
    t.true(sig.signature.length > 0);
  }
});

test('getConsensusSignedPortion - extracts correct signed portion', (t) => {
  if (!hasFixtures) {
    t.pass('Skipping: no fixtures');
    return;
  }

  const signedPortion = getConsensusSignedPortion(consensusText);
  t.true(signedPortion.length > 0, 'Signed portion extracted');
  t.true(
    signedPortion.startsWith('@type network-status-microdesc-consensus-3') ||
      signedPortion.startsWith('network-status-version'),
    'Starts with network-status'
  );
  t.true(signedPortion.endsWith('directory-signature '), 'Ends with directory-signature + space');
});

test('keyCertificates match signatures', (t) => {
  if (!hasFixtures) {
    t.pass('Skipping: no fixtures');
    return;
  }

  const signatures = parseConsensusSignatures(consensusText);

  let matchCount = 0;
  for (const sig of signatures) {
    const cert = keyCertificates.find(
      (c) =>
        c.identityFingerprint.toUpperCase() === sig.identityFingerprint.toUpperCase() &&
        c.signingKeyFingerprint.toUpperCase() === sig.signingKeyFingerprint.toUpperCase()
    );
    if (cert) {
      matchCount++;
      t.log(
        `Match: ${sig.identityFingerprint.slice(0, 8)} with signing key ${sig.signingKeyFingerprint.slice(0, 8)}`
      );
    } else {
      const authority = findAuthorityByFingerprint(sig.identityFingerprint);
      t.log(`No cert for: ${authority?.nickname ?? sig.identityFingerprint.slice(0, 8)}`);
    }
  }

  t.true(matchCount >= 5, `At least 5 signatures should have matching certs (got ${matchCount})`);
});

test('Node.js crypto - verifySignatureWithData works', (t) => {
  if (!hasFixtures) {
    t.pass('Skipping: no fixtures');
    return;
  }

  const signatures = parseConsensusSignatures(consensusText);
  const signedPortion = getConsensusSignedPortion(consensusText);

  let validCount = 0;
  for (const sig of signatures) {
    const cert = keyCertificates.find(
      (c) =>
        c.identityFingerprint.toUpperCase() === sig.identityFingerprint.toUpperCase() &&
        c.signingKeyFingerprint.toUpperCase() === sig.signingKeyFingerprint.toUpperCase()
    );
    if (!cert) continue;

    const valid = verifySignatureWithData(
      signedPortion,
      sig.signature,
      cert.signingKeyPem,
      sig.algorithm
    );
    const authority = findAuthorityByFingerprint(sig.identityFingerprint);
    t.log(
      `${authority?.nickname ?? sig.identityFingerprint.slice(0, 8)}: ${valid ? 'VALID' : 'INVALID'}`
    );
    if (valid) validCount++;
  }

  t.true(validCount >= 5, `At least 5 valid signatures (got ${validCount})`);
});

test('Node.js crypto - verifyConsensusSignatures works', (t) => {
  if (!hasFixtures) {
    t.pass('Skipping: no fixtures');
    return;
  }

  const result = verifyConsensusSignatures(consensusText, {
    keyCertificates,
    requiredSignatures: 5,
  });

  t.log(
    `Valid: ${result.valid}, count: ${result.validSignatureCount}/${result.requiredSignatureCount}`
  );
  for (const sig of result.signatures) {
    t.log(
      `  ${sig.nickname ?? sig.identityFingerprint.slice(0, 8)}: ${sig.valid ? 'OK' : sig.error}`
    );
  }

  t.true(result.valid, 'Consensus should be valid');
  t.true(
    result.validSignatureCount >= 5,
    `At least 5 valid signatures (got ${result.validSignatureCount})`
  );
});

test('Node.js crypto - verifyConsensusSignaturesAsync works', async (t) => {
  if (!hasFixtures) {
    t.pass('Skipping: no fixtures');
    return;
  }

  const result = await verifyConsensusSignaturesAsync(consensusText, {
    keyCertificates,
    requiredSignatures: 5,
  });

  t.log(
    `Valid: ${result.valid}, count: ${result.validSignatureCount}/${result.requiredSignatureCount}`
  );

  t.true(result.valid, 'Consensus should be valid');
  t.true(
    result.validSignatureCount >= 5,
    `At least 5 valid signatures (got ${result.validSignatureCount})`
  );
});

// ============================================================================
// Direct crypto.subtle tests to isolate the RSA verification
// ============================================================================

/**
 * NOTE: Standard crypto.subtle.verify uses RSASSA-PKCS1-v1_5 with DigestInfo,
 * but Tor uses unprefixed PKCS#1 v1.5 (raw hash without DigestInfo).
 * This test verifies that the hash extraction works correctly using our
 * publicDecrypt approach.
 */
test('Unprefixed PKCS#1 v1.5 - verify hash extraction works', async (t) => {
  if (!hasFixtures) {
    t.pass('Skipping: no fixtures');
    return;
  }

  const signatures = parseConsensusSignatures(consensusText);
  const signedPortion = getConsensusSignedPortion(consensusText);

  // Find a signature with a matching certificate
  const sig = signatures.find((s) =>
    keyCertificates.some(
      (c) =>
        c.identityFingerprint.toUpperCase() === s.identityFingerprint.toUpperCase() &&
        c.signingKeyFingerprint.toUpperCase() === s.signingKeyFingerprint.toUpperCase()
    )
  );

  if (!sig) {
    t.fail('No signature with matching certificate found');
    return;
  }

  const cert = keyCertificates.find(
    (c) =>
      c.identityFingerprint.toUpperCase() === sig.identityFingerprint.toUpperCase() &&
      c.signingKeyFingerprint.toUpperCase() === sig.signingKeyFingerprint.toUpperCase()
  )!;

  const authority = findAuthorityByFingerprint(sig.identityFingerprint);
  t.log(`Testing with ${authority?.nickname ?? sig.identityFingerprint.slice(0, 8)}`);
  t.log(`Signing key fingerprint: ${sig.signingKeyFingerprint}`);

  // Use Node.js crypto.publicDecrypt to extract the hash
  const nodePublicKey = nodeCrypto.createPublicKey(cert.signingKeyPem);
  const decrypted = nodeCrypto.publicDecrypt(
    { key: nodePublicKey, padding: nodeCrypto.constants.RSA_PKCS1_PADDING },
    sig.signature
  );
  t.log(`Decrypted hash length: ${decrypted.length} bytes`);

  // Compute expected hash
  const expectedHash = nodeCrypto.createHash('sha256').update(signedPortion).digest();
  t.log(`Expected hash: ${expectedHash.toString('hex').slice(0, 32)}...`);
  t.log(`Decrypted hash: ${decrypted.toString('hex').slice(0, 32)}...`);

  t.true(decrypted.equals(expectedHash), 'Extracted hash should match expected SHA-256');
});

// ============================================================================
// Browser shim simulation tests
// ============================================================================

test('Browser shim - pkcs1ToSpki conversion', async (t) => {
  if (!hasFixtures) {
    t.pass('Skipping: no fixtures');
    return;
  }

  // Find a certificate with a signing key
  const cert = keyCertificates[0];
  if (!cert) {
    t.fail('No certificates available');
    return;
  }

  t.log(`Testing key conversion for ${cert.identityFingerprint.slice(0, 8)}`);

  // The signing key PEM is in PKCS#1 format (RSA PUBLIC KEY)
  // We need to convert it to SPKI for crypto.subtle
  const pem = cert.signingKeyPem;
  t.log(`Key PEM starts with: ${pem.slice(0, 50)}...`);

  // Extract the base64 content
  const lines = pem.split('\n');
  const base64Lines = lines.filter((line) => !line.startsWith('-----') && line.trim().length > 0);
  const base64 = base64Lines.join('');
  const pkcs1Der = Buffer.from(base64, 'base64');

  t.log(`PKCS#1 DER length: ${pkcs1Der.length} bytes`);

  // Convert PKCS#1 to SPKI using the same algorithm as the browser shim
  const rsaAlgorithmId = Buffer.from([
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

  // BIT STRING: 0x00 prefix (no unused bits) + PKCS#1 key
  const bitStringContent = Buffer.concat([Buffer.from([0x00]), pkcs1Der]);

  // Encode BIT STRING length
  let bitStringHeader: Buffer;
  if (bitStringContent.length < 128) {
    bitStringHeader = Buffer.from([0x03, bitStringContent.length]);
  } else if (bitStringContent.length < 256) {
    bitStringHeader = Buffer.from([0x03, 0x81, bitStringContent.length]);
  } else {
    bitStringHeader = Buffer.from([
      0x03,
      0x82,
      (bitStringContent.length >> 8) & 0xff,
      bitStringContent.length & 0xff,
    ]);
  }

  // Outer SEQUENCE
  const innerLength = rsaAlgorithmId.length + bitStringHeader.length + bitStringContent.length;
  let outerSequence: Buffer;
  if (innerLength < 128) {
    outerSequence = Buffer.from([0x30, innerLength]);
  } else if (innerLength < 256) {
    outerSequence = Buffer.from([0x30, 0x81, innerLength]);
  } else {
    outerSequence = Buffer.from([0x30, 0x82, (innerLength >> 8) & 0xff, innerLength & 0xff]);
  }

  const spkiDer = Buffer.concat([outerSequence, rsaAlgorithmId, bitStringHeader, bitStringContent]);
  t.log(`SPKI DER length: ${spkiDer.length} bytes`);

  // Compare with Node.js generated SPKI
  const nodeSpki = nodeCrypto.createPublicKey(cert.signingKeyPem).export({
    type: 'spki',
    format: 'der',
  });
  t.log(`Node.js SPKI length: ${nodeSpki.length} bytes`);

  // Compare byte by byte
  if (Buffer.compare(spkiDer, nodeSpki) === 0) {
    t.pass('SPKI conversion matches Node.js');
  } else {
    // Log differences
    t.log('SPKI mismatch!');
    t.log(`First 50 bytes - ours: ${spkiDer.slice(0, 50).toString('hex')}`);
    t.log(`First 50 bytes - node: ${nodeSpki.slice(0, 50).toString('hex')}`);

    // Find first difference
    for (let i = 0; i < Math.min(spkiDer.length, nodeSpki.length); i++) {
      if (spkiDer[i] !== nodeSpki[i]) {
        t.log(
          `First diff at byte ${i}: ours=${spkiDer[i]?.toString(16)}, node=${nodeSpki[i]?.toString(16)}`
        );
        break;
      }
    }
    t.fail('SPKI conversion does not match Node.js');
  }

  // Try importing our SPKI into crypto.subtle
  try {
    const cryptoKey = await crypto.subtle.importKey(
      'spki',
      spkiDer,
      { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
      true,
      ['verify']
    );
    t.log('crypto.subtle.importKey succeeded with our SPKI');
    t.truthy(cryptoKey);
  } catch (err) {
    t.fail(`crypto.subtle.importKey failed: ${err}`);
  }
});

// NOTE: Standard crypto.subtle.verify uses RSASSA-PKCS1-v1_5 with DigestInfo,
// but Tor uses unprefixed PKCS#1 v1.5 (raw hash without DigestInfo).
// We implement this using pure-JS RSA (modular exponentiation with BigInt) in
// the browser shim's publicDecrypt function, which is used by verifySignatureAsync.
// This test verifies the async verification path works correctly.
test('verifySignatureWithDataAsync - pure-JS RSA verification', async (t) => {
  if (!hasFixtures) {
    t.pass('Skipping: no fixtures');
    return;
  }

  const signatures = parseConsensusSignatures(consensusText);
  const signedPortion = getConsensusSignedPortion(consensusText);

  let validCount = 0;
  for (const sig of signatures) {
    const cert = keyCertificates.find(
      (c) =>
        c.identityFingerprint.toUpperCase() === sig.identityFingerprint.toUpperCase() &&
        c.signingKeyFingerprint.toUpperCase() === sig.signingKeyFingerprint.toUpperCase()
    );
    if (!cert) continue;

    const authority = findAuthorityByFingerprint(sig.identityFingerprint);
    const name = authority?.nickname ?? sig.identityFingerprint.slice(0, 8);

    // Use the async verification function which handles both Node.js and browser paths
    const { verifySignatureWithDataAsync } = await import('./consensus-signature.ts');
    const valid = await verifySignatureWithDataAsync(
      signedPortion,
      sig.signature,
      cert.signingKeyPem,
      sig.algorithm
    );

    t.log(`${name}: ${valid ? 'VALID' : 'INVALID'}`);
    if (valid) validCount++;
  }

  t.true(validCount >= 5, `At least 5 valid signatures (got ${validCount})`);
});
