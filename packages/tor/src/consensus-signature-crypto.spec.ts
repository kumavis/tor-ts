/**
 * Test consensus signature verification using different crypto implementations.
 *
 * This test uses fixture data (downloaded consensus and authority certificates)
 * to verify that both Node.js crypto and the browser shim work correctly.
 */

import test from 'ava';
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
  type AuthorityKeyCertificate,
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

// Parse authority certificates (lazy initialized since it's now async)
let keyCertificates: AuthorityKeyCertificate[] = [];
let keyCertificatesLoaded = false;

function loadKeyCertificates(): AuthorityKeyCertificate[] {
  if (!keyCertificatesLoaded && hasFixtures) {
    keyCertificates = parseAllKeyCertificates(authKeysText);
    keyCertificatesLoaded = true;
  }
  return keyCertificates;
}

test('fixtures are available', (t) => {
  if (!hasFixtures) {
    t.fail(
      'Missing fixture files. Run: curl to download consensus and authority keys to packages/tor/src/fixtures/'
    );
  }
  t.true(consensusText.length > 0, 'Consensus text is not empty');
  t.true(authKeysText.length > 0, 'Authority keys text is not empty');
  const certs = loadKeyCertificates();
  t.true(certs.length > 0, `Parsed ${certs.length} key certificates`);
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

  const certs = loadKeyCertificates();
  const signatures = parseConsensusSignatures(consensusText);

  let matchCount = 0;
  for (const sig of signatures) {
    const cert = certs.find(
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

test('Node.js crypto - verifySignatureWithData works', async (t) => {
  if (!hasFixtures) {
    t.pass('Skipping: no fixtures');
    return;
  }

  const certs = loadKeyCertificates();
  const signatures = parseConsensusSignatures(consensusText);
  const signedPortion = getConsensusSignedPortion(consensusText);

  let validCount = 0;
  for (const sig of signatures) {
    const cert = certs.find(
      (c) =>
        c.identityFingerprint.toUpperCase() === sig.identityFingerprint.toUpperCase() &&
        c.signingKeyFingerprint.toUpperCase() === sig.signingKeyFingerprint.toUpperCase()
    );
    if (!cert) continue;

    const valid = await verifySignatureWithData(
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

test('Node.js crypto - verifyConsensusSignatures works', async (t) => {
  if (!hasFixtures) {
    t.pass('Skipping: no fixtures');
    return;
  }

  const certs = loadKeyCertificates();
  const result = await verifyConsensusSignatures(consensusText, {
    keyCertificates: certs,
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

// NOTE: Standard crypto.subtle.verify uses RSASSA-PKCS1-v1_5 with DigestInfo,
// but Tor uses unprefixed PKCS#1 v1.5 (raw hash without DigestInfo).
// We implement this using pure-JS RSA (modular exponentiation with BigInt) in
// the crypto/browser.ts module.
// This test verifies the async verification path works correctly.
test('verifySignatureWithData - async verification', async (t) => {
  if (!hasFixtures) {
    t.pass('Skipping: no fixtures');
    return;
  }

  const certs = loadKeyCertificates();
  const signatures = parseConsensusSignatures(consensusText);
  const signedPortion = getConsensusSignedPortion(consensusText);

  let validCount = 0;
  for (const sig of signatures) {
    const cert = certs.find(
      (c) =>
        c.identityFingerprint.toUpperCase() === sig.identityFingerprint.toUpperCase() &&
        c.signingKeyFingerprint.toUpperCase() === sig.signingKeyFingerprint.toUpperCase()
    );
    if (!cert) continue;

    const authority = findAuthorityByFingerprint(sig.identityFingerprint);
    const name = authority?.nickname ?? sig.identityFingerprint.slice(0, 8);

    // Use the async verification function
    const valid = await verifySignatureWithData(
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
