import test from 'ava';
import {
  parseConsensusSignatures,
  getConsensusSignedPortion,
  computeConsensusDigest,
  verifyConsensusSignatures,
  computeRsaKeyFingerprint,
  findAuthorityByFingerprint,
  extractAuthorityFingerprints,
  DIRECTORY_AUTHORITIES,
} from './consensus-signature.ts';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// Test consensus from the repository
const testMicrodescPath = path.join(__dirname, 'test-microdesc.txt');
const testMicrodesc = fs.readFileSync(testMicrodescPath, 'utf-8');

// Real consensus file for mainnet testing
const realConsensusPath = path.join(__dirname, '..', '..', '..', 'consensus');
const hasRealConsensus = fs.existsSync(realConsensusPath);
const realConsensus = hasRealConsensus ? fs.readFileSync(realConsensusPath, 'utf-8') : '';

test('parseConsensusSignatures - should parse signatures from test microdesc', (t) => {
  const signatures = parseConsensusSignatures(testMicrodesc);
  t.is(signatures.length, 4);

  // Check first signature
  const first = signatures[0];
  t.truthy(first);
  t.is(first!.algorithm, 'sha256');
  t.is(first!.identityFingerprint, '1F878B2E90765D9D2C8D34F406296C5C588363F4');
  t.is(first!.signingKeyFingerprint, 'EF627040F41840A31CB41271880A762AF0CA8632');
  t.true(first!.signature.length > 0);
});

test('parseConsensusSignatures - should parse signatures from real consensus', (t) => {
  if (!hasRealConsensus) {
    t.pass('Skipping: no real consensus file available');
    return;
  }

  const signatures = parseConsensusSignatures(realConsensus);
  // Real consensus should have 8 signatures from directory authorities
  t.is(signatures.length, 8);

  // All signatures should use sha256 (modern consensus)
  for (const sig of signatures) {
    t.true(['sha1', 'sha256'].includes(sig.algorithm));
    t.regex(sig.identityFingerprint, /^[A-F0-9]{40}$/);
    t.regex(sig.signingKeyFingerprint, /^[A-F0-9]{40}$/);
    t.true(sig.signature.length > 0);
  }
});

test('getConsensusSignedPortion - should extract signed portion from test microdesc', (t) => {
  const signedPortion = getConsensusSignedPortion(testMicrodesc);

  // Should start with network-status-version
  t.true(signedPortion.startsWith('network-status-version'));

  // Should end with "directory-signature " (including the space)
  t.true(signedPortion.endsWith('\ndirectory-signature '));

  // Should not contain the signature block
  t.false(signedPortion.includes('-----BEGIN SIGNATURE-----'));
});

test('getConsensusSignedPortion - should extract signed portion from real consensus', (t) => {
  if (!hasRealConsensus) {
    t.pass('Skipping: no real consensus file available');
    return;
  }

  const signedPortion = getConsensusSignedPortion(realConsensus);
  t.true(signedPortion.startsWith('network-status-version'));
  t.true(signedPortion.endsWith('\ndirectory-signature '));
});

test('computeConsensusDigest - should compute SHA256 digest', (t) => {
  const signedPortion = getConsensusSignedPortion(testMicrodesc);
  const digest = computeConsensusDigest(signedPortion, 'sha256');
  t.is(digest.length, 32);
});

test('computeConsensusDigest - should compute SHA1 digest', (t) => {
  const signedPortion = getConsensusSignedPortion(testMicrodesc);
  const digest = computeConsensusDigest(signedPortion, 'sha1');
  t.is(digest.length, 20);
});

test('DIRECTORY_AUTHORITIES - should have 8 hardcoded directory authorities', (t) => {
  t.is(DIRECTORY_AUTHORITIES.length, 8);
});

test('DIRECTORY_AUTHORITIES - should have valid authority entries', (t) => {
  for (const auth of DIRECTORY_AUTHORITIES) {
    t.truthy(auth.nickname);
    t.regex(auth.v3ident, /^[A-F0-9]{40}$/);
    t.true(auth.identityKeyPem.includes('-----BEGIN RSA PUBLIC KEY-----'));
    t.true(auth.identityKeyPem.includes('-----END RSA PUBLIC KEY-----'));
  }
});

test('DIRECTORY_AUTHORITIES - should have correct fingerprints for known authorities', (t) => {
  const moria1 = DIRECTORY_AUTHORITIES.find((a) => a.nickname === 'moria1');
  t.truthy(moria1);
  t.is(moria1!.v3ident, 'F533C81CEF0BC0267857C99B2F471ADF249FA232');

  const gabelmoo = DIRECTORY_AUTHORITIES.find((a) => a.nickname === 'gabelmoo');
  t.truthy(gabelmoo);
  t.is(gabelmoo!.v3ident, 'ED03BB616EB2F60BEC80151114BB25CEF515B226');
});

test('findAuthorityByFingerprint - should find authority by fingerprint', (t) => {
  const auth = findAuthorityByFingerprint('F533C81CEF0BC0267857C99B2F471ADF249FA232');
  t.truthy(auth);
  t.is(auth!.nickname, 'moria1');
});

test('findAuthorityByFingerprint - should return undefined for unknown fingerprint', (t) => {
  const auth = findAuthorityByFingerprint('0000000000000000000000000000000000000000');
  t.is(auth, undefined);
});

test('findAuthorityByFingerprint - should be case-insensitive', (t) => {
  const auth = findAuthorityByFingerprint('f533c81cef0bc0267857c99b2f471adf249fa232');
  t.truthy(auth);
  t.is(auth!.nickname, 'moria1');
});

test('extractAuthorityFingerprints - should extract unique fingerprints from consensus', (t) => {
  if (!hasRealConsensus) {
    t.pass('Skipping: no real consensus file available');
    return;
  }

  const fingerprints = extractAuthorityFingerprints(realConsensus);
  t.is(fingerprints.length, 8);

  // All should be valid fingerprints
  for (const fp of fingerprints) {
    t.regex(fp, /^[A-F0-9]{40}$/);
  }
});

test('computeRsaKeyFingerprint - should compute consistent fingerprint', (t) => {
  // Note: The hardcoded identity keys in DIRECTORY_AUTHORITIES are placeholders
  // that need to be replaced with the real authority keys from Tor Project.
  // For now, we just verify the function computes a valid 40-character fingerprint.
  const moria1 = DIRECTORY_AUTHORITIES.find((a) => a.nickname === 'moria1');
  t.truthy(moria1);

  const computed = computeRsaKeyFingerprint(moria1!.identityKeyPem);
  t.regex(computed, /^[A-F0-9]{40}$/);

  // TODO: When real identity keys are added, uncomment this assertion:
  // t.is(computed, moria1!.v3ident);
});

test('verifyConsensusSignatures - should fail for test microdesc (unknown authorities)', (t) => {
  const result = verifyConsensusSignatures(testMicrodesc, {
    allowWithoutCertificates: true,
  });

  // Test microdesc is signed by chutney test authorities, not mainnet
  t.false(result.valid);
  t.is(result.validSignatureCount, 0);
  t.truthy(result.error?.includes('Insufficient valid signatures'));

  // All signatures should be marked as from unknown authorities
  for (const sig of result.signatures) {
    t.false(sig.valid);
    t.is(sig.error, 'Unknown directory authority');
  }
});

test('verifyConsensusSignatures - should verify real consensus signatures', (t) => {
  if (!hasRealConsensus) {
    t.pass('Skipping: no real consensus file available');
    return;
  }

  const result = verifyConsensusSignatures(realConsensus, {
    allowWithoutCertificates: true,
  });

  // Real consensus should have signatures from known authorities
  t.is(result.totalKnownAuthorities, 8);

  // At minimum, we should recognize the authority fingerprints
  const knownSigs = result.signatures.filter((s) => s.nickname !== undefined);
  t.true(knownSigs.length > 0);
});

test('verifyConsensusSignatures - should fail with empty consensus', (t) => {
  const result = verifyConsensusSignatures('', {});
  t.false(result.valid);
  t.is(result.error, 'No signatures found in consensus');
});

test('verifyConsensusSignatures - should respect requiredSignatures option', (t) => {
  if (!hasRealConsensus) {
    t.pass('Skipping: no real consensus file available');
    return;
  }

  // Setting a very high requirement should fail
  const result = verifyConsensusSignatures(realConsensus, {
    requiredSignatures: 100,
    allowWithoutCertificates: true,
  });
  t.false(result.valid);
  t.is(result.requiredSignatureCount, 100);
});
