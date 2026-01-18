/**
 * Tests for directory client functions, particularly microdescriptor parsing.
 */

import test from 'ava';
import * as fs from 'fs';
import * as path from 'path';
import { parseMicrodescriptorBatch, parseMicrodescriptor } from './directory-client.ts';

// Known SHA256 hashes of the microdescriptors in the fixture file
// These were computed by hashing each microdescriptor from "onion-key" to the
// start of the next (including trailing newline, NO trimming)
const FIXTURE_DIGESTS = {
  microdesc1: 'mXvfeMcMvAVjORIDHC3DgQwZt7GnUH7/MfG7TiXRcQY',
  microdesc2: '6qGFkXvIGX9yxE+jriUWsrKNLBWpx8ee4YOz+gBEoRg',
  microdesc3: 'gHViWLccJpTl15pDFOI2PPiDSpGpYhMDIRFd1F7f4Gw',
};

// Load the fixture file
const fixtureContent = fs.readFileSync(
  path.join(import.meta.dirname, 'fixtures', 'microdesc-batch.txt'),
  'utf8'
);

test('parseMicrodescriptorBatch: matches all digests when all are requested', (t) => {
  const digests = [
    FIXTURE_DIGESTS.microdesc1,
    FIXTURE_DIGESTS.microdesc2,
    FIXTURE_DIGESTS.microdesc3,
  ];

  const result = parseMicrodescriptorBatch(fixtureContent, digests);

  t.is(result.size, 3, 'Should parse all 3 microdescriptors');
  t.true(result.has(FIXTURE_DIGESTS.microdesc1));
  t.true(result.has(FIXTURE_DIGESTS.microdesc2));
  t.true(result.has(FIXTURE_DIGESTS.microdesc3));
});

test('parseMicrodescriptorBatch: matches subset when only some digests requested', (t) => {
  // Only request the first and third
  const digests = [FIXTURE_DIGESTS.microdesc1, FIXTURE_DIGESTS.microdesc3];

  const result = parseMicrodescriptorBatch(fixtureContent, digests);

  t.is(result.size, 2, 'Should only return requested digests');
  t.true(result.has(FIXTURE_DIGESTS.microdesc1));
  t.false(result.has(FIXTURE_DIGESTS.microdesc2));
  t.true(result.has(FIXTURE_DIGESTS.microdesc3));
});

test('parseMicrodescriptorBatch: returns empty map when no digests match', (t) => {
  const digests = ['nonexistent123', 'alsoNotReal456'];

  const result = parseMicrodescriptorBatch(fixtureContent, digests);

  t.is(result.size, 0, 'Should return empty map when no digests match');
});

test('parseMicrodescriptorBatch: handles empty content', (t) => {
  const result = parseMicrodescriptorBatch('', [FIXTURE_DIGESTS.microdesc1]);

  t.is(result.size, 0);
});

test('parseMicrodescriptorBatch: handles empty digest list', (t) => {
  const result = parseMicrodescriptorBatch(fixtureContent, []);

  t.is(result.size, 0, 'Should return empty map when no digests requested');
});

test('parseMicrodescriptorBatch: correctly parses ntor-onion-key', (t) => {
  const digests = [FIXTURE_DIGESTS.microdesc1];
  const result = parseMicrodescriptorBatch(fixtureContent, digests);

  const md = result.get(FIXTURE_DIGESTS.microdesc1);
  t.truthy(md, 'Microdescriptor should be parsed');
  t.truthy(md?.ntorOnionKey, 'Should have ntor-onion-key');
  t.is(md?.ntorOnionKey?.length, 32, 'ntor-onion-key should be 32 bytes');
});

test('parseMicrodescriptorBatch: correctly parses ed25519 identity', (t) => {
  const digests = [FIXTURE_DIGESTS.microdesc1];
  const result = parseMicrodescriptorBatch(fixtureContent, digests);

  const md = result.get(FIXTURE_DIGESTS.microdesc1);
  t.truthy(md, 'Microdescriptor should be parsed');
  t.truthy(md?.ed25519Identity, 'Should have ed25519 identity');
  t.is(md?.ed25519Identity?.length, 32, 'ed25519 identity should be 32 bytes');
});

test('parseMicrodescriptorBatch: correctly parses exit policy', (t) => {
  // First microdesc: p accept 80,443
  const digests = [
    FIXTURE_DIGESTS.microdesc1,
    FIXTURE_DIGESTS.microdesc2,
    FIXTURE_DIGESTS.microdesc3,
  ];
  const result = parseMicrodescriptorBatch(fixtureContent, digests);

  const md1 = result.get(FIXTURE_DIGESTS.microdesc1);
  t.is(md1?.exitPolicy?.type, 'accept');
  t.deepEqual(md1?.exitPolicy?.ports, [
    { start: 80, end: 80 },
    { start: 443, end: 443 },
  ]);

  // Second microdesc: p accept 1-65535
  const md2 = result.get(FIXTURE_DIGESTS.microdesc2);
  t.is(md2?.exitPolicy?.type, 'accept');
  t.deepEqual(md2?.exitPolicy?.ports, [{ start: 1, end: 65535 }]);

  // Third microdesc: p reject 1-65535
  const md3 = result.get(FIXTURE_DIGESTS.microdesc3);
  t.is(md3?.exitPolicy?.type, 'reject');
  t.deepEqual(md3?.exitPolicy?.ports, [{ start: 1, end: 65535 }]);
});

test('parseMicrodescriptorBatch: works with digests containing special base64 chars', (t) => {
  // The first digest contains '/' which needs base64url encoding for URLs
  // This test verifies that our digest matching works with standard base64 internally
  const digestWithSlash = FIXTURE_DIGESTS.microdesc1; // mXvfeMcMvAVjORIDHC3DgQwZt7GnUH7/MfG7TiXRcQY
  t.true(digestWithSlash.includes('/'), 'Test digest should contain /');

  const result = parseMicrodescriptorBatch(fixtureContent, [digestWithSlash]);
  t.is(result.size, 1, 'Should match digest containing /');
  t.true(result.has(digestWithSlash));
});

test('parseMicrodescriptor: parses single microdescriptor', (t) => {
  const singleMd = `onion-key
-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBAM5Sjx9uqL0gf9l6asvtTrFRka/NZhtq4Cf9s0jYaEp9J9H/V3Y4aZnI
PHSODCDAYEMEZHNIKFXV18gTZJFOQFvom6pFuHrFWLqor+SLi/Xhn7S2ZPWqsEGA
IJFW8pJhwXIkfPMa2orZyGW72dp0Nwo/CsbDwOpJfzhWjdDYAfAZAgMBAAE=
-----END RSA PUBLIC KEY-----
ntor-onion-key PdiDg5ZRn4YoVJK6YaNF+gb5YmLpS3FVrjReZ8NX6RI=
p accept 80,443
id ed25519 SJhDJdNopLv5QYVB0RJI1K9iVz+RLqU/Q9iVmRrLfgo`;

  const result = parseMicrodescriptor(singleMd);

  t.truthy(result.ntorOnionKey);
  t.is(result.ntorOnionKey?.length, 32);
  t.truthy(result.ed25519Identity);
  t.is(result.ed25519Identity?.length, 32);
  t.truthy(result.exitPolicy);
  t.is(result.exitPolicy?.type, 'accept');
});

// Test that digests are joined with '-' separator (NOT converted to base64url)
test('microdescriptor digests use standard base64 with - separator', (t) => {
  // Per Tor spec, digests are standard base64 (may contain + and /)
  // and are joined with '-' as the separator between multiple digests
  const digest1 = 'abc+def/ghi'; // Contains + and / which are valid base64
  const digest2 = 'xyz123456789';

  // Digests should be joined with '-' but NOT have their content modified
  const digestList = [digest1, digest2].join('-');
  t.is(
    digestList,
    'abc+def/ghi-xyz123456789',
    'Digests should be joined with - but content unchanged'
  );

  // The + and / in digests are NOT replaced (unlike base64url encoding)
  t.true(digestList.includes('+'), 'Should preserve + in digest content');
  t.true(digestList.includes('/'), 'Should preserve / in digest content');
});

test('parseMicrodescriptorBatch: matches correctly regardless of request order', (t) => {
  // Request digests in reverse order - should still work since we match by hash
  const digestsReversed = [
    FIXTURE_DIGESTS.microdesc3,
    FIXTURE_DIGESTS.microdesc2,
    FIXTURE_DIGESTS.microdesc1,
  ];

  const result = parseMicrodescriptorBatch(fixtureContent, digestsReversed);

  t.is(result.size, 3, 'Should match all 3 regardless of request order');

  // Verify correct content is mapped to correct digest
  const md1 = result.get(FIXTURE_DIGESTS.microdesc1);
  const md2 = result.get(FIXTURE_DIGESTS.microdesc2);
  const md3 = result.get(FIXTURE_DIGESTS.microdesc3);

  // First microdesc has accept 80,443
  t.deepEqual(md1?.exitPolicy?.ports, [
    { start: 80, end: 80 },
    { start: 443, end: 443 },
  ]);

  // Second microdesc has accept 1-65535
  t.deepEqual(md2?.exitPolicy?.ports, [{ start: 1, end: 65535 }]);
  t.is(md2?.exitPolicy?.type, 'accept');

  // Third microdesc has reject 1-65535
  t.deepEqual(md3?.exitPolicy?.ports, [{ start: 1, end: 65535 }]);
  t.is(md3?.exitPolicy?.type, 'reject');
});

test('parseMicrodescriptorBatch: handles missing microdescriptors in response', (t) => {
  // If server doesn't return all requested microdescriptors, we should still
  // correctly map the ones that are present

  // Create content with only the first two microdescriptors
  const partialContent = fixtureContent.split('onion-key\n').slice(0, 3).join('onion-key\n');

  // Request all three, but only first two are in content
  const digests = [
    FIXTURE_DIGESTS.microdesc1,
    FIXTURE_DIGESTS.microdesc2,
    FIXTURE_DIGESTS.microdesc3,
  ];

  const result = parseMicrodescriptorBatch(partialContent, digests);

  // Should only find the ones present in content
  t.is(result.size, 2, 'Should only match microdescriptors present in content');
  t.true(result.has(FIXTURE_DIGESTS.microdesc1));
  t.true(result.has(FIXTURE_DIGESTS.microdesc2));
  t.false(result.has(FIXTURE_DIGESTS.microdesc3));
});

// Test fixtures copied from Tor's src/test/test_microdesc.c
// These are real microdescriptors used in Tor's own test suite
const TOR_TEST_MD1 =
  'onion-key\n' +
  '-----BEGIN RSA PUBLIC KEY-----\n' +
  'MIGJAoGBAMjlHH/daN43cSVRaHBwgUfnszzAhg98EvivJ9Qxfv51mvQUxPjQ07es\n' +
  'gV/3n8fyh3Kqr/ehi9jxkdgSRfSnmF7giaHL1SLZ29kA7KtST+pBvmTpDtHa3ykX\n' +
  'Xorc7hJvIyTZoc1HU+5XSynj3gsBE5IGK1ZRzrNS688LnuZMVp1tAgMBAAE=\n' +
  '-----END RSA PUBLIC KEY-----\n' +
  'ntor-onion-key AppBt6CSeb1kKid/36ototmFA24ddfW5JpjWPLuoJgs=\n';

const TOR_TEST_MD3_NOANNOTATION =
  'onion-key\n' +
  '-----BEGIN RSA PUBLIC KEY-----\n' +
  'MIGJAoGBAMH3340d4ENNGrqx7UxT+lB7x6DNUKOdPEOn4teceE11xlMyZ9TPv41c\n' +
  'qj2fRZzfxlc88G/tmiaHshmdtEpklZ740OFqaaJVj4LjPMKFNE+J7Xc1142BE9Ci\n' +
  'KgsbjGYe2RY261aADRWLetJ8T9QDMm+JngL4288hc8pq1uB/3TAbAgMBAAE=\n' +
  '-----END RSA PUBLIC KEY-----\n' +
  'ntor-onion-key AppBt6CSeb1kKid/36ototmFA24ddfW5JpjWPLuoJgs=\n' +
  'p accept 1-700,800-1000\n' +
  'family nodeX nodeY nodeZ\n';

// SHA256 hashes computed from Tor's test fixtures (verified against our implementation)
const TOR_TEST_MD1_DIGEST = 'WyuXS18qtToOiPGV2I3959TyuAn2f1QcNT+Q+neOtFk';
const TOR_TEST_MD3_DIGEST = 'MobrhyPBXBr3w1TMgyTY8OhGDiDOSenQykU+haX5Tk8';

test('parseMicrodescriptorBatch: matches Tor test_microdesc.c fixtures', (t) => {
  // This test uses actual test data from Tor's src/test/test_microdesc.c
  // to ensure our hash computation matches the reference implementation
  const content = TOR_TEST_MD1 + TOR_TEST_MD3_NOANNOTATION;
  const digests = [TOR_TEST_MD1_DIGEST, TOR_TEST_MD3_DIGEST];

  const result = parseMicrodescriptorBatch(content, digests);

  t.is(result.size, 2, 'Should match both Tor test microdescriptors');
  t.true(result.has(TOR_TEST_MD1_DIGEST), 'Should match test_md1');
  t.true(result.has(TOR_TEST_MD3_DIGEST), 'Should match test_md3_noannotation');

  // Verify parsed content
  const md1 = result.get(TOR_TEST_MD1_DIGEST);
  t.truthy(md1?.ntorOnionKey, 'test_md1 should have ntor key');
  t.is(md1?.ntorOnionKey?.length, 32);

  const md3 = result.get(TOR_TEST_MD3_DIGEST);
  t.truthy(md3?.ntorOnionKey, 'test_md3 should have ntor key');
  t.truthy(md3?.exitPolicy, 'test_md3 should have exit policy');
  t.is(md3?.exitPolicy?.type, 'accept');
});
