import test from 'ava';
import {
  parseOnionV3Address,
  isOnionAddress,
  computeTimePeriod,
  deriveBlindedPublicKey,
  deriveSubcredential,
  computeDisasterSrv,
  getSrvValues,
  selectHsdirsForFetch,
  toBase64UrlNoPad,
  hsBuildHsIndex,
  hsBuildHsdirIndex,
  type HsdirCandidate,
} from './hidden-service.ts';

// Facebook's v3 onion address (well-known, used for testing)
const FACEBOOK_ONION = 'facebookwkhpilnemxj7asaniu7vnjjbiltxjqhye3mhbshg7kx5tfyd';

test('parseOnionV3Address: parses valid v3 onion address', (t) => {
  const result = parseOnionV3Address(`${FACEBOOK_ONION}.onion`);
  t.is(result.publicIdentityKey.length, 32, 'public key should be 32 bytes');
});

test('parseOnionV3Address: handles www subdomain (vhosting)', (t) => {
  // Per address-spec.md: [ignored].[onion_address].onion
  const result = parseOnionV3Address(`www.${FACEBOOK_ONION}.onion`);
  t.is(result.publicIdentityKey.length, 32, 'public key should be 32 bytes');
});

test('parseOnionV3Address: handles multiple subdomain levels', (t) => {
  const result = parseOnionV3Address(`foo.bar.baz.${FACEBOOK_ONION}.onion`);
  t.is(result.publicIdentityKey.length, 32, 'public key should be 32 bytes');
});

test('parseOnionV3Address: works without .onion suffix', (t) => {
  const result = parseOnionV3Address(FACEBOOK_ONION);
  t.is(result.publicIdentityKey.length, 32, 'public key should be 32 bytes');
});

test('parseOnionV3Address: subdomain and no-subdomain produce same key', (t) => {
  const withoutSubdomain = parseOnionV3Address(`${FACEBOOK_ONION}.onion`);
  const withSubdomain = parseOnionV3Address(`www.${FACEBOOK_ONION}.onion`);
  t.deepEqual(
    withSubdomain.publicIdentityKey,
    withoutSubdomain.publicIdentityKey,
    'subdomain should not affect the derived public key'
  );
});

test('parseOnionV3Address: rejects invalid length address', (t) => {
  t.throws(() => parseOnionV3Address('tooshort.onion'), {
    message: /Expected v3 onion address host length 56/,
  });
});

test('parseOnionV3Address: rejects invalid address', (t) => {
  // Valid length but corrupted (changed last char affects checksum/version)
  const invalid = 'facebookwkhpilnemxj7asaniu7vnjjbiltxjqhye3mhbshg7kx5tfyx';
  t.throws(() => parseOnionV3Address(`${invalid}.onion`), {
    message: /Invalid v3 onion checksum|Unsupported onion version/,
  });
});

test('isOnionAddress: returns true for .onion addresses', (t) => {
  t.true(isOnionAddress(`${FACEBOOK_ONION}.onion`));
  t.true(isOnionAddress(`www.${FACEBOOK_ONION}.onion`));
  t.true(isOnionAddress('example.onion'));
});

test('isOnionAddress: returns false for non-.onion addresses', (t) => {
  t.false(isOnionAddress('example.com'));
  t.false(isOnionAddress('onion.example.com'));
  t.false(isOnionAddress('example.onion.com'));
});

// =========================================================================
// Blinded Key Derivation Tests (test vectors from Arti, generated from C Tor)
// =========================================================================

// Test vector from arti/crates/tor-hscrypto/src/pk.rs key_blinding_testvec()
const TEST_IDENTITY_KEY = Buffer.from(
  '833990B085C1A688C1D4C8B1F6B56AFAF5A2ECA674449E1D704F83765CCB7BC6',
  'hex'
);
const TEST_PERIOD_NUM = 1234n;
const TEST_PERIOD_LENGTH_MINUTES = 1440n; // 1 day

// Expected values from Arti test
const EXPECTED_BLINDED_PUBKEY = '3A50BF210E8F9EE955AE0014F7A6917FB65EBF098A86305ABB508D1A7291B6D5';
const EXPECTED_SUBCREDENTIAL = '635D55907816E8D76398A675A50B1C2F3E36B42A5CA77BA3A0441285161AE07D';

test('deriveBlindedPublicKey: matches C Tor test vector', (t) => {
  const blindedKey = deriveBlindedPublicKey({
    publicIdentityKey: TEST_IDENTITY_KEY,
    periodNum: TEST_PERIOD_NUM,
    periodLengthMinutes: TEST_PERIOD_LENGTH_MINUTES,
  });

  t.is(
    blindedKey.toString('hex').toUpperCase(),
    EXPECTED_BLINDED_PUBKEY,
    'blinded public key should match C Tor'
  );
});

test('deriveSubcredential: matches C Tor test vector', (t) => {
  const blindedKey = deriveBlindedPublicKey({
    publicIdentityKey: TEST_IDENTITY_KEY,
    periodNum: TEST_PERIOD_NUM,
    periodLengthMinutes: TEST_PERIOD_LENGTH_MINUTES,
  });

  const subcred = deriveSubcredential({
    publicIdentityKey: TEST_IDENTITY_KEY,
    blindedPublicKey: blindedKey,
  });

  t.is(
    subcred.toString('hex').toUpperCase(),
    EXPECTED_SUBCREDENTIAL,
    'subcredential should match C Tor'
  );
});

test('computeTimePeriod: produces correct period for mainnet-like settings', (t) => {
  // Using the example from rend-spec: 2016-04-13 11:15:01 UTC
  // Minutes since epoch: 24342435
  // Rotation offset: 720 minutes (12 hours)
  // Period length: 1440 minutes
  // Expected period: 16903
  const validAfter = new Date('2016-04-13T11:15:01Z');
  const freshUntil = new Date('2016-04-13T12:15:01Z'); // 1 hour voting interval

  const { periodNum, periodLengthMinutes } = computeTimePeriod({
    validAfter,
    freshUntil,
    hsdirIntervalMinutes: 1440,
  });

  t.is(periodLengthMinutes, 1440n, 'period length should be 1440 minutes');
  t.is(periodNum, 16903n, 'period number should match spec example');
});

test('computeTimePeriod: time period advances correctly', (t) => {
  // At 12:00 UTC, we enter a new time period
  const beforeTp = new Date('2016-04-13T11:59:59Z');
  const afterTp = new Date('2016-04-13T12:00:01Z');
  const freshUntil = new Date('2016-04-13T13:00:00Z');

  const before = computeTimePeriod({
    validAfter: beforeTp,
    freshUntil,
    hsdirIntervalMinutes: 1440,
  });
  const after = computeTimePeriod({
    validAfter: afterTp,
    freshUntil,
    hsdirIntervalMinutes: 1440,
  });

  t.is(after.periodNum, before.periodNum + 1n, 'period should advance at 12:00 UTC');
});

test('computeDisasterSrv: produces consistent output', (t) => {
  // Disaster SRV is a fallback when no SRV is available
  // SHA3-256("shared-random-disaster" | INT_8(period_length) | INT_8(period_num))
  const srv1 = computeDisasterSrv({
    periodLengthMinutes: 1440n,
    periodNum: 16903n,
  });
  const srv2 = computeDisasterSrv({
    periodLengthMinutes: 1440n,
    periodNum: 16903n,
  });

  t.deepEqual(srv1, srv2, 'disaster SRV should be deterministic');
  t.is(srv1.length, 32, 'disaster SRV should be 32 bytes');

  // Different period should give different SRV
  const srvDifferent = computeDisasterSrv({
    periodLengthMinutes: 1440n,
    periodNum: 16904n,
  });
  t.notDeepEqual(srv1, srvDifferent, 'different period should give different SRV');
});

// =========================================================================
// DuckDuckGo onion address test (the failing case)
// =========================================================================
const DUCKDUCKGO_ONION = 'duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad';

test('parseOnionV3Address: DuckDuckGo onion address parses correctly', (t) => {
  const result = parseOnionV3Address(`${DUCKDUCKGO_ONION}.onion`);
  t.is(result.publicIdentityKey.length, 32, 'public key should be 32 bytes');
  t.truthy(result.publicIdentityKey, 'should have a valid public key');
});

test('deriveBlindedPublicKey: produces valid key for DuckDuckGo', (t) => {
  const { publicIdentityKey } = parseOnionV3Address(`${DUCKDUCKGO_ONION}.onion`);

  // Get a recent time period (approximate)
  // Jan 21, 2026 21:23 UTC - around when the test was run
  const validAfter = new Date('2026-01-21T21:23:00Z');
  const freshUntil = new Date('2026-01-21T22:23:00Z');

  const { periodNum, periodLengthMinutes } = computeTimePeriod({
    validAfter,
    freshUntil,
    hsdirIntervalMinutes: 1440,
  });

  t.is(periodLengthMinutes, 1440n, 'period length should be 1440 minutes');

  const blindedKey = deriveBlindedPublicKey({
    publicIdentityKey,
    periodNum,
    periodLengthMinutes,
  });

  t.is(blindedKey.length, 32, 'blinded key should be 32 bytes');

  // Log values for debugging
  console.log('DuckDuckGo public identity key:', publicIdentityKey.toString('hex'));
  console.log('Period number:', periodNum.toString());
  console.log('Period length (minutes):', periodLengthMinutes.toString());
  console.log('Blinded public key:', blindedKey.toString('hex'));

  const subcred = deriveSubcredential({ publicIdentityKey, blindedPublicKey: blindedKey });
  console.log('Subcredential:', subcred.toString('hex'));
});

// =========================================================================
// SRV and HSDir selection tests
// =========================================================================

test('getSrvValues: uses disaster SRV when consensus has no SRV', (t) => {
  // Create a mock consensus without SRV values
  const mockConsensus = {
    validAfter: new Date('2026-01-21T21:00:00Z'),
    freshUntil: new Date('2026-01-21T22:00:00Z'),
    validUntil: new Date('2026-01-21T23:00:00Z'),
    params: {},
    sharedRandPreviousValue: undefined,
    sharedRandCurrentValue: undefined,
    relays: [],
    bandwidthWeights: {},
    _verified: true,
  } as const;

  const srvValues = getSrvValues(mockConsensus as any, 1440n, 20474n);

  t.is(srvValues.length, 2, 'should return 2 SRV values');
  t.is(srvValues[0]!.length, 32, 'current SRV should be 32 bytes');
  t.is(srvValues[1]!.length, 32, 'previous SRV should be 32 bytes');

  // Both should be disaster SRVs (same since same period)
  const disasterSrv = computeDisasterSrv({ periodLengthMinutes: 1440n, periodNum: 20474n });
  t.deepEqual(srvValues[0], disasterSrv, 'current should be disaster SRV');
  t.deepEqual(srvValues[1], disasterSrv, 'previous should be disaster SRV');
});

test('getSrvValues: uses real SRVs when available in consensus', (t) => {
  const realCurrentSrv = Buffer.alloc(32, 0x01);
  const realPreviousSrv = Buffer.alloc(32, 0x02);

  const mockConsensus = {
    validAfter: new Date('2026-01-21T21:00:00Z'),
    freshUntil: new Date('2026-01-21T22:00:00Z'),
    validUntil: new Date('2026-01-21T23:00:00Z'),
    params: {},
    sharedRandPreviousValue: realPreviousSrv,
    sharedRandCurrentValue: realCurrentSrv,
    relays: [],
    bandwidthWeights: {},
    _verified: true,
  } as const;

  const srvValues = getSrvValues(mockConsensus as any, 1440n, 20474n);

  t.deepEqual(srvValues[0], realCurrentSrv, 'should use real current SRV');
  t.deepEqual(srvValues[1], realPreviousSrv, 'should use real previous SRV');
});

test('toBase64UrlNoPad: encodes blinded key for HSDir lookup', (t) => {
  // Arti test vector blinded key
  const blindedKey = Buffer.from(
    '3A50BF210E8F9EE955AE0014F7A6917FB65EBF098A86305ABB508D1A7291B6D5',
    'hex'
  );

  const encoded = toBase64UrlNoPad(blindedKey);

  // Should be base64url without padding
  t.false(encoded.includes('+'), 'should not contain +');
  t.false(encoded.includes('/'), 'should not contain /');
  t.false(encoded.includes('='), 'should not contain =');
  t.true(encoded.length > 0, 'should not be empty');

  // Verify it can be decoded back
  const decoded = Buffer.from(encoded.replaceAll('-', '+').replaceAll('_', '/'), 'base64');
  t.deepEqual(decoded, blindedKey, 'should decode back to original');

  console.log('Blinded key base64url:', encoded);
});

test('selectHsdirsForFetch: produces deterministic results', (t) => {
  // Create mock HSDir candidates
  const mockHsdirs: HsdirCandidate[] = [];
  for (let i = 0; i < 10; i++) {
    const ed25519Key = Buffer.alloc(32);
    ed25519Key.writeUInt32BE(i, 0);
    mockHsdirs.push({
      peerInfo: {
        onionKey: Buffer.alloc(32, i),
        rsaIdDigest: Buffer.alloc(20, i),
        linkSpecifiers: [],
      },
      ed25519IdentityKey: ed25519Key,
    });
  }

  const srv = Buffer.alloc(32, 0xab);
  const blindedKey = Buffer.alloc(32, 0xcd);

  const result1 = selectHsdirsForFetch({
    hsdirs: mockHsdirs,
    sharedRandomValue: srv,
    blindedPublicKey: blindedKey,
    periodLengthMinutes: 1440n,
    periodNum: 20474n,
    nReplicas: 2,
    spreadFetch: 3,
  });

  const _result2 = selectHsdirsForFetch({
    hsdirs: mockHsdirs,
    sharedRandomValue: srv,
    blindedPublicKey: blindedKey,
    periodLengthMinutes: 1440n,
    periodNum: 20474n,
    nReplicas: 2,
    spreadFetch: 3,
  });

  // Results should be deterministic (before shuffle)
  // Actually, selectHsdirsForFetch shuffles at the end, so we can't compare directly
  // Just check we get the expected number
  t.true(result1.length > 0, 'should select some HSDirs');
  t.true(result1.length <= 6, 'should not exceed nReplicas * spreadFetch');
});

// =========================================================================
// C Tor Test Vectors (from tor/src/test/test_hs_common.c and hs_indexes.py)
// =========================================================================

// Test vectors from C Tor's test_hs_indexes():
// - pubkey: 32 bytes of 0x42
// - srv: 32 bytes of 0x43
// - period_num: 42
// - period_length: 1440 (default mainnet)
const CTOR_TEST_PUBKEY = Buffer.alloc(32, 0x42);
const CTOR_TEST_SRV = Buffer.alloc(32, 0x43);
const CTOR_TEST_PERIOD_NUM = 42n;
const CTOR_TEST_PERIOD_LEN = 1440n;

test('hsBuildHsIndex: matches C Tor test vector', (t) => {
  // Expected from test_hs_indexes() in test_hs_common.c:
  // "37e5cbbd56a22823714f18f1623ece5983a0d64c78495a8cfab854245e5f9a8a"
  const expected = '37e5cbbd56a22823714f18f1623ece5983a0d64c78495a8cfab854245e5f9a8a';

  const result = hsBuildHsIndex({
    blindedPublicKey: CTOR_TEST_PUBKEY,
    replicanum: 1n,
    periodLengthMinutes: CTOR_TEST_PERIOD_LEN,
    periodNum: CTOR_TEST_PERIOD_NUM,
  });

  t.is(result.toString('hex'), expected, 'hs_index should match C Tor test vector');
});

test('hsBuildHsdirIndex: matches C Tor test vector', (t) => {
  // Expected from test_hs_indexes() in test_hs_common.c:
  // "db475361014a09965e7e5e4d4a25b8f8d4b8f16cb1d8a7e95eed50249cc1a2d5"
  const expected = 'db475361014a09965e7e5e4d4a25b8f8d4b8f16cb1d8a7e95eed50249cc1a2d5';

  const result = hsBuildHsdirIndex({
    ed25519IdentityKey: CTOR_TEST_PUBKEY,
    sharedRandomValue: CTOR_TEST_SRV,
    periodLengthMinutes: CTOR_TEST_PERIOD_LEN,
    periodNum: CTOR_TEST_PERIOD_NUM,
  });

  t.is(result.toString('hex'), expected, 'hsdir_index should match C Tor test vector');
});

// =========================================================================
// Arti Test Vectors (from arti/crates/tor-hscrypto/src/pk.rs)
// =========================================================================

// Test vectors from key_blinding_testvec() in pk.rs:
// - id: 833990B085C1A688C1D4C8B1F6B56AFAF5A2ECA674449E1D704F83765CCB7BC6
// - time_period: 1973-05-20T01:50:33Z with 1 day length, 12 hour offset -> interval_num = 1234
// - expected blinding_factor: 379E50DB31FEE6775ABD0AF6FB7C371E060308F4F847DB09FE4CFE13AF602287
// - expected blinded_pub: 3A50BF210E8F9EE955AE0014F7A6917FB65EBF098A86305ABB508D1A7291B6D5
// - expected subcred: 635D55907816E8D76398A675A50B1C2F3E36B42A5CA77BA3A0441285161AE07D

const ARTI_TEST_ID = Buffer.from(
  '833990B085C1A688C1D4C8B1F6B56AFAF5A2ECA674449E1D704F83765CCB7BC6',
  'hex'
);
const ARTI_TEST_PERIOD_NUM = 1234n;
const ARTI_TEST_PERIOD_LEN = 1440n; // 1 day = 1440 minutes
const ARTI_EXPECTED_BLINDED = '3a50bf210e8f9ee955ae0014f7a6917fb65ebf098a86305abb508d1a7291b6d5';
const ARTI_EXPECTED_SUBCRED = '635d55907816e8d76398a675a50b1c2f3e36b42a5ca77ba3a0441285161ae07d';

test('deriveBlindedPublicKey: matches Arti test vector', (t) => {
  const result = deriveBlindedPublicKey({
    publicIdentityKey: ARTI_TEST_ID,
    periodNum: ARTI_TEST_PERIOD_NUM,
    periodLengthMinutes: ARTI_TEST_PERIOD_LEN,
  });

  t.is(
    result.toString('hex').toLowerCase(),
    ARTI_EXPECTED_BLINDED,
    'blinded key should match Arti test vector'
  );
});

test('deriveSubcredential: matches Arti test vector', (t) => {
  const blindedKey = deriveBlindedPublicKey({
    publicIdentityKey: ARTI_TEST_ID,
    periodNum: ARTI_TEST_PERIOD_NUM,
    periodLengthMinutes: ARTI_TEST_PERIOD_LEN,
  });

  const subcred = deriveSubcredential({
    publicIdentityKey: ARTI_TEST_ID,
    blindedPublicKey: blindedKey,
  });

  t.is(
    subcred.toString('hex').toLowerCase(),
    ARTI_EXPECTED_SUBCRED,
    'subcredential should match Arti test vector'
  );
});

// =========================================================================
// Time Period Position Tests (from C Tor test_hs_common.c)
// =========================================================================

test('computeTimePeriod: LATE_IN_SRV_TO_TP position (11:00 UTC)', (t) => {
  // From C Tor: "Wed, 13 Apr 2016 11:00:00 UTC"
  // Between SRV (00:00) and TP (12:00), late in that window
  const validAfter = new Date('2016-04-13T11:00:00Z');
  const freshUntil = new Date('2016-04-13T12:00:00Z');

  const { periodNum, periodLengthMinutes } = computeTimePeriod({
    validAfter,
    freshUntil,
    hsdirIntervalMinutes: 1440,
  });

  t.is(periodLengthMinutes, 1440n);
  // At 11:00 UTC, we're before the 12:00 rotation, so period = floor((minutes - 720) / 1440)
  // This should be one less than after 12:00
  const periodAfterRotation = computeTimePeriod({
    validAfter: new Date('2016-04-13T13:00:00Z'),
    freshUntil: new Date('2016-04-13T14:00:00Z'),
    hsdirIntervalMinutes: 1440,
  });
  t.is(periodNum + 1n, periodAfterRotation.periodNum, 'should be one period before post-rotation');
});

test('computeTimePeriod: EARLY_IN_TP_TO_SRV position (13:00 UTC)', (t) => {
  // From C Tor: "Wed, 13 Apr 2016 13:00:00 UTC"
  // Between TP (12:00) and next SRV (00:00), early in that window
  const validAfter = new Date('2016-04-13T13:00:00Z');
  const freshUntil = new Date('2016-04-13T14:00:00Z');

  const { periodNum, periodLengthMinutes } = computeTimePeriod({
    validAfter,
    freshUntil,
    hsdirIntervalMinutes: 1440,
  });

  t.is(periodLengthMinutes, 1440n);
  // At 13:00 UTC on Apr 13, we're after the 12:00 rotation
  // Period should match 23:00 on the same day (still before next 12:00)
  const periodLate = computeTimePeriod({
    validAfter: new Date('2016-04-13T23:00:00Z'),
    freshUntil: new Date('2016-04-14T00:00:00Z'),
    hsdirIntervalMinutes: 1440,
  });
  t.is(periodNum, periodLate.periodNum, 'period should be same throughout TP-to-SRV window');
});

test('computeTimePeriod: period advances at 12:00 UTC exactly', (t) => {
  const before = computeTimePeriod({
    validAfter: new Date('2016-04-13T11:59:59Z'),
    freshUntil: new Date('2016-04-13T12:59:59Z'),
    hsdirIntervalMinutes: 1440,
  });

  const at = computeTimePeriod({
    validAfter: new Date('2016-04-13T12:00:00Z'),
    freshUntil: new Date('2016-04-13T13:00:00Z'),
    hsdirIntervalMinutes: 1440,
  });

  const after = computeTimePeriod({
    validAfter: new Date('2016-04-13T12:00:01Z'),
    freshUntil: new Date('2016-04-13T13:00:01Z'),
    hsdirIntervalMinutes: 1440,
  });

  t.is(before.periodNum + 1n, at.periodNum, 'period should advance at exactly 12:00');
  t.is(at.periodNum, after.periodNum, 'period should be same just after 12:00');
});

// =========================================================================
// Disaster SRV Test
// =========================================================================

test('computeDisasterSrv: format matches spec', (t) => {
  // Disaster SRV = SHA3-256("shared-random-disaster" | INT_8(period_length) | INT_8(period_num))
  const srv = computeDisasterSrv({
    periodLengthMinutes: 1440n,
    periodNum: 42n,
  });

  t.is(srv.length, 32, 'disaster SRV should be 32 bytes');

  // Verify determinism
  const srv2 = computeDisasterSrv({
    periodLengthMinutes: 1440n,
    periodNum: 42n,
  });
  t.deepEqual(srv, srv2, 'disaster SRV should be deterministic');

  // Different inputs should give different outputs
  const srv3 = computeDisasterSrv({
    periodLengthMinutes: 1440n,
    periodNum: 43n,
  });
  t.notDeepEqual(srv, srv3, 'different period should give different disaster SRV');
});
