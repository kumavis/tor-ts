import test from 'ava';
import { parseOnionV3Address, isOnionAddress } from './hidden-service.ts';

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
