/**
 * Test that node.ts and browser.ts export the same API surface.
 *
 * This ensures that the two implementations are interchangeable.
 */

import test from 'ava';
import * as nodeExports from './node.ts';
import * as browserExports from './browser.ts';

test('node and browser exports have the same function names', (t) => {
  const nodeKeys = Object.keys(nodeExports).sort();
  const browserKeys = Object.keys(browserExports).sort();

  t.deepEqual(nodeKeys, browserKeys, 'Export names should match');
});

test('node and browser exports have the same types for each export', (t) => {
  const nodeKeys = Object.keys(nodeExports) as (keyof typeof nodeExports)[];

  for (const key of nodeKeys) {
    const nodeType = typeof nodeExports[key];
    const browserType = typeof browserExports[key as keyof typeof browserExports];

    t.is(nodeType, browserType, `Type of ${key} should match`);
  }
});

// Test individual exports exist
test('sha1 is exported as a function', (t) => {
  t.is(typeof nodeExports.sha1, 'function');
  t.is(typeof browserExports.sha1, 'function');
});

test('sha256 is exported as a function', (t) => {
  t.is(typeof nodeExports.sha256, 'function');
  t.is(typeof browserExports.sha256, 'function');
});

test('sha512 is exported as a function', (t) => {
  t.is(typeof nodeExports.sha512, 'function');
  t.is(typeof browserExports.sha512, 'function');
});

test('sha3_256 is exported as a function', (t) => {
  t.is(typeof nodeExports.sha3_256, 'function');
  t.is(typeof browserExports.sha3_256, 'function');
});

test('shake256 is exported as a function', (t) => {
  t.is(typeof nodeExports.shake256, 'function');
  t.is(typeof browserExports.shake256, 'function');
});

test('hmac is exported as a function', (t) => {
  t.is(typeof nodeExports.hmac, 'function');
  t.is(typeof browserExports.hmac, 'function');
});

test('sha256Hash is exported', (t) => {
  t.truthy(nodeExports.sha256Hash);
  t.truthy(browserExports.sha256Hash);
});

test('randomBytes is exported as a function', (t) => {
  t.is(typeof nodeExports.randomBytes, 'function');
  t.is(typeof browserExports.randomBytes, 'function');
});

test('verifyUnprefixedPkcs1Signature is exported as a function', (t) => {
  t.is(typeof nodeExports.verifyUnprefixedPkcs1Signature, 'function');
  t.is(typeof browserExports.verifyUnprefixedPkcs1Signature, 'function');
});

test('computeRsaKeyFingerprint is exported as a function', (t) => {
  t.is(typeof nodeExports.computeRsaKeyFingerprint, 'function');
  t.is(typeof browserExports.computeRsaKeyFingerprint, 'function');
});

// Test that hash functions produce the same outputs
test('sha1 produces same output in both implementations', (t) => {
  const input = Buffer.from('test data');
  const nodeResult = nodeExports.sha1(input);
  const browserResult = browserExports.sha1(input);

  t.true(nodeResult.equals(browserResult), 'sha1 outputs should match');
});

test('sha256 produces same output in both implementations', (t) => {
  const input = Buffer.from('test data');
  const nodeResult = nodeExports.sha256(input);
  const browserResult = browserExports.sha256(input);

  t.true(nodeResult.equals(browserResult), 'sha256 outputs should match');
});

test('sha512 produces same output in both implementations', (t) => {
  const input = Buffer.from('test data');
  const nodeResult = nodeExports.sha512(input);
  const browserResult = browserExports.sha512(input);

  t.true(nodeResult.equals(browserResult), 'sha512 outputs should match');
});

test('sha3_256 produces same output in both implementations', (t) => {
  const input = Buffer.from('test data');
  const nodeResult = nodeExports.sha3_256(input);
  const browserResult = browserExports.sha3_256(input);

  t.true(nodeResult.equals(browserResult), 'sha3_256 outputs should match');
});

test('shake256 produces same output in both implementations', (t) => {
  const input = Buffer.from('test data');
  const outputLength = 32;

  const nodeResult = nodeExports.shake256(input, { dkLen: outputLength });
  const browserResult = browserExports.shake256(input, { dkLen: outputLength });

  t.deepEqual(nodeResult, browserResult, 'shake256 outputs should match');
});

test('hmac produces same output in both implementations', (t) => {
  const key = Buffer.from('secret key');
  const message = Buffer.from('test message');

  const nodeResult = nodeExports.hmac(nodeExports.sha256Hash, key, message);
  const browserResult = browserExports.hmac(browserExports.sha256Hash, key, message);

  t.deepEqual(nodeResult, browserResult, 'hmac outputs should match');
});

test('randomBytes returns correct length in both implementations', (t) => {
  const size = 32;
  const nodeResult = nodeExports.randomBytes(size);
  const browserResult = browserExports.randomBytes(size);

  t.is(nodeResult.length, size, 'Node randomBytes should return correct length');
  t.is(browserResult.length, size, 'Browser randomBytes should return correct length');
});

test('sha256 with multiple inputs produces same output', (t) => {
  const input1 = Buffer.from('hello');
  const input2 = Buffer.from('world');

  const nodeResult = nodeExports.sha256(input1, input2);
  const browserResult = browserExports.sha256(input1, input2);

  t.true(nodeResult.equals(browserResult), 'sha256 with multiple inputs should match');
});

// Test RSA functions with a real key
const TEST_RSA_PUBLIC_KEY_PEM = `-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBALRiMLAhpFMAl/dstBpWFYmk0QjB4/39kFutAFj3LLmFtuIi031JHZ83
oL/E6WCbLkP5AcTLGgvvDw8+iA88AQCf+Y8lZNhP7a7bP6Lf4gZ+A1zTbLzBsRfj
TmYRaR4YMY9/o2b2GCpmKXcjB3i15Z0HnfrD8sG0sFdoU9Q1dNXJAgMBAAE=
-----END RSA PUBLIC KEY-----`;

test('computeRsaKeyFingerprint produces same output in both implementations', (t) => {
  const nodeResult = nodeExports.computeRsaKeyFingerprint(TEST_RSA_PUBLIC_KEY_PEM);
  const browserResult = browserExports.computeRsaKeyFingerprint(TEST_RSA_PUBLIC_KEY_PEM);

  t.is(nodeResult, browserResult, 'computeRsaKeyFingerprint outputs should match');
});

// Test elliptic curve exports
test('x25519 is exported', (t) => {
  t.truthy(nodeExports.x25519);
  t.truthy(browserExports.x25519);
});

test('ed25519 is exported', (t) => {
  t.truthy(nodeExports.ed25519);
  t.truthy(browserExports.ed25519);
});

test('ed25519VerifySync is exported as a function', (t) => {
  t.is(typeof nodeExports.ed25519VerifySync, 'function');
  t.is(typeof browserExports.ed25519VerifySync, 'function');
});

test('x25519 key generation works in both implementations', (t) => {
  // Generate a private key
  const privateKey = nodeExports.randomBytes(32);

  // Derive public key using both implementations
  const nodePublic = nodeExports.x25519.getPublicKey(privateKey);
  const browserPublic = browserExports.x25519.getPublicKey(privateKey);

  t.deepEqual(nodePublic, browserPublic, 'x25519 public keys should match');
});
