import test from 'ava';
import crypto from 'node:crypto';
import { x25519, ed25519 } from '@noble/curves/ed25519';
import * as ed from '@noble/ed25519';
import { sha512 } from '@noble/hashes/sha512';

import {
  generateHiddenServiceKeys,
  loadHiddenServiceKeys,
  deriveBlindedPrivateKey,
  deriveTimePeriodKeys,
  generateIntroPointKeys,
  generateDescriptor,
  buildEstablishIntroPayload,
  parseIntroduce2,
  completeHsNtorServer,
  sha3,
  kdfShake256,
  mac,
  dMac,
  aes256CtrXor,
  base32EncodeLowerNoPad,
  createEd25519Certificate,
  encryptDescriptorLayer,
  type IntroductionPoint,
} from './hidden-service-host.ts';
import {
  parseOnionV3Address,
  deriveBlindedPublicKey,
  deriveSubcredential,
} from './hidden-service.ts';
import { LinkSpecifierTypes } from './messaging.ts';
import type { PeerInfo } from './circuit.ts';

// Enable synchronous ed25519 methods
ed.etc.sha512Sync = (...m) => sha512(ed.etc.concatBytes(...m));

// =============================================================================
// Key Generation Tests
// =============================================================================

test('generateHiddenServiceKeys creates valid keys', (t) => {
  const keys = generateHiddenServiceKeys();

  // Check that all fields are populated
  t.truthy(keys.identityPrivateKey);
  t.truthy(keys.identityPublicKey);
  t.truthy(keys.onionAddressBase);
  t.truthy(keys.onionAddress);

  // Check key lengths
  t.is(keys.identityPrivateKey.length, 32);
  t.is(keys.identityPublicKey.length, 32);

  // Check onion address format
  t.is(keys.onionAddressBase.length, 56);
  t.true(keys.onionAddress.endsWith('.onion'));
  t.is(keys.onionAddress, `${keys.onionAddressBase}.onion`);
});

test('generateHiddenServiceKeys creates unique keys each time', (t) => {
  const keys1 = generateHiddenServiceKeys();
  const keys2 = generateHiddenServiceKeys();

  t.false(keys1.identityPrivateKey.equals(keys2.identityPrivateKey));
  t.false(keys1.identityPublicKey.equals(keys2.identityPublicKey));
  t.not(keys1.onionAddress, keys2.onionAddress);
});

test('loadHiddenServiceKeys recovers the same address from private key', (t) => {
  const original = generateHiddenServiceKeys();
  const loaded = loadHiddenServiceKeys(original.identityPrivateKey);

  t.deepEqual(loaded.identityPrivateKey, original.identityPrivateKey);
  t.deepEqual(loaded.identityPublicKey, original.identityPublicKey);
  t.is(loaded.onionAddressBase, original.onionAddressBase);
  t.is(loaded.onionAddress, original.onionAddress);
});

test('generated onion address is parseable by parseOnionV3Address', (t) => {
  const keys = generateHiddenServiceKeys();
  const parsed = parseOnionV3Address(keys.onionAddress);

  t.deepEqual(parsed.publicIdentityKey, keys.identityPublicKey);
});

// =============================================================================
// Blinded Key Derivation Tests
// =============================================================================

test('deriveBlindedPrivateKey produces consistent public key', (t) => {
  const keys = generateHiddenServiceKeys();
  const periodNum = 1000n;
  const periodLengthMinutes = 1440n;

  const { blindedPrivateKey: _blindedPrivateKey, blindedPublicKey } = deriveBlindedPrivateKey({
    identityPrivateKey: keys.identityPrivateKey,
    periodNum,
    periodLengthMinutes,
  });

  // Check that the blinded public key matches what we'd get from the public key side
  const blindedFromPublic = deriveBlindedPublicKey({
    publicIdentityKey: keys.identityPublicKey,
    periodNum,
    periodLengthMinutes,
  });

  t.deepEqual(blindedPublicKey, blindedFromPublic);
});

test('deriveBlindedPrivateKey produces different keys for different periods', (t) => {
  const keys = generateHiddenServiceKeys();

  const blinded1 = deriveBlindedPrivateKey({
    identityPrivateKey: keys.identityPrivateKey,
    periodNum: 1000n,
    periodLengthMinutes: 1440n,
  });

  const blinded2 = deriveBlindedPrivateKey({
    identityPrivateKey: keys.identityPrivateKey,
    periodNum: 1001n,
    periodLengthMinutes: 1440n,
  });

  t.false(blinded1.blindedPrivateKey.equals(blinded2.blindedPrivateKey));
  t.false(blinded1.blindedPublicKey.equals(blinded2.blindedPublicKey));
});

test('deriveTimePeriodKeys produces valid key material', (t) => {
  const keys = generateHiddenServiceKeys();
  const validAfter = new Date();

  const tpKeys = deriveTimePeriodKeys({
    keys,
    validAfter,
  });

  t.truthy(tpKeys.blindedPrivateKey);
  t.truthy(tpKeys.blindedPublicKey);
  t.truthy(tpKeys.subcredential);
  t.truthy(tpKeys.descriptorSigningPrivateKey);
  t.truthy(tpKeys.descriptorSigningPublicKey);

  t.is(tpKeys.blindedPrivateKey.length, 32);
  t.is(tpKeys.blindedPublicKey.length, 32);
  t.is(tpKeys.subcredential.length, 32);
  t.is(tpKeys.descriptorSigningPrivateKey.length, 32);
  t.is(tpKeys.descriptorSigningPublicKey.length, 32);
});

// =============================================================================
// Crypto Primitive Tests
// =============================================================================

test('sha3 produces 32-byte output', (t) => {
  const result = sha3(Buffer.from('test'));
  t.is(result.length, 32);
});

test('sha3 is deterministic', (t) => {
  const input = Buffer.from('hello world');
  const result1 = sha3(input);
  const result2 = sha3(input);
  t.deepEqual(result1, result2);
});

test('sha3 with multiple inputs is deterministic', (t) => {
  const a = Buffer.from('hello');
  const b = Buffer.from('world');
  const result1 = sha3(a, b);
  const result2 = sha3(a, b);
  t.deepEqual(result1, result2);
});

test('kdfShake256 produces requested length', (t) => {
  const input = Buffer.from('key material');
  const result64 = kdfShake256(input, 64);
  const result128 = kdfShake256(input, 128);

  t.is(result64.length, 64);
  t.is(result128.length, 128);
});

test('mac produces 32-byte output', (t) => {
  const key = Buffer.from('secret key');
  const message = Buffer.from('message');
  const result = mac(key, message);
  t.is(result.length, 32);
});

test('dMac produces 32-byte output', (t) => {
  const macKey = Buffer.from('mac key');
  const salt = Buffer.from('salt');
  const encrypted = Buffer.from('encrypted data');
  const result = dMac(macKey, salt, encrypted);
  t.is(result.length, 32);
});

test('aes256CtrXor is symmetric', (t) => {
  const key = crypto.randomBytes(32);
  const iv = crypto.randomBytes(16);
  const plaintext = Buffer.from('hello world this is a test');

  const encrypted = aes256CtrXor(key, iv, plaintext);
  const decrypted = aes256CtrXor(key, iv, encrypted);

  t.deepEqual(decrypted, plaintext);
});

test('base32EncodeLowerNoPad produces lowercase output', (t) => {
  const input = Buffer.from([0x48, 0x65, 0x6c, 0x6c, 0x6f]); // "Hello"
  const result = base32EncodeLowerNoPad(input);

  t.is(result, result.toLowerCase());
  t.false(result.includes('='));
});

test('base32EncodeLowerNoPad handles various lengths', (t) => {
  // Test different input lengths
  for (let len = 1; len <= 35; len++) {
    const input = crypto.randomBytes(len);
    const encoded = base32EncodeLowerNoPad(input);
    t.truthy(encoded.length > 0);
  }
});

// =============================================================================
// Introduction Point Key Tests
// =============================================================================

test('generateIntroPointKeys creates valid key material', (t) => {
  const peerInfo: PeerInfo = {
    onionKey: crypto.randomBytes(32),
    rsaIdDigest: crypto.randomBytes(20),
    linkSpecifiers: [
      { type: LinkSpecifierTypes.TlsOverTcpIPv4, data: Buffer.from([127, 0, 0, 1, 0x1f, 0x90]) },
      { type: LinkSpecifierTypes.LegacyId, data: crypto.randomBytes(20) },
    ],
  };
  const ed25519Id = crypto.randomBytes(32);

  const intro = generateIntroPointKeys(peerInfo, ed25519Id);

  t.truthy(intro.authKeyPrivate);
  t.truthy(intro.authKeyPublic);
  t.truthy(intro.encKeyPrivate);
  t.truthy(intro.encKeyPublic);

  t.is(intro.authKeyPrivate.length, 32);
  t.is(intro.authKeyPublic.length, 32);
  t.is(intro.encKeyPrivate.length, 32);
  t.is(intro.encKeyPublic.length, 32);

  t.false(intro.established);
  t.deepEqual(intro.peerInfo, peerInfo);
  t.deepEqual(intro.ed25519IdentityKey, ed25519Id);
});

// =============================================================================
// Ed25519 Certificate Tests
// =============================================================================

test('createEd25519Certificate produces valid certificate', (t) => {
  const signingPrivate = Buffer.from(ed25519.utils.randomPrivateKey());
  const signingPublic = Buffer.from(ed25519.getPublicKey(signingPrivate));
  const certifiedKey = crypto.randomBytes(32);

  const cert = createEd25519Certificate({
    certType: 0x09,
    expirationHours: 100000,
    certifiedKey,
    certifiedKeyType: 0x01,
    signingKey: signingPublic,
    signingPrivateKey: signingPrivate,
    includeSigningKeyExtension: true,
  });

  // Should have version, type, expiration, key type, key, extensions, signature
  t.true(cert.length > 64 + 32 + 10);

  // Version should be 0x01
  t.is(cert[0], 0x01);
  // Cert type should match
  t.is(cert[1], 0x09);
});

// =============================================================================
// Descriptor Encryption Tests
// =============================================================================

test('encryptDescriptorLayer produces encrypted output', (t) => {
  const plaintext = Buffer.from('test plaintext data');
  const secretData = crypto.randomBytes(32);
  const subcredential = crypto.randomBytes(32);
  const revisionCounter = 1n;

  const encrypted = encryptDescriptorLayer({
    plaintext,
    secretData,
    subcredential,
    revisionCounter,
    stringConstant: 'hsdir-encrypted-data',
  });

  // Output should have salt (16) + encrypted data (padded) + MAC (32)
  t.true(encrypted.length >= 16 + 10000 + 32);

  // Salt should be random (first 16 bytes)
  const salt = encrypted.subarray(0, 16);
  t.false(salt.every((b) => b === 0));

  // MAC should be at the end (last 32 bytes)
  const macValue = encrypted.subarray(encrypted.length - 32);
  t.is(macValue.length, 32);
});

// =============================================================================
// Descriptor Generation Tests
// =============================================================================

test('generateDescriptor produces valid descriptor format', (t) => {
  const keys = generateHiddenServiceKeys();
  const validAfter = new Date();

  const timePeriodKeys = deriveTimePeriodKeys({
    keys,
    validAfter,
  });

  const peerInfo: PeerInfo = {
    onionKey: crypto.randomBytes(32),
    rsaIdDigest: crypto.randomBytes(20),
    linkSpecifiers: [
      { type: LinkSpecifierTypes.TlsOverTcpIPv4, data: Buffer.from([127, 0, 0, 1, 0x1f, 0x90]) },
      { type: LinkSpecifierTypes.LegacyId, data: crypto.randomBytes(20) },
    ],
  };
  const introPoint = generateIntroPointKeys(peerInfo, crypto.randomBytes(32));

  const descriptor = generateDescriptor({
    keys,
    timePeriodKeys,
    introPoints: [introPoint],
    revisionCounter: 1n,
  });

  // Check descriptor contains required fields
  t.true(descriptor.includes('hs-descriptor 3'));
  t.true(descriptor.includes('descriptor-lifetime 180'));
  t.true(descriptor.includes('descriptor-signing-key-cert'));
  t.true(descriptor.includes('revision-counter 1'));
  t.true(descriptor.includes('superencrypted'));
  t.true(descriptor.includes('-----BEGIN MESSAGE-----'));
  t.true(descriptor.includes('-----END MESSAGE-----'));
  t.true(descriptor.includes('signature '));
});

// =============================================================================
// ESTABLISH_INTRO Payload Tests
// =============================================================================

test('buildEstablishIntroPayload produces valid payload', (t) => {
  const authKeyPrivate = Buffer.from(ed25519.utils.randomPrivateKey());
  const authKeyPublic = Buffer.from(ed25519.getPublicKey(authKeyPrivate));
  const circuitMacKey = crypto.randomBytes(32);

  const payload = buildEstablishIntroPayload({
    authKeyPublic,
    authKeyPrivate,
    circuitMacKey,
  });

  // Should have: type(1) + len(2) + key(32) + nExt(1) + handshakeAuth(32) + sig(64) = 132
  t.is(payload.length, 132);

  // First byte should be auth key type (0x02 for ed25519)
  t.is(payload[0], 0x02);

  // Bytes 1-2 should be auth key length (32)
  t.is(payload.readUInt16BE(1), 32);

  // Bytes 3-34 should be the auth key
  t.deepEqual(payload.subarray(3, 35), authKeyPublic);

  // Byte 35 should be N_EXTENSIONS (0)
  t.is(payload[35], 0);
});

// =============================================================================
// INTRODUCE2 Parsing Tests
// =============================================================================

test('parseIntroduce2 extracts fields correctly', (t) => {
  // Build a mock INTRODUCE2 payload
  const legacyKeyId = Buffer.alloc(20, 0);
  const authKeyType = Buffer.from([0x02]);
  const authKeyLen = Buffer.from([0x00, 0x20]);
  const authKey = crypto.randomBytes(32);
  const nExtensions = Buffer.from([0x00]);
  const clientPk = crypto.randomBytes(32);
  const encryptedData = crypto.randomBytes(100);
  const macValue = crypto.randomBytes(32);

  const payload = Buffer.concat([
    legacyKeyId,
    authKeyType,
    authKeyLen,
    authKey,
    nExtensions,
    clientPk,
    encryptedData,
    macValue,
  ]);

  const parsed = parseIntroduce2(payload);

  t.deepEqual(parsed.authKey, authKey);
  t.deepEqual(parsed.clientPk, clientPk);
  t.deepEqual(parsed.encryptedData, encryptedData);
  t.deepEqual(parsed.macValue, macValue);
});

test('parseIntroduce2 throws on invalid auth key type', (t) => {
  const legacyKeyId = Buffer.alloc(20, 0);
  const authKeyType = Buffer.from([0x01]); // Wrong type
  const authKeyLen = Buffer.from([0x00, 0x20]);
  const authKey = crypto.randomBytes(32);
  const nExtensions = Buffer.from([0x00]);
  const clientPk = crypto.randomBytes(32);
  const encryptedData = crypto.randomBytes(100);
  const macValue = crypto.randomBytes(32);

  const payload = Buffer.concat([
    legacyKeyId,
    authKeyType,
    authKeyLen,
    authKey,
    nExtensions,
    clientPk,
    encryptedData,
    macValue,
  ]);

  t.throws(() => parseIntroduce2(payload), { message: /auth key type/ });
});

// =============================================================================
// hs-ntor Server Completion Tests
// =============================================================================

test('completeHsNtorServer produces valid output', (t) => {
  const clientPrivate = Buffer.from(x25519.utils.randomPrivateKey());
  const clientPk = Buffer.from(x25519.getPublicKey(clientPrivate));

  const peerInfo: PeerInfo = {
    onionKey: crypto.randomBytes(32),
    rsaIdDigest: crypto.randomBytes(20),
    linkSpecifiers: [],
  };
  const introPoint = generateIntroPointKeys(peerInfo, crypto.randomBytes(32));
  const subcredential = crypto.randomBytes(32);

  const result = completeHsNtorServer({
    clientPk,
    introPoint,
    subcredential,
  });

  // rendezvous1Data should be Y (32 bytes) + AUTH (32 bytes) = 64 bytes
  t.is(result.rendezvous1Data.length, 64);

  // cipherPair should have forward and backward ciphers
  t.truthy(result.cipherPair.forward);
  t.truthy(result.cipherPair.backward);
  t.truthy(result.cipherPair.forward.key);
  t.truthy(result.cipherPair.forward.digest);
  t.truthy(result.cipherPair.backward.key);
  t.truthy(result.cipherPair.backward.digest);
});

// =============================================================================
// Integration-like Tests
// =============================================================================

test('full key generation and time period derivation flow', (t) => {
  // Generate identity keys
  const keys = generateHiddenServiceKeys();

  // Verify the address is valid
  const parsed = parseOnionV3Address(keys.onionAddress);
  t.deepEqual(parsed.publicIdentityKey, keys.identityPublicKey);

  // Derive time period keys
  const validAfter = new Date('2025-01-12T00:00:00Z');
  const freshUntil = new Date('2025-01-12T01:00:00Z');

  const tpKeys = deriveTimePeriodKeys({
    keys,
    validAfter,
    freshUntil,
  });

  // Verify subcredential matches what client would compute
  const clientSubcred = deriveSubcredential({
    publicIdentityKey: keys.identityPublicKey,
    blindedPublicKey: tpKeys.blindedPublicKey,
  });
  t.deepEqual(tpKeys.subcredential, clientSubcred);
});

test('descriptor generation with multiple intro points', (t) => {
  const keys = generateHiddenServiceKeys();
  const validAfter = new Date();

  const timePeriodKeys = deriveTimePeriodKeys({
    keys,
    validAfter,
  });

  // Create multiple intro points
  const introPoints: IntroductionPoint[] = [];
  for (let i = 0; i < 3; i++) {
    const peerInfo: PeerInfo = {
      onionKey: crypto.randomBytes(32),
      rsaIdDigest: crypto.randomBytes(20),
      linkSpecifiers: [
        {
          type: LinkSpecifierTypes.TlsOverTcpIPv4,
          data: Buffer.from([127, 0, 0, 1, 0x1f, 0x90 + i]),
        },
        { type: LinkSpecifierTypes.LegacyId, data: crypto.randomBytes(20) },
      ],
    };
    introPoints.push(generateIntroPointKeys(peerInfo, crypto.randomBytes(32)));
  }

  const descriptor = generateDescriptor({
    keys,
    timePeriodKeys,
    introPoints,
    revisionCounter: 42n,
  });

  // Check revision counter
  t.true(descriptor.includes('revision-counter 42'));

  // The descriptor should be properly structured
  t.true(descriptor.startsWith('hs-descriptor 3\n'));
  t.true(descriptor.includes('\nsignature '));
});

test('loading keys preserves ability to generate same descriptors', (t) => {
  const original = generateHiddenServiceKeys();
  const loaded = loadHiddenServiceKeys(original.identityPrivateKey);

  const validAfter = new Date('2025-01-01T00:00:00Z');

  const origTpKeys = deriveTimePeriodKeys({ keys: original, validAfter });
  const loadedTpKeys = deriveTimePeriodKeys({ keys: loaded, validAfter });

  // Time period keys should match (except for random descriptor signing keys)
  t.deepEqual(origTpKeys.blindedPublicKey, loadedTpKeys.blindedPublicKey);
  t.deepEqual(origTpKeys.subcredential, loadedTpKeys.subcredential);
  t.is(origTpKeys.periodNum, loadedTpKeys.periodNum);
  t.is(origTpKeys.periodLengthMinutes, loadedTpKeys.periodLengthMinutes);
});
