import test from 'ava';
import { x25519, ed25519, randomBytes, ed25519VerifySync } from 'tor-crypto';
import * as ed from '@noble/ed25519';

import {
  generateHiddenServiceKeys,
  loadHiddenServiceKeys,
  computeOnionAddress,
  deriveBlindedPrivateKey,
  signWithBlindedKey,
  deriveTimePeriodKeys,
  generateIntroPointKeys,
  buildEstablishIntroPayload,
  parseIntroduce2,
  decryptIntroduce2,
  completeHsNtorServer,
  generateDescriptor,
  curve25519PubkeyToEd25519,
  encryptDescriptorLayer,
  createEd25519Certificate,
  type IntroductionPoint,
} from './hidden-service-host.ts';
import { sha3, mac, dMac, kdfShake256, base32EncodeLowerNoPad } from 'tor-crypto';
import {
  parseOnionV3Address,
  deriveBlindedPublicKey,
  deriveSubcredential,
  hsNtorComplete,
  buildIntroduce1Payload,
  makeHsRendezvousCipherPairFromKeySeed,
} from './hidden-service.ts';
import { LinkSpecifierTypes } from './messaging.ts';
import type { PeerInfo } from './circuit.ts';

function makePeerInfo(seed = 0): PeerInfo {
  const _ = seed;
  return {
    onionKey: Buffer.from(x25519.utils.randomPrivateKey()),
    rsaIdDigest: Buffer.from(randomBytes(20)),
    linkSpecifiers: [
      { type: LinkSpecifierTypes.TlsOverTcpIPv4, data: Buffer.from([127, 0, 0, 1, 0x1f, 0x90]) },
      { type: LinkSpecifierTypes.LegacyId, data: Buffer.from(randomBytes(20)) },
    ],
  };
}

// =============================================================================
// Key generation + onion address
// =============================================================================

test('generateHiddenServiceKeys produces 32-byte ed25519 keypair + 56-char onion base', (t) => {
  const keys = generateHiddenServiceKeys();
  t.is(keys.identityPrivateKey.length, 32);
  t.is(keys.identityPublicKey.length, 32);
  t.is(keys.onionAddressBase.length, 56);
  t.is(keys.onionAddress, `${keys.onionAddressBase}.onion`);
});

test('generateHiddenServiceKeys produces unique identities', (t) => {
  const a = generateHiddenServiceKeys();
  const b = generateHiddenServiceKeys();
  t.false(a.identityPrivateKey.equals(b.identityPrivateKey));
  t.not(a.onionAddress, b.onionAddress);
});

test('loadHiddenServiceKeys recovers the same address from the seed', (t) => {
  const original = generateHiddenServiceKeys();
  const loaded = loadHiddenServiceKeys(original.identityPrivateKey);
  t.deepEqual(loaded.identityPublicKey, original.identityPublicKey);
  t.is(loaded.onionAddress, original.onionAddress);
});

test('loadHiddenServiceKeys rejects wrong-sized seeds', (t) => {
  t.throws(() => loadHiddenServiceKeys(Buffer.alloc(31)), { message: /32 bytes/ });
});

test('computeOnionAddress matches the round-trip via parseOnionV3Address', (t) => {
  const keys = generateHiddenServiceKeys();
  const addr = computeOnionAddress(keys.identityPublicKey);
  t.is(addr, keys.onionAddress);
  const { publicIdentityKey } = parseOnionV3Address(addr);
  t.deepEqual(publicIdentityKey, keys.identityPublicKey);
});

// =============================================================================
// Blinded key derivation + EdDSA signing
// =============================================================================

test('deriveBlindedPrivateKey: server blinded public key matches client derivation', (t) => {
  const keys = generateHiddenServiceKeys();
  const periodNum = 1234n;
  const periodLengthMinutes = 1440n;

  const { blindedPublicKey } = deriveBlindedPrivateKey({
    identityPrivateKey: keys.identityPrivateKey,
    periodNum,
    periodLengthMinutes,
  });
  const clientBlinded = deriveBlindedPublicKey({
    publicIdentityKey: keys.identityPublicKey,
    periodNum,
    periodLengthMinutes,
  });
  t.deepEqual(blindedPublicKey, clientBlinded);
});

test('deriveBlindedPrivateKey: different periods produce different keys', (t) => {
  const keys = generateHiddenServiceKeys();
  const a = deriveBlindedPrivateKey({
    identityPrivateKey: keys.identityPrivateKey,
    periodNum: 1000n,
    periodLengthMinutes: 1440n,
  });
  const b = deriveBlindedPrivateKey({
    identityPrivateKey: keys.identityPrivateKey,
    periodNum: 1001n,
    periodLengthMinutes: 1440n,
  });
  t.false(a.blindedPrivateKey.equals(b.blindedPrivateKey));
  t.false(a.blindedPublicKey.equals(b.blindedPublicKey));
});

test('signWithBlindedKey: signature verifies under the blinded public key', (t) => {
  const keys = generateHiddenServiceKeys();
  const { blindedPublicKey, blindedSigningKey } = deriveBlindedPrivateKey({
    identityPrivateKey: keys.identityPrivateKey,
    periodNum: 42n,
    periodLengthMinutes: 1440n,
  });
  const msg = Buffer.from('a descriptor signing key cert body or whatever', 'ascii');
  const sig = signWithBlindedKey(msg, blindedSigningKey, blindedPublicKey);
  t.is(sig.length, 64);
  t.true(ed25519VerifySync(sig, msg, blindedPublicKey));
});

test('signWithBlindedKey: rejects 32-byte blinded private key (must be expanded form)', (t) => {
  const keys = generateHiddenServiceKeys();
  const { blindedPrivateKey, blindedPublicKey } = deriveBlindedPrivateKey({
    identityPrivateKey: keys.identityPrivateKey,
    periodNum: 1n,
    periodLengthMinutes: 1440n,
  });
  t.throws(() => signWithBlindedKey(Buffer.from('msg'), blindedPrivateKey, blindedPublicKey), {
    message: /64 bytes/,
  });
});

test('deriveTimePeriodKeys: subcredential matches client deriveSubcredential', (t) => {
  const keys = generateHiddenServiceKeys();
  const validAfter = new Date('2025-01-12T00:00:00Z');
  const freshUntil = new Date('2025-01-12T01:00:00Z');
  const tp = deriveTimePeriodKeys({ keys, validAfter, freshUntil });
  const expected = deriveSubcredential({
    publicIdentityKey: keys.identityPublicKey,
    blindedPublicKey: tp.blindedPublicKey,
  });
  t.deepEqual(tp.subcredential, expected);
});

test('deriveTimePeriodKeys: emits both 32-byte private + 64-byte signing key', (t) => {
  const keys = generateHiddenServiceKeys();
  const tp = deriveTimePeriodKeys({ keys, validAfter: new Date() });
  t.is(tp.blindedPrivateKey.length, 32);
  t.is(tp.blindedSigningKey.length, 64);
  // The first 32 bytes of the signing key are the canonical scalar.
  t.deepEqual(tp.blindedSigningKey.subarray(0, 32), tp.blindedPrivateKey);
});

// =============================================================================
// Crypto primitives (sanity)
// =============================================================================

test('sha3 is deterministic and 32 bytes', (t) => {
  const a = sha3(Buffer.from('hello'));
  const b = sha3(Buffer.from('hello'));
  t.is(a.length, 32);
  t.deepEqual(a, b);
});

test('mac vs dMac produce different outputs (different domain separation)', (t) => {
  const k = Buffer.from('a key');
  const m = Buffer.from('a message');
  const macOut = mac(k, m);
  const dMacOut = dMac(k, Buffer.from('salt'), m);
  t.is(macOut.length, 32);
  t.is(dMacOut.length, 32);
  t.false(macOut.equals(dMacOut));
});

test('kdfShake256 honors requested length', (t) => {
  const out = kdfShake256(Buffer.from('seed'), 80);
  t.is(out.length, 80);
});

test('base32EncodeLowerNoPad is lowercase + unpadded', (t) => {
  const out = base32EncodeLowerNoPad(Buffer.from('Hello'));
  t.is(out, out.toLowerCase());
  t.false(out.includes('='));
});

// =============================================================================
// curve25519 -> ed25519 (proposal 228 appendix A)
// =============================================================================

test('curve25519PubkeyToEd25519: deterministic, 32 bytes, sign bit clear', (t) => {
  const u = Buffer.from(x25519.utils.randomPrivateKey());
  const pub = Buffer.from(x25519.getPublicKey(u));
  const ed = curve25519PubkeyToEd25519(pub);
  const ed2 = curve25519PubkeyToEd25519(pub);
  t.is(ed.length, 32);
  t.deepEqual(ed, ed2);
  t.is((ed[31] ?? 0) & 0x80, 0); // sign bit forced to 0
});

test('curve25519PubkeyToEd25519: distinct inputs map to distinct outputs', (t) => {
  const a = Buffer.from(x25519.getPublicKey(x25519.utils.randomPrivateKey()));
  const b = Buffer.from(x25519.getPublicKey(x25519.utils.randomPrivateKey()));
  t.notDeepEqual(curve25519PubkeyToEd25519(a), curve25519PubkeyToEd25519(b));
});

test('curve25519PubkeyToEd25519: rejects non-32-byte input', (t) => {
  t.throws(() => curve25519PubkeyToEd25519(Buffer.alloc(31)), { message: /32 bytes/ });
});

// =============================================================================
// ESTABLISH_INTRO byte format + signature
// =============================================================================

test('buildEstablishIntroPayload: byte layout matches rend-spec-v3 §3.1.1', (t) => {
  const authKeyPrivate = Buffer.from(ed25519.utils.randomPrivateKey());
  const authKeyPublic = Buffer.from(ed25519.getPublicKey(authKeyPrivate));
  const circuitMacKey = Buffer.from(randomBytes(20)); // 20-byte ntor KH

  const payload = buildEstablishIntroPayload({
    authKeyPublic,
    authKeyPrivate,
    circuitMacKey,
  });

  // Layout: AUTH_KEY_TYPE(1) || AUTH_KEY_LEN(2) || AUTH_KEY(32) || N_EXT(1)
  //      || HANDSHAKE_AUTH(32) || SIG_LEN(2) || SIG(64) = 134 bytes
  t.is(payload.length, 1 + 2 + 32 + 1 + 32 + 2 + 64);
  t.is(payload[0], 0x02); // AUTH_KEY_TYPE = ed25519
  t.is(payload.readUInt16BE(1), 32);
  t.deepEqual(payload.subarray(3, 35), authKeyPublic);
  t.is(payload[35], 0); // N_EXT
  // SIG_LEN at offset 1+2+32+1+32 = 68
  t.is(payload.readUInt16BE(68), 64);
});

test('buildEstablishIntroPayload: SIG verifies over "Tor establish-intro cell v1" || body || HANDSHAKE_AUTH', (t) => {
  const authKeyPrivate = Buffer.from(ed25519.utils.randomPrivateKey());
  const authKeyPublic = Buffer.from(ed25519.getPublicKey(authKeyPrivate));
  const circuitMacKey = Buffer.from(randomBytes(20));

  const payload = buildEstablishIntroPayload({
    authKeyPublic,
    authKeyPrivate,
    circuitMacKey,
  });

  const body = payload.subarray(0, 36); // through N_EXT
  const handshakeAuth = payload.subarray(36, 68);
  const sig = payload.subarray(70); // skip SIG_LEN

  const signedInput = Buffer.concat([
    Buffer.from('Tor establish-intro cell v1', 'ascii'),
    body,
    handshakeAuth,
  ]);
  t.true(ed25519VerifySync(sig, signedInput, authKeyPublic));
});

// =============================================================================
// Ed25519 certificate
// =============================================================================

test('createEd25519Certificate: produces well-formed cert with signing-key extension', (t) => {
  const sk = Buffer.from(ed25519.utils.randomPrivateKey());
  const pk = Buffer.from(ed25519.getPublicKey(sk));
  const certifiedKey = Buffer.from(randomBytes(32));

  const cert = createEd25519Certificate({
    certType: 0x09,
    expirationHours: 100000,
    certifiedKey,
    certifiedKeyType: 0x01,
    signingKey: pk,
    includeSigningKeyExtension: true,
    signFn: (msg) => Buffer.from(ed.sign(msg, sk)),
  });
  // Body: VERSION(1) + CERT_TYPE(1) + EXPIRATION(4) + KEY_TYPE(1) + KEY(32) + N_EXT(1) + ext(4+32) + SIG(64)
  t.is(cert.length, 1 + 1 + 4 + 1 + 32 + 1 + (4 + 32) + 64);
  t.is(cert[0], 0x01);
  t.is(cert[1], 0x09);
  t.deepEqual(cert.subarray(7, 39), certifiedKey);
});

// =============================================================================
// Descriptor encryption + parse round-trip
// =============================================================================

test('encryptDescriptorLayer: pads to multiple of 10000 bytes + emits MAC tail', async (t) => {
  const enc = await encryptDescriptorLayer({
    plaintext: Buffer.from('hi'),
    secretData: Buffer.from(randomBytes(32)),
    subcredential: Buffer.from(randomBytes(32)),
    revisionCounter: 1n,
    stringConstant: 'hsdir-encrypted-data',
  });
  // salt(16) + ciphertext(>=10000, padded) + mac(32)
  t.is(enc.length, 16 + 10000 + 32);
});

test('generateDescriptor: produces a parseable v3 descriptor with required fields', async (t) => {
  const keys = generateHiddenServiceKeys();
  const tp = deriveTimePeriodKeys({ keys, validAfter: new Date() });
  const intro: IntroductionPoint = generateIntroPointKeys(
    makePeerInfo(),
    Buffer.from(randomBytes(32))
  );

  const descriptor = await generateDescriptor({
    keys,
    timePeriodKeys: tp,
    introPoints: [intro],
    revisionCounter: 7n,
  });

  t.true(descriptor.startsWith('hs-descriptor 3\n'));
  t.true(descriptor.includes('descriptor-lifetime 180'));
  t.true(descriptor.includes('descriptor-signing-key-cert'));
  t.true(descriptor.includes('revision-counter 7'));
  t.true(descriptor.includes('superencrypted'));
  t.true(descriptor.includes('-----BEGIN MESSAGE-----'));
  t.true(descriptor.includes('-----END MESSAGE-----'));
  t.true(descriptor.includes('\nsignature '));
});

// =============================================================================
// INTRODUCE2: client INTRODUCE1 -> server parse + decrypt round-trip
// =============================================================================

test('decryptIntroduce2 round-trips against the client buildIntroduce1Payload', async (t) => {
  // Fix a deterministic-ish setup
  const keys = generateHiddenServiceKeys();
  const tp = deriveTimePeriodKeys({ keys, validAfter: new Date() });
  const intro = generateIntroPointKeys(makePeerInfo(), Buffer.from(randomBytes(32)));

  // Client builds an INTRODUCE1 to this intro point. The 20-byte cookie and
  // a real rendezvous-point PeerInfo are required.
  const rendezvousPoint = makePeerInfo();
  const rendezvousCookie = Buffer.from(randomBytes(20));
  const { payload } = await buildIntroduce1Payload({
    introAuthKeyEd25519: intro.authKeyPublic,
    serviceEncKey: intro.encKeyPublic,
    N_hs_subcred: tp.subcredential,
    rendezvousCookie,
    rendezvousPoint,
  });

  // INTRODUCE1 and INTRODUCE2 share the same payload bytes (the IP just
  // forwards them to the service).
  const parsed = parseIntroduce2(payload);
  t.deepEqual(parsed.authKey, intro.authKeyPublic);

  const decrypted = await decryptIntroduce2({
    parsed,
    introPoint: intro,
    subcredential: tp.subcredential,
  });

  t.deepEqual(decrypted.rendezvousCookie, rendezvousCookie);
  // RP link specifiers should round-trip as-is.
  t.is(decrypted.linkSpecifiers.length, rendezvousPoint.linkSpecifiers.length);
});

test('parseIntroduce2 rejects non-ed25519 auth key type', (t) => {
  // 20 zero bytes (legacy id) + bad type
  const bad = Buffer.concat([Buffer.alloc(20), Buffer.from([0x01])]);
  t.throws(() => parseIntroduce2(bad), { message: /auth key type/ });
});

test('decryptIntroduce2 fails MAC check when subcredential is wrong', async (t) => {
  const keys = generateHiddenServiceKeys();
  const tp = deriveTimePeriodKeys({ keys, validAfter: new Date() });
  const intro = generateIntroPointKeys(makePeerInfo(), Buffer.from(randomBytes(32)));
  const rendezvousPoint = makePeerInfo();
  const { payload } = await buildIntroduce1Payload({
    introAuthKeyEd25519: intro.authKeyPublic,
    serviceEncKey: intro.encKeyPublic,
    N_hs_subcred: tp.subcredential,
    rendezvousCookie: Buffer.from(randomBytes(20)),
    rendezvousPoint,
  });
  const parsed = parseIntroduce2(payload);
  await t.throwsAsync(
    decryptIntroduce2({
      parsed,
      introPoint: intro,
      subcredential: Buffer.from(randomBytes(32)), // wrong
    }),
    { message: /MAC verification failed/ }
  );
});

// =============================================================================
// hs-ntor: server completion vs. client completion → matching cipher pairs
// =============================================================================

test('completeHsNtorServer + hsNtorComplete agree on NTOR_KEY_SEED → cipher pairs', async (t) => {
  const keys = generateHiddenServiceKeys();
  const tp = deriveTimePeriodKeys({ keys, validAfter: new Date() });
  const intro = generateIntroPointKeys(makePeerInfo(), Buffer.from(randomBytes(32)));

  // Client builds INTRODUCE1 against this intro point (gives us X + state).
  const rendezvousPoint = makePeerInfo();
  const { payload, state } = await buildIntroduce1Payload({
    introAuthKeyEd25519: intro.authKeyPublic,
    serviceEncKey: intro.encKeyPublic,
    N_hs_subcred: tp.subcredential,
    rendezvousCookie: Buffer.from(randomBytes(20)),
    rendezvousPoint,
  });
  const parsed = parseIntroduce2(payload);

  // Server completes hs-ntor → produces RENDEZVOUS1 data + a cipher pair.
  const { rendezvous1Data, cipherPair: serverPair } = completeHsNtorServer({
    clientPk: parsed.clientPk,
    introPoint: intro,
    subcredential: tp.subcredential,
  });

  // Client receives RENDEZVOUS1 → derives NTOR_KEY_SEED → builds matching pair.
  const Y = rendezvous1Data.subarray(0, 32);
  const auth = rendezvous1Data.subarray(32, 64);
  const { NTOR_KEY_SEED } = hsNtorComplete({ state, Y, auth });
  const clientPair = makeHsRendezvousCipherPairFromKeySeed(NTOR_KEY_SEED);

  // The roles flip on the server side. Encrypting with the client's "forward"
  // produces ciphertext the server decrypts with its "backward". A simple
  // symmetric round-trip through both ciphers should land back on plaintext.
  const plaintext = Buffer.from(randomBytes(64));
  const cipherText = await clientPair.forward.key.encrypt(plaintext);
  const recovered = await serverPair.backward.key.decrypt(Buffer.from(cipherText));
  t.deepEqual(Buffer.from(recovered), plaintext);

  // And vice-versa: server forward → client backward should also round-trip.
  const responsePlain = Buffer.from(randomBytes(48));
  const responseCipher = await serverPair.forward.key.encrypt(responsePlain);
  const responseRecovered = await clientPair.backward.key.decrypt(Buffer.from(responseCipher));
  t.deepEqual(Buffer.from(responseRecovered), responsePlain);
});

// (`hsNtorDeriveEncAndMac` ↔ server agreement is already covered by the
// "decryptIntroduce2 round-trips against the client buildIntroduce1Payload"
// test above — that exercises the full client-encrypt → server-decrypt
// path including the KDF, so a separate placeholder is just dead weight.)

// =============================================================================
// publishHiddenService — surface + argument validation
// =============================================================================

import { publishHiddenService } from './hidden-service-host.ts';

test('publishHiddenService is exported as a function', (t) => {
  t.is(typeof publishHiddenService, 'function');
});

test('publishHiddenService rejects out-of-range ports', async (t) => {
  // We don't need a real TorClient — the port check fires first.
  await t.throwsAsync(
    publishHiddenService({
      // @ts-expect-error — passing a stub torClient on purpose
      torClient: {},
      port: 0,
      onConnection: () => {},
    }),
    { message: /Invalid port/ }
  );
  await t.throwsAsync(
    publishHiddenService({
      // @ts-expect-error
      torClient: {},
      port: 70000,
      onConnection: () => {},
    }),
    { message: /Invalid port/ }
  );
});

test('publishHiddenService rejects non-function onConnection', async (t) => {
  await t.throwsAsync(
    publishHiddenService({
      // @ts-expect-error
      torClient: {},
      port: 80,
      // @ts-expect-error
      onConnection: 'not a function',
    }),
    { message: /onConnection/ }
  );
});

test('publishHiddenService identityKey is round-trippable as a 32-byte seed', (t) => {
  // Independent of publishHiddenService (which needs a TorClient): just
  // assert generateHiddenServiceKeys + loadHiddenServiceKeys preserve the
  // seed exactly, which is what the round-trip property guarantees.
  const a = generateHiddenServiceKeys();
  const b = loadHiddenServiceKeys(a.identityPrivateKey);
  t.deepEqual(Uint8Array.from(b.identityPrivateKey), Uint8Array.from(a.identityPrivateKey));
  t.is(b.onionAddress, a.onionAddress);
});
