/**
 * Hidden-service hosting (rend-spec-v3 server side).
 *
 * Pairs with the client implementation in `./hidden-service.ts`. This module
 * generates v3 onion identities, builds + uploads descriptors, accepts
 * INTRODUCE2 cells at established introduction points, and completes the
 * hs-ntor handshake at rendezvous points.
 *
 * Protocol references (sections cited in the relevant function):
 *   - rend-spec-v3.txt §2.5  (descriptor format)
 *   - rend-spec-v3.txt §3.1  (ESTABLISH_INTRO)
 *   - rend-spec-v3.txt §3.3  (INTRODUCE2)
 *   - rend-spec-v3.txt §4    (rendezvous + hs-ntor)
 *   - tor-spec.txt §5.2.2    (ntor KH used as ESTABLISH_INTRO MAC_KEY)
 *   - proposal 228 appendix A (curve25519 -> ed25519 enc-key conversion)
 */

// `events` is the standard Node module name and is also the package name
// browser bundlers (webpack, vite via vite-plugin-node-polyfills, etc.)
// shim to a portable EventEmitter implementation. This keeps the host
// usable in service-worker contexts where the goblin-chat-tor example
// runs.
import { EventEmitter } from 'events';
import {
  x25519,
  ed25519,
  sha3_256,
  shake256,
  randomBytes,
  ed25519VerifySync,
  makeAes256CtrKey,
  aes256CtrXor,
} from 'tor-crypto';
import * as ed from '@noble/ed25519';
import { sha512 } from '@noble/hashes/sha512';

import { BytesReader, bufferFromUint } from './util.ts';
import { RelayCell } from './relay-cell.ts';
import {
  Circuit,
  CircuitStream,
  type CircuitCipherPair,
  type PeerInfo,
  type CopyableHash,
} from './circuit.ts';
import { type LinkSpecifier, LinkSpecifierTypes } from './messaging.ts';
import { pickRelayWithFlags } from './build-circuit/util.ts';
import {
  DirectoryClient,
  lookupPeerInfo,
  lookupPeerInfoWithEd25519IdentityKey,
} from './directory-client.ts';
import {
  computeTimePeriod,
  deriveBlindedPublicKey,
  deriveSubcredential,
} from './hidden-service.ts';
import type { VerifiedMicroDescConsensus, MicroDescNodeInfo } from './build-circuit/directory.ts';
import type { TorClient } from './client.ts';

// `@noble/ed25519` needs sha512Sync configured for sync verify/sign. The
// `tor-crypto/curves` module imported above runs that wiring at load time,
// so calling `ed.sign(...)` works directly. We still keep the `sha512`
// import — it's used for the blinded-key seed-expansion and the RH' nonce
// derivation (both SHA-512 per Tor's donna implementation).

// rend-spec-v3 constants
const HASH_LEN = 32; // SHA3-256
const MAC_KEY_LEN = 32;
const S_KEY_LEN = 32; // AES-256 key
const S_IV_LEN = 16; // AES block / iv length
const DESCRIPTOR_PADDING_MULTIPLE = 10000;
const AUTH_CLIENT_PADDING_MULTIPLE = 16;

// Ed25519 certificate types (cert-spec.txt + rend-spec-v3 §2.5.1)
const CERT_TYPE_HS_BLINDED_ID_V_SIGNING = 0x08;
const CERT_TYPE_HS_IP_V_SIGNING = 0x09;
const CERT_TYPE_HS_IP_CC_SIGNING = 0x0b;
const EXT_TYPE_SIGNED_WITH_ED25519_KEY = 0x04;

// hs-ntor protocol id (rend-spec-v3 §3.3)
const HS_NTOR_PROTOID = Buffer.from('tor-hs-ntor-curve25519-sha3-256-1', 'ascii');

// ============================================================================
// Small crypto helpers (mirror hidden-service.ts; intentionally duplicated to
// avoid widening that file's public surface)
// ============================================================================

function sha3(...parts: Buffer[]): Buffer {
  return Buffer.from(sha3_256(Buffer.concat(parts)));
}

function kdfShake256(input: Buffer, length: number): Buffer {
  return Buffer.from(shake256(input, { dkLen: length }));
}

function u64be(n: bigint): Buffer {
  const b = Buffer.alloc(8);
  b.writeBigUInt64BE(n);
  return b;
}

/** SHA3-256 MAC per rend-spec-v3 §0.3: SHA3_256(htonll(len(k)) | k | m). */
function mac(key: Buffer, message: Buffer): Buffer {
  return sha3(u64be(BigInt(key.length)), key, message);
}

/**
 * Domain-separated MAC for descriptor layers (rend-spec-v3 §2.5.1.1):
 * SHA3_256(htonll(len(macKey)) | macKey | htonll(len(salt)) | salt | encrypted).
 */
function dMac(macKey: Buffer, salt: Buffer, encrypted: Buffer): Buffer {
  return sha3(u64be(BigInt(macKey.length)), macKey, u64be(BigInt(salt.length)), salt, encrypted);
}

function bytesToBigIntLE(bytes: Uint8Array): bigint {
  let n = 0n;
  for (let i = bytes.length - 1; i >= 0; i--) {
    n = (n << 8n) | BigInt(bytes[i] ?? 0);
  }
  return n;
}

function bigIntToBytesLE(n: bigint, length: number): Buffer {
  const out = Buffer.alloc(length);
  let temp = n;
  for (let i = 0; i < length; i++) {
    out[i] = Number(temp & 0xffn);
    temp >>= 8n;
  }
  return out;
}

/** Modular inverse via Fermat's little theorem; p must be prime. */
function modInverse(a: bigint, p: bigint): bigint {
  // a^(p-2) mod p
  let result = 1n;
  let base = ((a % p) + p) % p;
  let exp = p - 2n;
  while (exp > 0n) {
    if (exp & 1n) result = (result * base) % p;
    base = (base * base) % p;
    exp >>= 1n;
  }
  return result;
}

/** Browser-compatible CopyableHash backed by SHA3-256. */
class Sha3_256Hash implements CopyableHash {
  private accumulated: Uint8Array[] = [];
  update(data: Buffer | Uint8Array): this {
    this.accumulated.push(Uint8Array.from(data));
    return this;
  }
  copy(): Sha3_256Hash {
    const cloned = new Sha3_256Hash();
    cloned.accumulated = [...this.accumulated];
    return cloned;
  }
  digest(): Buffer {
    const totalLength = this.accumulated.reduce((s, a) => s + a.length, 0);
    const combined = new Uint8Array(totalLength);
    let offset = 0;
    for (const a of this.accumulated) {
      combined.set(a, offset);
      offset += a.length;
    }
    return Buffer.from(sha3_256(combined));
  }
}

function createSha3_256Hash(): Sha3_256Hash {
  return new Sha3_256Hash();
}

/**
 * Convert a curve25519 (Montgomery) public key to its ed25519 (Edwards)
 * equivalent per proposal 228 appendix A.
 *
 * The Edwards y-coordinate is `(u - 1) / (u + 1) mod p`, where u is the
 * Montgomery x-coordinate (the curve25519 pubkey, little-endian). The sign
 * bit (high bit of the last byte) is set to 0 — proposal 228 requires both
 * sides of the certificate use the same convention, and 0 is canonical.
 *
 * Used to build the certified key inside the descriptor's `enc-key-cert`
 * (rend-spec-v3 §2.5.2.2).
 */
function curve25519PubkeyToEd25519(curvePub: Buffer): Buffer {
  if (curvePub.length !== 32) {
    throw new Error(`curve25519 public key must be 32 bytes, got ${curvePub.length}`);
  }
  const p = ed25519.CURVE.Fp.ORDER; // 2^255 - 19
  // Curve25519 spec: clamp the high bit of the input u to zero before use.
  // Tor's encoding doesn't bother because well-formed pubkeys already have
  // the high bit clear, but we mask defensively.
  const ucopy = Buffer.from(curvePub);
  ucopy[31] = (ucopy[31] ?? 0) & 0x7f;
  const u = bytesToBigIntLE(ucopy);
  const num = (u + p - 1n) % p;
  const den = (u + 1n) % p;
  const denInv = modInverse(den, p);
  const y = (num * denInv) % p;
  const out = bigIntToBytesLE(y, 32);
  // Clear sign bit (use canonical positive x). Proposal 228 §A: sign = 0.
  out[31] = (out[31] ?? 0) & 0x7f;
  return out;
}

// ============================================================================
// Public types
// ============================================================================

/** Hidden-service identity (long-term). */
export interface HiddenServiceKeys {
  /** Long-term identity private key (32-byte ed25519 seed). */
  identityPrivateKey: Buffer;
  /** Long-term identity public key (32 bytes). */
  identityPublicKey: Buffer;
  /** Computed .onion address without the trailing `.onion`. */
  onionAddressBase: string;
  /** Full onion address, e.g. `xxxx.onion`. */
  onionAddress: string;
}

/** Time-period-specific descriptor key material. */
export interface TimePeriodKeys {
  periodNum: bigint;
  periodLengthMinutes: bigint;
  /** Canonical encoding of the blinded scalar `a'` (32 bytes). Not a seed. */
  blindedPrivateKey: Buffer;
  /** Blinded public key `BASE * a'` (32 bytes). */
  blindedPublicKey: Buffer;
  /** 64-byte donna-format expanded secret for blinded EdDSA signing. */
  blindedSigningKey: Buffer;
  subcredential: Buffer;
  /** Fresh 32-byte ed25519 seed for the descriptor signing key. */
  descriptorSigningPrivateKey: Buffer;
  descriptorSigningPublicKey: Buffer;
}

/** A live (or pending) introduction point with its per-IP key material. */
export interface IntroductionPoint {
  peerInfo: PeerInfo;
  /** Ed25519 identity key of the IP relay (used for the Ed25519Id link spec). */
  ed25519IdentityKey: Buffer;
  /** KP_hs_ipt_sid private (ed25519 seed). */
  authKeyPrivate: Buffer;
  /** KP_hs_ipt_sid public. */
  authKeyPublic: Buffer;
  /** KP_hss_ntor private (curve25519 scalar). */
  encKeyPrivate: Buffer;
  /** KP_hss_ntor public (curve25519 pubkey). */
  encKeyPublic: Buffer;
  /** Live circuit to the IP (set after ESTABLISH_INTRO succeeds). */
  circuit: Circuit | undefined;
  /** True after we observe INTRO_ESTABLISHED. */
  established: boolean;
}

/** Parsed INTRODUCE2 payload (rend-spec-v3 §3.3). */
export interface Introduce2Parsed {
  authKey: Buffer;
  clientPk: Buffer;
  encryptedData: Buffer;
  macValue: Buffer;
}

/** Decrypted INTRODUCE2 contents. */
export interface Introduce2Decrypted {
  rendezvousCookie: Buffer;
  onionKeyType: number;
  onionKey: Buffer;
  linkSpecifiers: LinkSpecifier[];
}

/** RFC4648 base32 alphabet, lowercase, unpadded. */
function base32EncodeLowerNoPad(buf: Buffer): string {
  const alphabet = 'abcdefghijklmnopqrstuvwxyz234567';
  let bits = 0;
  let value = 0;
  let out = '';
  for (let i = 0; i < buf.length; i++) {
    value = (value << 8) | (buf[i] ?? 0);
    bits += 8;
    while (bits >= 5) {
      out += alphabet[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += alphabet[(value << (5 - bits)) & 31];
  return out;
}

// ============================================================================
// Onion address + key generation
// ============================================================================

/**
 * Compute the v3 onion address from an ed25519 identity public key.
 * Format (address-spec.txt §6): base32(pubkey || checksum || version) + ".onion"
 * where checksum = SHA3-256(".onion checksum" || pubkey || version)[:2].
 */
export function computeOnionAddress(identityPublicKey: Buffer): string {
  const version = Buffer.from([0x03]);
  const checksum = sha3(
    Buffer.from('.onion checksum', 'ascii'),
    identityPublicKey,
    version
  ).subarray(0, 2);
  return base32EncodeLowerNoPad(Buffer.concat([identityPublicKey, checksum, version])) + '.onion';
}

function makeKeysFromSeed(identityPrivateKey: Buffer): HiddenServiceKeys {
  const identityPublicKey = Buffer.from(ed25519.getPublicKey(identityPrivateKey));
  const onionAddress = computeOnionAddress(identityPublicKey);
  const onionAddressBase = onionAddress.slice(0, -'.onion'.length);
  return { identityPrivateKey, identityPublicKey, onionAddressBase, onionAddress };
}

/** Generate a fresh hidden-service identity keypair + onion address. */
export function generateHiddenServiceKeys(): HiddenServiceKeys {
  return makeKeysFromSeed(Buffer.from(ed25519.utils.randomPrivateKey()));
}

/** Recover a hidden-service identity from an existing 32-byte ed25519 seed. */
export function loadHiddenServiceKeys(identityPrivateKey: Buffer): HiddenServiceKeys {
  if (identityPrivateKey.length !== 32) {
    throw new Error(`identityPrivateKey must be 32 bytes, got ${identityPrivateKey.length}`);
  }
  return makeKeysFromSeed(identityPrivateKey);
}

// ============================================================================
// Blinded key derivation (private side)
// ============================================================================

/**
 * Derive the blinded ed25519 keypair for a given time period.
 *
 * The blinding factor `h` is the same as on the client side
 * (`deriveBlindedPublicKey` in hidden-service.ts). Multiplying the identity
 * scalar by `h mod n` yields the blinded scalar; the corresponding public
 * key is `BASE * blindedScalar`. See rend-spec-v3 §A.2.
 *
 * Returns:
 *   - `blindedPrivateKey` (32 bytes): canonical little-endian encoding of
 *     the blinded scalar `a'`. NOT a seed — must be signed with
 *     {@link signWithBlindedKey}, which expects the donna-format expanded
 *     secret `a' || RH'` returned via `blindedSigningKey`.
 *   - `blindedPublicKey` (32 bytes): `BASE * a'`.
 *   - `blindedSigningKey` (64 bytes): the donna-format expanded secret
 *     `a' || RH'` ready to feed to {@link signWithBlindedKey}. Per Tor's
 *     `ed25519_donna_blind_secret_key`, RH' = SHA-512("Derive temporary
 *     signing key hash input" || RH)[:32], where RH = SHA-512(seed)[32:64].
 */
export function deriveBlindedPrivateKey(params: {
  identityPrivateKey: Buffer;
  periodNum: bigint;
  periodLengthMinutes: bigint;
}): { blindedPrivateKey: Buffer; blindedPublicKey: Buffer; blindedSigningKey: Buffer } {
  const blindStr = Buffer.from('Derive temporary signing key\0', 'ascii');
  const basepointStr = Buffer.from(
    '(15112221349535400772501151409588531511454012693041857206046113283949847762202, ' +
      '46316835694926478169428394003475163141307993866256225615783033603165251855960)',
    'ascii'
  );
  const identityPublicKey = Buffer.from(ed25519.getPublicKey(params.identityPrivateKey));
  const N = Buffer.concat([
    Buffer.from('key-blind', 'ascii'),
    u64be(params.periodNum),
    u64be(params.periodLengthMinutes),
  ]);
  const h = Buffer.from(sha3(blindStr, identityPublicKey, basepointStr, N));
  // Clamp `h` per ed25519
  h[0] = (h[0] ?? 0) & 248;
  h[31] = (h[31] ?? 0) & 63;
  h[31] = (h[31] ?? 0) | 64;
  const hScalar = bytesToBigIntLE(h) % ed25519.CURVE.n;

  // Identity scalar = lower 32 bytes of SHA-512(seed), clamped.
  const expanded = Buffer.from(sha512(params.identityPrivateKey));
  const identityScalarBytes = Buffer.from(expanded.subarray(0, 32));
  identityScalarBytes[0] = (identityScalarBytes[0] ?? 0) & 248;
  identityScalarBytes[31] = (identityScalarBytes[31] ?? 0) & 63;
  identityScalarBytes[31] = (identityScalarBytes[31] ?? 0) | 64;
  const identityScalar = bytesToBigIntLE(identityScalarBytes);

  const blindedScalar = (identityScalar * hScalar) % ed25519.CURVE.n;
  const blindedPrivateKey = bigIntToBytesLE(blindedScalar, 32);
  const blindedPublicKey = Buffer.from(
    ed25519.ExtendedPoint.BASE.multiply(blindedScalar).toRawBytes()
  );

  // Build the 64-byte donna-format expanded secret needed for blinded EdDSA
  // signatures. RH' = SHA-512("Derive temporary signing key hash input" || RH).
  const RH = expanded.subarray(32, 64);
  const RHPrime = Buffer.from(
    sha512(
      Buffer.concat([Buffer.from('Derive temporary signing key hash input', 'ascii'), RH])
    )
  ).subarray(0, 32);
  const blindedSigningKey = Buffer.concat([blindedPrivateKey, RHPrime]);

  return { blindedPrivateKey, blindedPublicKey, blindedSigningKey };
}

/**
 * Sign `msg` with a blinded ed25519 expanded secret key per RFC 8032 EdDSA,
 * with the donna twist Tor uses: the scalar is taken directly (not
 * re-expanded/clamped), and the nonce prefix is the second 32 bytes of the
 * input. This matches `ed25519_donna_open_/sign_` behavior used by Tor for
 * blinded keys (see rend-spec-v3 §A.2 and Tor's
 * `ed25519_donna_blind_secret_key` / `ed25519_donna_sign`).
 *
 * Used to sign the descriptor-signing-key cert and any other artefact whose
 * authority chains back to the blinded key. Regular descriptor body / cert
 * signing uses the freshly-generated descriptor signing keypair via
 * `@noble/ed25519`'s normal `ed.sign`.
 */
export function signWithBlindedKey(
  msg: Buffer,
  blindedSigningKey: Buffer,
  blindedPublicKey: Buffer
): Buffer {
  if (blindedSigningKey.length !== 64) {
    throw new Error(`blindedSigningKey must be 64 bytes, got ${blindedSigningKey.length}`);
  }
  const a = bytesToBigIntLE(blindedSigningKey.subarray(0, 32));
  const RHPrime = blindedSigningKey.subarray(32, 64);
  const L = ed25519.CURVE.n;

  // r = SHA-512(RH' || msg) mod L
  const rHash = Buffer.from(sha512(Buffer.concat([RHPrime, msg])));
  const r = bytesToBigIntLE(rHash) % L;

  // R = r * BASE
  const Rpoint = ed25519.ExtendedPoint.BASE.multiply(r);
  const R = Buffer.from(Rpoint.toRawBytes());

  // k = SHA-512(R || A || msg) mod L
  const kHash = Buffer.from(sha512(Buffer.concat([R, blindedPublicKey, msg])));
  const k = bytesToBigIntLE(kHash) % L;

  // S = (r + k * a) mod L
  const S = (r + ((k * a) % L)) % L;
  const Sbytes = bigIntToBytesLE(S, 32);

  return Buffer.concat([R, Sbytes]);
}

/**
 * Derive the full descriptor key bundle for a given consensus's time window.
 * Generates a fresh descriptor signing keypair on each call.
 */
export function deriveTimePeriodKeys(params: {
  keys: HiddenServiceKeys;
  validAfter: Date;
  freshUntil?: Date;
  hsdirIntervalMinutes?: number;
}): TimePeriodKeys {
  const tpArgs: Parameters<typeof computeTimePeriod>[0] = { validAfter: params.validAfter };
  if (params.freshUntil !== undefined) tpArgs.freshUntil = params.freshUntil;
  if (params.hsdirIntervalMinutes !== undefined) {
    tpArgs.hsdirIntervalMinutes = params.hsdirIntervalMinutes;
  }
  const { periodNum, periodLengthMinutes } = computeTimePeriod(tpArgs);

  const { blindedPrivateKey, blindedPublicKey, blindedSigningKey } = deriveBlindedPrivateKey({
    identityPrivateKey: params.keys.identityPrivateKey,
    periodNum,
    periodLengthMinutes,
  });

  const subcredential = deriveSubcredential({
    publicIdentityKey: params.keys.identityPublicKey,
    blindedPublicKey,
  });

  const descriptorSigningPrivateKey = Buffer.from(ed25519.utils.randomPrivateKey());
  const descriptorSigningPublicKey = Buffer.from(
    ed25519.getPublicKey(descriptorSigningPrivateKey)
  );

  return {
    periodNum,
    periodLengthMinutes,
    blindedPrivateKey,
    blindedPublicKey,
    blindedSigningKey,
    subcredential,
    descriptorSigningPrivateKey,
    descriptorSigningPublicKey,
  };
}

// ============================================================================
// Introduction point key generation
// ============================================================================

/**
 * Generate fresh per-IP key material (auth + enc) for a candidate intro point.
 * The IP relay's identity comes in via `peerInfo` + `ed25519IdentityKey`.
 */
export function generateIntroPointKeys(
  peerInfo: PeerInfo,
  ed25519IdentityKey: Buffer
): IntroductionPoint {
  const authKeyPrivate = Buffer.from(ed25519.utils.randomPrivateKey());
  const authKeyPublic = Buffer.from(ed25519.getPublicKey(authKeyPrivate));
  const encKeyPrivate = Buffer.from(x25519.utils.randomPrivateKey());
  const encKeyPublic = Buffer.from(x25519.getPublicKey(encKeyPrivate));
  return {
    peerInfo,
    ed25519IdentityKey,
    authKeyPrivate,
    authKeyPublic,
    encKeyPrivate,
    encKeyPublic,
    circuit: undefined,
    established: false,
  };
}

// ============================================================================
// Ed25519 certificate builder (cert-spec.txt §2.1)
// ============================================================================

/**
 * Build a proposal-220-format ed25519 certificate.
 *
 * Layout: VERSION[1] || CERT_TYPE[1] || EXPIRATION[4] || CERT_KEY_TYPE[1] ||
 *         CERTIFIED_KEY[32] || N_EXTENSIONS[1] || EXT* || SIG[64].
 *
 * `signFn` lets the caller plug in either `ed.sign` (regular seeds) or
 * {@link signWithBlindedKey} (blinded scalars).
 */
function createEd25519Certificate(params: {
  certType: number;
  expirationHours: number;
  certifiedKey: Buffer;
  certifiedKeyType: number;
  signingKey: Buffer; // public key of the signer (goes in optional extension)
  includeSigningKeyExtension: boolean;
  signFn: (msg: Buffer) => Buffer;
}): Buffer {
  const extensions: Buffer[] = [];
  if (params.includeSigningKeyExtension) {
    const extData = params.signingKey;
    const extHeader = Buffer.alloc(4);
    extHeader.writeUInt16BE(extData.length, 0);
    extHeader.writeUInt8(EXT_TYPE_SIGNED_WITH_ED25519_KEY, 2);
    extHeader.writeUInt8(0, 3); // ExtFlags
    extensions.push(Buffer.concat([extHeader, extData]));
  }

  const certBody = Buffer.concat([
    Buffer.from([0x01]), // VERSION
    Buffer.from([params.certType]),
    bufferFromUint(4, params.expirationHours),
    Buffer.from([params.certifiedKeyType]),
    params.certifiedKey,
    Buffer.from([extensions.length]),
    ...extensions,
  ]);

  const signature = params.signFn(certBody);
  return Buffer.concat([certBody, signature]);
}

// ============================================================================
// Descriptor encryption (rend-spec-v3 §2.5.1.1)
// ============================================================================

/**
 * Encrypt a descriptor layer.
 *
 * Output: salt[16] || ciphertext || mac[32]. Plaintext is NUL-padded to a
 * multiple of 10000 bytes before encryption (rend-spec-v3 §2.5.1.1).
 */
async function encryptDescriptorLayer(params: {
  plaintext: Buffer;
  secretData: Buffer;
  subcredential: Buffer;
  revisionCounter: bigint;
  stringConstant: string;
}): Promise<Buffer> {
  const salt = Buffer.from(randomBytes(16));

  const secretInput = Buffer.concat([
    params.secretData,
    params.subcredential,
    u64be(params.revisionCounter),
  ]);

  const keys = kdfShake256(
    Buffer.concat([secretInput, salt, Buffer.from(params.stringConstant, 'ascii')]),
    S_KEY_LEN + S_IV_LEN + MAC_KEY_LEN
  );
  const secretKey = keys.subarray(0, S_KEY_LEN);
  const secretIv = keys.subarray(S_KEY_LEN, S_KEY_LEN + S_IV_LEN);
  const macKey = keys.subarray(S_KEY_LEN + S_IV_LEN);

  // Pad to nearest multiple of DESCRIPTOR_PADDING_MULTIPLE. If the plaintext
  // is already a multiple, add zero padding (matches Tor and Arti).
  const padLen =
    DESCRIPTOR_PADDING_MULTIPLE - (params.plaintext.length % DESCRIPTOR_PADDING_MULTIPLE);
  const paddedPlaintext = Buffer.concat([params.plaintext, Buffer.alloc(padLen, 0)]);

  const encrypted = await aes256CtrXor(secretKey, secretIv, paddedPlaintext);
  const macValue = dMac(macKey, salt, encrypted);

  return Buffer.concat([salt, encrypted, macValue]);
}

/** Build the link-specifiers block: count[1] || (type[1] || len[1] || data[len])*. */
function buildLinkSpecifiersBlock(linkSpecifiers: LinkSpecifier[]): Buffer {
  const parts: Buffer[] = [Buffer.from([linkSpecifiers.length])];
  for (const ls of linkSpecifiers) {
    parts.push(Buffer.from([ls.type]));
    parts.push(Buffer.from([ls.data.length]));
    parts.push(ls.data);
  }
  return Buffer.concat(parts);
}

function pemBlock(name: string, body: Buffer): string[] {
  const lines: string[] = [`-----BEGIN ${name}-----`];
  const b64 = body.toString('base64');
  for (let i = 0; i < b64.length; i += 64) lines.push(b64.slice(i, i + 64));
  lines.push(`-----END ${name}-----`);
  return lines;
}

// ============================================================================
// Descriptor plaintext + assembly (rend-spec-v3 §2.5.2)
// ============================================================================

/**
 * Build the second-layer (inner) plaintext: a `create2-formats` line plus,
 * per intro point, an `introduction-point` block with `onion-key`,
 * `auth-key` cert, `enc-key`, and `enc-key-cert`.
 *
 * The intro-point certs are signed by the descriptor signing key (cert
 * types 0x09 and 0x0b); their certified key is the IP's auth ed25519 key
 * and the curve25519→ed25519 conversion of the IP's enc key respectively.
 */
function generateInnerLayerPlaintext(params: {
  introPoints: IntroductionPoint[];
  timePeriodKeys: TimePeriodKeys;
  certExpirationHours: number;
}): Buffer {
  const lines: string[] = [];
  lines.push('create2-formats 2');

  for (const intro of params.introPoints) {
    const lsBlock = buildLinkSpecifiersBlock(intro.peerInfo.linkSpecifiers);
    lines.push(`introduction-point ${lsBlock.toString('base64')}`);
    lines.push(`onion-key ntor ${intro.peerInfo.onionKey.toString('base64')}`);

    // auth-key cert (type 0x09): certifies the IP's auth ed25519 key,
    // signed by the descriptor signing key.
    const authKeyCert = createEd25519Certificate({
      certType: CERT_TYPE_HS_IP_V_SIGNING,
      expirationHours: params.certExpirationHours,
      certifiedKey: intro.authKeyPublic,
      certifiedKeyType: 0x01, // ed25519
      signingKey: params.timePeriodKeys.descriptorSigningPublicKey,
      includeSigningKeyExtension: true,
      signFn: (msg) => Buffer.from(ed.sign(msg, params.timePeriodKeys.descriptorSigningPrivateKey)),
    });
    lines.push('auth-key');
    lines.push(...pemBlock('ED25519 CERT', authKeyCert));

    lines.push(`enc-key ntor ${intro.encKeyPublic.toString('base64')}`);

    // enc-key-cert (type 0x0b): certifies the ed25519-equivalent of the IP's
    // curve25519 enc key (proposal 228 appendix A), signed by the descriptor
    // signing key.
    const encKeyEd = curve25519PubkeyToEd25519(intro.encKeyPublic);
    const encKeyCert = createEd25519Certificate({
      certType: CERT_TYPE_HS_IP_CC_SIGNING,
      expirationHours: params.certExpirationHours,
      certifiedKey: encKeyEd,
      certifiedKeyType: 0x01, // ed25519
      signingKey: params.timePeriodKeys.descriptorSigningPublicKey,
      includeSigningKeyExtension: true,
      signFn: (msg) => Buffer.from(ed.sign(msg, params.timePeriodKeys.descriptorSigningPrivateKey)),
    });
    lines.push('enc-key-cert');
    lines.push(...pemBlock('ED25519 CERT', encKeyCert));
  }

  return Buffer.from(lines.join('\n') + '\n', 'utf8');
}

/**
 * Build the first-layer (outer-encrypted) plaintext.
 *
 * Includes:
 *   - `desc-auth-type x25519` (always present per spec)
 *   - `desc-auth-ephemeral-key` — a real x25519 pubkey (NOT random bytes)
 *   - exactly N `auth-client` lines, where N is a multiple of 16 (we use 16
 *     fakes when client auth is disabled, hiding presence per §2.5.1.2)
 *   - `encrypted` block containing the second-layer ciphertext
 */
function generateFirstLayerPlaintext(innerEncrypted: Buffer): Buffer {
  // Generate a real ephemeral x25519 keypair so the value is a valid pubkey,
  // not just random bytes (some verifiers reject malformed pubkeys).
  const ephPriv = Buffer.from(x25519.utils.randomPrivateKey());
  const ephPub = Buffer.from(x25519.getPublicKey(ephPriv));

  const lines: string[] = [];
  lines.push('desc-auth-type x25519');
  lines.push(`desc-auth-ephemeral-key ${ephPub.toString('base64')}`);

  // Padding to AUTH_CLIENT_PADDING_MULTIPLE entries with random fakes.
  for (let i = 0; i < AUTH_CLIENT_PADDING_MULTIPLE; i++) {
    const clientId = Buffer.from(randomBytes(8)).toString('base64').replace(/=+$/, '');
    const iv = Buffer.from(randomBytes(16)).toString('base64').replace(/=+$/, '');
    const cookie = Buffer.from(randomBytes(16)).toString('base64').replace(/=+$/, '');
    lines.push(`auth-client ${clientId} ${iv} ${cookie}`);
  }

  lines.push('encrypted');
  lines.push(...pemBlock('MESSAGE', innerEncrypted));
  return Buffer.from(lines.join('\n') + '\n', 'utf8');
}

/**
 * Build a complete v3 hidden-service descriptor as a string.
 *
 * The two encrypted layers, descriptor-signing-key cert, and trailing
 * ed25519 signature line are assembled per rend-spec-v3 §2.5.
 *
 * The descriptor body is signed by the descriptor signing key (a fresh
 * ed25519 keypair); the descriptor signing key cert is in turn signed by
 * the time-period blinded key via {@link signWithBlindedKey}.
 */
export async function generateDescriptor(params: {
  keys: HiddenServiceKeys;
  timePeriodKeys: TimePeriodKeys;
  introPoints: IntroductionPoint[];
  revisionCounter: bigint;
  /** Cert expiration in hours-since-epoch (default: now + 7d). */
  certExpirationHours?: number;
  /** Descriptor lifetime in minutes (default 180 = 3h, the spec maximum). */
  descriptorLifetimeMinutes?: number;
}): Promise<string> {
  const { timePeriodKeys, introPoints, revisionCounter } = params;
  const certExpirationHours =
    params.certExpirationHours ?? Math.floor(Date.now() / (60 * 60 * 1000)) + 24 * 7;
  const descriptorLifetimeMinutes = params.descriptorLifetimeMinutes ?? 180;

  const innerPlaintext = generateInnerLayerPlaintext({
    introPoints,
    timePeriodKeys,
    certExpirationHours,
  });
  const innerEncrypted = await encryptDescriptorLayer({
    plaintext: innerPlaintext,
    secretData: timePeriodKeys.blindedPublicKey,
    subcredential: timePeriodKeys.subcredential,
    revisionCounter,
    stringConstant: 'hsdir-encrypted-data',
  });

  const firstLayerPlaintext = generateFirstLayerPlaintext(innerEncrypted);
  const superencrypted = await encryptDescriptorLayer({
    plaintext: firstLayerPlaintext,
    secretData: timePeriodKeys.blindedPublicKey,
    subcredential: timePeriodKeys.subcredential,
    revisionCounter,
    stringConstant: 'hsdir-superencrypted-data',
  });

  const lines: string[] = [];
  lines.push('hs-descriptor 3');
  lines.push(`descriptor-lifetime ${descriptorLifetimeMinutes}`);

  // descriptor-signing-key-cert (cert type 0x08): signed by the BLINDED key.
  const signingKeyCert = createEd25519Certificate({
    certType: CERT_TYPE_HS_BLINDED_ID_V_SIGNING,
    expirationHours: certExpirationHours,
    certifiedKey: timePeriodKeys.descriptorSigningPublicKey,
    certifiedKeyType: 0x01,
    signingKey: timePeriodKeys.blindedPublicKey,
    includeSigningKeyExtension: true,
    signFn: (msg) =>
      signWithBlindedKey(msg, timePeriodKeys.blindedSigningKey, timePeriodKeys.blindedPublicKey),
  });
  lines.push('descriptor-signing-key-cert');
  lines.push(...pemBlock('ED25519 CERT', signingKeyCert));

  lines.push(`revision-counter ${revisionCounter}`);

  lines.push('superencrypted');
  lines.push(...pemBlock('MESSAGE', superencrypted));

  // Sign the descriptor body with the descriptor signing key. The signed
  // input is "Tor onion service descriptor sig v3" || body, where body is
  // everything BEFORE the trailing "signature" line (rend-spec-v3 §2.5.4).
  const descriptorBody = lines.join('\n') + '\n';
  const sigInput = Buffer.concat([
    Buffer.from('Tor onion service descriptor sig v3', 'ascii'),
    Buffer.from(descriptorBody, 'utf8'),
  ]);
  const signature = Buffer.from(ed.sign(sigInput, timePeriodKeys.descriptorSigningPrivateKey));
  lines.push('signature ' + signature.toString('base64'));

  return lines.join('\n') + '\n';
}

// ============================================================================
// ESTABLISH_INTRO (rend-spec-v3 §3.1.1)
// ============================================================================

/**
 * Build the body of an ESTABLISH_INTRO cell (extensible / "v1" format).
 *
 * Layout:
 *   AUTH_KEY_TYPE   [1] = 0x02 (Ed25519)
 *   AUTH_KEY_LEN    [2]
 *   AUTH_KEY        [AUTH_KEY_LEN]
 *   N_EXTENSIONS    [1]
 *   EXTENSIONS      [variable]
 *   HANDSHAKE_AUTH  [MAC_LEN=32 bytes] = MAC(circuitMacKey, body-so-far)
 *   SIG_LEN         [2 bytes]
 *   SIG             [SIG_LEN bytes]   ed25519 signature with auth key
 *
 * `circuitMacKey` MUST be the last hop's ntor KH (`Circuit.getLastHopNtorKh()`)
 * — anything else and the IP relay will reject the cell. SIG signs
 * "Tor establish-intro cell v1" || (every byte from AUTH_KEY_TYPE through
 * HANDSHAKE_AUTH inclusive).
 */
export function buildEstablishIntroPayload(params: {
  authKeyPublic: Buffer;
  authKeyPrivate: Buffer;
  circuitMacKey: Buffer;
}): Buffer {
  const AUTH_KEY_TYPE_ED25519 = 0x02;

  // Pre-MAC body: AUTH_KEY_TYPE || AUTH_KEY_LEN || AUTH_KEY || N_EXTENSIONS
  const body = Buffer.concat([
    Buffer.from([AUTH_KEY_TYPE_ED25519]),
    bufferFromUint(2, params.authKeyPublic.length),
    params.authKeyPublic,
    Buffer.from([0x00]), // N_EXTENSIONS = 0
  ]);

  // HANDSHAKE_AUTH = MAC(circuitMacKey, body)
  const handshakeAuth = mac(params.circuitMacKey, body);

  // SIG signs "Tor establish-intro cell v1" || body || HANDSHAKE_AUTH.
  const toSign = Buffer.concat([
    Buffer.from('Tor establish-intro cell v1', 'ascii'),
    body,
    handshakeAuth,
  ]);
  const signature = Buffer.from(ed.sign(toSign, params.authKeyPrivate));

  // Cell payload: body || HANDSHAKE_AUTH || SIG_LEN || SIG
  return Buffer.concat([body, handshakeAuth, bufferFromUint(2, signature.length), signature]);
}

// ============================================================================
// INTRODUCE2 (rend-spec-v3 §3.3) — server side
// ============================================================================

/**
 * Parse an INTRODUCE2 payload into its raw fields. Does no crypto; pure
 * structural parsing that mirrors the client's INTRODUCE1 layout.
 *
 *   LEGACY_KEY_ID  [20] (zeros for v3)
 *   AUTH_KEY_TYPE  [1] = 0x02
 *   AUTH_KEY_LEN   [2] = 32
 *   AUTH_KEY       [32]
 *   N_EXTENSIONS   [1]
 *   EXTENSIONS     [variable]   (each: type[1] len[1] data[len])
 *   CLIENT_PK      [32]
 *   ENCRYPTED      [variable, includes trailing 32-byte MAC]
 */
export function parseIntroduce2(payload: Buffer): Introduce2Parsed {
  const reader = new BytesReader(payload);
  reader.readBytes(20); // LEGACY_KEY_ID

  const authKeyType = reader.readUIntBE(1);
  if (authKeyType !== 0x02) {
    throw new Error(`Unexpected INTRODUCE2 auth key type: ${authKeyType}`);
  }
  const authKeyLen = reader.readUIntBE(2);
  if (authKeyLen !== 32) {
    throw new Error(`Unexpected INTRODUCE2 auth key length: ${authKeyLen}`);
  }
  const authKey = reader.readBytes(32);

  const nExtensions = reader.readUIntBE(1);
  for (let i = 0; i < nExtensions; i++) {
    const extType = reader.readUIntBE(1);
    void extType;
    const extLen = reader.readUIntBE(1);
    reader.readBytes(extLen);
  }

  const clientPk = reader.readBytes(32);
  const tail = reader.readRemainder();
  if (tail.length < 32) throw new Error('INTRODUCE2 trailing data too short for MAC');

  const encryptedData = tail.subarray(0, tail.length - 32);
  const macValue = tail.subarray(tail.length - 32);

  return { authKey, clientPk, encryptedData, macValue };
}

/**
 * Decrypt and authenticate an INTRODUCE2 payload, returning the rendezvous
 * cookie + rendezvous-point info the client placed inside.
 *
 * Mirrors the client's hs-ntor INTRODUCE1 encryption: shared secret is
 * `EXP(b, X)` (server enc-key private × client ephemeral pub); KDF is the
 * same SHAKE256 used in {@link encryptDescriptorLayer}; MAC must match the
 * trailing 32 bytes of the INTRODUCE2 payload.
 */
export async function decryptIntroduce2(params: {
  parsed: Introduce2Parsed;
  introPoint: IntroductionPoint;
  subcredential: Buffer;
}): Promise<Introduce2Decrypted> {
  const { parsed, introPoint, subcredential } = params;

  const t_hsenc = Buffer.from(`${HS_NTOR_PROTOID.toString('ascii')}:hs_key_extract`, 'ascii');
  const m_hsexpand = Buffer.from(`${HS_NTOR_PROTOID.toString('ascii')}:hs_key_expand`, 'ascii');

  // EXP(X, b): server enc-key private × client ephemeral pub
  const expXb = Buffer.from(x25519.scalarMult(introPoint.encKeyPrivate, parsed.clientPk));

  const introSecret = Buffer.concat([
    expXb,
    parsed.authKey,
    parsed.clientPk,
    introPoint.encKeyPublic,
    HS_NTOR_PROTOID,
  ]);

  const info = Buffer.concat([m_hsexpand, subcredential]);
  const keys = kdfShake256(Buffer.concat([introSecret, t_hsenc, info]), S_KEY_LEN + MAC_KEY_LEN);
  const encKey = keys.subarray(0, S_KEY_LEN);
  const macKey = keys.subarray(S_KEY_LEN);

  // MAC covers everything from LEGACY_KEY_ID through ENCRYPTED (rend-spec-v3
  // §3.3.2). Reconstruct that input from parsed fields.
  const macInput = Buffer.concat([
    Buffer.alloc(20), // LEGACY_KEY_ID
    Buffer.from([0x02]), // AUTH_KEY_TYPE
    Buffer.from([0x00, 0x20]), // AUTH_KEY_LEN
    parsed.authKey,
    Buffer.from([0x00]), // N_EXT
    parsed.clientPk,
    parsed.encryptedData,
  ]);
  const expected = mac(macKey, macInput);
  if (!expected.equals(parsed.macValue)) {
    throw new Error('INTRODUCE2 MAC verification failed');
  }

  const iv0 = Buffer.alloc(16, 0);
  const decrypted = await aes256CtrXor(encKey, iv0, parsed.encryptedData);

  const r = new BytesReader(decrypted);
  const rendezvousCookie = r.readBytes(20);

  const nExt = r.readUIntBE(1);
  for (let i = 0; i < nExt; i++) {
    r.readUIntBE(1);
    const extLen = r.readUIntBE(1);
    r.readBytes(extLen);
  }

  const onionKeyType = r.readUIntBE(1);
  const onionKeyLen = r.readUIntBE(2);
  const onionKey = r.readBytes(onionKeyLen);

  const nLs = r.readUIntBE(1);
  const linkSpecifiers: LinkSpecifier[] = [];
  for (let i = 0; i < nLs; i++) {
    const lsType = r.readUIntBE(1);
    const lsLen = r.readUIntBE(1);
    const lsData = r.readBytes(lsLen);
    linkSpecifiers.push({ type: lsType, data: lsData });
  }

  return { rendezvousCookie, onionKeyType, onionKey, linkSpecifiers };
}

// ============================================================================
// hs-ntor server side (rend-spec-v3 §4.2)
// ============================================================================

/**
 * Complete the hs-ntor handshake from the server's perspective and produce
 * the RENDEZVOUS1 payload + the rendezvous-circuit cipher pair.
 *
 * The cipher pair is intentionally swapped relative to the client:
 *   - client side `forward` = client→service; the service receives those.
 *   - client side `backward` = service→client; the service writes those.
 *
 * That means the host stores `cipherPair.forward = client's backward`,
 * `cipherPair.backward = client's forward`, so `Circuit.encryptForward` /
 * `decryptBackward` line up with what the client's virtual hop expects.
 */
export function completeHsNtorServer(params: {
  /** X — the client's ephemeral curve25519 pubkey from the INTRODUCE2 cell. */
  clientPk: Buffer;
  introPoint: IntroductionPoint;
  subcredential: Buffer;
}): { rendezvous1Data: Buffer; cipherPair: CircuitCipherPair } {
  const { clientPk, introPoint } = params;

  const y = Buffer.from(x25519.utils.randomPrivateKey());
  const Y = Buffer.from(x25519.getPublicKey(y));

  const t_hsenc = Buffer.from(`${HS_NTOR_PROTOID.toString('ascii')}:hs_key_extract`, 'ascii');
  const t_hsverify = Buffer.from(`${HS_NTOR_PROTOID.toString('ascii')}:hs_verify`, 'ascii');
  const t_hsmac = Buffer.from(`${HS_NTOR_PROTOID.toString('ascii')}:hs_mac`, 'ascii');
  const m_hsexpand = Buffer.from(`${HS_NTOR_PROTOID.toString('ascii')}:hs_key_expand`, 'ascii');

  const expXy = Buffer.from(x25519.scalarMult(y, clientPk));
  const expXb = Buffer.from(x25519.scalarMult(introPoint.encKeyPrivate, clientPk));

  const rendSecret = Buffer.concat([
    expXy,
    expXb,
    introPoint.authKeyPublic,
    introPoint.encKeyPublic,
    clientPk,
    Y,
    HS_NTOR_PROTOID,
  ]);

  const NTOR_KEY_SEED = mac(rendSecret, t_hsenc);
  const verify = mac(rendSecret, t_hsverify);
  const authInput = Buffer.concat([
    verify,
    introPoint.authKeyPublic,
    introPoint.encKeyPublic,
    Y,
    clientPk,
    HS_NTOR_PROTOID,
    Buffer.from('Server', 'ascii'),
  ]);
  const AUTH = mac(authInput, t_hsmac);

  const rendezvous1Data = Buffer.concat([Y, AUTH]);

  // KDF for rendezvous circuit cipher pair. Same shape as the client's
  // makeHsRendezvousCipherPairFromKeySeed but with the directions swapped.
  const K = kdfShake256(
    Buffer.concat([NTOR_KEY_SEED, m_hsexpand]),
    HASH_LEN * 2 + S_KEY_LEN * 2
  );
  const reader = new BytesReader(K);
  const fSeed = reader.readBytes(HASH_LEN);
  const bSeed = reader.readBytes(HASH_LEN);
  const Kf = reader.readBytes(S_KEY_LEN);
  const Kb = reader.readBytes(S_KEY_LEN);

  const forwardDigest = createSha3_256Hash();
  const backwardDigest = createSha3_256Hash();
  forwardDigest.update(fSeed);
  backwardDigest.update(bSeed);

  const forwardKey = makeAes256CtrKey(Kf);
  const backwardKey = makeAes256CtrKey(Kb);

  // Swap forward/backward: from the service's POV, what the client sends as
  // "forward" is what we receive as "backward" and vice versa.
  const cipherPair: CircuitCipherPair = {
    forward: { key: backwardKey, digest: backwardDigest },
    backward: { key: forwardKey, digest: forwardDigest },
  };

  return { rendezvous1Data, cipherPair };
}

// ============================================================================
// HiddenServiceHost — control surface
// ============================================================================

/**
 * Wait for the next relay cell on `circuit` matching `relayCommand`.
 * Resolves with the cell or rejects on timeout / circuit destruction.
 */
async function waitForRelayCommand(
  circuit: Circuit,
  relayCommand: number,
  timeoutMs: number
): Promise<{ streamId: number; relayCommand: number; data: Buffer }> {
  return await new Promise((resolve, reject) => {
    let settled = false;
    const cleanup = () => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      circuit.off('relay', onRelay);
      circuit.off('destroyed', onDestroyed);
    };
    const onRelay = (evt: { streamId: number; relayCommand: number; data: Buffer }) => {
      if (evt.relayCommand !== relayCommand) return;
      cleanup();
      resolve(evt);
    };
    const onDestroyed = () => {
      cleanup();
      reject(new Error(`Circuit destroyed while waiting for relayCommand=${relayCommand}`));
    };
    const timer = setTimeout(() => {
      cleanup();
      reject(new Error(`Timed out waiting for relayCommand=${relayCommand}`));
    }, timeoutMs);
    circuit.on('relay', onRelay);
    circuit.once('destroyed', onDestroyed);
  });
}

/**
 * Look up the rendezvous-point relay's full PeerInfo (onion key + Ed25519 id)
 * given the link specifiers the client sent inside INTRODUCE2.
 *
 * The link specifiers always include the legacy RSA identity digest; we use
 * that to locate the relay in the consensus and then `lookupPeerInfo` to
 * fetch its server descriptor (for ntor onion key + Ed25519 identity).
 *
 * Falls back to a stripped peer if the consensus / directory lookup fails;
 * the caller will then fail at circuit-extension time with a clearer error.
 */
async function rendezvousPointPeerInfo(
  linkSpecifiers: LinkSpecifier[],
  consensus: VerifiedMicroDescConsensus,
  dirClient: DirectoryClient
): Promise<PeerInfo> {
  const legacyId = linkSpecifiers.find((ls) => ls.type === LinkSpecifierTypes.LegacyId);
  if (!legacyId) {
    throw new Error('Rendezvous point link specifiers missing legacy identity');
  }
  const rsaIdHex = legacyId.data.toString('hex');
  const node = consensus.relays.find(
    (r: MicroDescNodeInfo) => r.rsaIdDigest.toString('hex') === rsaIdHex
  );
  if (!node) {
    throw new Error(`Rendezvous point ${rsaIdHex.slice(0, 8)} not in consensus`);
  }
  return await lookupPeerInfo(dirClient, node);
}

/**
 * The HiddenServiceHost orchestrates the server side of a v3 onion service
 * over the Chutney test network: bootstrap → pick + establish intro points
 * → publish descriptor → handle INTRODUCE2 → complete rendezvous.
 *
 * Application code subscribes to the `'rendezvous'` event to receive the
 * rendezvous Circuit (with the virtual hop already added) and is then
 * responsible for handling incoming RELAY_BEGIN / RELAY_DATA / RELAY_END
 * cells per its application protocol.
 *
 * NOTE: the descriptor refresh / rotate-on-time-period machinery is
 * deliberately minimal. It re-uploads on a 30-minute timer, which is fine
 * for the chutney integration test but a real deployment would want to
 * key rotation off the consensus's `valid-after` boundaries.
 */
export class HiddenServiceHost extends EventEmitter {
  readonly keys: HiddenServiceKeys;
  private timePeriodKeys: TimePeriodKeys | undefined;
  private introPoints: IntroductionPoint[] = [];
  private revisionCounter: bigint = 0n;
  private running = false;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  private torClient: TorClient<any> | undefined;
  private refreshInterval: ReturnType<typeof setInterval> | undefined;
  private log: (msg: string) => void;

  constructor(keys?: HiddenServiceKeys, options: { log?: (msg: string) => void } = {}) {
    super();
    this.keys = keys ?? generateHiddenServiceKeys();
    this.log = options.log ?? ((msg) => console.log(`[hs-host] ${msg}`));
  }

  get onionAddress(): string {
    return this.keys.onionAddress;
  }

  /**
   * Start the hidden service over a {@link TorClient}. Bootstraps from the
   * client's already-established consensus + bootstrap circuit, picks +
   * establishes `numIntroPoints` introduction points, and uploads the
   * descriptor to ~6 HSDirs.
   *
   * Works for any TorClient implementation — chutney, mainnet, or
   * Snowflake-backed browser.
   */
  async start(
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    torClient: TorClient<any>,
    options: {
      numIntroPoints?: number;
      perStepTimeoutMs?: number;
      descriptorRefreshMs?: number;
    } = {}
  ): Promise<void> {
    const numIntroPoints = options.numIntroPoints ?? 3;
    const perStepTimeoutMs = options.perStepTimeoutMs ?? 120_000;
    const descriptorRefreshMs = options.descriptorRefreshMs ?? 30 * 60 * 1000;

    if (this.running) throw new Error('Hidden service is already running');

    this.torClient = torClient;
    this.log(`starting hidden service ${this.keys.onionAddress}`);

    const consensus = torClient.consensus;
    if (!consensus.validAfter) {
      throw new Error('TorClient consensus missing valid-after');
    }

    // 1. Derive descriptor key bundle for this consensus's time window.
    const tpArgs: Parameters<typeof deriveTimePeriodKeys>[0] = {
      keys: this.keys,
      validAfter: consensus.validAfter,
    };
    if (consensus.freshUntil) tpArgs.freshUntil = consensus.freshUntil;
    this.timePeriodKeys = deriveTimePeriodKeys(tpArgs);

    // 2. Pick + establish intro points. Mainnet relays advertise rich flag
    //    sets; chutney's tiny network usually only has Running+Stable, so we
    //    accept any relay with Stable+Running and exclude obvious non-IPs.
    const introCandidates = consensus.relays.filter((r) => {
      const flags = r.flags ?? [];
      if (flags.includes('BadExit')) return false;
      if (flags.includes('Authority')) return false;
      return flags.includes('Stable') && flags.includes('Running');
    });
    if (introCandidates.length === 0) {
      throw new Error('No suitable introduction-point candidates in consensus');
    }

    const used: MicroDescNodeInfo[] = [];
    for (let i = 0; i < numIntroPoints && used.length < introCandidates.length; i++) {
      const relay = pickRelayWithFlags(introCandidates, [], used);
      used.push(relay);
      try {
        const { peerInfo, ed25519IdentityKey } = await lookupPeerInfoWithEd25519IdentityKey(
          torClient.dirClient,
          relay
        );
        const intro = generateIntroPointKeys(peerInfo, ed25519IdentityKey);
        await this.establishIntroPoint(intro, perStepTimeoutMs);
        this.introPoints.push(intro);
      } catch (err) {
        this.log(
          `intro point ${relay.nickname} failed: ${err instanceof Error ? err.message : err}`
        );
      }
    }
    if (this.introPoints.filter((i) => i.established).length === 0) {
      throw new Error('Failed to establish any introduction points');
    }
    this.log(`established ${this.introPoints.length} introduction points`);

    // 3. Upload the descriptor.
    await this.uploadDescriptor();

    this.running = true;
    this.refreshInterval = setInterval(() => {
      this.uploadDescriptor().catch((err) =>
        this.log(`descriptor refresh failed: ${err instanceof Error ? err.message : err}`)
      );
    }, descriptorRefreshMs);
    this.refreshInterval.unref?.();

    this.log(`running at ${this.keys.onionAddress}`);
  }

  /** Number of intro points whose ESTABLISH_INTRO is currently acknowledged. */
  numActiveIntroPoints(): number {
    return this.introPoints.filter((i) => i.established && !i.circuit?.isDestroyed).length;
  }

  /**
   * Build a 3-hop circuit terminating at `intro`, send ESTABLISH_INTRO using
   * the last hop's ntor KH as MAC_KEY, and arm an INTRODUCE2 listener.
   */
  private async establishIntroPoint(
    intro: IntroductionPoint,
    timeoutMs: number
  ): Promise<void> {
    if (!this.torClient) {
      throw new Error('Hidden service not bootstrapped (torClient missing)');
    }

    const introCircuit = await this.torClient.buildCircuitToTarget(intro.peerInfo);
    intro.circuit = introCircuit;

    const circuitMacKey = introCircuit.getLastHopNtorKh();
    const payload = buildEstablishIntroPayload({
      authKeyPublic: intro.authKeyPublic,
      authKeyPrivate: intro.authKeyPrivate,
      circuitMacKey,
    });

    await introCircuit.sendRelayMessage({
      streamId: 0,
      relayCommand: RelayCell.ESTABLISH_INTRO,
      data: payload,
    });

    await waitForRelayCommand(introCircuit, RelayCell.INTRO_ESTABLISHED, timeoutMs);
    intro.established = true;

    // Wire up the INTRODUCE2 handler. We don't await — INTRODUCE2 cells are
    // unsolicited from our POV. Errors are logged but don't tear down the IP.
    introCircuit.on('relay', (evt) => {
      if (evt.relayCommand === RelayCell.INTRODUCE2) {
        this.handleIntroduce2(intro, evt.data).catch((err) => {
          this.log(`INTRODUCE2 handling failed: ${err instanceof Error ? err.message : err}`);
          this.emit('introduce2-error', err);
        });
      }
    });
  }

  /**
   * Build, sign, and POST the descriptor to the first ~6 HSDirs in the
   * consensus. Increments `revisionCounter` so refreshes look fresh.
   */
  private async uploadDescriptor(): Promise<void> {
    if (!this.timePeriodKeys || !this.torClient) {
      throw new Error('Hidden service not initialized');
    }

    const established = this.introPoints.filter((i) => i.established);
    if (established.length === 0) {
      this.log('no established intro points; skipping descriptor upload');
      return;
    }

    this.revisionCounter++;
    const descriptor = await generateDescriptor({
      keys: this.keys,
      timePeriodKeys: this.timePeriodKeys,
      introPoints: established,
      revisionCounter: this.revisionCounter,
    });
    this.log(`descriptor generated (rev ${this.revisionCounter}, ${descriptor.length} bytes)`);

    const consensus = this.torClient.consensus;
    const hsdirNodes = consensus.relays.filter((r) => (r.flags ?? []).includes('HSDir'));
    if (hsdirNodes.length === 0) {
      this.log('no HSDir nodes in consensus; cannot publish');
      return;
    }

    let uploads = 0;
    for (const hsdir of hsdirNodes.slice(0, 6)) {
      try {
        const peerInfo = await lookupPeerInfo(this.torClient.dirClient, hsdir);
        const circuit = await this.torClient.buildCircuitToTarget(peerInfo);

        const stream = await circuit.openDirectoryStream();
        const body = Buffer.from(descriptor, 'utf8');
        const request = Buffer.from(
          `POST /tor/hs/3/publish HTTP/1.0\r\n` +
            `Host: hsdir\r\n` +
            `Content-Type: text/plain\r\n` +
            `Content-Length: ${body.length}\r\n` +
            `\r\n`,
          'ascii'
        );
        await stream.write(Buffer.concat([request, body]));

        const responseChunks: Buffer[] = [];
        await new Promise<void>((resolve, reject) => {
          const timer = setTimeout(() => {
            stream.off('data', onData);
            stream.off('end', onEnd);
            reject(new Error('descriptor upload timeout'));
          }, 30_000);
          const onData = (d: Buffer) => responseChunks.push(Buffer.from(d));
          const onEnd = () => {
            clearTimeout(timer);
            resolve();
          };
          stream.on('data', onData);
          stream.once('end', onEnd);
        });

        const responseText = Buffer.concat(responseChunks).toString('utf8');
        if (responseText.startsWith('HTTP/') && responseText.includes(' 200 ')) {
          uploads++;
          this.log(`uploaded to HSDir ${hsdir.nickname}`);
        } else {
          this.log(`HSDir ${hsdir.nickname} rejected: ${responseText.split('\r\n')[0] ?? '(no response)'}`);
        }
        circuit.destroy();
      } catch (err) {
        this.log(
          `HSDir ${hsdir.nickname} upload failed: ${err instanceof Error ? err.message : err}`
        );
      }
    }
    this.log(`descriptor uploaded to ${uploads}/${Math.min(6, hsdirNodes.length)} HSDirs`);
  }

  /**
   * Handle a single INTRODUCE2 cell: parse + decrypt, build a circuit to
   * the rendezvous point, send RENDEZVOUS1 with the cipher pair derived
   * from hs-ntor, attach the virtual hop, and emit `'rendezvous'` to the
   * application.
   *
   * After the rendezvous circuit is up, BEGIN cells from the client are
   * intercepted, server-side {@link CircuitStream} objects are allocated
   * and CONNECTED is sent, and each accepted stream is emitted as
   * `'connection'` for the application.
   */
  private async handleIntroduce2(intro: IntroductionPoint, data: Buffer): Promise<void> {
    if (!this.timePeriodKeys || !this.torClient) {
      throw new Error('Hidden service not initialized');
    }

    const parsed = parseIntroduce2(data);
    const decrypted = await decryptIntroduce2({
      parsed,
      introPoint: intro,
      subcredential: this.timePeriodKeys.subcredential,
    });

    const rendPeer = await rendezvousPointPeerInfo(
      decrypted.linkSpecifiers,
      this.torClient.consensus,
      this.torClient.dirClient
    );

    const rendCircuit = await this.torClient.buildCircuitToTarget(rendPeer);

    const { rendezvous1Data, cipherPair } = completeHsNtorServer({
      clientPk: parsed.clientPk,
      introPoint: intro,
      subcredential: this.timePeriodKeys.subcredential,
    });

    await rendCircuit.sendRelayMessage({
      streamId: 0,
      relayCommand: RelayCell.RENDEZVOUS1,
      data: Buffer.concat([decrypted.rendezvousCookie, rendezvous1Data]),
    });
    rendCircuit.addVirtualHop(cipherPair);

    this.log('rendezvous complete; arming BEGIN handler');
    this.attachServerSideStreamHandler(rendCircuit);
    this.emit('rendezvous', { circuit: rendCircuit });
  }

  /**
   * Intercept BEGIN cells on a rendezvous circuit and surface each as a
   * server-side {@link CircuitStream}. The stream's `write()` is overridden
   * to short-circuit the client-side flow-control machinery and send DATA
   * cells directly via the circuit's last (virtual) hop.
   */
  private attachServerSideStreamHandler(circuit: Circuit): void {
    const acceptStreamId = (streamId: number, destination: string): CircuitStream | undefined => {
      // Reject if a stream with this id already exists (replay or buggy peer).
      if (circuit.streams.some((s) => s.streamId === streamId)) return undefined;

      const stream = new CircuitStream();
      stream.streamId = streamId;
      stream.destination = destination;
      stream.write = async (data: Buffer) => {
        await circuit.sendRelayMessage({
          streamId,
          relayCommand: RelayCell.DATA,
          data,
        });
      };
      // The connectionLatch is a client-side artifact; pre-resolve it so the
      // existing CONNECTED handler in Circuit.receiveRelayMessage doesn't
      // throw if a stray CONNECTED arrives, and so application code that
      // does `await stream.write(...)` doesn't deadlock waiting on it.
      stream.connectionLatch.resolve();
      circuit.streams.push(stream);
      return stream;
    };

    circuit.on(
      'relay',
      (evt: { streamId: number; relayCommand: number; data: Buffer }) => {
        if (evt.relayCommand !== RelayCell.BEGIN) return;
        // BEGIN body: <addr:port>\0<flags 4 bytes>
        const nul = evt.data.indexOf(0);
        if (nul < 0) {
          this.log(`BEGIN streamId=${evt.streamId} missing NUL terminator`);
          return;
        }
        const addrPort = evt.data.subarray(0, nul).toString('ascii');
        const lastColon = addrPort.lastIndexOf(':');
        const portStr = lastColon >= 0 ? addrPort.slice(lastColon + 1) : addrPort;
        const port = Number.parseInt(portStr, 10);

        if (!this.acceptPort(port)) {
          this.log(`refusing BEGIN streamId=${evt.streamId} for port=${port} (filtered)`);
          // Reject with REASON_NOTDIRECTORY (6) — generic "we don't want this".
          circuit.sendRelayMessage({
            streamId: evt.streamId,
            relayCommand: RelayCell.END,
            data: Buffer.from([6]),
          }).catch(() => undefined);
          return;
        }

        const stream = acceptStreamId(evt.streamId, addrPort);
        if (!stream) return;

        // Send CONNECTED (8 zero bytes = no IPv4 + ttl=0) to accept.
        circuit
          .sendRelayMessage({
            streamId: evt.streamId,
            relayCommand: RelayCell.CONNECTED,
            data: Buffer.alloc(8),
          })
          .then(() => {
            // Hand the accepted stream to the application.
            this.emit('connection', stream);
            // Also forward to the per-host onConnection callback if set.
            this.onConnectionCallback?.(stream);
          })
          .catch((err) => {
            this.log(
              `failed to send CONNECTED for stream ${evt.streamId}: ${err instanceof Error ? err.message : err}`
            );
            stream.destroy(err instanceof Error ? err : new Error(String(err)));
          });
      }
    );
  }

  /**
   * Test whether to accept a BEGIN cell for a given destination port.
   * Default: accept everything; overridden via constructor options.
   */
  private acceptPort: (port: number) => boolean = () => true;
  private onConnectionCallback: ((stream: CircuitStream) => void) | undefined;

  /**
   * Override the port-accept policy. Called by the {@link publishHiddenService}
   * factory to enforce the user's `port` setting.
   */
  setAcceptPort(fn: (port: number) => boolean): void {
    this.acceptPort = fn;
  }

  /** Set the per-stream connection callback (used by {@link publishHiddenService}). */
  setOnConnection(cb: (stream: CircuitStream) => void): void {
    this.onConnectionCallback = cb;
  }

  /**
   * Tear down all intro circuits + timers and resolve. Idempotent; never
   * rejects. The injected TorClient is NOT destroyed — the caller owns it.
   */
  async unpublish(): Promise<void> {
    if (!this.running && this.introPoints.length === 0 && !this.refreshInterval) return;
    this.log('stopping hidden service');
    this.running = false;
    if (this.refreshInterval) {
      clearInterval(this.refreshInterval);
      this.refreshInterval = undefined;
    }
    for (const intro of this.introPoints) {
      try {
        intro.circuit?.destroy();
      } catch {
        // best-effort
      }
    }
    this.introPoints = [];
    this.torClient = undefined;
    this.emit('stopped');
  }

  /** Synchronous alias for {@link unpublish} (kept for backward-compat). */
  stop(): void {
    void this.unpublish();
  }
}

// ============================================================================
// Test helpers (re-exports)
// ============================================================================
//
// These are private to the module but exposed for the spec tests so we can
// assert on the small primitives (matching the surface PR #21 had).

export {
  sha3,
  mac,
  dMac,
  kdfShake256,
  base32EncodeLowerNoPad,
  curve25519PubkeyToEd25519,
  encryptDescriptorLayer,
  createEd25519Certificate,
};

// ============================================================================
// publishHiddenService — high-level factory matching HS-HOST-API.md
// ============================================================================

/** Options for {@link publishHiddenService}. */
export interface PublishHiddenServiceOptions {
  /**
   * Bootstrapped TorClient (mainnet, chutney, or browser/Snowflake).
   * Typed as `TorClient<any>` so concrete clients with narrower channel
   * types (e.g. `TorClient<TlsChannelConnection>`) can be passed without a
   * cast — the host only uses the channel-agnostic surface
   * (`consensus`, `dirClient`, `buildCircuitToTarget`).
   */
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  torClient: TorClient<any>;
  /** Virtual port the onion service will accept BEGIN cells for. */
  port: number;
  /** Called once per accepted incoming stream (one per BEGIN). */
  onConnection: (stream: CircuitStream) => void;
  /**
   * 32-byte ed25519 seed that pins the .onion address. If omitted a fresh
   * identity is generated; the caller can persist `host.identityKey`.
   */
  identityKey?: Buffer | Uint8Array;
  /** Number of intro points to maintain (default 3). */
  numIntroPoints?: number;
  /** How often to republish the descriptor (default 30 minutes). */
  descriptorRefreshMs?: number;
  /** Per-step timeout for circuit / handshake operations (default 120s). */
  perStepTimeoutMs?: number;
  log?: (msg: string) => void;
}

/** Handle returned by {@link publishHiddenService}. */
export interface HsHost {
  readonly onion: string;
  readonly identityKey: Uint8Array;
  numActiveIntroPoints(): number;
  unpublish(): Promise<void>;
}

/**
 * Publish a v3 onion service over a {@link TorClient} and surface inbound
 * BEGIN-streams to the application via `onConnection`.
 *
 * Resolves once at least one introduction point is established AND the
 * descriptor has been uploaded to at least one HSDir (the host's start()
 * method enforces that invariant before resolving). Errors during steady
 * state (intro circuit dies, an HSDir 5xx's during refresh) are surfaced
 * via `log` only — they don't reject the original promise or escape.
 *
 * The returned `unpublish()` is idempotent and never rejects. The injected
 * `torClient` is not destroyed; the caller owns it.
 */
export async function publishHiddenService(
  opts: PublishHiddenServiceOptions
): Promise<HsHost> {
  const { torClient, port, onConnection, identityKey, log } = opts;
  if (port <= 0 || port > 0xffff) {
    throw new Error(`Invalid port ${port}`);
  }
  if (typeof onConnection !== 'function') {
    throw new Error('onConnection must be a function');
  }

  const keys = identityKey
    ? loadHiddenServiceKeys(Buffer.from(identityKey))
    : generateHiddenServiceKeys();

  const constructorOpts = log ? { log } : {};
  const host = new HiddenServiceHost(keys, constructorOpts);
  host.setAcceptPort((p) => p === port);
  host.setOnConnection(onConnection);

  const startOpts: Parameters<HiddenServiceHost['start']>[1] = {};
  if (opts.numIntroPoints !== undefined) startOpts.numIntroPoints = opts.numIntroPoints;
  if (opts.descriptorRefreshMs !== undefined) startOpts.descriptorRefreshMs = opts.descriptorRefreshMs;
  if (opts.perStepTimeoutMs !== undefined) startOpts.perStepTimeoutMs = opts.perStepTimeoutMs;

  await host.start(torClient, startOpts);

  return {
    onion: host.onionAddress,
    identityKey: Uint8Array.from(keys.identityPrivateKey),
    numActiveIntroPoints: () => host.numActiveIntroPoints(),
    unpublish: () => host.unpublish(),
  };
}
