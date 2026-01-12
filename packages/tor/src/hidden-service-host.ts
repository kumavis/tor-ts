/**
 * Hidden Service Hosting Support
 *
 * This module implements v3 onion service hosting (rend-spec-v3.txt).
 * It allows creating and running a hidden service that can accept connections
 * from Tor clients.
 *
 * Key concepts:
 * - Identity key pair (KP_hs_id): Long-term ed25519 key, forms basis of .onion address
 * - Blinded key pair (KP_hs_blind_id): Time-period specific blinding of identity key
 * - Descriptor signing key (KP_hs_desc_sign): Signs descriptors
 * - Introduction point auth key (KP_hs_ipt_sid): Authenticates at intro points
 * - Service encryption key (KP_hss_ntor): For hs-ntor key exchange
 */

import crypto from 'node:crypto';
import { EventEmitter } from 'node:events';
import { x25519, ed25519 } from '@noble/curves/ed25519';
import { sha3_256, shake256 } from '@noble/hashes/sha3';
import * as ed from '@noble/ed25519';
import { sha512 } from '@noble/hashes/sha512';
import { BytesReader, bufferFromUint } from './util.ts';
import { RelayCell } from './relay-cell.ts';
import { makeAes256CtrKey } from './aes.ts';
import { Circuit, type CircuitCipherPair, type PeerInfo, type CopyableHash } from './circuit.ts';
import { TlsChannelConnection } from './channel.ts';
import type { LinkSpecifier } from './messaging.ts';
import { LinkSpecifierTypes } from './messaging.ts';
import {
  getChutneyMicrodescConsensus,
  getRandomChutneyCircuitPath,
  getRandomChutneyCircuitPathToTargetSafe,
} from './build-circuit/chutney.ts';
import { pickRelayWithFlags } from './build-circuit/util.ts';
import {
  DirectoryClient,
  lookupPeerInfo,
  lookupPeerInfoWithEd25519IdentityKey,
} from './directory-client.ts';
import { computeTimePeriod, deriveSubcredential } from './hidden-service.ts';

// Enable synchronous ed25519 methods
ed.etc.sha512Sync = (...m) => sha512(ed.etc.concatBytes(...m));

// Constants from rend-spec-v3
const HASH_LEN = 32; // SHA3-256
const MAC_KEY_LEN = 32;
const S_KEY_LEN = 32; // AES-256 key
const S_IV_LEN = 16; // AES block/iv length

// Ed25519 certificate types for hidden services
const CERT_TYPE_HS_BLINDED_ID_V_SIGNING = 0x08;
const CERT_TYPE_HS_IP_V_SIGNING = 0x09;
const CERT_TYPE_HS_IP_CC_SIGNING = 0x0b;

// Extension types
const EXT_TYPE_SIGNED_WITH_ED25519_KEY = 0x04;

// hs-ntor protocol ID
const HS_NTOR_PROTOID = Buffer.from('tor-hs-ntor-curve25519-sha3-256-1', 'ascii');

/**
 * Browser-compatible SHA3-256 hash wrapper.
 */
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
    const totalLength = this.accumulated.reduce((sum, arr) => sum + arr.length, 0);
    const combined = new Uint8Array(totalLength);
    let offset = 0;
    for (const arr of this.accumulated) {
      combined.set(arr, offset);
      offset += arr.length;
    }
    return Buffer.from(sha3_256(combined));
  }
}

function createSha3_256Hash(): Sha3_256Hash {
  return new Sha3_256Hash();
}

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

function mac(key: Buffer, message: Buffer): Buffer {
  const keyLen = u64be(BigInt(key.length));
  return sha3(keyLen, key, message);
}

function dMac(macKey: Buffer, salt: Buffer, encrypted: Buffer): Buffer {
  const macKeyLen = u64be(BigInt(macKey.length));
  const saltLen = u64be(BigInt(salt.length));
  return sha3(macKeyLen, macKey, saltLen, salt, encrypted);
}

function aes256CtrXor(key: Buffer, iv: Buffer, data: Buffer): Buffer {
  const cipher = crypto.createCipheriv('aes-256-ctr', key, iv);
  return Buffer.concat([cipher.update(data), cipher.final()]);
}

function bytesToBigIntLE(bytes: Uint8Array): bigint {
  let n = 0n;
  for (let i = bytes.length - 1; i >= 0; i--) {
    n = (n << 8n) | BigInt(bytes[i] ?? 0);
  }
  return n;
}

/**
 * Base32 encode (RFC4648, lowercase, no padding)
 */
function base32EncodeLowerNoPad(buf: Buffer): string {
  const alphabet = 'abcdefghijklmnopqrstuvwxyz234567';
  let bits = 0;
  let value = 0;
  let output = '';

  for (let i = 0; i < buf.length; i++) {
    value = (value << 8) | (buf[i] ?? 0);
    bits += 8;
    while (bits >= 5) {
      output += alphabet[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }

  if (bits > 0) {
    output += alphabet[(value << (5 - bits)) & 31];
  }

  return output;
}

/**
 * Hidden service key material
 */
export interface HiddenServiceKeys {
  /** Long-term identity private key (ed25519) */
  identityPrivateKey: Buffer;
  /** Long-term identity public key (ed25519) */
  identityPublicKey: Buffer;
  /** Computed .onion address (without .onion suffix) */
  onionAddressBase: string;
  /** Full .onion address */
  onionAddress: string;
}

/**
 * Time-period specific key material
 */
export interface TimePeriodKeys {
  periodNum: bigint;
  periodLengthMinutes: bigint;
  /** Blinded private key for this time period */
  blindedPrivateKey: Buffer;
  /** Blinded public key for this time period */
  blindedPublicKey: Buffer;
  /** Subcredential for this time period */
  subcredential: Buffer;
  /** Descriptor signing private key */
  descriptorSigningPrivateKey: Buffer;
  /** Descriptor signing public key */
  descriptorSigningPublicKey: Buffer;
}

/**
 * Introduction point configuration
 */
export interface IntroductionPoint {
  /** The relay serving as introduction point */
  peerInfo: PeerInfo;
  /** Ed25519 identity key of the intro point relay */
  ed25519IdentityKey: Buffer;
  /** Auth key private (KP_hs_ipt_sid) */
  authKeyPrivate: Buffer;
  /** Auth key public (KP_hs_ipt_sid) */
  authKeyPublic: Buffer;
  /** Service encryption key private (KP_hss_ntor) - curve25519 */
  encKeyPrivate: Buffer;
  /** Service encryption key public (KP_hss_ntor) - curve25519 */
  encKeyPublic: Buffer;
  /** Circuit to the introduction point */
  circuit: Circuit | undefined;
  /** Whether ESTABLISH_INTRO has been acknowledged */
  established: boolean;
}

/**
 * Generate new hidden service identity keys
 */
export function generateHiddenServiceKeys(): HiddenServiceKeys {
  const identityPrivateKey = Buffer.from(ed25519.utils.randomPrivateKey());
  const identityPublicKey = Buffer.from(ed25519.getPublicKey(identityPrivateKey));

  // Compute .onion address: base32(pubkey || checksum || version)
  const version = Buffer.from([0x03]);
  const checksumInput = Buffer.concat([
    Buffer.from('.onion checksum', 'ascii'),
    identityPublicKey,
    version,
  ]);
  const checksum = sha3(checksumInput).subarray(0, 2);
  const addressBytes = Buffer.concat([identityPublicKey, checksum, version]);
  const onionAddressBase = base32EncodeLowerNoPad(addressBytes);

  return {
    identityPrivateKey,
    identityPublicKey,
    onionAddressBase,
    onionAddress: `${onionAddressBase}.onion`,
  };
}

/**
 * Load hidden service keys from existing key material
 */
export function loadHiddenServiceKeys(identityPrivateKey: Buffer): HiddenServiceKeys {
  const identityPublicKey = Buffer.from(ed25519.getPublicKey(identityPrivateKey));

  const version = Buffer.from([0x03]);
  const checksumInput = Buffer.concat([
    Buffer.from('.onion checksum', 'ascii'),
    identityPublicKey,
    version,
  ]);
  const checksum = sha3(checksumInput).subarray(0, 2);
  const addressBytes = Buffer.concat([identityPublicKey, checksum, version]);
  const onionAddressBase = base32EncodeLowerNoPad(addressBytes);

  return {
    identityPrivateKey,
    identityPublicKey,
    onionAddressBase,
    onionAddress: `${onionAddressBase}.onion`,
  };
}

/**
 * Derive the blinded private key from identity private key and time period parameters.
 *
 * Per rend-spec-v3.txt section 2.2.1:
 * The blinded private key is computed by multiplying the identity private scalar
 * by the blinding factor h (which is the same used for public key blinding).
 */
export function deriveBlindedPrivateKey(params: {
  identityPrivateKey: Buffer;
  periodNum: bigint;
  periodLengthMinutes: bigint;
}): { blindedPrivateKey: Buffer; blindedPublicKey: Buffer } {
  // Compute the blinding factor h (same as for public key blinding)
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
  const hRaw = sha3(blindStr, identityPublicKey, basepointStr, N);
  const h = Buffer.from(hRaw);

  // Clamp per ed25519 spec
  h[0] = (h[0] ?? 0) & 248;
  h[31] = (h[31] ?? 0) & 63;
  h[31] = (h[31] ?? 0) | 64;

  // Get the identity private scalar from the seed
  // ed25519 private key is a 32-byte seed, hash it to get the scalar
  const privateHash = Buffer.from(sha512(params.identityPrivateKey));
  const identityScalar = privateHash.subarray(0, 32);
  // Clamp the identity scalar
  identityScalar[0] = (identityScalar[0] ?? 0) & 248;
  identityScalar[31] = (identityScalar[31] ?? 0) & 63;
  identityScalar[31] = (identityScalar[31] ?? 0) | 64;

  // Multiply scalars: blindedScalar = identityScalar * h mod n
  const n = ed25519.CURVE.n;
  const identityScalarInt = bytesToBigIntLE(identityScalar);
  const hInt = bytesToBigIntLE(h);
  const blindedScalarInt = (identityScalarInt * hInt) % n;

  // Convert back to little-endian bytes
  const blindedPrivateKey = Buffer.alloc(32);
  let temp = blindedScalarInt;
  for (let i = 0; i < 32; i++) {
    blindedPrivateKey[i] = Number(temp & 0xffn);
    temp >>= 8n;
  }

  // Compute blinded public key by multiplying base point by blinded scalar
  const blindedPublicKey = Buffer.from(
    ed25519.ExtendedPoint.BASE.multiply(blindedScalarInt).toRawBytes()
  );

  return { blindedPrivateKey, blindedPublicKey };
}

/**
 * Derive time-period specific keys
 */
export function deriveTimePeriodKeys(params: {
  keys: HiddenServiceKeys;
  validAfter: Date;
  freshUntil?: Date;
  hsdirIntervalMinutes?: number;
}): TimePeriodKeys {
  const timePeriodArgs: { validAfter: Date; freshUntil?: Date; hsdirIntervalMinutes?: number } = {
    validAfter: params.validAfter,
  };
  if (params.freshUntil !== undefined) {
    timePeriodArgs.freshUntil = params.freshUntil;
  }
  if (params.hsdirIntervalMinutes !== undefined) {
    timePeriodArgs.hsdirIntervalMinutes = params.hsdirIntervalMinutes;
  }
  const { periodNum, periodLengthMinutes } = computeTimePeriod(timePeriodArgs);

  const { blindedPrivateKey, blindedPublicKey } = deriveBlindedPrivateKey({
    identityPrivateKey: params.keys.identityPrivateKey,
    periodNum,
    periodLengthMinutes,
  });

  const subcredential = deriveSubcredential({
    publicIdentityKey: params.keys.identityPublicKey,
    blindedPublicKey,
  });

  // Generate descriptor signing key pair
  const descriptorSigningPrivateKey = Buffer.from(ed25519.utils.randomPrivateKey());
  const descriptorSigningPublicKey = Buffer.from(ed25519.getPublicKey(descriptorSigningPrivateKey));

  return {
    periodNum,
    periodLengthMinutes,
    blindedPrivateKey,
    blindedPublicKey,
    subcredential,
    descriptorSigningPrivateKey,
    descriptorSigningPublicKey,
  };
}

/**
 * Generate introduction point key material
 */
export function generateIntroPointKeys(
  peerInfo: PeerInfo,
  ed25519IdentityKey: Buffer
): IntroductionPoint {
  // Generate auth key (ed25519)
  const authKeyPrivate = Buffer.from(ed25519.utils.randomPrivateKey());
  const authKeyPublic = Buffer.from(ed25519.getPublicKey(authKeyPrivate));

  // Generate encryption key (curve25519 for hs-ntor)
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

/**
 * Create an Ed25519 certificate (tor-cert.txt format)
 */
function createEd25519Certificate(params: {
  certType: number;
  expirationHours: number;
  certifiedKey: Buffer;
  certifiedKeyType: number;
  signingKey: Buffer;
  signingPrivateKey: Buffer;
  includeSigningKeyExtension: boolean;
}): Buffer {
  // VERSION [1 byte] = 0x01
  // CERT_TYPE [1 byte]
  // EXPIRATION_DATE [4 bytes] = hours since epoch
  // CERT_KEY_TYPE [1 byte]
  // CERTIFIED_KEY [32 bytes]
  // N_EXTENSIONS [1 byte]
  // EXTENSIONS [variable]
  // SIGNATURE [64 bytes]

  const extensions: Buffer[] = [];
  if (params.includeSigningKeyExtension) {
    // Extension: SIGNED_WITH_ED25519_KEY
    const extData = params.signingKey;
    const extHeader = Buffer.alloc(4);
    extHeader.writeUInt16BE(extData.length, 0); // ExtLength
    extHeader.writeUInt8(EXT_TYPE_SIGNED_WITH_ED25519_KEY, 2); // ExtType
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

  // Sign the certificate body
  const signature = Buffer.from(ed.sign(certBody, params.signingPrivateKey));

  return Buffer.concat([certBody, signature]);
}

/**
 * Build link specifiers block for descriptor
 */
function buildLinkSpecifiersBlock(linkSpecifiers: LinkSpecifier[]): Buffer {
  const parts: Buffer[] = [Buffer.from([linkSpecifiers.length])];
  for (const ls of linkSpecifiers) {
    parts.push(Buffer.from([ls.type]));
    parts.push(Buffer.from([ls.data.length]));
    parts.push(ls.data);
  }
  return Buffer.concat(parts);
}

/**
 * Encrypt a layer of the descriptor
 */
function encryptDescriptorLayer(params: {
  plaintext: Buffer;
  secretData: Buffer;
  subcredential: Buffer;
  revisionCounter: bigint;
  stringConstant: string;
}): Buffer {
  const salt = crypto.randomBytes(16);

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

  // Pad plaintext to a multiple of 10000 bytes (rend-spec-v3 padding)
  const padLen = 10000 - (params.plaintext.length % 10000);
  const paddedPlaintext = Buffer.concat([params.plaintext, Buffer.alloc(padLen, 0)]);

  const encrypted = aes256CtrXor(secretKey, secretIv, paddedPlaintext);
  const macValue = dMac(macKey, salt, encrypted);

  return Buffer.concat([salt, encrypted, macValue]);
}

/**
 * Generate the inner (second) layer plaintext of the descriptor
 */
function generateInnerLayerPlaintext(params: {
  introPoints: IntroductionPoint[];
  timePeriodKeys: TimePeriodKeys;
}): Buffer {
  const lines: string[] = [];
  lines.push('create2-formats 2');

  for (const intro of params.introPoints) {
    // introduction-point <link-specifiers-base64>
    const lsBlock = buildLinkSpecifiersBlock(intro.peerInfo.linkSpecifiers);
    lines.push(`introduction-point ${lsBlock.toString('base64')}`);

    // onion-key ntor <ntor-pubkey-base64>
    lines.push(`onion-key ntor ${intro.peerInfo.onionKey.toString('base64')}`);

    // auth-key
    // -----BEGIN ED25519 CERT-----
    // <certificate>
    // -----END ED25519 CERT-----
    const now = Date.now();
    const expirationHours = Math.floor(now / (60 * 60 * 1000)) + 24 * 7; // Valid for 7 days
    const authKeyCert = createEd25519Certificate({
      certType: CERT_TYPE_HS_IP_V_SIGNING,
      expirationHours,
      certifiedKey: intro.authKeyPublic,
      certifiedKeyType: 0x01, // Ed25519 key
      signingKey: params.timePeriodKeys.descriptorSigningPublicKey,
      signingPrivateKey: params.timePeriodKeys.descriptorSigningPrivateKey,
      includeSigningKeyExtension: true,
    });
    lines.push('auth-key');
    lines.push('-----BEGIN ED25519 CERT-----');
    const authKeyCertB64 = authKeyCert.toString('base64');
    for (let i = 0; i < authKeyCertB64.length; i += 64) {
      lines.push(authKeyCertB64.slice(i, i + 64));
    }
    lines.push('-----END ED25519 CERT-----');

    // enc-key ntor <enc-key-base64>
    lines.push(`enc-key ntor ${intro.encKeyPublic.toString('base64')}`);

    // enc-key-cert
    // -----BEGIN ED25519 CERT-----
    // <certificate>
    // -----END ED25519 CERT-----
    // The certified key here is the enc-key converted to ed25519 format
    // For simplicity, we'll use the SHA-256 hash of the curve25519 key
    const encKeyHash = sha3(intro.encKeyPublic);
    const encKeyCert = createEd25519Certificate({
      certType: CERT_TYPE_HS_IP_CC_SIGNING,
      expirationHours,
      certifiedKey: encKeyHash,
      certifiedKeyType: 0x01,
      signingKey: params.timePeriodKeys.descriptorSigningPublicKey,
      signingPrivateKey: params.timePeriodKeys.descriptorSigningPrivateKey,
      includeSigningKeyExtension: true,
    });
    lines.push('enc-key-cert');
    lines.push('-----BEGIN ED25519 CERT-----');
    const encKeyCertB64 = encKeyCert.toString('base64');
    for (let i = 0; i < encKeyCertB64.length; i += 64) {
      lines.push(encKeyCertB64.slice(i, i + 64));
    }
    lines.push('-----END ED25519 CERT-----');
  }

  return Buffer.from(lines.join('\n') + '\n', 'utf8');
}

/**
 * Generate the first (outer encrypted) layer plaintext
 */
function generateFirstLayerPlaintext(innerEncrypted: Buffer): Buffer {
  const lines: string[] = [];
  lines.push('desc-auth-type x25519');
  lines.push('desc-auth-ephemeral-key ' + crypto.randomBytes(32).toString('base64'));
  lines.push('encrypted');
  lines.push('-----BEGIN MESSAGE-----');
  const innerB64 = innerEncrypted.toString('base64');
  for (let i = 0; i < innerB64.length; i += 64) {
    lines.push(innerB64.slice(i, i + 64));
  }
  lines.push('-----END MESSAGE-----');
  return Buffer.from(lines.join('\n') + '\n', 'utf8');
}

/**
 * Generate a complete v3 hidden service descriptor
 */
export function generateDescriptor(params: {
  keys: HiddenServiceKeys;
  timePeriodKeys: TimePeriodKeys;
  introPoints: IntroductionPoint[];
  revisionCounter: bigint;
}): string {
  const { keys: _keys, timePeriodKeys, introPoints, revisionCounter } = params;

  // Generate inner layer plaintext
  const innerPlaintext = generateInnerLayerPlaintext({ introPoints, timePeriodKeys });

  // Encrypt inner layer (hsdir-encrypted-data)
  const innerEncrypted = encryptDescriptorLayer({
    plaintext: innerPlaintext,
    secretData: timePeriodKeys.blindedPublicKey,
    subcredential: timePeriodKeys.subcredential,
    revisionCounter,
    stringConstant: 'hsdir-encrypted-data',
  });

  // Generate first layer plaintext
  const firstLayerPlaintext = generateFirstLayerPlaintext(innerEncrypted);

  // Encrypt first layer (hsdir-superencrypted-data)
  const superencrypted = encryptDescriptorLayer({
    plaintext: firstLayerPlaintext,
    secretData: timePeriodKeys.blindedPublicKey,
    subcredential: timePeriodKeys.subcredential,
    revisionCounter,
    stringConstant: 'hsdir-superencrypted-data',
  });

  // Build descriptor
  const lines: string[] = [];
  lines.push('hs-descriptor 3');
  lines.push(`descriptor-lifetime 180`);

  // descriptor-signing-key-cert
  const now = Date.now();
  const expirationHours = Math.floor(now / (60 * 60 * 1000)) + 24 * 7;
  const signingKeyCert = createEd25519Certificate({
    certType: CERT_TYPE_HS_BLINDED_ID_V_SIGNING,
    expirationHours,
    certifiedKey: timePeriodKeys.descriptorSigningPublicKey,
    certifiedKeyType: 0x01,
    signingKey: timePeriodKeys.blindedPublicKey,
    signingPrivateKey: timePeriodKeys.blindedPrivateKey,
    includeSigningKeyExtension: true,
  });
  lines.push('descriptor-signing-key-cert');
  lines.push('-----BEGIN ED25519 CERT-----');
  const signingKeyCertB64 = signingKeyCert.toString('base64');
  for (let i = 0; i < signingKeyCertB64.length; i += 64) {
    lines.push(signingKeyCertB64.slice(i, i + 64));
  }
  lines.push('-----END ED25519 CERT-----');

  lines.push(`revision-counter ${revisionCounter}`);

  // superencrypted
  lines.push('superencrypted');
  lines.push('-----BEGIN MESSAGE-----');
  const superB64 = superencrypted.toString('base64');
  for (let i = 0; i < superB64.length; i += 64) {
    lines.push(superB64.slice(i, i + 64));
  }
  lines.push('-----END MESSAGE-----');

  // Sign the descriptor
  const descriptorBody = lines.join('\n') + '\n';
  const sigPrefix = 'Tor onion service descriptor sig v3';
  const sigInput = Buffer.concat([
    Buffer.from(sigPrefix, 'ascii'),
    Buffer.from(descriptorBody, 'utf8'),
  ]);
  const signature = Buffer.from(ed.sign(sigInput, timePeriodKeys.descriptorSigningPrivateKey));

  lines.push('signature ' + signature.toString('base64'));

  return lines.join('\n') + '\n';
}

/**
 * Build ESTABLISH_INTRO cell payload
 *
 * Per rend-spec-v3.txt section 3.1.1:
 * AUTH_KEY_TYPE    [1 byte]
 * AUTH_KEY_LEN     [2 bytes]
 * AUTH_KEY         [AUTH_KEY_LEN bytes]
 * N_EXTENSIONS     [1 byte]
 * EXTENSIONS       [variable]
 * HANDSHAKE_AUTH   [MAC_LEN bytes]
 * SIG              [64 bytes for ed25519]
 */
export function buildEstablishIntroPayload(params: {
  authKeyPublic: Buffer;
  authKeyPrivate: Buffer;
  circuitMacKey: Buffer; // Derived from circuit handshake
}): Buffer {
  const AUTH_KEY_TYPE_ED25519 = 0x02;

  // Build the body (everything before HANDSHAKE_AUTH)
  const body = Buffer.concat([
    Buffer.from([AUTH_KEY_TYPE_ED25519]),
    bufferFromUint(2, params.authKeyPublic.length),
    params.authKeyPublic,
    Buffer.from([0x00]), // N_EXTENSIONS = 0
  ]);

  // Compute HANDSHAKE_AUTH = MAC(circuit_mac_key, body)
  const handshakeAuth = mac(params.circuitMacKey, body);

  // Build message to sign (body || HANDSHAKE_AUTH)
  const toSign = Buffer.concat([body, handshakeAuth]);

  // Sign with auth key
  const signature = Buffer.from(ed.sign(toSign, params.authKeyPrivate));

  return Buffer.concat([body, handshakeAuth, signature]);
}

/**
 * Parse INTRODUCE2 cell payload
 *
 * Per rend-spec-v3.txt section 3.3:
 * LEGACY_KEY_ID    [20 bytes] - all zeros for v3
 * AUTH_KEY_TYPE    [1 byte] = 0x02
 * AUTH_KEY_LEN     [2 bytes] = 32
 * AUTH_KEY         [32 bytes]
 * N_EXTENSIONS     [1 byte]
 * EXTENSIONS       [variable]
 * CLIENT_PK        [32 bytes] - curve25519 ephemeral public key
 * ENCRYPTED_DATA   [remaining bytes]
 * MAC              [32 bytes] - at end of ENCRYPTED_DATA
 */
export interface Introduce2Parsed {
  authKey: Buffer;
  clientPk: Buffer;
  encryptedData: Buffer;
  macValue: Buffer;
}

export function parseIntroduce2(payload: Buffer): Introduce2Parsed {
  const reader = new BytesReader(payload);

  const _legacyKeyId = reader.readBytes(20);
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

  // Skip extensions
  for (let i = 0; i < nExtensions; i++) {
    const extLen = reader.readUIntBE(2);
    reader.readBytes(extLen + 2); // type + flags + data
  }

  const clientPk = reader.readBytes(32);
  const encryptedAndMac = reader.readRemainder();

  if (encryptedAndMac.length < 32) {
    throw new Error('INTRODUCE2 encrypted data too short for MAC');
  }

  const encryptedData = encryptedAndMac.subarray(0, encryptedAndMac.length - 32);
  const macValue = encryptedAndMac.subarray(encryptedAndMac.length - 32);

  return { authKey, clientPk, encryptedData, macValue };
}

/**
 * Decrypt INTRODUCE2 encrypted data and extract rendezvous information
 */
export interface Introduce2Decrypted {
  rendezvousCookie: Buffer;
  onionKeyType: number;
  onionKey: Buffer;
  linkSpecifiers: LinkSpecifier[];
}

export function decryptIntroduce2(params: {
  parsed: Introduce2Parsed;
  introPoint: IntroductionPoint;
  subcredential: Buffer;
}): Introduce2Decrypted {
  const { parsed, introPoint, subcredential } = params;

  // Derive decryption keys using hs-ntor
  const t_hsenc = Buffer.from(`${HS_NTOR_PROTOID.toString('ascii')}:hs_key_extract`, 'ascii');
  const m_hsexpand = Buffer.from(`${HS_NTOR_PROTOID.toString('ascii')}:hs_key_expand`, 'ascii');

  // EXP(X, b) where X is client ephemeral, b is our encryption private key
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

  // Verify MAC
  // The MAC covers: LEGACY_KEY_ID || AUTH_KEY_TYPE || AUTH_KEY_LEN || AUTH_KEY || N_EXT || CLIENT_PK || ENCRYPTED
  const macInput = Buffer.concat([
    Buffer.alloc(20), // LEGACY_KEY_ID
    Buffer.from([0x02]), // AUTH_KEY_TYPE
    Buffer.from([0x00, 0x20]), // AUTH_KEY_LEN
    parsed.authKey,
    Buffer.from([0x00]), // N_EXT
    parsed.clientPk,
    parsed.encryptedData,
  ]);
  const expectedMac = mac(macKey, macInput);
  if (!expectedMac.equals(parsed.macValue)) {
    throw new Error('INTRODUCE2 MAC verification failed');
  }

  // Decrypt
  const iv0 = Buffer.alloc(16, 0);
  const decrypted = aes256CtrXor(encKey, iv0, parsed.encryptedData);

  // Parse decrypted data
  const decReader = new BytesReader(decrypted);
  const rendezvousCookie = decReader.readBytes(20);
  const nExtensions = decReader.readUIntBE(1);

  // Skip extensions
  for (let i = 0; i < nExtensions; i++) {
    const extLen = decReader.readUIntBE(2);
    decReader.readBytes(extLen + 2);
  }

  const onionKeyType = decReader.readUIntBE(1);
  const onionKeyLen = decReader.readUIntBE(2);
  const onionKey = decReader.readBytes(onionKeyLen);

  // Parse link specifiers
  const nLinkSpecs = decReader.readUIntBE(1);
  const linkSpecifiers: LinkSpecifier[] = [];
  for (let i = 0; i < nLinkSpecs; i++) {
    const lsType = decReader.readUIntBE(1);
    const lsLen = decReader.readUIntBE(1);
    const lsData = decReader.readBytes(lsLen);
    linkSpecifiers.push({ type: lsType, data: lsData });
  }

  return {
    rendezvousCookie,
    onionKeyType,
    onionKey,
    linkSpecifiers,
  };
}

/**
 * Complete hs-ntor handshake (server side) and build RENDEZVOUS1 cell
 */
export function completeHsNtorServer(params: {
  clientPk: Buffer; // X
  introPoint: IntroductionPoint;
  subcredential: Buffer;
}): { rendezvous1Data: Buffer; cipherPair: CircuitCipherPair } {
  const { clientPk, introPoint, subcredential: _subcredential } = params;

  // Generate server ephemeral keypair
  const y = Buffer.from(x25519.utils.randomPrivateKey());
  const Y = Buffer.from(x25519.getPublicKey(y));

  const t_hsenc = Buffer.from(`${HS_NTOR_PROTOID.toString('ascii')}:hs_key_extract`, 'ascii');
  const t_hsverify = Buffer.from(`${HS_NTOR_PROTOID.toString('ascii')}:hs_verify`, 'ascii');
  const t_hsmac = Buffer.from(`${HS_NTOR_PROTOID.toString('ascii')}:hs_mac`, 'ascii');
  const m_hsexpand = Buffer.from(`${HS_NTOR_PROTOID.toString('ascii')}:hs_key_expand`, 'ascii');

  // Compute shared secrets
  const expXy = Buffer.from(x25519.scalarMult(y, clientPk));
  const expXb = Buffer.from(x25519.scalarMult(introPoint.encKeyPrivate, clientPk));

  // rend_secret_hs_input
  const rendSecret = Buffer.concat([
    expXy,
    expXb,
    introPoint.authKeyPublic,
    introPoint.encKeyPublic,
    clientPk,
    Y,
    HS_NTOR_PROTOID,
  ]);

  // NTOR_KEY_SEED
  const NTOR_KEY_SEED = mac(rendSecret, t_hsenc);

  // Compute AUTH
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

  // RENDEZVOUS1 cell data: Y || AUTH
  const rendezvous1Data = Buffer.concat([Y, AUTH]);

  // Derive cipher pair from NTOR_KEY_SEED
  // Note: For the service, forward = client->service, backward = service->client
  // But since we're the service, we need to swap these
  const K = kdfShake256(Buffer.concat([NTOR_KEY_SEED, m_hsexpand]), HASH_LEN * 2 + S_KEY_LEN * 2);
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

  // Swap forward/backward for service side
  const cipherPair: CircuitCipherPair = {
    forward: { key: backwardKey, digest: backwardDigest },
    backward: { key: forwardKey, digest: forwardDigest },
  };

  return { rendezvous1Data, cipherPair };
}

/**
 * Get rendezvous point PeerInfo from link specifiers
 */
export function getRendezvousPointPeerInfo(linkSpecifiers: LinkSpecifier[]): PeerInfo {
  const legacyId = linkSpecifiers.find((ls) => ls.type === LinkSpecifierTypes.LegacyId);
  if (!legacyId) {
    throw new Error('Rendezvous point link specifiers missing legacy identity');
  }

  // Find onion key from link specifiers or use a placeholder
  // In a real implementation, we'd need to look this up
  const onionKey = Buffer.alloc(32); // Placeholder

  return {
    onionKey,
    rsaIdDigest: Buffer.from(legacyId.data),
    linkSpecifiers,
  };
}

/**
 * Wait for a specific relay command on a circuit
 */
async function waitForRelayCommand(
  circuit: Circuit,
  relayCommand: number,
  timeoutMs: number
): Promise<{ streamId: number; relayCommand: number; data: Buffer }> {
  return await new Promise((resolve, reject) => {
    const onRelay = (evt: { streamId: number; relayCommand: number; data: Buffer }) => {
      if (evt.relayCommand !== relayCommand) return;
      cleanup();
      resolve(evt);
    };
    const t = setTimeout(() => {
      cleanup();
      reject(new Error(`Timed out waiting for relayCommand=${relayCommand}`));
    }, timeoutMs);
    const cleanup = () => {
      clearTimeout(t);
      circuit.off('relay', onRelay);
    };
    circuit.on('relay', onRelay);
  });
}

/**
 * Hidden Service Host - manages a running onion service
 */
export class HiddenServiceHost extends EventEmitter {
  readonly keys: HiddenServiceKeys;
  private timePeriodKeys: TimePeriodKeys | undefined;
  private introPoints: IntroductionPoint[] = [];
  private revisionCounter: bigint = 0n;
  private running = false;
  private bootstrapCircuit: Circuit | undefined;
  private refreshInterval: ReturnType<typeof setInterval> | undefined;

  constructor(keys?: HiddenServiceKeys) {
    super();
    this.keys = keys ?? generateHiddenServiceKeys();
  }

  get onionAddress(): string {
    return this.keys.onionAddress;
  }

  /**
   * Start the hidden service over Chutney test network
   */
  async startOverChutney(
    params: {
      numIntroPoints?: number;
      overallTimeoutMs?: number;
    } = {}
  ): Promise<void> {
    const numIntroPoints = params.numIntroPoints ?? 3;
    const overallTimeoutMs = params.overallTimeoutMs ?? 120_000;

    if (this.running) {
      throw new Error('Hidden service is already running');
    }

    console.log(`hs-host: starting hidden service ${this.keys.onionAddress}`);

    // Get consensus
    const { consensus } = await getChutneyMicrodescConsensus();
    if (!consensus.validAfter) {
      throw new Error('Consensus missing valid-after');
    }

    // Derive time-period keys
    const timeArgs: Parameters<typeof deriveTimePeriodKeys>[0] = {
      keys: this.keys,
      validAfter: consensus.validAfter,
    };
    if (consensus.freshUntil) {
      timeArgs.freshUntil = consensus.freshUntil;
    }
    this.timePeriodKeys = deriveTimePeriodKeys(timeArgs);

    // Build bootstrap circuit for directory lookups
    const bootstrapPath = await getRandomChutneyCircuitPath();
    const bootstrapFirst = bootstrapPath[0];
    if (!bootstrapFirst) throw new Error('Empty bootstrap circuit path');

    const bootstrapChannel = new TlsChannelConnection();
    await bootstrapChannel.connectPeerInfo(bootstrapFirst);
    this.bootstrapCircuit = new Circuit({ path: bootstrapPath, channel: bootstrapChannel });
    await this.bootstrapCircuit.connect();

    const dirClient = new DirectoryClient(this.bootstrapCircuit);

    // Select introduction points
    const introCandidates = consensus.relays.filter((r) => {
      const flags = r.flags ?? [];
      // Any relay with Stable and Running can be an intro point
      return flags.includes('Stable') && flags.includes('Running');
    });

    const selectedIntros = [];
    const usedDigests = new Set<string>();
    for (let i = 0; i < numIntroPoints && i < introCandidates.length; i++) {
      const relay = pickRelayWithFlags(
        introCandidates,
        [],
        introCandidates.filter((c) => usedDigests.has(c.rsaIdDigest.toString('hex')))
      );
      usedDigests.add(relay.rsaIdDigest.toString('hex'));
      selectedIntros.push(relay);
    }

    // Look up intro point info and generate keys
    for (const introRelay of selectedIntros) {
      try {
        const { peerInfo, ed25519IdentityKey } = await lookupPeerInfoWithEd25519IdentityKey(
          dirClient,
          introRelay
        );
        const introPoint = generateIntroPointKeys(peerInfo, ed25519IdentityKey);
        this.introPoints.push(introPoint);
      } catch (err) {
        console.warn(`hs-host: failed to look up intro point ${introRelay.nickname}:`, err);
      }
    }

    if (this.introPoints.length === 0) {
      throw new Error('Failed to select any introduction points');
    }

    console.log(`hs-host: selected ${this.introPoints.length} introduction points`);

    // Establish introduction points
    for (const intro of this.introPoints) {
      try {
        await this.establishIntroPoint(intro, overallTimeoutMs);
      } catch (err) {
        console.warn(`hs-host: failed to establish intro point:`, err);
      }
    }

    const establishedCount = this.introPoints.filter((i) => i.established).length;
    if (establishedCount === 0) {
      throw new Error('Failed to establish any introduction points');
    }

    console.log(`hs-host: established ${establishedCount} introduction points`);

    // Upload descriptor to HSDirs
    await this.uploadDescriptor();

    this.running = true;

    // Set up periodic descriptor refresh
    this.refreshInterval = setInterval(
      () => {
        this.uploadDescriptor().catch((err) => {
          console.warn('hs-host: descriptor refresh failed:', err);
        });
      },
      30 * 60 * 1000
    ); // Every 30 minutes

    console.log(`hs-host: hidden service running at ${this.keys.onionAddress}`);
  }

  /**
   * Establish a single introduction point
   */
  private async establishIntroPoint(intro: IntroductionPoint, timeoutMs: number): Promise<void> {
    console.log(`hs-host: building circuit to intro point`);

    // Build circuit to intro point
    const introPath = await getRandomChutneyCircuitPathToTargetSafe(
      this.bootstrapCircuit!,
      intro.peerInfo
    );
    const introChannel = new TlsChannelConnection();
    const introFirst = introPath[0];
    if (!introFirst) throw new Error('Empty intro circuit path');
    await introChannel.connectPeerInfo(introFirst);
    const introCircuit = new Circuit({ path: introPath, channel: introChannel });
    await introCircuit.connect();

    intro.circuit = introCircuit;

    // Build ESTABLISH_INTRO payload
    // For circuit MAC key, we use a placeholder (in real implementation,
    // this would be derived from the circuit handshake)
    const circuitMacKey = crypto.randomBytes(32);
    const establishPayload = buildEstablishIntroPayload({
      authKeyPublic: intro.authKeyPublic,
      authKeyPrivate: intro.authKeyPrivate,
      circuitMacKey,
    });

    // Send ESTABLISH_INTRO
    console.log(`hs-host: sending ESTABLISH_INTRO`);
    await introCircuit.sendRelayMessage({
      streamId: 0,
      relayCommand: RelayCell.ESTABLISH_INTRO,
      data: establishPayload,
    });

    // Wait for INTRO_ESTABLISHED
    await waitForRelayCommand(introCircuit, RelayCell.INTRO_ESTABLISHED, timeoutMs);
    console.log(`hs-host: received INTRO_ESTABLISHED`);

    intro.established = true;

    // Set up handler for INTRODUCE2 cells
    introCircuit.on(
      'relay',
      async (evt: { streamId: number; relayCommand: number; data: Buffer }) => {
        if (evt.relayCommand === RelayCell.INTRODUCE2) {
          try {
            await this.handleIntroduce2(intro, evt.data);
          } catch (err) {
            console.warn('hs-host: error handling INTRODUCE2:', err);
          }
        }
      }
    );
  }

  /**
   * Handle an INTRODUCE2 cell from a client
   */
  private async handleIntroduce2(intro: IntroductionPoint, data: Buffer): Promise<void> {
    console.log(`hs-host: received INTRODUCE2`);

    if (!this.timePeriodKeys) {
      throw new Error('Time period keys not initialized');
    }

    // Parse INTRODUCE2
    const parsed = parseIntroduce2(data);

    // Decrypt to get rendezvous information
    const decrypted = decryptIntroduce2({
      parsed,
      introPoint: intro,
      subcredential: this.timePeriodKeys.subcredential,
    });

    console.log(`hs-host: rendezvous cookie: ${decrypted.rendezvousCookie.toString('hex')}`);

    // Build circuit to rendezvous point
    const rendPeerInfo = getRendezvousPointPeerInfo(decrypted.linkSpecifiers);

    // Look up the actual onion key for the rendezvous point
    if (this.bootstrapCircuit) {
      const dirClient = new DirectoryClient(this.bootstrapCircuit);
      const { consensus } = await getChutneyMicrodescConsensus();
      const rendRelay = consensus.relays.find((r) =>
        r.rsaIdDigest.equals(rendPeerInfo.rsaIdDigest)
      );
      if (rendRelay) {
        const fullPeerInfo = await lookupPeerInfo(dirClient, rendRelay);
        rendPeerInfo.onionKey = fullPeerInfo.onionKey;
        rendPeerInfo.linkSpecifiers = fullPeerInfo.linkSpecifiers;
      }
    }

    const rendPath = await getRandomChutneyCircuitPathToTargetSafe(
      this.bootstrapCircuit!,
      rendPeerInfo
    );
    const rendChannel = new TlsChannelConnection();
    const rendFirst = rendPath[0];
    if (!rendFirst) throw new Error('Empty rendezvous circuit path');
    await rendChannel.connectPeerInfo(rendFirst);
    const rendCircuit = new Circuit({ path: rendPath, channel: rendChannel });
    await rendCircuit.connect();

    console.log(`hs-host: built circuit to rendezvous point`);

    // Complete hs-ntor and get RENDEZVOUS1 data
    const { rendezvous1Data, cipherPair } = completeHsNtorServer({
      clientPk: parsed.clientPk,
      introPoint: intro,
      subcredential: this.timePeriodKeys.subcredential,
    });

    // Send RENDEZVOUS1
    const rendezvous1Payload = Buffer.concat([decrypted.rendezvousCookie, rendezvous1Data]);
    console.log(`hs-host: sending RENDEZVOUS1`);
    await rendCircuit.sendRelayMessage({
      streamId: 0,
      relayCommand: RelayCell.RENDEZVOUS1,
      data: rendezvous1Payload,
    });

    // Add virtual hop for end-to-end encryption with client
    rendCircuit.addVirtualHop(cipherPair);

    console.log(`hs-host: rendezvous complete, awaiting client connection`);

    // Emit event so the host application can handle the connection
    this.emit('rendezvous', { circuit: rendCircuit });
  }

  /**
   * Upload descriptor to HSDirs
   */
  private async uploadDescriptor(): Promise<void> {
    if (!this.timePeriodKeys || !this.bootstrapCircuit) {
      throw new Error('Hidden service not initialized');
    }

    const establishedIntros = this.introPoints.filter((i) => i.established);
    if (establishedIntros.length === 0) {
      console.warn('hs-host: no established intro points, skipping descriptor upload');
      return;
    }

    this.revisionCounter++;

    const descriptor = generateDescriptor({
      keys: this.keys,
      timePeriodKeys: this.timePeriodKeys,
      introPoints: establishedIntros,
      revisionCounter: this.revisionCounter,
    });

    console.log(`hs-host: generated descriptor (rev ${this.revisionCounter})`);

    // Find HSDirs
    const { consensus } = await getChutneyMicrodescConsensus();
    const hsdirNodes = consensus.relays.filter((r) => (r.flags ?? []).includes('HSDir'));

    if (hsdirNodes.length === 0) {
      console.warn('hs-host: no HSDir nodes found');
      return;
    }

    const dirClient = new DirectoryClient(this.bootstrapCircuit);

    // Upload to each HSDir
    let uploadCount = 0;
    for (const hsdir of hsdirNodes.slice(0, 6)) {
      try {
        const peerInfo = await lookupPeerInfo(dirClient, hsdir);

        // Build circuit to HSDir
        const path = await getRandomChutneyCircuitPathToTargetSafe(this.bootstrapCircuit, peerInfo);
        const channel = new TlsChannelConnection();
        const first = path[0];
        if (!first) continue;
        await channel.connectPeerInfo(first);
        const circuit = new Circuit({ path, channel });
        await circuit.connect();

        // Open directory stream and POST descriptor
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

        // Wait for response
        const chunks: Buffer[] = [];
        await new Promise<void>((resolve, reject) => {
          const timeout = setTimeout(() => {
            stream.off('data', onData);
            stream.off('end', onEnd);
            reject(new Error('Descriptor upload timeout'));
          }, 30000);

          const onData = (d: Buffer) => chunks.push(Buffer.from(d));
          const onEnd = () => {
            clearTimeout(timeout);
            resolve();
          };

          stream.on('data', onData);
          stream.once('end', onEnd);
        });

        const response = Buffer.concat(chunks).toString('utf8');
        if (response.includes('200')) {
          uploadCount++;
          console.log(`hs-host: descriptor uploaded to ${hsdir.nickname}`);
        }

        circuit.destroy();
      } catch (err) {
        console.warn(`hs-host: failed to upload to ${hsdir.nickname}:`, err);
      }
    }

    console.log(`hs-host: uploaded descriptor to ${uploadCount} HSDirs`);
  }

  /**
   * Stop the hidden service
   */
  stop(): void {
    if (!this.running) return;

    console.log(`hs-host: stopping hidden service`);

    if (this.refreshInterval) {
      clearInterval(this.refreshInterval);
      this.refreshInterval = undefined;
    }

    for (const intro of this.introPoints) {
      try {
        intro.circuit?.destroy();
      } catch {
        // ignore
      }
    }
    this.introPoints = [];

    try {
      this.bootstrapCircuit?.destroy();
    } catch {
      // ignore
    }
    this.bootstrapCircuit = undefined;

    this.running = false;
    this.emit('stopped');
  }
}

// Export for testing
export {
  sha3,
  kdfShake256,
  mac,
  dMac,
  aes256CtrXor,
  base32EncodeLowerNoPad,
  createEd25519Certificate,
  encryptDescriptorLayer,
};
