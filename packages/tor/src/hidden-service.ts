import crypto from 'node:crypto';
import { x25519, ed25519, sha3_256, shake256 } from 'tor-crypto';
import { BytesReader, shuffleInPlace } from './util.ts';
import type { LinkSpecifier } from './messaging.ts';
import { RelayCell } from './relay-cell.ts';
import { makeAes256CtrKey } from './aes.ts';
import { parseEd25519Certificate } from './cert.ts';
import { Circuit, type CircuitCipherPair, type PeerInfo, type CopyableHash } from './circuit.ts';
import { pickRelayWithFlags } from './build-circuit/util.ts';
import {
  DirectoryClient,
  lookupPeerInfo,
  lookupPeerInfoWithEd25519IdentityKey,
} from './directory-client.ts';
import type { VerifiedMicroDescConsensus } from './build-circuit/directory.ts';

const HASH_LEN = 32; // SHA3-256
const MAC_KEY_LEN = 32;
const S_KEY_LEN = 32; // AES-256 key
const S_IV_LEN = 16; // AES block/iv length

const RELAY_PAYLOAD_LEN = 509 - 11;

/**
 * Time period information derived from a consensus, used for HS descriptor location.
 */
export interface TimePeriodInfo {
  periodLengthMinutes: bigint;
  periodCandidates: bigint[];
  nReplicas: number;
  spreadFetch: number;
}

// ============================================================================
// Generic Hidden Service Connection Types
// ============================================================================

/**
 * Function type for building circuits to a target relay.
 * This abstracts the platform-specific circuit building (browser vs Node.js).
 *
 * @param target - The target relay (final hop)
 * @param options.avoid - Relays to avoid in path selection
 * @returns A connected circuit
 */
export type BuildCircuitFn = (
  target: PeerInfo,
  options?: { avoid?: PeerInfo[] }
) => Promise<Circuit>;

/**
 * Options for the core hidden service connection flow.
 */
export interface HsConnectionOptions {
  /** Overall timeout in milliseconds (default: 120000) */
  overallTimeoutMs?: number;
  /** Timeout per handshake operation (default: min of overallTimeoutMs, 120000) */
  perHandshakeTimeoutMs?: number;
  /** Max introduction attempts (default: 6) */
  maxIntroAttempts?: number;
  /** Logging function for status updates */
  log?: (message: string) => void;
  /** Generate random bytes (default: crypto.getRandomValues for browser compat) */
  randomBytes?: (length: number) => Uint8Array;
}

/**
 * Result of a successful hidden service connection.
 */
export interface HsConnectionResult {
  /** The rendezvous circuit with virtual hop to the hidden service */
  circuit: Circuit;
  /** The parsed descriptor (contains intro points for reference) */
  descriptor: HiddenServiceDescriptor;
}

/**
 * Context for hidden service connection.
 * Contains bootstrap resources and platform-specific circuit builder.
 */
export interface HsConnectionContext {
  /** Verified consensus */
  consensus: VerifiedMicroDescConsensus;
  /** Bootstrap circuit for directory lookups */
  bootstrapCircuit: Circuit;
  /** Directory client for relay info lookups */
  dirClient: DirectoryClient;
  /** Function to build circuits to a target relay */
  buildCircuit: BuildCircuitFn;
}

/**
 * Computes time period information from a consensus for HS descriptor location.
 *
 * @param consensus - The consensus document
 * @returns Time period info needed for HS operations
 */
export function computeTimePeriodInfo(consensus: VerifiedMicroDescConsensus): TimePeriodInfo {
  if (!consensus.validAfter) {
    throw new Error('Consensus missing valid-after; cannot compute HS time period');
  }

  const hsdirInterval = consensus.params['hsdir-interval'] ?? 1440;
  const timeArgs: Parameters<typeof computeTimePeriod>[0] = { validAfter: consensus.validAfter };
  if (consensus.freshUntil) timeArgs.freshUntil = consensus.freshUntil;

  // On mainnet, hsdir-interval == derived (votingIntervalSec * 24)/60 because the voting interval is 1h.
  // On testing networks (including Chutney), Tor ignores hsdir-interval and derives the period length from
  // the voting interval, which is typically much shorter than 1h. To match Tor behavior across both cases,
  // only pass hsdir-interval when it matches the derived value; otherwise let computeTimePeriod derive it.
  const votingIntervalSec = consensus.freshUntil
    ? Math.floor((consensus.freshUntil.getTime() - consensus.validAfter.getTime()) / 1000)
    : 3600;
  const derivedPeriodMinutes = Math.max(1, Math.floor((votingIntervalSec * 24) / 60));
  if (hsdirInterval === derivedPeriodMinutes) {
    timeArgs.hsdirIntervalMinutes = hsdirInterval;
  }

  const { periodNum: basePeriodNum, periodLengthMinutes } = computeTimePeriod(timeArgs);
  const periodCandidates = [basePeriodNum, basePeriodNum - 1n, basePeriodNum + 1n].filter(
    (n) => n >= 0n
  );
  const nReplicas = Math.min(16, Math.max(1, consensus.params['hsdir_n_replicas'] ?? 2));
  const spreadFetch = Math.min(128, Math.max(1, consensus.params['hsdir_spread_fetch'] ?? 3));

  return { periodLengthMinutes, periodCandidates, nReplicas, spreadFetch };
}

/**
 * Returns SRV values from a consensus for HS hash ring computation, with disaster SRV fallbacks.
 *
 * @param consensus - The consensus document
 * @param periodLengthMinutes - The period length in minutes
 * @param periodNum - The period number
 * @returns Array of SRV values to try (current and previous, with disaster fallbacks)
 */
export function getSrvValues(
  consensus: VerifiedMicroDescConsensus,
  periodLengthMinutes: bigint,
  periodNum: bigint
): Buffer[] {
  const disasterSrv = computeDisasterSrv({ periodLengthMinutes, periodNum });
  return [
    consensus.sharedRandCurrentValue ?? disasterSrv,
    consensus.sharedRandPreviousValue ?? disasterSrv,
  ];
}

function sha3(...parts: Buffer[]): Buffer {
  return Buffer.from(sha3_256(Buffer.concat(parts)));
}

/**
 * Browser-compatible SHA3-256 hash wrapper that provides Node.js-like interface.
 * Uses tor-crypto internally, which works in both Node.js and browsers.
 */
class Sha3_256Hash implements CopyableHash {
  private accumulated: Uint8Array[] = [];

  update(data: Buffer | Uint8Array): this {
    // IMPORTANT: Copy the data to avoid issues if the caller mutates the buffer later.
    // This is critical for relay cell digest computation where the integrity field
    // is set after the digest is updated.
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

function bytesToBigIntLE(bytes: Uint8Array): bigint {
  let n = 0n;
  for (let i = bytes.length - 1; i >= 0; i--) {
    n = (n << 8n) | BigInt(bytes[i] ?? 0);
  }
  return n;
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
  const cipher = crypto.createDecipheriv('aes-256-ctr', key, iv);
  return Buffer.concat([cipher.update(data), cipher.final()]);
}

/**
 * Browser-compatible async AES-256-CTR XOR using Web Crypto.
 * This version works in both Node.js (18+) and browsers.
 */
export async function aes256CtrXorAsync(key: Buffer, iv: Buffer, data: Buffer): Promise<Buffer> {
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    Uint8Array.from(key),
    { name: 'AES-CTR' },
    false,
    ['encrypt', 'decrypt']
  );
  const result = await crypto.subtle.encrypt(
    {
      name: 'AES-CTR',
      counter: Uint8Array.from(iv),
      length: 64,
    },
    cryptoKey,
    Uint8Array.from(data)
  );
  return Buffer.from(result);
}

export function toBase64UrlNoPad(buf: Buffer): string {
  return buf.toString('base64').replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
}

export function computeDisasterSrv(params: {
  periodLengthMinutes: bigint;
  periodNum: bigint;
}): Buffer {
  // Tor-compatible disaster SRV (see tor hs_common.c compute_disaster_srv()):
  // SHA3-256("shared-random-disaster" | INT_8(period_length) | INT_8(period_num))
  const prefix = Buffer.from('shared-random-disaster', 'ascii');
  return sha3(prefix, u64be(params.periodLengthMinutes), u64be(params.periodNum));
}

function hsBuildHsIndex(params: {
  blindedPublicKey: Buffer;
  replicanum: bigint;
  periodLengthMinutes: bigint;
  periodNum: bigint;
}): Buffer {
  // SHA3-256("store-at-idx" | blinded_public_key |
  //          INT_8(replicanum) | INT_8(period_length) | INT_8(period_num))
  const prefix = Buffer.from('store-at-idx', 'ascii');
  return sha3(
    prefix,
    params.blindedPublicKey,
    u64be(params.replicanum),
    u64be(params.periodLengthMinutes),
    u64be(params.periodNum)
  );
}

function hsBuildHsdirIndex(params: {
  ed25519IdentityKey: Buffer;
  sharedRandomValue: Buffer;
  periodLengthMinutes: bigint;
  periodNum: bigint;
}): Buffer {
  // SHA3-256("node-idx" | node_identity |
  //          shared_random_value | INT_8(period_num) | INT_8(period_length))
  // Note order matches tor hs_build_hsdir_index().
  const prefix = Buffer.from('node-idx', 'ascii');
  return sha3(
    prefix,
    params.ed25519IdentityKey,
    params.sharedRandomValue,
    u64be(params.periodNum),
    u64be(params.periodLengthMinutes)
  );
}

export type HsdirCandidate = {
  peerInfo: PeerInfo;
  ed25519IdentityKey: Buffer;
};

export function selectHsdirsForFetch(params: {
  hsdirs: HsdirCandidate[];
  sharedRandomValue: Buffer;
  blindedPublicKey: Buffer;
  periodLengthMinutes: bigint;
  periodNum: bigint;
  nReplicas: number;
  spreadFetch: number;
}): PeerInfo[] {
  const ring = params.hsdirs
    .map((h) => {
      const idx = hsBuildHsdirIndex({
        ed25519IdentityKey: h.ed25519IdentityKey,
        sharedRandomValue: params.sharedRandomValue,
        periodLengthMinutes: params.periodLengthMinutes,
        periodNum: params.periodNum,
      });
      return { ...h, idx };
    })
    .sort((a, b) => Buffer.compare(a.idx, b.idx));

  if (ring.length === 0) return [];

  const selected = new Set<string>();
  const out: PeerInfo[] = [];

  for (let replica = 1; replica <= params.nReplicas; replica++) {
    const hsIdx = hsBuildHsIndex({
      blindedPublicKey: params.blindedPublicKey,
      replicanum: BigInt(replica),
      periodLengthMinutes: params.periodLengthMinutes,
      periodNum: params.periodNum,
    });

    let start = ring.findIndex((x) => Buffer.compare(x.idx, hsIdx) > 0);
    if (start === -1) start = 0;

    let added = 0;
    for (let step = 0; step < ring.length && added < params.spreadFetch; step++) {
      const entry = ring[(start + step) % ring.length]!;
      const key = entry.peerInfo.rsaIdDigest.toString('hex');
      if (selected.has(key)) continue;
      selected.add(key);
      out.push(entry.peerInfo);
      added++;
    }
  }

  return shuffleInPlace(out);
}

function base32DecodeLowerNoPad(s: string): Buffer {
  // RFC4648 base32 alphabet, accepting lowercase or uppercase.
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const clean = s.toUpperCase().replaceAll('=', '');
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const ch of clean) {
    const idx = alphabet.indexOf(ch);
    if (idx === -1) throw new Error(`Invalid base32 char: ${ch}`);
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out.push((value >>> bits) & 0xff);
    }
  }
  return Buffer.from(out);
}

export function parseOnionV3Address(onion: string): { publicIdentityKey: Buffer } {
  // Strip .onion suffix and any subdomain prefix (per address-spec.md: [ignored].[onion_address].onion)
  const withoutSuffix = onion.toLowerCase().endsWith('.onion')
    ? onion.slice(0, -'.onion'.length)
    : onion;
  // The actual onion address is the last dot-separated component (subdomains are for vhosting)
  const parts = withoutSuffix.split('.');
  const host = parts[parts.length - 1] ?? '';
  if (host.length !== 56) {
    throw new Error(`Expected v3 onion address host length 56, got ${host.length}`);
  }
  const raw = base32DecodeLowerNoPad(host);
  if (raw.length !== 35) {
    throw new Error(`Expected v3 onion decoded length 35, got ${raw.length}`);
  }
  const pub = raw.subarray(0, 32);
  const checksum = raw.subarray(32, 34);
  const version = raw[34];
  if (version !== 3) {
    throw new Error(`Unsupported onion version: ${version}`);
  }
  const checksumExpected = sha3(
    Buffer.from('.onion checksum', 'ascii'),
    pub,
    Buffer.from([version])
  ).subarray(0, 2);
  if (!checksum.equals(checksumExpected)) {
    throw new Error('Invalid v3 onion checksum');
  }
  return { publicIdentityKey: Buffer.from(pub) };
}

/**
 * Check if a hostname is a .onion address.
 */
export function isOnionAddress(hostname: string): boolean {
  return hostname.toLowerCase().endsWith('.onion');
}

export function computeTimePeriod(params: {
  validAfter: Date;
  freshUntil?: Date;
  hsdirIntervalMinutes?: number;
}): { periodNum: bigint; periodLengthMinutes: bigint } {
  // Tor's HS time period math (see tor src/feature/hs/hs_common.c):
  // - period_length (minutes): consensus param hsdir_interval in normal networks.
  // - testing networks: period_length is derived from SRV protocol run duration
  //   (24 rounds of the voting interval), i.e. (voting_interval_seconds*24)/60.
  // - rotation offset (minutes): sr_state_get_phase_duration()/60 which is
  //   effectively (voting_interval_seconds*12)/60 in common configurations.

  const minutesSinceEpoch = BigInt(Math.floor(params.validAfter.getTime() / 60_000));

  let votingIntervalSeconds = 3600; // default 1 hour
  if (params.freshUntil) {
    const deltaSec = Math.floor((params.freshUntil.getTime() - params.validAfter.getTime()) / 1000);
    if (Number.isFinite(deltaSec) && deltaSec > 0) votingIntervalSeconds = deltaSec;
  }

  let periodLengthMinutes: bigint;
  if (params.hsdirIntervalMinutes !== undefined) {
    periodLengthMinutes = BigInt(params.hsdirIntervalMinutes);
  } else {
    const derived = Math.floor((votingIntervalSeconds * 24) / 60);
    periodLengthMinutes = BigInt(Math.max(1, derived));
  }

  const rotationOffsetMinutes = BigInt(Math.floor((12 * votingIntervalSeconds) / 60));
  const adjusted = minutesSinceEpoch - rotationOffsetMinutes;
  const periodNum = adjusted / periodLengthMinutes;
  return { periodNum, periodLengthMinutes };
}

export function deriveBlindedPublicKey(params: {
  publicIdentityKey: Buffer;
  periodNum: bigint;
  periodLengthMinutes: bigint;
}): Buffer {
  // Tor-compatible blinding parameter construction (see tor hs_common.c):
  // h = SHA3_256("Derive temporary signing key\\0" | A | [secret] | str_ed25519_basepoint | N)
  const blindStr = Buffer.from('Derive temporary signing key\0', 'ascii');
  const basepointStr = Buffer.from(
    '(15112221349535400772501151409588531511454012693041857206046113283949847762202, ' +
      '46316835694926478169428394003475163141307993866256225615783033603165251855960)',
    'ascii'
  );
  const N = Buffer.concat([
    Buffer.from('key-blind', 'ascii'),
    u64be(params.periodNum),
    u64be(params.periodLengthMinutes),
  ]);
  const hRaw = sha3(blindStr, params.publicIdentityKey, basepointStr, N);
  const h = Buffer.from(hRaw);
  // clamp per ed25519
  h[0] = (h[0] ?? 0) & 248;
  h[31] = (h[31] ?? 0) & 63;
  h[31] = (h[31] ?? 0) | 64;
  const scalar = bytesToBigIntLE(h) % ed25519.CURVE.n;
  const A = ed25519.ExtendedPoint.fromHex(params.publicIdentityKey);
  const APrime = A.multiply(scalar).toRawBytes();
  return Buffer.from(APrime);
}

export function deriveSubcredential(params: {
  publicIdentityKey: Buffer;
  blindedPublicKey: Buffer;
}): Buffer {
  const cred = sha3(Buffer.from('credential', 'ascii'), params.publicIdentityKey);
  return sha3(Buffer.from('subcredential', 'ascii'), cred, params.blindedPublicKey);
}

function extractArmoredMessage(text: string, begin: string, end: string): Buffer {
  const start = text.indexOf(begin);
  if (start === -1) throw new Error(`Missing ${begin} armor`);
  const endIdx = text.indexOf(end, start);
  if (endIdx === -1) throw new Error(`Missing ${end} armor`);
  const body = text
    .slice(start + begin.length, endIdx)
    .replaceAll('\r', '')
    .split('\n')
    .map((l) => l.trim())
    .filter((l) => l.length > 0)
    .join('');
  return Buffer.from(body, 'base64');
}

type HsOuter = { revisionCounter: bigint; superencrypted: Buffer };

function parseHsDescriptorOuter(text: string): HsOuter {
  const revMatch = text.match(/^revision-counter\s+(\d+)\s*$/m);
  if (!revMatch?.[1]) throw new Error('Missing revision-counter');
  const revisionCounter = BigInt(revMatch[1]);
  const superencrypted = extractArmoredMessage(
    text,
    '-----BEGIN MESSAGE-----',
    '-----END MESSAGE-----'
  );
  return { revisionCounter, superencrypted };
}

function decryptHsLayer(params: {
  ciphertext: Buffer;
  secretData: Buffer;
  subcred: Buffer;
  revisionCounter: bigint;
  stringConstant: string;
}): Buffer {
  const { ciphertext, secretData, subcred, revisionCounter, stringConstant } = params;
  if (ciphertext.length < 16 + 32) throw new Error('Encrypted layer too short');
  const salt = ciphertext.subarray(0, 16);
  const macIn = ciphertext.subarray(ciphertext.length - 32);
  const encrypted = ciphertext.subarray(16, ciphertext.length - 32);

  const secretInput = Buffer.concat([secretData, subcred, u64be(revisionCounter)]);
  const keys = kdfShake256(
    Buffer.concat([secretInput, salt, Buffer.from(stringConstant, 'ascii')]),
    S_KEY_LEN + S_IV_LEN + MAC_KEY_LEN
  );
  const secretKey = keys.subarray(0, S_KEY_LEN);
  const secretIv = keys.subarray(S_KEY_LEN, S_KEY_LEN + S_IV_LEN);
  const macKey = keys.subarray(S_KEY_LEN + S_IV_LEN);
  const macExpected = dMac(macKey, salt, encrypted);
  if (!macIn.equals(macExpected)) {
    throw new Error('Descriptor layer MAC check failed');
  }
  return aes256CtrXor(secretKey, secretIv, encrypted);
}

/**
 * Async version of decryptHsLayer using Web Crypto (browser-compatible).
 */
async function decryptHsLayerAsync(params: {
  ciphertext: Buffer;
  secretData: Buffer;
  subcred: Buffer;
  revisionCounter: bigint;
  stringConstant: string;
}): Promise<Buffer> {
  const { ciphertext, secretData, subcred, revisionCounter, stringConstant } = params;
  if (ciphertext.length < 16 + 32) throw new Error('Encrypted layer too short');
  const salt = ciphertext.subarray(0, 16);
  const macIn = ciphertext.subarray(ciphertext.length - 32);
  const encrypted = ciphertext.subarray(16, ciphertext.length - 32);

  const secretInput = Buffer.concat([secretData, subcred, u64be(revisionCounter)]);
  const keys = kdfShake256(
    Buffer.concat([secretInput, salt, Buffer.from(stringConstant, 'ascii')]),
    S_KEY_LEN + S_IV_LEN + MAC_KEY_LEN
  );
  const secretKey = keys.subarray(0, S_KEY_LEN);
  const secretIv = keys.subarray(S_KEY_LEN, S_KEY_LEN + S_IV_LEN);
  const macKey = keys.subarray(S_KEY_LEN + S_IV_LEN);
  const macExpected = dMac(macKey, salt, encrypted);
  if (!macIn.equals(macExpected)) {
    throw new Error('Descriptor layer MAC check failed');
  }
  return await aes256CtrXorAsync(secretKey, secretIv, encrypted);
}

function trimTrailingNuls(b: Buffer): Buffer {
  let end = b.length;
  while (end > 0 && b[end - 1] === 0x00) end--;
  return b.subarray(0, end);
}

function parseFirstLayerPlaintext(text: string): { innerEncrypted: Buffer } {
  // Find the `encrypted` armored message. (There can also be other fields.)
  const encryptedIdx = text.indexOf('\nencrypted');
  if (encryptedIdx === -1 && !text.startsWith('encrypted')) {
    throw new Error('Missing encrypted field in first layer plaintext');
  }
  const begin = '-----BEGIN MESSAGE-----';
  const end = '-----END MESSAGE-----';
  const start = text.indexOf(begin);
  if (start === -1) throw new Error('Missing encrypted MESSAGE armor in first layer');
  const endIdx = text.indexOf(end, start);
  if (endIdx === -1) throw new Error('Missing encrypted MESSAGE end armor in first layer');
  const armored = text.slice(start, endIdx + end.length);
  const innerEncrypted = extractArmoredMessage(armored, begin, end);
  return { innerEncrypted };
}

export type IntroPoint = {
  linkSpecifiers: LinkSpecifier[];
  introPointOnionKey: Buffer; // curve25519 pubkey for ntor to intro point
  authKeyEd25519: Buffer; // KP_hs_ipt_sid
  serviceEncKey: Buffer; // KP_hss_ntor (curve25519 pubkey for hs-ntor)
};

export type HiddenServiceDescriptor = {
  introPoints: IntroPoint[];
};

function parseLinkSpecifiersBlock(block: Buffer): LinkSpecifier[] {
  const r = new BytesReader(block);
  const n = r.readUIntBE(1);
  const out: LinkSpecifier[] = [];
  for (let i = 0; i < n; i++) {
    const type = r.readUIntBE(1);
    const len = r.readUIntBE(1);
    const data = r.readBytes(len);
    out.push({ type, data });
  }
  return out;
}

function parseSecondLayerPlaintext(text: string): HiddenServiceDescriptor {
  const lines = text.replaceAll('\r', '').split('\n');
  const introPoints: IntroPoint[] = [];

  let current: Partial<IntroPoint> | undefined;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i] ?? '';
    if (line.startsWith('introduction-point ')) {
      if (current) {
        // finalize previous if complete
        if (
          current.linkSpecifiers &&
          current.introPointOnionKey &&
          current.authKeyEd25519 &&
          current.serviceEncKey
        ) {
          introPoints.push(current as IntroPoint);
        }
      }
      const b64 = line.slice('introduction-point '.length).trim();
      const block = Buffer.from(b64, 'base64');
      current = { linkSpecifiers: parseLinkSpecifiersBlock(block) };
      continue;
    }
    if (!current) continue;
    if (line.startsWith('onion-key ntor ')) {
      current.introPointOnionKey = Buffer.from(
        line.slice('onion-key ntor '.length).trim(),
        'base64'
      );
      continue;
    }
    if (line === 'auth-key') {
      // Next lines include BEGIN/END ED25519 CERT armor
      const certBegin = '-----BEGIN ED25519 CERT-----';
      const certEnd = '-----END ED25519 CERT-----';
      const rest = lines.slice(i + 1).join('\n');
      const certBody = extractArmoredMessage(rest, certBegin, certEnd);
      const cert = parseEd25519Certificate(certBody);
      current.authKeyEd25519 = Buffer.from(cert.key);
      // Move index to end of cert
      const endLineIdx = lines.findIndex((l, idx) => idx > i && l.includes(certEnd));
      if (endLineIdx !== -1) i = endLineIdx;
      continue;
    }
    if (line.startsWith('enc-key ntor ')) {
      current.serviceEncKey = Buffer.from(line.slice('enc-key ntor '.length).trim(), 'base64');
      continue;
    }
  }

  if (
    current &&
    current.linkSpecifiers &&
    current.introPointOnionKey &&
    current.authKeyEd25519 &&
    current.serviceEncKey
  ) {
    introPoints.push(current as IntroPoint);
  }

  return { introPoints };
}

/**
 * Fetch and decrypt a hidden service descriptor via a directory stream.
 * This is the browser-compatible version that uses async Web Crypto.
 *
 * @param circuit - An existing circuit to use for the directory stream
 * @param hsdirPeer - The HSDir peer info (used for logging, not for connection)
 * @param blindedPublicKey - The blinded public key for the HS
 * @param subcred - The subcredential for decryption
 * @param timeoutMs - Timeout for the request
 */
export async function fetchHsDescriptorOverDirectoryStream(
  circuit: Circuit,
  _hsdirPeer: PeerInfo,
  blindedPublicKey: Buffer,
  subcred: Buffer,
  timeoutMs: number
): Promise<HiddenServiceDescriptor | undefined> {
  const z = toBase64UrlNoPad(blindedPublicKey);

  try {
    const stream = await circuit.openDirectoryStream();

    const requestText =
      `GET /tor/hs/3/${encodeURIComponent(z)} HTTP/1.0\r\n` +
      `Host: hsdir\r\n` +
      `Connection: close\r\n` +
      `\r\n`;

    const chunks: Buffer[] = [];
    stream.on('data', (d: Buffer) => chunks.push(Buffer.from(d)));

    const endedP = new Promise<void>((resolve, reject) => {
      stream.once('end', (err?: Error) => {
        if (err) reject(err);
        else resolve();
      });
    });

    await Promise.race([
      stream.write(Buffer.from(requestText, 'ascii')),
      new Promise<never>((_r, rej) =>
        setTimeout(() => rej(new Error('dir request write timeout')), timeoutMs)
      ),
    ]);

    await Promise.race([
      endedP,
      new Promise<never>((_r, rej) =>
        setTimeout(() => rej(new Error('dir request read timeout')), timeoutMs)
      ),
    ]);

    const resp = Buffer.concat(chunks).toString('utf8');
    if (!resp.startsWith('HTTP/')) return undefined;
    if (!resp.includes(' 200 ')) return undefined;

    const split = resp.split('\r\n\r\n');
    if (split.length < 2) return undefined;
    const outerText = split.slice(1).join('\r\n\r\n');

    // Parse and decrypt the descriptor
    const outer = parseHsDescriptorOuter(outerText);
    const firstPlain = trimTrailingNuls(
      await decryptHsLayerAsync({
        ciphertext: outer.superencrypted,
        secretData: blindedPublicKey,
        subcred,
        revisionCounter: outer.revisionCounter,
        stringConstant: 'hsdir-superencrypted-data',
      })
    );
    const firstText = firstPlain.toString('utf8');
    const { innerEncrypted } = parseFirstLayerPlaintext(firstText);
    const secondPlain = trimTrailingNuls(
      await decryptHsLayerAsync({
        ciphertext: innerEncrypted,
        secretData: blindedPublicKey,
        subcred,
        revisionCounter: outer.revisionCounter,
        stringConstant: 'hsdir-encrypted-data',
      })
    );
    return parseSecondLayerPlaintext(secondPlain.toString('utf8'));
  } catch {
    return undefined;
  }
}

/**
 * WARNING: This function fetches the hidden service descriptor using a direct (non-Tor) HTTP request
 * to HSDir `ip:dirPort` via Node’s global `fetch()`.
 *
 * This is **not** privacy-preserving under Tor’s anonymity assumptions, and it is also incomplete
 * (many real HSDirs have `DirPort 0`, so this approach won’t work reliably on mainnet).
 *
 * Prefer fetching via a directory stream (BEGIN_DIR / RELAY_BEGIN_DIR) over a circuit to the HSDir.
 */
export async function dangerouslyLookupHiddenServiceDescriptor(params: {
  onionAddress: string;
  hsdirCandidates: Array<{ ip: string; dirPort: number }>;
  validAfter: Date;
  freshUntil?: Date;
  hsdirIntervalMinutes?: number;
  timeoutMs?: number;
}): Promise<{
  blindedPublicKey: Buffer;
  subcred: Buffer;
  descriptor: HiddenServiceDescriptor;
}> {
  const { publicIdentityKey } = parseOnionV3Address(params.onionAddress);
  const timePeriodArgs: Parameters<typeof computeTimePeriod>[0] = {
    validAfter: params.validAfter,
  };
  if (params.freshUntil) timePeriodArgs.freshUntil = params.freshUntil;
  if (params.hsdirIntervalMinutes !== undefined)
    timePeriodArgs.hsdirIntervalMinutes = params.hsdirIntervalMinutes;
  const { periodNum: basePeriodNum, periodLengthMinutes } = computeTimePeriod(timePeriodArgs);
  const timeoutMs = params.timeoutMs ?? 60_000;
  const deadline = Date.now() + timeoutMs;

  const periodCandidates = [basePeriodNum, basePeriodNum - 1n, basePeriodNum + 1n].filter(
    (n) => n >= 0n
  );

  let blindedPublicKey: Buffer | undefined;
  let subcred: Buffer | undefined;
  let outerText: string | undefined;

  while (!outerText && Date.now() <= deadline) {
    for (const periodNum of periodCandidates) {
      blindedPublicKey = deriveBlindedPublicKey({
        publicIdentityKey,
        periodNum,
        periodLengthMinutes,
      });
      subcred = deriveSubcredential({ publicIdentityKey, blindedPublicKey });
      const z = toBase64UrlNoPad(blindedPublicKey);

      for (const hsdir of params.hsdirCandidates) {
        if (!Number.isFinite(hsdir.dirPort) || hsdir.dirPort <= 0) continue;
        const url = `http://${hsdir.ip}:${hsdir.dirPort}/tor/hs/3/${encodeURIComponent(z)}`;
        let res: Response;
        try {
          res = await fetch(url);
        } catch {
          continue;
        }
        if (!res.ok) continue;
        outerText = await res.text();
        break;
      }
      if (outerText) break;
    }
    if (!outerText) {
      await new Promise((r) => setTimeout(r, 1000));
    }
  }

  if (!outerText || !blindedPublicKey || !subcred) {
    throw new Error('Failed to download hidden service descriptor from any HSDir candidate');
  }

  const outer = parseHsDescriptorOuter(outerText);
  const firstPlain = trimTrailingNuls(
    decryptHsLayer({
      ciphertext: outer.superencrypted,
      secretData: blindedPublicKey,
      subcred,
      revisionCounter: outer.revisionCounter,
      stringConstant: 'hsdir-superencrypted-data',
    })
  );
  const firstText = firstPlain.toString('utf8');
  const { innerEncrypted } = parseFirstLayerPlaintext(firstText);
  const secondPlain = trimTrailingNuls(
    decryptHsLayer({
      ciphertext: innerEncrypted,
      secretData: blindedPublicKey,
      subcred,
      revisionCounter: outer.revisionCounter,
      stringConstant: 'hsdir-encrypted-data',
    })
  );
  const descriptor = parseSecondLayerPlaintext(secondPlain.toString('utf8'));
  return { blindedPublicKey, subcred, descriptor };
}

export type HsNtorClientState = {
  x: Buffer;
  X: Buffer;
  B: Buffer;
  AUTH_KEY: Buffer;
  N_hs_subcred: Buffer;
};

function hsNtorDeriveEncAndMac(params: {
  x: Buffer;
  X: Buffer;
  B: Buffer;
  AUTH_KEY: Buffer;
  N_hs_subcred: Buffer;
}): { ENC_KEY: Buffer; MAC_KEY: Buffer } {
  const PROTOID = Buffer.from('tor-hs-ntor-curve25519-sha3-256-1', 'ascii');
  const t_hsenc = Buffer.from(`${PROTOID.toString('ascii')}:hs_key_extract`, 'ascii');
  const m_hsexpand = Buffer.from(`${PROTOID.toString('ascii')}:hs_key_expand`, 'ascii');

  const expBx = Buffer.from(x25519.scalarMult(params.x, params.B));
  const introSecret = Buffer.concat([expBx, params.AUTH_KEY, params.X, params.B, PROTOID]);
  const info = Buffer.concat([m_hsexpand, params.N_hs_subcred]);
  const hsKeys = kdfShake256(Buffer.concat([introSecret, t_hsenc, info]), S_KEY_LEN + MAC_KEY_LEN);
  const ENC_KEY = hsKeys.subarray(0, S_KEY_LEN);
  const MAC_KEY = hsKeys.subarray(S_KEY_LEN);
  return { ENC_KEY, MAC_KEY };
}

export function hsNtorComplete(params: { state: HsNtorClientState; Y: Buffer; auth: Buffer }): {
  NTOR_KEY_SEED: Buffer;
} {
  const PROTOID = Buffer.from('tor-hs-ntor-curve25519-sha3-256-1', 'ascii');
  const t_hsenc = Buffer.from(`${PROTOID.toString('ascii')}:hs_key_extract`, 'ascii');
  const t_hsverify = Buffer.from(`${PROTOID.toString('ascii')}:hs_verify`, 'ascii');
  const t_hsmac = Buffer.from(`${PROTOID.toString('ascii')}:hs_mac`, 'ascii');

  const { x, X, B, AUTH_KEY } = params.state;
  const expYx = Buffer.from(x25519.scalarMult(x, params.Y));
  const expBx = Buffer.from(x25519.scalarMult(x, B));
  const rendSecret = Buffer.concat([expYx, expBx, AUTH_KEY, B, X, params.Y, PROTOID]);
  const NTOR_KEY_SEED = mac(rendSecret, t_hsenc);
  const verify = mac(rendSecret, t_hsverify);
  const authInput = Buffer.concat([
    verify,
    AUTH_KEY,
    B,
    params.Y,
    X,
    PROTOID,
    Buffer.from('Server', 'ascii'),
  ]);
  const AUTH_INPUT_MAC = mac(authInput, t_hsmac);
  if (!AUTH_INPUT_MAC.equals(params.auth)) {
    throw new Error('hs-ntor AUTH_INPUT_MAC verification failed');
  }
  return { NTOR_KEY_SEED };
}

export function makeHsRendezvousCipherPairFromKeySeed(NTOR_KEY_SEED: Buffer) {
  const PROTOID = Buffer.from('tor-hs-ntor-curve25519-sha3-256-1', 'ascii');
  const m_hsexpand = Buffer.from(`${PROTOID.toString('ascii')}:hs_key_expand`, 'ascii');
  const K = kdfShake256(Buffer.concat([NTOR_KEY_SEED, m_hsexpand]), HASH_LEN * 2 + S_KEY_LEN * 2);
  const r = new BytesReader(K);
  const fSeed = r.readBytes(HASH_LEN);
  const bSeed = r.readBytes(HASH_LEN);
  const Kf = r.readBytes(S_KEY_LEN);
  const Kb = r.readBytes(S_KEY_LEN);

  // Use browser-compatible SHA3-256 implementation
  const forwardDigest = createSha3_256Hash();
  const backwardDigest = createSha3_256Hash();
  forwardDigest.update(fSeed);
  backwardDigest.update(bSeed);

  const forwardKey = makeAes256CtrKey(Kf);
  const backwardKey = makeAes256CtrKey(Kb);

  const cipherPair: CircuitCipherPair = {
    forward: { key: forwardKey, digest: forwardDigest },
    backward: { key: backwardKey, digest: backwardDigest },
  };
  return cipherPair;
}

export function peerInfoFromIntroPoint(intro: IntroPoint): PeerInfo {
  const legacyId = intro.linkSpecifiers.find((ls) => ls.type === 2 /* LegacyId */);
  if (!legacyId) throw new Error('Introduction point link specifiers missing legacy identity');
  return {
    onionKey: intro.introPointOnionKey,
    rsaIdDigest: Buffer.from(legacyId.data),
    linkSpecifiers: intro.linkSpecifiers,
  };
}

export async function buildIntroduce1Payload(params: {
  introAuthKeyEd25519: Buffer;
  serviceEncKey: Buffer;
  N_hs_subcred: Buffer;
  rendezvousCookie: Buffer;
  rendezvousPoint: PeerInfo;
}): Promise<{ payload: Buffer; state: HsNtorClientState }> {
  const AUTH_KEY = params.introAuthKeyEd25519;
  const legacyKeyId = Buffer.alloc(20, 0);
  const AUTH_KEY_TYPE = Buffer.from([0x02]); // ed25519
  const AUTH_KEY_LEN = Buffer.from([0x00, 0x20]); // 32
  const N_EXT = Buffer.from([0x00]);
  const header = Buffer.concat([legacyKeyId, AUTH_KEY_TYPE, AUTH_KEY_LEN, AUTH_KEY, N_EXT]);

  // Plaintext body (decrypted payload) for INTRODUCE2 [PROCESS_INTRO2]
  const ONION_KEY_TYPE = Buffer.from([0x01]); // ntor
  const ONION_KEY_LEN = Buffer.from([0x00, 0x20]); // 32
  const ONION_KEY = params.rendezvousPoint.onionKey;
  const linkSpecifiersBlock = Buffer.concat([
    Buffer.from([params.rendezvousPoint.linkSpecifiers.length]),
    ...params.rendezvousPoint.linkSpecifiers.map((ls) =>
      Buffer.concat([Buffer.from([ls.type]), Buffer.from([ls.data.length]), ls.data])
    ),
  ]);
  const plaintext = Buffer.concat([
    params.rendezvousCookie,
    Buffer.from([0x00]), // N_EXTENSIONS
    ONION_KEY_TYPE,
    ONION_KEY_LEN,
    ONION_KEY,
    linkSpecifiersBlock,
  ]);

  // Pad plaintext to fill the rest of the relay payload (see [FMT_INTRO1]).
  const encryptedSectionLen = RELAY_PAYLOAD_LEN - header.length;
  const encryptedDataLen = encryptedSectionLen - 32 /* CLIENT_PK */ - 32; /* MAC */
  if (encryptedDataLen <= plaintext.length) {
    throw new Error(
      `INTRODUCE1 plaintext too large (need <= ${encryptedDataLen}, got ${plaintext.length})`
    );
  }
  const paddedPlaintext = Buffer.concat([
    plaintext,
    Buffer.alloc(encryptedDataLen - plaintext.length),
  ]);

  // hs-ntor client keypair
  const x = Buffer.from(x25519.utils.randomPrivateKey());
  const X = Buffer.from(x25519.getPublicKey(x));
  const B = params.serviceEncKey;

  const { ENC_KEY, MAC_KEY } = hsNtorDeriveEncAndMac({
    x,
    X,
    B,
    AUTH_KEY,
    N_hs_subcred: params.N_hs_subcred,
  });
  const iv0 = Buffer.alloc(16, 0);
  // Use async Web Crypto version for browser compatibility
  const C = await aes256CtrXorAsync(ENC_KEY, iv0, paddedPlaintext);
  const macInput = Buffer.concat([header, X, C]);
  const M = mac(MAC_KEY, macInput);

  const payload = Buffer.concat([header, X, C, M]);
  if (payload.length !== RELAY_PAYLOAD_LEN) {
    throw new Error(
      `INTRODUCE1 payload length mismatch: ${payload.length} != ${RELAY_PAYLOAD_LEN}`
    );
  }
  return {
    payload,
    state: { x, X, B, AUTH_KEY, N_hs_subcred: params.N_hs_subcred },
  };
}

/**
 * Wait for a specific relay command on a circuit.
 * Useful for hidden service protocol handshakes (RENDEZVOUS, INTRODUCE_ACK, etc).
 *
 * @param circuit - The circuit to listen on
 * @param relayCommand - The relay command to wait for
 * @param timeoutMs - Timeout in milliseconds
 * @returns The relay event data
 */
export async function waitForRelayCommand(
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

// ============================================================================
// Core Hidden Service Connection (Platform-Agnostic)
// ============================================================================

/**
 * Core hidden service connection flow.
 *
 * This implements the full HSv3 client protocol:
 * 1. Find HSDir nodes and fetch descriptor
 * 2. Build rendezvous circuit and establish rendezvous point
 * 3. Build intro circuit and send INTRODUCE1
 * 4. Complete hs-ntor handshake on RENDEZVOUS2
 *
 * Platform-specific concerns (channel creation, path selection) are abstracted
 * via the `buildCircuit` function in the context.
 *
 * @param ctx - Connection context with consensus, circuits, and circuit builder
 * @param onionAddress - The .onion address to connect to
 * @param options - Connection options
 * @returns The rendezvous circuit with virtual hop to the hidden service
 */
export async function connectToHiddenServiceCore(
  ctx: HsConnectionContext,
  onionAddress: string,
  options: HsConnectionOptions = {}
): Promise<HsConnectionResult> {
  const {
    overallTimeoutMs = 120_000,
    perHandshakeTimeoutMs = Math.min(overallTimeoutMs, 120_000),
    maxIntroAttempts = 6,
    log = () => {},
    randomBytes = (len) => {
      const arr = new Uint8Array(len);
      crypto.getRandomValues(arr);
      return arr;
    },
  } = options;

  const { consensus, bootstrapCircuit, dirClient, buildCircuit } = ctx;

  if (!consensus.validAfter) {
    throw new Error('Consensus missing valid-after');
  }

  // Step 1: Parse onion address
  log('Parsing onion address...');
  const { publicIdentityKey } = parseOnionV3Address(onionAddress);

  // Step 2: Find HSDir nodes
  log('Locating hidden service directory nodes...');
  const hsdirNodes = (consensus.relays ?? []).filter((r) => {
    if (!(r.flags ?? []).includes('HSDir')) return false;
    const hsdirProto = r.protocols?.HSDir;
    if (!hsdirProto) return false;
    return hsdirProto.split(',').some((v) => v.includes('2'));
  });

  if (hsdirNodes.length === 0) {
    throw new Error('No HSDir candidates found in consensus');
  }

  // Build HSDir candidates with Ed25519 identity keys
  log('Looking up HSDir identity keys...');
  const shuffledHsdirNodes = shuffleInPlace([...hsdirNodes]);

  const hsdirCandidates: HsdirCandidate[] = [];
  const batchSize = Math.min(10, shuffledHsdirNodes.length);
  const hsdirResults = await Promise.all(
    shuffledHsdirNodes.slice(0, batchSize).map(async (n) => {
      try {
        const { peerInfo, ed25519IdentityKey } = await lookupPeerInfoWithEd25519IdentityKey(
          dirClient,
          n
        );
        return { peerInfo, ed25519IdentityKey } satisfies HsdirCandidate;
      } catch {
        return undefined;
      }
    })
  );
  hsdirCandidates.push(...hsdirResults.filter((x): x is HsdirCandidate => Boolean(x)));

  if (hsdirCandidates.length === 0) {
    throw new Error('Failed to build any HSDir candidates');
  }

  // Step 3: Compute time period info and fetch descriptor
  const { periodLengthMinutes, periodCandidates, nReplicas, spreadFetch } =
    computeTimePeriodInfo(consensus);

  let subcred: Buffer | undefined;
  let blindedPublicKey: Buffer | undefined;
  let descriptor: HiddenServiceDescriptor | undefined;

  log('Fetching hidden service descriptor...');
  const descriptorDeadline = Date.now() + Math.min(overallTimeoutMs, 180_000);

  for (const periodNum of periodCandidates) {
    if (descriptor) break;
    if (Date.now() > descriptorDeadline) break;

    blindedPublicKey = deriveBlindedPublicKey({
      publicIdentityKey,
      periodNum,
      periodLengthMinutes,
    });
    subcred = deriveSubcredential({ publicIdentityKey, blindedPublicKey });

    const srvValues = getSrvValues(consensus, periodLengthMinutes, periodNum);

    for (const srv of srvValues) {
      if (descriptor) break;

      const hsdirPeersThisRound = selectHsdirsForFetch({
        hsdirs: hsdirCandidates,
        sharedRandomValue: srv,
        blindedPublicKey,
        periodLengthMinutes,
        periodNum,
        nReplicas,
        spreadFetch,
      });

      for (const hsdirPeer of hsdirPeersThisRound) {
        if (Date.now() > descriptorDeadline) break;

        try {
          const got = await fetchHsDescriptorOverDirectoryStream(
            bootstrapCircuit,
            hsdirPeer,
            blindedPublicKey,
            subcred,
            perHandshakeTimeoutMs
          );
          if (got) {
            descriptor = got;
            break;
          }
        } catch {
          // Continue to next HSDir
        }
      }
    }
  }

  if (!descriptor || !subcred || !blindedPublicKey) {
    throw new Error('Failed to download hidden service descriptor');
  }

  log(`Found ${descriptor.introPoints.length} introduction point(s)`);

  // Step 4: Shuffle intro points and select rendezvous point
  const introPoints = shuffleInPlace([...descriptor.introPoints]);
  if (introPoints.length === 0) {
    throw new Error('Descriptor contained no introduction points');
  }

  log('Selecting rendezvous point...');
  const rendCandidates = consensus.relays.filter((r) => {
    const versions = r.protocols?.HSRend;
    if (!versions) return true;
    return versions.split(',').some((v) => v.includes('2'));
  });
  const rendNodeInfo = pickRelayWithFlags(
    rendCandidates.length ? rendCandidates : consensus.relays,
    [],
    []
  );
  const rendezvousPoint = await lookupPeerInfo(dirClient, rendNodeInfo);

  // Step 5: Build rendezvous circuit and establish rendezvous
  log('Building rendezvous circuit...');
  const rendCircuit = await buildCircuit(rendezvousPoint, { avoid: [] });

  const rendezvousCookie = Buffer.from(randomBytes(20));
  log('Establishing rendezvous point...');
  await rendCircuit.sendRelayMessage({
    streamId: 0,
    relayCommand: RelayCell.ESTABLISH_RENDEZVOUS,
    data: rendezvousCookie,
  });
  await waitForRelayCommand(rendCircuit, RelayCell.RENDEZVOUS_ESTABLISHED, perHandshakeTimeoutMs);

  // Step 6: Try intro points until one succeeds
  const introErrors: Error[] = [];
  let successfulIntro:
    | { intro: IntroPoint; introCircuit: Circuit; state: HsNtorClientState }
    | undefined;

  for (let attempt = 0; attempt < maxIntroAttempts; attempt++) {
    const intro = introPoints[attempt % introPoints.length]!;

    let introCircuit: Circuit | undefined;
    try {
      log(`Building introduction circuit (attempt ${attempt + 1}/${maxIntroAttempts})...`);
      const introPeer = peerInfoFromIntroPoint(intro);
      introCircuit = await buildCircuit(introPeer, { avoid: [rendezvousPoint] });

      log(`Sending introduction (attempt ${attempt + 1}/${maxIntroAttempts})...`);
      const { payload: introducePayload, state } = await buildIntroduce1Payload({
        introAuthKeyEd25519: intro.authKeyEd25519,
        serviceEncKey: intro.serviceEncKey,
        N_hs_subcred: subcred,
        rendezvousCookie,
        rendezvousPoint,
      });

      await introCircuit.sendRelayMessage({
        streamId: 0,
        relayCommand: RelayCell.INTRODUCE1,
        data: introducePayload,
      });

      const ack = await waitForRelayCommand(
        introCircuit,
        RelayCell.INTRODUCE_ACK,
        perHandshakeTimeoutMs
      );
      if (ack.data.length < 2) throw new Error('INTRODUCE_ACK too short');
      const status = ack.data.readUInt16BE(0);
      if (status !== 0) {
        throw new Error(`INTRODUCE_ACK status=${status}`);
      }

      successfulIntro = { intro, introCircuit, state };
      log(`Introduction succeeded on attempt ${attempt + 1}`);
      break;
    } catch (err) {
      const error = err instanceof Error ? err : new Error(String(err));
      introErrors.push(error);
      log(`Introduction attempt ${attempt + 1}/${maxIntroAttempts} failed: ${error.message}`);
      introCircuit?.destroy();
    }
  }

  if (!successfulIntro) {
    rendCircuit.destroy();
    const errorSummary = introErrors.map((e) => e.message).join('; ');
    throw new Error(`All ${maxIntroAttempts} introduction attempts failed: ${errorSummary}`);
  }

  const { introCircuit, state } = successfulIntro;
  introCircuit.destroy();

  // Step 7: Wait for RENDEZVOUS2 and complete hs-ntor
  log('Waiting for rendezvous completion...');
  const r2 = await waitForRelayCommand(rendCircuit, RelayCell.RENDEZVOUS2, overallTimeoutMs);
  if (r2.data.length < 64) throw new Error('RENDEZVOUS2 too short');

  const Y = r2.data.subarray(0, 32);
  const auth = r2.data.subarray(32, 64);
  const { NTOR_KEY_SEED } = hsNtorComplete({ state, Y, auth });
  const cipherPair = makeHsRendezvousCipherPairFromKeySeed(NTOR_KEY_SEED);
  rendCircuit.addVirtualHop(cipherPair);

  log('Connected to hidden service!');

  return { circuit: rendCircuit, descriptor };
}
