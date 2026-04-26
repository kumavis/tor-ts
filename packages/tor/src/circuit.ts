import { x25519, sha1, makeAes128CtrKey, randomBytes } from 'tor-crypto';

/**
 * Interface for a hash that supports update, copy, and digest operations.
 * This is used instead of Node.js crypto.Hash for browser compatibility.
 */
export interface CopyableHash {
  update(data: Buffer | Uint8Array): this;
  copy(): CopyableHash;
  digest(): Buffer;
}

/**
 * Browser-compatible SHA-1 hash wrapper that provides Node.js-like interface.
 * Uses tor-crypto internally, which works in both Node.js and browsers.
 */
export class Sha1Hash implements CopyableHash {
  private accumulated: Uint8Array[] = [];

  update(data: Buffer | Uint8Array): this {
    // IMPORTANT: Copy the data to avoid issues if the caller mutates the buffer later.
    // This is critical for relay cell digest computation where the integrity field
    // is set after the digest is updated.
    this.accumulated.push(Uint8Array.from(data));
    return this;
  }

  copy(): Sha1Hash {
    const cloned = new Sha1Hash();
    cloned.accumulated = [...this.accumulated];
    return cloned;
  }

  digest(): Buffer {
    // Concatenate all accumulated data and hash
    const totalLength = this.accumulated.reduce((sum, arr) => sum + arr.length, 0);
    const combined = new Uint8Array(totalLength);
    let offset = 0;
    for (const arr of this.accumulated) {
      combined.set(arr, offset);
      offset += arr.length;
    }
    return Buffer.from(sha1(combined));
  }
}

/**
 * Create a new SHA-1 hash instance (browser-compatible).
 */
function createSha1Hash(): Sha1Hash {
  return new Sha1Hash();
}

import { ChannelConnection } from './channel.ts';
import {
  MessageCells as MessageCellType,
  serializeRelayCellPayload,
  setRelayCellIntegrity,
  checkRelayCellRecognized,
  parseRelayCellPayload,
  parseCreate2Cell,
  chunkDataForRelayDataCells,
} from './messaging.ts';
import type {
  MessageCell,
  CellCreated2,
  Create2ClientHandshake,
  CellDestroy,
  CellRelay,
  CellRelayUnparsed,
  LinkSpecifier,
} from './messaging.ts';
import {
  makeCreate2ClientHandshakeForNtor,
  parseCreate2ServerHandshakeForNtor,
  getKeySeedFromNtorServerHandshake,
  KDF_RFC5869,
} from './ntor.ts';
import type { NtorServerHandshake } from './ntor.ts';
import {
  RelayCell,
  RelayEndError,
  RelayEndReasons,
  RelayEndReasonNames,
  serializeExtend2,
  getRelayCellName,
} from './relay-cell.ts';
import { BytesReader, PromiseLatch } from './util.ts';
import EventEmitter from 'node:events';
import { ReadableStream, WritableStream } from 'stream/web';

const KEY_LEN = 16;
const HASH_LEN = 20;

// Circuit timing constants (per Tor spec path-spec/learning-timeouts.md)
/** Default circuit build timeout in milliseconds (before learning) */
export const DEFAULT_CIRCUIT_BUILD_TIMEOUT_MS = 60_000;
/** MaxCircuitDirtiness - after this many ms since first stream, no new streams attach */
export const MAX_CIRCUIT_DIRTINESS_MS = 10 * 60 * 1000; // 10 minutes

const DestroyReasonNames: Record<number, string> = {
  0: 'NONE',
  1: 'PROTOCOL',
  2: 'INTERNAL',
  3: 'REQUESTED',
  4: 'HIBERNATING',
  5: 'RESOURCELIMIT',
  6: 'CONNECTFAILED',
  7: 'OR_IDENTITY',
  8: 'CHANNEL_CLOSED',
  9: 'FINISHED',
  10: 'TIMEOUT',
  11: 'DESTROYED',
  12: 'NOSUCHSERVICE',
};

type HopClientHandshake =
  | { kind: 'fast'; x: Buffer }
  | { kind: 'ntor'; handshake: Create2ClientHandshake };

export type HopKey = {
  encrypt(message: Buffer): Promise<Uint8Array>;
  decrypt(message: Buffer): Promise<Uint8Array>;
};

export interface Cipher {
  key: HopKey;
  digest: CopyableHash;
}

export type CircuitCipherPair = {
  forward: Cipher;
  backward: Cipher;
};

class CipherPair {
  forward: Cipher;
  backward: Cipher;
  constructor(forward: Cipher, backward: Cipher) {
    this.forward = forward;
    this.backward = backward;
  }
}

class Tor1Cipher implements Cipher {
  key: HopKey;
  digest: CopyableHash;
  constructor(key: HopKey, digest: CopyableHash) {
    this.key = key;
    this.digest = digest;
  }
}

export type PeerInfo = {
  onionKey: Buffer;
  rsaIdDigest: Buffer;
  /** Ed25519 identity key (32 bytes). Optional for legacy relays. */
  ed25519Id?: Buffer;
  linkSpecifiers: Array<LinkSpecifier>;
};

class Hop {
  isConnected = false;
  peerInfo!: PeerInfo;
  /**
   * Settles when the EXTEND2/CREATE_FAST handshake for this hop completes
   * (or fails). Uses {@link PromiseLatch} rather than a Promise so that a
   * rejection arriving before any caller has called `.wait()` is harmless —
   * the DESTROY-cell handler iterates every unconnected hop, but the loop
   * in `Circuit.connect()` only awaits one hop at a time.
   */
  handshakeLatch = new PromiseLatch<void>();
  cipherPair!: CipherPair;

  ntorEphemeralKeyPrivate!: Buffer;
  ntorEphemeralKeyPublic!: Buffer;
  createFastX?: Buffer;

  /**
   * The ntor KH for this hop — the 20-byte DIGEST_LEN nonce derived from the
   * ntor handshake KDF, used as the MAC_KEY for ESTABLISH_INTRO HANDSHAKE_AUTH
   * (rend-spec-v3 §3.1.1.2 / tor-spec.txt §5.2.2). Only set for ntor hops.
   */
  ntorKh?: Buffer;

  async encryptForward(data: Buffer) {
    return Buffer.from(await this.cipherPair.forward.key.encrypt(data));
  }
  async decryptBackward(data: Buffer) {
    return Buffer.from(await this.cipherPair.backward.key.decrypt(data));
  }
  async witnessForwardPayload(relayCellPayload: Buffer) {
    // update the forwardDigest and set the integrity
    this.cipherPair.forward.digest.update(relayCellPayload);
    const integrity = this.cipherPair.forward.digest.copy().digest().subarray(0, 4);
    return integrity;
  }

  // Track cell counts for circuit SENDME
  private backwardCellCount = 0; // All relay cells received
  private dataCellsSinceLastCircuitSendme = 0; // Only DATA cells, for triggering SENDME

  /**
   * Update the backward digest after receiving a relay cell.
   * Per proposal 289, the digest is computed over ALL relay cell payloads.
   *
   * IMPORTANT: Per tor-spec 6.1 and the C/Rust implementations, ONLY the digest
   * field (bytes 5-8) is zeroed for digest computation. The recognized field
   * (bytes 1-2) is NOT zeroed - it's included as-is in the hash (and will be 0
   * since that's how we detected the cell was for us).
   *
   * This updates the digest but does NOT trigger SENDME. Use recordDataCellReceived()
   * for that.
   */
  witnessBackwardPayload(relayCellPayload: Buffer): void {
    this.backwardCellCount++;

    // Update running digest with the payload, zeroing ONLY the digest field.
    // Per tor-spec 6.1 and proposal 289: digest is computed with the digest
    // field (bytes 5-8) zeroed. The recognized field is NOT zeroed.
    const payloadForDigest = Buffer.from(relayCellPayload);
    // Zero ONLY the digest/integrity field (bytes 5-8)
    payloadForDigest[5] = 0;
    payloadForDigest[6] = 0;
    payloadForDigest[7] = 0;
    payloadForDigest[8] = 0;
    this.cipherPair.backward.digest.update(payloadForDigest);
  }

  /**
   * Record that a DATA cell was received for circuit-level flow control.
   * Per tor-spec 7.3, circuit SENDME is triggered by DATA cells only,
   * not all relay cells. But the SENDME digest comes from the running
   * digest which includes ALL cells.
   *
   * Returns the digest to use for circuit SENDME if we've hit 100 DATA cells.
   */
  recordDataCellReceived(): Buffer | undefined {
    this.dataCellsSinceLastCircuitSendme++;

    // Check if we need to send circuit SENDME (every 100 DATA cells)
    // Per proposal 289, the digest to use is from the current running digest
    // which includes ALL relay cells received so far.
    if (this.dataCellsSinceLastCircuitSendme >= CIRCUIT_SENDME_INCREMENT) {
      this.dataCellsSinceLastCircuitSendme = 0;
      const digest = this.cipherPair.backward.digest.copy().digest();
      return digest;
    }

    return undefined;
  }

  /**
   * Get the current backward digest for SENDME authentication.
   * Per proposal 289, this is the last 20 bytes of the running digest.
   */
  getBackwardDigest(): Buffer {
    return this.cipherPair.backward.digest.copy().digest();
  }
  createClientHandshake(): HopClientHandshake {
    // If we don't have the peer's ntor onion key, fall back to CREATE_FAST.
    if (this.peerInfo.onionKey.length !== 32) {
      const x = randomBytes(HASH_LEN);
      this.createFastX = x;
      return { kind: 'fast', x };
    }
    this.ntorEphemeralKeyPrivate = Buffer.from(x25519.utils.randomPrivateKey());
    this.ntorEphemeralKeyPublic = Buffer.from(x25519.getPublicKey(this.ntorEphemeralKeyPrivate));
    const clientHandshake = makeCreate2ClientHandshakeForNtor({
      ownOnionKey: this.ntorEphemeralKeyPublic,
      peerOnionKey: this.peerInfo.onionKey,
      peerRsaIdDigest: this.peerInfo.rsaIdDigest,
    });
    return { kind: 'ntor', handshake: clientHandshake };
  }
  receiveCreatedFastHandshake({ y, kh }: { y: Buffer; kh: Buffer }) {
    const x = this.createFastX;
    if (!x) throw new Error('CREATE_FAST state missing');
    if (x.length !== HASH_LEN || y.length !== HASH_LEN || kh.length !== HASH_LEN) {
      throw new Error('CREATE_FAST handshake sizes are invalid');
    }
    const k0 = Buffer.concat([x, y]);
    const k = KDF_TOR(k0, 3 * HASH_LEN + 2 * KEY_LEN);
    const expectedKh = k.subarray(0, HASH_LEN);
    if (!expectedKh.equals(kh)) {
      throw new Error('CREATE_FAST handshake verification failed (KH mismatch)');
    }
    const keyMaterial = k.subarray(HASH_LEN);
    this.cipherPair = makeTor1CipherPairFromKeyMaterial(keyMaterial);
    this.isConnected = true;
    this.handshakeLatch.resolve();
  }
  async receiveCreated2Handshake(handshake: NtorServerHandshake) {
    const { serverNtorEphemeralKeyPublic, serverNtorAuth } = handshake;
    // generate Kf_1, Kb_1
    const keySeed = getKeySeedFromNtorServerHandshake({
      clientNtorEphemeralKeyPrivate: this.ntorEphemeralKeyPrivate,
      clientNtorEphemeralKeyPublic: this.ntorEphemeralKeyPublic,
      serverNtorIdentityKeyPublic: this.peerInfo.onionKey,
      serverRsaIdentityKeyDigest: this.peerInfo.rsaIdDigest,
      serverNtorEphemeralKeyPublic,
      serverNtorAuth,
    });
    // Per tor-spec.txt §5.2.2 the ntor KDF emits Df, Db, Kf, Kb followed by a
    // DIGEST_LEN trailing nonce that takes the place of KH for the hidden
    // service protocol. We always derive it so HiddenServiceHost can use it
    // as the MAC_KEY for ESTABLISH_INTRO HANDSHAKE_AUTH.
    const keyMaterial = KDF_RFC5869(keySeed, 2 * HASH_LEN + 2 * KEY_LEN + HASH_LEN);
    this.cipherPair = makeTor1CipherPairFromKeyMaterial(keyMaterial);
    this.ntorKh = Buffer.from(keyMaterial.subarray(2 * HASH_LEN + 2 * KEY_LEN));
    this.isConnected = true;
    this.handshakeLatch.resolve();
  }
  toString() {
    const firstLinkSpecifier = this.peerInfo.linkSpecifiers[0];
    if (!firstLinkSpecifier) {
      return `hop:unknown`;
    }
    const port = firstLinkSpecifier.data.subarray(4).readInt16BE();
    return `hop:${port}`;
  }
}

class VirtualHop extends Hop {
  constructor(cipherPair: CipherPair) {
    super();
    this.cipherPair = cipherPair;
    this.isConnected = true;
    this.handshakeLatch.resolve();
  }
  toString() {
    return 'hop:virtual';
  }
}

// Flow control constants (per Tor spec section 7.3)
// Stream-level window: start at 500, send SENDME every 50 cells
const STREAM_WINDOW_START = 500;
const STREAM_SENDME_INCREMENT = 50;

// Circuit-level window: start at 1000
// Per proposal 289, send SENDME every 100 cells (but some relays may use different values)
const CIRCUIT_WINDOW_START = 1000;
const CIRCUIT_SENDME_INCREMENT = 100;

// SENDME v1 authentication (proposal 289)
const SENDME_VERSION = 0x01;
const SENDME_DIGEST_LEN = 20;
export class CircuitStream extends EventEmitter {
  streamId!: number;
  destination!: string;
  destroyed = false;
  /**
   * Settles when RELAY_CONNECTED arrives (resolved) or when the stream is
   * destroyed before connecting (rejected). Uses {@link PromiseLatch} rather
   * than a Promise so a DESTROY arriving in the brief window between
   * `circuit.open()` returning and the caller's first `await` is harmless —
   * if no one is waiting, `reject()` is a no-op rather than an unhandled
   * rejection. Late waiters get a Promise already in the right state.
   */
  connectionLatch = new PromiseLatch<void>();
  source: ReadableStream;
  sink: WritableStream;

  // Flow control: track cells received since last SENDME (deliver window)
  deliverWindow = STREAM_WINDOW_START;
  cellsSinceLastSendme = 0;

  // Flow control: track cells we can send (package window)
  // Per tor-spec 7.3: "The stream-level PACKAGE_WINDOW and the circuit PACKAGE_WINDOW
  // both start at 500 and the stream-level SENDME increment is 50."
  packageWindow = STREAM_WINDOW_START;

  // Promise that resolves when package window has capacity
  private packageWindowWaiters: Array<() => void> = [];

  constructor() {
    super();
    const { source, sink } = createSourceAndSinkForCircuit(this);
    this.source = source;
    this.sink = sink;
    // Stream-level errors are also surfaced via connectionLatch (for the
    // open() awaiter) and via 'end' (for readers); this listener exists so
    // EventEmitter doesn't crash when nobody else handles 'error'.
    this.on('error', (err) => {
      console.warn(`[CircuitStream ${this.streamId}] error:`, err.message);
    });
  }
  write!: (data: Buffer) => Promise<void>;

  // Called by Circuit when a DATA cell is received for this stream
  // Returns true if we should send a SENDME
  recordDeliveredCell(): boolean {
    this.cellsSinceLastSendme++;
    this.deliverWindow--;

    // Send SENDME every STREAM_SENDME_INCREMENT cells
    if (this.cellsSinceLastSendme >= STREAM_SENDME_INCREMENT) {
      this.cellsSinceLastSendme = 0;
      this.deliverWindow += STREAM_SENDME_INCREMENT;
      return true; // Signal that we should send a SENDME
    }
    return false;
  }

  /**
   * Record that we sent a DATA cell on this stream.
   * Decrements package window. Returns true if we can send more.
   */
  recordSentCell(): boolean {
    this.packageWindow--;
    return this.packageWindow > 0;
  }

  /**
   * Handle incoming SENDME for this stream - increment package window.
   * Per tor-spec 7.3: increment by 50 cells.
   */
  handleSendme(): void {
    this.packageWindow += STREAM_SENDME_INCREMENT;
    // Wake up any waiters
    this.wakePackageWindowWaiters();
  }

  // XON/XOFF flow control (prop324)
  private xoffActive = false;
  private xonWaiters: Array<() => void> = [];

  /**
   * Handle XOFF: stop sending on this stream.
   * Per prop324: the remote side's buffer is full.
   */
  handleXoff(): void {
    this.xoffActive = true;
  }

  /**
   * Handle XON: resume sending on this stream.
   * Per prop324: data contains the rate at which we can send.
   */
  handleXon(_data: Buffer): void {
    // TODO: parse XON data for rate limit (prop324)
    this.xoffActive = false;
    // Wake up any XON waiters
    const waiters = this.xonWaiters.splice(0);
    for (const resolve of waiters) {
      resolve();
    }
  }

  /**
   * Wait until not XOFF'd.
   */
  private async waitForXon(): Promise<void> {
    if (!this.xoffActive) return;
    return new Promise((resolve, reject) => {
      const cleanup = () => {
        this.off('end', onEnd);
      };
      const onEnd = () => {
        cleanup();
        reject(new Error('Stream ended while waiting for XON'));
      };
      this.once('end', onEnd);
      this.xonWaiters.push(() => {
        cleanup();
        resolve();
      });
    });
  }

  private wakePackageWindowWaiters(): void {
    const waiters = this.packageWindowWaiters.splice(0);
    for (const resolve of waiters) {
      resolve();
    }
  }

  /**
   * Wait until package window has capacity to send.
   * Also waits for XON if XOFF'd.
   */
  async waitForPackageWindow(): Promise<void> {
    if (this.destroyed) {
      throw new Error('Stream is destroyed');
    }
    // Wait for XOFF to clear
    await this.waitForXon();
    if (this.packageWindow > 0) {
      return;
    }
    return new Promise((resolve, reject) => {
      const cleanup = () => {
        this.off('end', onEnd);
      };
      const onEnd = () => {
        cleanup();
        reject(new Error('Stream ended while waiting for package window'));
      };
      this.once('end', onEnd);
      this.packageWindowWaiters.push(() => {
        cleanup();
        resolve();
      });
    });
  }

  close() {
    this.destroy();
  }
  destroy(err?: Error) {
    if (this.destroyed) return;
    this.destroyed = true;
    if (err) {
      // Guard the latch settlement: if RELAY_CONNECTED already arrived we've
      // resolved it, and a second settle attempt would throw. A late destroy
      // after a successful connect is legitimate (e.g. exit-policy
      // RELAY_END) — just emit the error and leave the connection latch
      // alone, since the caller already saw the successful resolve.
      if (this.connectionLatch.isPending()) {
        this.connectionLatch.reject(err);
      }
      this.emit('error', err);
    }
    // Wake up any package window waiters with rejection
    this.wakePackageWindowWaiters();
    // Wake up any XON waiters
    const xonWaiters = this.xonWaiters.splice(0);
    for (const resolve of xonWaiters) {
      resolve();
    }
    this.emit('end');
  }
}

export class Circuit extends EventEmitter {
  channel: ChannelConnection;
  hops: Array<Hop> = [];
  unsubscribeFromChannel: (() => void) | undefined;
  circuitId: Buffer;
  relayMessageCount = 0;
  lastStreamId = 0;
  streams: Array<CircuitStream> = [];
  private loggedIgnoredRelayCommands = new Set<number>();

  // Circuit-level flow control (receive side - deliver window)
  private circuitDeliverWindow = CIRCUIT_WINDOW_START;
  private circuitCellsSinceLastSendme = 0;
  private circuitSendmeCount = 0;

  // Circuit-level flow control (send side - package window)
  // Per tor-spec 7.3: "The circuit PACKAGE_WINDOW starts at 1000"
  private circuitPackageWindow = CIRCUIT_WINDOW_START;
  private circuitPackageWindowWaiters: Array<() => void> = [];

  // SENDME queue to prevent race conditions
  // For circuit SENDME, we include the digest captured at queue time
  private sendmeQueue: Array<{
    type: 'stream' | 'circuit';
    stream?: CircuitStream;
    hop: Hop;
    digest?: Buffer; // For circuit SENDME: digest at time of queueing
  }> = [];
  private sendmeProcessing = false;

  // Circuit lifecycle tracking
  /** When the circuit was created */
  createdAt: number = Date.now();
  /** When the circuit became "dirty" (first stream attached). undefined = clean */
  dirtyAt: number | undefined;
  /** Whether this circuit has been destroyed */
  isDestroyed = false;

  constructor({ path, channel }: { path: Array<PeerInfo>; channel: ChannelConnection }) {
    super();
    this.channel = channel;
    // select circuitId
    const protocolVersion = channel.getProtocolVersion();
    const circuitId = createRandomCircuitId(protocolVersion, true);
    this.circuitId = circuitId;
    // setup hops
    for (let i = 0; i < path.length; i++) {
      const relayPeerInfo = path[i];
      if (!relayPeerInfo) {
        throw new Error(`Missing peer info for hop index=${i}`);
      }
      const relayedHop = new Hop();
      relayedHop.peerInfo = relayPeerInfo;
      this.hops.push(relayedHop);
    }
    // listen for messages
    this.unsubscribeFromChannel = channel.subscribeCircuit(
      circuitId,
      '*',
      (message: MessageCell) => {
        this.receiveMessage(message);
      }
    );
  }

  get firstHop() {
    const hop = this.hops[0];
    if (!hop) {
      throw new Error('Circuit has no hops');
    }
    return hop;
  }
  get lastHop() {
    const hop = this.hops[this.hops.length - 1];
    if (!hop) {
      throw new Error('Circuit has no hops');
    }
    return hop;
  }

  /**
   * Return the last hop's ntor KH — the 20-byte trailing nonce from the
   * ntor KDF, used as the MAC_KEY for the ESTABLISH_INTRO HANDSHAKE_AUTH
   * field (rend-spec-v3 §3.1.1.2). Throws if the last hop was built with
   * CREATE_FAST or hasn't completed an ntor handshake yet.
   */
  getLastHopNtorKh(): Buffer {
    const kh = this.lastHop.ntorKh;
    if (!kh) {
      throw new Error(
        'Last hop has no ntorKh — circuit was built with CREATE_FAST or handshake incomplete'
      );
    }
    return kh;
  }

  /**
   * Connect to all hops in sequence.
   * @param options.timeoutMs - Overall timeout in milliseconds (default: 60000)
   */
  async connect(options?: { timeoutMs?: number }) {
    const timeoutMs = options?.timeoutMs ?? DEFAULT_CIRCUIT_BUILD_TIMEOUT_MS;
    const deadline = Date.now() + timeoutMs;

    for (const hop of this.hops) {
      const remainingMs = deadline - Date.now();
      if (remainingMs <= 0) {
        throw new Error(
          `Circuit build timeout: exceeded ${timeoutMs}ms after ${this.hops.indexOf(hop)} hops`
        );
      }
      await this.performHandshakeForHopWithTimeout(hop, remainingMs);
    }
  }

  /**
   * Perform handshake for a hop with timeout.
   */
  private async performHandshakeForHopWithTimeout(hop: Hop, timeoutMs: number): Promise<void> {
    const timeoutPromise = new Promise<never>((_, reject) => {
      setTimeout(() => reject(new Error(`Hop handshake timeout after ${timeoutMs}ms`)), timeoutMs);
    });

    await Promise.race([this.performHandshakeForHop(hop), timeoutPromise]);
  }

  async performHandshakeForHop(hop: Hop) {
    if (hop.isConnected) {
      throw new Error('hop already connected during handshake attempt');
    }
    const clientHandshake = hop.createClientHandshake();
    if (hop === this.firstHop) {
      // this is our first hop - either CREATE2 (ntor) or CREATE_FAST
      if (clientHandshake.kind === 'fast') {
        this.channel.sendMessage(MessageCellType.CREATE_FAST, {
          circuitId: this.circuitId,
          x: clientHandshake.x,
        });
      } else {
        this.channel.sendMessage(MessageCellType.CREATE2, {
          circuitId: this.circuitId,
          handshake: clientHandshake.handshake,
        });
      }
    } else {
      if (clientHandshake.kind !== 'ntor') {
        throw new Error('CREATE_FAST is only supported for the first hop');
      }
      // extending the relay - send extend2 to previous hop
      const handshakeHopIndex = this.hops.indexOf(hop);
      const targetHop = this.hops[handshakeHopIndex - 1];
      const extend2PayloadPlaintext = serializeExtend2({
        linkSpecifiers: hop.peerInfo.linkSpecifiers,
        handshake: clientHandshake.handshake,
      });
      await this.sendRelayMessage(
        {
          streamId: 0,
          relayCommand: RelayCell.EXTEND2,
          data: extend2PayloadPlaintext,
        },
        targetHop
      );
    }
    // wait until handshake response has been received
    await hop.handshakeLatch.wait();
  }

  async sendRelayMessage(relayCell: CellRelay, targetHop: Hop = this.lastHop) {
    const relayCellPayload = serializeRelayCellPayload(relayCell);
    const targetHopIndex = this.hops.indexOf(targetHop);
    const integrity = await targetHop.witnessForwardPayload(relayCellPayload);
    setRelayCellIntegrity(relayCellPayload, integrity);
    // encrypt
    let currentPayload = relayCellPayload;
    const backHops = this.hops.slice(0, targetHopIndex + 1).reverse();
    for (const backHop of backHops) {
      currentPayload = await backHop.encryptForward(currentPayload);
    }
    // send over channel
    this.relayMessageCount++;
    const relayType =
      this.relayMessageCount > 8 ? MessageCellType.RELAY : MessageCellType.RELAY_EARLY;
    this.channel.sendMessageWithPayload(this.circuitId, relayType, currentPayload);
  }

  receiveMessage(message: MessageCell) {
    switch (message.command) {
      case MessageCellType.RELAY: {
        // Note: receiveRelayMessage is async but we don't await it here to avoid
        // blocking the message processing loop. Errors are handled within the method.
        this.receiveRelayMessage(message.message as CellRelayUnparsed).catch((err) => {
          console.warn('Error in receiveRelayMessage:', err.message);
        });
        break;
      }
      case MessageCellType.CREATED_FAST: {
        const createdFastMessage = message.message as { y: Buffer; kh: Buffer };
        this.firstHop.receiveCreatedFastHandshake(createdFastMessage);
        break;
      }
      case MessageCellType.CREATED2: {
        const created2Message = message.message as CellCreated2;
        const serverHandshake = parseCreate2ServerHandshakeForNtor(created2Message.handshake);
        this.firstHop.receiveCreated2Handshake(serverHandshake);
        break;
      }
      case MessageCellType.DESTROY: {
        // A DESTROY cell may arrive on a circuit we've already torn down —
        // e.g. after the retry wrapper gave up on this circuit but the guard
        // is still flushing. Ignore silently; there's no in-flight state left
        // to fail and the corresponding unsubscribe happened during destroy().
        if (this.isDestroyed) break;
        const destroyMessage = message.message as CellDestroy;
        const reason = destroyMessage.reason;
        const reasonName = DestroyReasonNames[reason] ?? `UNKNOWN_${reason}`;
        const err = new Error(`circuit destroyed: ${reasonName} (${reason})`);
        console.warn('! got destroy', { reason, reasonName });
        // Reject any in-flight hop handshakes so circuit.connect() cannot hang.
        for (const hop of this.hops) {
          if (!hop.isConnected) {
            hop.handshakeLatch.reject(err);
          }
        }
        this.streams.forEach((stream) => {
          stream.destroy(err);
        });
        // Stop listening for any additional cells on this circuit.
        if (this.unsubscribeFromChannel) {
          this.unsubscribeFromChannel();
          this.unsubscribeFromChannel = undefined;
        }
        break;
      }
      default:
        throw new Error(`Circuit received unknown message type: ${message.command}`);
    }
  }

  async receiveRelayMessage(relayMessage: CellRelayUnparsed) {
    // decrypt and identify target hop
    let currentPayload = relayMessage.payload;
    let targetHop: Hop | undefined;
    for (const hop of this.hops) {
      if (!hop.isConnected) continue;
      currentPayload = Buffer.from(await hop.decryptBackward(currentPayload));
      const looksRecognized = checkRelayCellRecognized(currentPayload);
      if (looksRecognized) {
        targetHop = hop;
        // Update backward digest for SENDME authentication (proposal 289)
        // This must be called for every recognized cell BEFORE parsing.
        // The digest includes ALL relay cells, but SENDME is triggered by DATA cells only.
        hop.witnessBackwardPayload(currentPayload);
        break;
      }
    }
    if (!targetHop) {
      console.warn('did not find matching hop for relay message');
      return;
    }
    // parse and process relay message
    const relayCell = parseRelayCellPayload(currentPayload);
    const { streamId, relayCommand, data } = relayCell;

    // Allow higher-level protocols (like onion services) to observe relay cells.
    // Note: for performance, listeners should filter on relayCommand/streamId.
    this.emit('relay', { streamId, relayCommand, data, targetHop });

    const stream =
      streamId === 0 ? undefined : this.streams.find((stream) => stream.streamId === streamId);
    switch (relayCommand) {
      case RelayCell.EXTENDED2: {
        const create2Cell = parseCreate2Cell(data);
        const handshake = parseCreate2ServerHandshakeForNtor(create2Cell.handshake);
        const targetHopIndex = this.hops.indexOf(targetHop);
        const nextHop = this.hops[targetHopIndex + 1];
        if (!nextHop) {
          throw new Error('Received EXTENDED2 but no next hop exists');
        }
        nextHop.receiveCreated2Handshake(handshake);
        return;
      }
      case RelayCell.CONNECTED: {
        if (!stream) {
          throw new Error(`Got CONNECTED for unknown streamId=${streamId}`);
        }
        stream.connectionLatch.resolve();
        return;
      }
      case RelayCell.RENDEZVOUS_ESTABLISHED:
      case RelayCell.RENDEZVOUS2:
      case RelayCell.INTRODUCE_ACK:
      case RelayCell.INTRO_ESTABLISHED: {
        // Hidden service relay commands are handled by callers listening on
        // the circuit's 'relay' event.
        return;
      }
      case RelayCell.DATA: {
        if (!stream) {
          throw new Error(`Got DATA for unknown streamId=${streamId}`);
        }
        // Stream-level flow control
        const shouldSendStreamSendme = stream.recordDeliveredCell();
        if (shouldSendStreamSendme) {
          this.queueSendme('stream', targetHop, stream);
        }

        // Circuit-level flow control: count DATA cells only, but use the running
        // digest which includes ALL relay cells.
        const sendmeDigest = targetHop.recordDataCellReceived();
        if (sendmeDigest) {
          this.queueSendme('circuit', targetHop, undefined, sendmeDigest);
        }

        stream.emit('data', data);
        return;
      }
      case RelayCell.END: {
        if (!stream) {
          throw new Error(`Got END for unknown streamId=${streamId}`);
        }
        const reason = data[0] ?? 0;
        const reasonName = RelayEndReasonNames[reason] || `UNKNOWN_REASON_${reason}`;
        if (reason === RelayEndReasons.REASON_DONE) {
          // ended normally
          stream.close();
          return;
        }
        const payloadHex = data.toString('hex');
        console.warn(
          `Got ungraceful end for stream ${streamId} with reason ${reasonName} (payload 0x${payloadHex})`
        );
        stream.destroy(new RelayEndError(reason, payloadHex));
        return;
      }
      case RelayCell.SENDME: {
        // Flow control message - increment package window
        // Per tor-spec 7.3: SENDME with streamId=0 is circuit-level, otherwise stream-level
        if (streamId === 0) {
          // Circuit-level SENDME: increment circuit package window by 100
          this.circuitPackageWindow += CIRCUIT_SENDME_INCREMENT;
          // Wake up any waiters blocked on circuit package window
          const waiters = this.circuitPackageWindowWaiters.splice(0);
          for (const resolve of waiters) {
            resolve();
          }
        } else {
          // Stream-level SENDME: increment stream package window by 50
          if (stream) {
            stream.handleSendme();
          } else {
            console.warn(`Got SENDME for unknown streamId=${streamId}`);
          }
        }
        return;
      }
      case RelayCell.DROP: {
        // Padding / control cell that should be ignored.
        if (!this.loggedIgnoredRelayCommands.has(relayCommand)) {
          this.loggedIgnoredRelayCommands.add(relayCommand);
          console.log(
            `ignoring RELAY_${getRelayCellName(relayCommand)} (${relayCommand}) ` +
              `for streamId=${streamId} on ${targetHop.toString()}`
          );
        }
        return;
      }
      case RelayCell.XON: {
        // Stream-level flow control: resume sending on this stream
        // Per prop324: XON contains the new send rate
        if (stream) {
          stream.handleXon(data);
        }
        return;
      }
      case RelayCell.XOFF: {
        // Stream-level flow control: stop sending on this stream
        if (stream) {
          stream.handleXoff();
        }
        return;
      }
      case RelayCell.PADDING_NEGOTIATE:
      case RelayCell.PADDING_NEGOTIATED: {
        // Circuit-level padding negotiation - log and ignore for now
        if (!this.loggedIgnoredRelayCommands.has(relayCommand)) {
          this.loggedIgnoredRelayCommands.add(relayCommand);
          console.log(
            `ignoring RELAY_${getRelayCellName(relayCommand)} (${relayCommand}) ` +
              `for streamId=${streamId} (circuit padding not implemented)`
          );
        }
        return;
      }
      default: {
        throw new Error(`Hop received unknown relay message type ${relayCommand}`);
      }
    }
  }

  async writeToStream(stream: CircuitStream, data: Buffer) {
    const { streamId, destroyed } = stream;
    if (destroyed) {
      throw new Error('stream is destroyed');
    }
    for (const chunk of chunkDataForRelayDataCells(data)) {
      // Flow control: wait for both circuit and stream package windows
      // Per tor-spec 7.3: "If a package window reaches 0, the relay or client
      // stops reading from TCP connections for all streams on the corresponding
      // circuit, and sends no more DATA-bearing cells"
      await this.waitForCircuitPackageWindow();
      await stream.waitForPackageWindow();

      const relayCell = {
        streamId,
        relayCommand: RelayCell.DATA,
        data: chunk,
      };
      await this.sendRelayMessage(relayCell);

      // Decrement package windows after sending
      this.circuitPackageWindow--;
      stream.recordSentCell();
    }
  }

  /**
   * Wait until circuit package window has capacity to send.
   * Per tor-spec 7.3: we must wait for SENDME from relay before sending more.
   */
  private async waitForCircuitPackageWindow(): Promise<void> {
    if (this.isDestroyed) {
      throw new Error('Circuit is destroyed');
    }
    if (this.circuitPackageWindow > 0) {
      return;
    }
    return new Promise((resolve, reject) => {
      const cleanup = () => {
        this.off('destroyed', onDestroyed);
      };
      const onDestroyed = () => {
        cleanup();
        reject(new Error('Circuit destroyed while waiting for package window'));
      };
      this.once('destroyed', onDestroyed);
      this.circuitPackageWindowWaiters.push(() => {
        cleanup();
        resolve();
      });
    });
  }

  /**
   * Queue a SENDME to be sent and start processing if not already running.
   * For circuit SENDME, capture the digest NOW (not when we actually send).
   */
  private queueSendme(
    type: 'stream' | 'circuit',
    hop: Hop,
    stream?: CircuitStream,
    digest?: Buffer
  ): void {
    const item: (typeof this.sendmeQueue)[number] = { type, hop };
    if (stream !== undefined) item.stream = stream;
    if (digest !== undefined) item.digest = digest;
    this.sendmeQueue.push(item);
    this.processSendmeQueue();
  }

  /**
   * Process the SENDME queue sequentially to avoid race conditions.
   */
  private async processSendmeQueue(): Promise<void> {
    if (this.sendmeProcessing) return;
    this.sendmeProcessing = true;

    while (this.sendmeQueue.length > 0) {
      const sendme = this.sendmeQueue.shift()!;
      try {
        if (sendme.type === 'stream' && sendme.stream) {
          await this.doSendStreamSendme(sendme.stream, sendme.hop);
        } else if (sendme.type === 'circuit' && sendme.digest) {
          await this.doSendCircuitSendme(sendme.hop, sendme.digest);
        }
      } catch (err) {
        console.warn(`Failed to send ${sendme.type} SENDME:`, err);
      }
    }

    this.sendmeProcessing = false;
  }

  /**
   * Send a stream-level SENDME to acknowledge received cells and allow more data.
   * Per Tor spec section 7.3, SENDME is sent after every 50 cells received.
   */
  private async doSendStreamSendme(stream: CircuitStream, targetHop: Hop): Promise<void> {
    const { streamId } = stream;
    // Stream-level SENDME has the streamId set, and empty data
    await this.sendRelayMessage(
      {
        streamId,
        relayCommand: RelayCell.SENDME,
        data: Buffer.alloc(0),
      },
      targetHop
    );
  }

  /**
   * Send a circuit-level SENDME to acknowledge received cells on the circuit.
   * Per Tor spec section 7.3, circuit SENDME is sent after every 100 DATA cells.
   * Per proposal 289, SENDME v1 includes authentication digest.
   *
   * @param targetHop - The hop to send the SENDME to
   * @param digest - The 20-byte SHA1 digest for authentication (includes ALL relay cells)
   */
  private async doSendCircuitSendme(targetHop: Hop, digest: Buffer): Promise<void> {
    this.circuitSendmeCount++;

    // For SENDME v1 (authenticated), the data field contains:
    // - VERSION (1 byte)
    // - DATA_LEN (2 bytes)
    // - DATA (20 bytes) = digest captured when SENDME was triggered
    const sendmeData = Buffer.alloc(1 + 2 + SENDME_DIGEST_LEN);
    sendmeData[0] = SENDME_VERSION;
    sendmeData.writeUInt16BE(SENDME_DIGEST_LEN, 1);
    digest.copy(sendmeData, 3, 0, SENDME_DIGEST_LEN);
    await this.sendRelayMessage(
      {
        streamId: 0,
        relayCommand: RelayCell.SENDME,
        data: sendmeData,
      },
      targetHop
    );
  }

  // TODO: delete?
  async open(destination: string): Promise<CircuitStream> {
    const stream = this.createStream(destination);
    await this.performStreamHandshake(stream);
    return stream;
  }

  async openDirectoryStream(): Promise<CircuitStream> {
    const stream = this.createStream('(dir)');
    await this.performDirectoryStreamHandshake(stream);
    return stream;
  }

  openStream(destination: string): CircuitStream {
    const stream = this.createStream(destination);
    // kick off handshake, but dont wait for it
    // Note: we intentionally don't await here. Errors are handled via:
    // 1. The connectionLatch.wait() rejection (for callers who await it)
    // 2. The 'error' event on the stream
    // We catch here to prevent unhandled promise rejection from performStreamHandshake.
    this.performStreamHandshake(stream).catch(() => {
      // Errors are already emitted via stream 'error' event and connectionLatch rejection
    });
    return stream;
  }

  createStream(destination: string): CircuitStream {
    // Mark circuit as dirty on first stream
    if (this.dirtyAt === undefined) {
      this.dirtyAt = Date.now();
    }

    const streamId = ++this.lastStreamId;
    const stream = new CircuitStream();
    stream.streamId = streamId;
    stream.destination = destination;
    // TODO better to use event emitter so its self-contained?
    stream.write = async (data: Buffer) => {
      await stream.connectionLatch.wait();
      await this.writeToStream(stream, data);
    };
    this.streams.push(stream);
    return stream;
  }

  /**
   * Check if this circuit is "clean" (no streams have been attached).
   */
  isClean(): boolean {
    return this.dirtyAt === undefined;
  }

  /**
   * Check if new streams can attach to this circuit.
   * After MaxCircuitDirtiness (10 min), no new streams can attach.
   */
  canAttachNewStreams(): boolean {
    if (this.isDestroyed) return false;
    if (this.dirtyAt === undefined) return true; // Clean circuits can always accept streams

    const dirtyDuration = Date.now() - this.dirtyAt;
    return dirtyDuration < MAX_CIRCUIT_DIRTINESS_MS;
  }

  /**
   * Get the time remaining before this circuit becomes unusable for new streams.
   * Returns undefined if clean, 0 if already expired, or remaining milliseconds.
   */
  getRemainingDirtinessMs(): number | undefined {
    if (this.dirtyAt === undefined) return undefined;
    const remaining = MAX_CIRCUIT_DIRTINESS_MS - (Date.now() - this.dirtyAt);
    return Math.max(0, remaining);
  }

  async performStreamHandshake(stream: CircuitStream): Promise<void> {
    const { streamId, destination } = stream;
    console.log(`opening stream ${streamId} to ${destination}`);
    // RELAY_BEGIN
    //   ADDRPORT [nul-terminated string]
    //   FLAGS    [4 bytes]
    const flagsData = Buffer.alloc(4);
    const data = Buffer.concat([Buffer.from(destination, 'ascii'), Buffer.from([0x00]), flagsData]);
    await this.sendRelayMessage({
      streamId,
      relayCommand: RelayCell.BEGIN,
      data,
    });
    await stream.connectionLatch.wait();
  }

  async performDirectoryStreamHandshake(stream: CircuitStream): Promise<void> {
    const { streamId } = stream;
    // tor-spec: RELAY_BEGIN_DIR has an empty body.
    await this.sendRelayMessage({
      streamId,
      relayCommand: RelayCell.BEGIN_DIR,
      data: Buffer.alloc(0),
    });
    await stream.connectionLatch.wait();
  }

  /**
   * Destroy this circuit.
   * @param options.preserveChannel - If true, don't destroy the underlying channel.
   *   Use this when the channel is shared with another circuit.
   */
  destroy(options?: { preserveChannel?: boolean }) {
    if (this.isDestroyed) return;
    this.isDestroyed = true;

    // Emit destroyed event for any waiters (e.g., package window waiters)
    this.emit('destroyed');

    // Wake up any package window waiters
    const waiters = this.circuitPackageWindowWaiters.splice(0);
    for (const resolve of waiters) {
      resolve(); // They'll check isDestroyed flag
    }

    if (this.unsubscribeFromChannel) {
      this.unsubscribeFromChannel();
    }
    if (!options?.preserveChannel) {
      this.channel.destroy();
    }

    // Destroy all streams
    for (const stream of this.streams) {
      stream.destroy(new Error('Circuit destroyed'));
    }
    this.streams = [];
  }

  /**
   * Add an additional (virtual) hop at the end of this circuit.
   * Used for protocols like onion-service rendezvous, where the rendezvous
   * circuit gains an extra end-to-end crypto layer after a handshake.
   */
  addVirtualHop(cipherPair: CircuitCipherPair) {
    this.hops.push(new VirtualHop(cipherPair as CipherPair));
  }

  /**
   * Attach a passive observer to this circuit's `'relay'` event for the
   * lifetime of a single critical wait. Call `detach()` when you no longer
   * care; call `snapshot()` to read what arrived. Useful for diagnosing
   * timeouts where you need to know whether *anything* came in vs whether
   * a specific cell came in but you were not the one who consumed it.
   *
   * The observer never resolves anything itself — it's strictly read-only.
   */
  observeRelayTraffic(): RelayTrafficObserver {
    const counts = new Map<number, number>();
    let total = 0;
    const onRelay = (evt: { streamId: number; relayCommand: number; data: Buffer }): void => {
      total += 1;
      counts.set(evt.relayCommand, (counts.get(evt.relayCommand) ?? 0) + 1);
    };
    this.on('relay', onRelay);
    return {
      snapshot: () => ({
        totalCells: total,
        commandSummary: [...counts.entries()]
          .sort(([, a], [, b]) => b - a)
          .map(([cmd, n]) => `cmd=${cmd}×${n}`)
          .join(' '),
      }),
      detach: () => {
        this.off('relay', onRelay);
      },
    };
  }
}

/**
 * Read-only handle returned by {@link Circuit.observeRelayTraffic}. Holds
 * cumulative counts of `'relay'` events received since attach; `snapshot()`
 * returns the totals so far, and `detach()` removes the listener.
 */
export type RelayTrafficObserver = {
  snapshot: () => { totalCells: number; commandSummary: string };
  detach: () => void;
};

function createRandomCircuitId(protocolVersion: number, isInitiator: boolean): Buffer {
  if (protocolVersion === undefined) {
    throw new Error('protocolVersion is undefined');
  }
  // circuitId length is variable based on protocol version
  const circuitIdLength = circuitIdLengthForProtocolVersion(protocolVersion);
  const randomId = randomBytes(circuitIdLength);
  // In link protocol version 4 or higher, whichever node initiated the
  // connection MUST set its MSB to 1, and whichever node didn't initiate
  // the connection MUST set its MSB to 0.
  if (isInitiator && protocolVersion >= 4) {
    const firstByte = randomId[0];
    if (firstByte === undefined) {
      throw new Error('random circuit id is empty');
    }
    randomId[0] = firstByte | 0x80;
  }
  return randomId;
}

export function circuitIdLengthForProtocolVersion(protocolVersion: number | undefined): number {
  // CIRCID_LEN is 2 for link protocol versions 1, 2, and 3.  CIRCID_LEN
  // is 4 for link protocol version 4 or higher.  The first VERSIONS cell,
  // and any cells sent before the first VERSIONS cell, always have
  // CIRCID_LEN == 2 for backward compatibility.

  // for the "any cells sent before the first VERSIONS cell" case, we use an undefined protocol
  // version
  return protocolVersion && protocolVersion >= 4 ? 4 : 2;
}

function createSourceAndSinkForCircuit(circuitStream: CircuitStream) {
  // stream consumer can write to this
  // and it gets forwarded to the circuit
  const sink = new WritableStream({
    write: (chunk) => {
      // Must return the promise to properly propagate errors to the WritableStream
      return circuitStream.write(chunk);
    },
    close: () => {
      circuitStream.close();
    },
    abort: (err) => {
      circuitStream.destroy(err);
    },
  });
  // stream consumer can read from this
  // and it gets data forwarded from the circuit
  let streamErrored = false;
  const source = new ReadableStream({
    start: (controller) => {
      circuitStream.on('data', (data) => {
        if (!streamErrored) {
          controller.enqueue(data);
        }
      });
      circuitStream.on('end', () => {
        // Only close if we haven't already errored
        if (!streamErrored) {
          controller.close();
        }
      });
      // Handle errors from the circuit stream
      circuitStream.on('error', (err) => {
        if (!streamErrored) {
          streamErrored = true;
          controller.error(err);
        }
      });
    },
    cancel: () => {
      circuitStream.destroy();
    },
  });
  return { source, sink };
}

function makeTor1CipherPairFromKeyMaterial(keyMaterial: Buffer) {
  const keyMaterialReader = new BytesReader(keyMaterial);
  // Use browser-compatible SHA-1 implementation
  const forwardDigest = createSha1Hash();
  const backwardDigest = createSha1Hash();
  forwardDigest.update(keyMaterialReader.readBytes(HASH_LEN));
  backwardDigest.update(keyMaterialReader.readBytes(HASH_LEN));
  // we use 128-bit AES in counter mode, with an IV of all 0 bytes.
  const forwardKey = makeAes128CtrKey(keyMaterialReader.readBytes(KEY_LEN));
  const backwardKey = makeAes128CtrKey(keyMaterialReader.readBytes(KEY_LEN));
  return new CipherPair(
    new Tor1Cipher(forwardKey, forwardDigest),
    new Tor1Cipher(backwardKey, backwardDigest)
  );
}

function KDF_TOR(keyMaterial: Buffer, length: number): Buffer {
  // K = H(K0 | [00]) | H(K0 | [01]) | H(K0 | [02]) | ...
  // Use browser-compatible SHA-1 implementation
  const blocks: Buffer[] = [];
  for (let i = 0; Buffer.concat(blocks).length < length; i++) {
    const digest = createSha1Hash()
      .update(Buffer.concat([keyMaterial, Buffer.from([i])]))
      .digest();
    blocks.push(digest);
  }
  return Buffer.concat(blocks).subarray(0, length);
}
