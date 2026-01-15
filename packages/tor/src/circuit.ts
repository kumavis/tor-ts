import { x25519, sha1 as sha1Noble } from 'tor-crypto';
import { makeAes128CtrKey } from './aes.ts';
import crypto from 'node:crypto';

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
    return Buffer.from(sha1Noble(combined));
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
import { RelayCell, RelayEndReasons, RelayEndReasonNames, serializeExtend2 } from './relay-cell.ts';
import { BytesReader, deferred } from './util.ts';
import EventEmitter from 'node:events';
import { ReadableStream, WritableStream } from 'stream/web';

const KEY_LEN = 16;
const HASH_LEN = 20;

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
  linkSpecifiers: Array<LinkSpecifier>;
};

class Hop {
  isConnected = false;
  peerInfo!: PeerInfo;
  handshakePromiseKit = deferred<void>();
  cipherPair!: CipherPair;

  ntorEphemeralKeyPrivate!: Buffer;
  ntorEphemeralKeyPublic!: Buffer;
  createFastX?: Buffer;

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
      const x = crypto.randomBytes(HASH_LEN);
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
    this.handshakePromiseKit.resolve();
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
    const keyMaterial = KDF_RFC5869(keySeed, 2 * HASH_LEN + 2 * KEY_LEN);
    this.cipherPair = makeTor1CipherPairFromKeyMaterial(keyMaterial);
    this.isConnected = true;
    this.handshakePromiseKit.resolve();
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
    this.handshakePromiseKit.resolve();
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
  connectionPromiseKit = deferred<void>();
  source: ReadableStream;
  sink: WritableStream;

  // Flow control: track cells received since last SENDME
  deliverWindow = STREAM_WINDOW_START;
  cellsSinceLastSendme = 0;

  constructor() {
    super();
    const { source, sink } = createSourceAndSinkForCircuit(this);
    this.source = source;
    this.sink = sink;
    // Prevent unhandled error events - errors are also reported via connectionPromiseKit
    this.on('error', (err) => {
      console.warn(`[CircuitStream ${this.streamId}] error:`, err.message);
    });
    // Note: deferred() now includes a built-in catch handler to prevent unhandled rejection warnings.
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

  close() {
    this.destroy();
  }
  destroy(err?: Error) {
    if (this.destroyed) return;
    this.destroyed = true;
    if (err) {
      this.connectionPromiseKit.reject(err);
      this.emit('error', err);
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

  // Circuit-level flow control
  private circuitDeliverWindow = CIRCUIT_WINDOW_START;
  private circuitCellsSinceLastSendme = 0;
  private circuitSendmeCount = 0;

  // SENDME queue to prevent race conditions
  // For circuit SENDME, we include the digest captured at queue time
  private sendmeQueue: Array<{
    type: 'stream' | 'circuit';
    stream?: CircuitStream;
    hop: Hop;
    digest?: Buffer; // For circuit SENDME: digest at time of queueing
  }> = [];
  private sendmeProcessing = false;

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

  async connect() {
    for (const hop of this.hops) {
      await this.performHandshakeForHop(hop);
    }
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
    await hop.handshakePromiseKit.promise;
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
        const destroyMessage = message.message as CellDestroy;
        const reason = destroyMessage.reason;
        const reasonName = DestroyReasonNames[reason] ?? `UNKNOWN_${reason}`;
        const err = new Error(`circuit destroyed: ${reasonName} (${reason})`);
        console.warn('! got destroy', { reason, reasonName });
        // Reject any in-flight hop handshakes so circuit.connect() cannot hang.
        for (const hop of this.hops) {
          if (!hop.isConnected) {
            hop.handshakePromiseKit.reject(err);
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
        stream.connectionPromiseKit.resolve();
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
        stream.destroy(
          new Error(`stream ended: ${reasonName} (${reason}) payload=0x${payloadHex}`)
        );
        return;
      }
      case RelayCell.SENDME: {
        // Flow control message. We currently don't implement SENDME-based windows,
        // but we should never crash on it (real relays send it routinely).
        if (!this.loggedIgnoredRelayCommands.has(relayCommand)) {
          this.loggedIgnoredRelayCommands.add(relayCommand);
          console.log(
            `ignoring RELAY_${RelayCell[relayCommand] ?? relayCommand} (${relayCommand}) ` +
              `for streamId=${streamId} on ${targetHop.toString()} (flow control not implemented)`
          );
        }
        return;
      }
      case RelayCell.DROP: {
        // Padding / control cell that should be ignored.
        if (!this.loggedIgnoredRelayCommands.has(relayCommand)) {
          this.loggedIgnoredRelayCommands.add(relayCommand);
          console.log(
            `ignoring RELAY_${RelayCell[relayCommand] ?? relayCommand} (${relayCommand}) ` +
              `for streamId=${streamId} on ${targetHop.toString()}`
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
      const relayCell = {
        streamId,
        relayCommand: RelayCell.DATA,
        data: chunk,
      };
      await this.sendRelayMessage(relayCell);
    }
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
    // 1. The connectionPromiseKit.promise rejection (for callers who await it)
    // 2. The 'error' event on the stream
    // We catch here to prevent unhandled promise rejection from performStreamHandshake.
    this.performStreamHandshake(stream).catch(() => {
      // Errors are already emitted via stream 'error' event and connectionPromiseKit rejection
    });
    return stream;
  }

  createStream(destination: string): CircuitStream {
    const streamId = ++this.lastStreamId;
    const stream = new CircuitStream();
    stream.streamId = streamId;
    stream.destination = destination;
    // TODO better to use event emitter so its self-contained?
    stream.write = async (data: Buffer) => {
      await stream.connectionPromiseKit.promise;
      await this.writeToStream(stream, data);
    };
    this.streams.push(stream);
    return stream;
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
    await stream.connectionPromiseKit.promise;
  }

  async performDirectoryStreamHandshake(stream: CircuitStream): Promise<void> {
    const { streamId } = stream;
    // tor-spec: RELAY_BEGIN_DIR has an empty body.
    await this.sendRelayMessage({
      streamId,
      relayCommand: RelayCell.BEGIN_DIR,
      data: Buffer.alloc(0),
    });
    await stream.connectionPromiseKit.promise;
  }

  /**
   * Destroy this circuit.
   * @param options.preserveChannel - If true, don't destroy the underlying channel.
   *   Use this when the channel is shared with another circuit.
   */
  destroy(options?: { preserveChannel?: boolean }) {
    if (this.unsubscribeFromChannel) {
      this.unsubscribeFromChannel();
    }
    if (!options?.preserveChannel) {
      this.channel.destroy();
    }
  }

  /**
   * Add an additional (virtual) hop at the end of this circuit.
   * Used for protocols like onion-service rendezvous, where the rendezvous
   * circuit gains an extra end-to-end crypto layer after a handshake.
   */
  addVirtualHop(cipherPair: CircuitCipherPair) {
    this.hops.push(new VirtualHop(cipherPair as CipherPair));
  }
}

function createRandomCircuitId(protocolVersion: number, isInitiator: boolean): Buffer {
  if (protocolVersion === undefined) {
    throw new Error('protocolVersion is undefined');
  }
  // circuitId length is variable based on protocol version
  const circuitIdLength = circuitIdLengthForProtocolVersion(protocolVersion);
  const randomId = crypto.randomBytes(circuitIdLength);
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
