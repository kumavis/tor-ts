import { EventEmitter } from 'node:events';
import tls from 'node:tls';
import { makeRandomServerName } from './tls.ts';
import { validateCertsCellForIdentities } from './cert.ts';
import type { RsaId } from './cert.ts';
import {
  MessageCells,
  serializeCommand,
  readCellsFromData,
  AddressTypes,
  serializeCellWithPayload,
  linkSpecifierToAddressAndPort,
} from './messaging.ts';
import type {
  MessageCell,
  AddressAndPort,
  CellVersions,
  CellNetInfo,
  NetInfoAddress,
} from './messaging.ts';
import { sha256, sha1 } from './util.ts';
import type { PeerInfo } from './circuit.ts';
import { circuitIdLengthForProtocolVersion } from './circuit.ts';
import { getTime as defaultGetTime } from './time.ts';
import type { GetTime } from './time.ts';

const defaultLinkSupportedVersions = [3, 4, 5];

export class ChannelConnection {
  isInitiator: boolean;
  getTime: GetTime;
  incommingCommands: EventEmitter;
  state: {
    linkProtocolVersion: number | undefined;
    handShakeInProgress: boolean;
  };
  peerConnectionDetails?: {
    cert: tls.DetailedPeerCertificate;
    addressInfo: NodejsPeerAddressInfo;
  };
  peerIdentity?: {
    rsaId: RsaId;
    rsaIdDigest: Buffer;
    ed25519Id: Buffer;
  };
  _clientHandshakeDigestData: never[];
  _serverHandshakeDigestData: never[];
  _incommingHandshakeDigestData: any;
  _outgoingHandshakeDigestData: any;
  _incomingDataBuffer: Buffer;

  constructor({
    isInitiator = true,
    getTime = defaultGetTime,
  }: { isInitiator?: boolean; getTime?: GetTime } = {}) {
    this.isInitiator = isInitiator;
    this.getTime = getTime;
    this.incommingCommands = new EventEmitter();
    this.state = {
      linkProtocolVersion: undefined,
      handShakeInProgress: true,
    };
    this._clientHandshakeDigestData = [];
    this._serverHandshakeDigestData = [];
    this._incommingHandshakeDigestData = this.isInitiator
      ? this._clientHandshakeDigestData
      : this._serverHandshakeDigestData;
    this._outgoingHandshakeDigestData = this.isInitiator
      ? this._serverHandshakeDigestData
      : this._clientHandshakeDigestData;
    this._incomingDataBuffer = Buffer.alloc(0);
  }

  async performHandshake() {
    // TODO: use NETINFO timestamp to determine clock skew
    const now = this.getTime();
    const clockSkew = 0;

    const handshakePromise = this.promiseForHandshake();

    const supportedVersions = defaultLinkSupportedVersions;
    if (!this.peerConnectionDetails) {
      throw new Error('peerConnectionDetails is undefined');
    }
    const peerCert = this.peerConnectionDetails.cert.raw;
    const peerAddressInfo = this.peerConnectionDetails.addressInfo;

    // need to do this synchronously so subsequent messages are parsed correctly based on the protocol version
    this.incommingCommands.once('VERSIONS', (versionsCell: MessageCell) => {
      // determine shared link protocol version
      const linkProtocolVersion = getHighestSharedNumber(
        supportedVersions,
        versionsCell.message.versions
      );
      if (linkProtocolVersion === undefined) {
        throw new Error('No shared link protocol version');
      }
      this.state.linkProtocolVersion = linkProtocolVersion;
    });
    // send our handshake intro
    this.sendVersions({ versions: supportedVersions });

    // receive their handshake intro
    const { certsCell } = await handshakePromise;

    // sha256 hash of (DER-encoded) peer certificate for this connection
    const peerCertSha256 = sha256(peerCert);
    const { rsaId, ed25519Id } = validateCertsCellForIdentities(
      certsCell.message,
      peerCertSha256,
      now,
      clockSkew
    );
    const rsaIdDigest = sha1(rsaId.export({ type: 'pkcs1', format: 'der' }));
    this.peerIdentity = { rsaId, rsaIdDigest, ed25519Id };

    this.sendNetInfo({
      //   Clients SHOULD send "0" as their timestamp, to
      //  avoid fingerprinting.
      time: 0,
      otherAddress: (() => {
        const otherAddress = nodejsPeerAddressToNetInfo(peerAddressInfo);
        if (!otherAddress) {
          throw new Error('Missing peer address info for NETINFO');
        }
        return otherAddress;
      })(),
      addresses: [],
    });
    this.state.handShakeInProgress = false;
  }
  sendVersions(versionsCell: CellVersions): void {
    this.sendMessage(MessageCells.VERSIONS, versionsCell);
  }
  sendNetInfo(netInfoCell: CellNetInfo): void {
    this.sendMessage(MessageCells.NETINFO, netInfoCell);
  }
  async promiseForHandshake(): Promise<any> {
    const [versionsCell, certsCell, authChallengeCell] = await receiveEvents(
      ['VERSIONS', 'CERTS', 'AUTH_CHALLENGE'],
      this.incommingCommands
    );
    return { versionsCell, certsCell, authChallengeCell };
  }
  onData(data: Buffer): void {
    // console.log(`< received data (${data.length} bytes)`)
    const { handShakeInProgress } = this.state;
    this._incomingDataBuffer = Buffer.concat([this._incomingDataBuffer, data]);

    const getVersion = () => this.state.linkProtocolVersion;

    // Parse only complete cells; keep any remainder buffered.
    while (true) {
      const circIdLen = circuitIdLengthForProtocolVersion(getVersion());
      if (this._incomingDataBuffer.length < circIdLen + 1) break;
      const command = this._incomingDataBuffer.readUInt8(circIdLen);

      const isVariable = command === MessageCells.VERSIONS || command >= 128;
      let totalLen: number;
      if (isVariable) {
        if (this._incomingDataBuffer.length < circIdLen + 1 + 2) break;
        const payloadLen = this._incomingDataBuffer.readUInt16BE(circIdLen + 1);
        totalLen = circIdLen + 1 + 2 + payloadLen;
      } else {
        totalLen = circIdLen + 1 + 509;
      }
      if (this._incomingDataBuffer.length < totalLen) break;

      const cellData = this._incomingDataBuffer.subarray(0, totalLen);
      this._incomingDataBuffer = this._incomingDataBuffer.subarray(totalLen);

      for (const cell of readCellsFromData(cellData, getVersion)) {
        if (handShakeInProgress) {
          this._incommingHandshakeDigestData.push(cell.data);
        }
        this.incommingCommands.emit(cell.commandName, cell);
        this.incommingCommands.emit('*', cell);
      }
    }
  }
  sendMessage(messageType: number, messageParams: any): void {
    const { handShakeInProgress } = this.state;
    const serializedCell = serializeCommand(
      messageType,
      messageParams,
      this.state.linkProtocolVersion
    );
    // console.log(`>> sending ${MessageCells[messageType]} (${serializedCell.length} bytes)`)
    if (handShakeInProgress) {
      this._outgoingHandshakeDigestData.push(serializedCell);
    }
    this.sendData(serializedCell);
  }
  sendMessageWithPayload(circuitId: Buffer, messageType: number, payloadBytes: Buffer): void {
    const { handShakeInProgress } = this.state;
    const serializedCell = serializeCellWithPayload(circuitId, messageType, payloadBytes);
    // console.log(`>> sending ${MessageCells[messageType]} (${serializedCell.length} bytes on ${circuitId.toString('hex')})`)
    // console.log(`>> ${serializedCell.toString('hex')}`)
    if (handShakeInProgress) {
      this._outgoingHandshakeDigestData.push(serializedCell);
    }
    this.sendData(serializedCell);
  }
  receiveEvent(eventName: string): Promise<any> {
    return receiveEvent(eventName, this.incommingCommands);
  }
  receiveEvents(eventNames: Array<string>): Promise<any[]> {
    return receiveEvents(eventNames, this.incommingCommands);
  }
  subscribeCircuit(
    circuitId: Buffer,
    eventName: string,
    handler: (message: MessageCell) => void
  ): () => void {
    const listener = (message: MessageCell) => {
      if (!circuitId.equals(message.circId)) return;
      handler(message);
    };
    this.incommingCommands.on(eventName, listener);
    const unsubscribe = () => {
      this.incommingCommands.off(eventName, listener);
    };
    return unsubscribe;
  }
  getProtocolVersion(): number {
    const version = this.state.linkProtocolVersion;
    if (version === undefined) {
      throw new Error('Link protocol version is not yet negotiated');
    }
    return version;
  }
  // virtual - override
  sendData(_serializedCell: any) {
    throw new Error("virtual method 'sendData' not implemented.");
  }
  destroy() {
    this.incommingCommands.removeAllListeners();
  }
}

export class TlsChannelConnection extends ChannelConnection {
  socket?: tls.TLSSocket;

  async connectPeerInfo(gatewayPeerInfo: PeerInfo, additonalOptions?: { localPort: number }) {
    const firstLinkSpecifier = gatewayPeerInfo.linkSpecifiers[0];
    if (!firstLinkSpecifier) {
      throw new Error('Missing link specifier for peer');
    }
    return this.connect(linkSpecifierToAddressAndPort(firstLinkSpecifier), additonalOptions);
  }

  async connect(server: AddressAndPort, additonalOptions?: { localPort: number }) {
    const tlsOptions = {
      servername: makeRandomServerName(),
      rejectUnauthorized: false,
      ...additonalOptions,
    };
    const socket = tls.connect(server.port, server.ip, tlsOptions);
    this.socket = socket;
    const socketReadyP = new Promise<void>((resolve) => {
      socket.once('secureConnect', resolve);
    });
    socket.on('data', (data) => {
      this.onData(data);
    });
    // socket.on('end',() => { console.log('end') });
    // socket.on('close',() => { console.log('close') });
    // socket.on('error', (err) => { console.log('error', err) });
    await socketReadyP;
    // perform handshake
    this.peerConnectionDetails = {
      cert: socket.getPeerCertificate(true),
      addressInfo: socket.address() as NodejsPeerAddressInfo,
    };
    await this.performHandshake();
  }

  sendData(data: Buffer) {
    // console.log(`> sending data (${data.length} bytes)`)
    if (!this.socket) {
      throw new Error('socket is undefined');
    }
    this.socket.write(data);
  }

  destroy(): void {
    super.destroy();
    this.socket?.destroy();
  }
}

function receiveEvent(eventName: string, eventEmitter: EventEmitter): Promise<any> {
  return new Promise((resolve) => {
    eventEmitter.once(eventName, resolve);
  });
}

function receiveEvents(eventNames: Array<string>, eventEmitter: EventEmitter): Promise<any> {
  return Promise.all(
    eventNames.map((eventName) => {
      return receiveEvent(eventName, eventEmitter);
    })
  );
}

function getHighestSharedNumber(listA: Array<number>, listB: Array<number>): number | undefined {
  return listB.reduce((highestNumber: number | undefined, number: number) => {
    if (highestNumber === undefined) {
      return number;
    }
    if (listA.includes(number) && number > highestNumber) {
      return number;
    }
    return highestNumber;
  }, undefined);
}

// ============================================================================
// Channel Manager for connection reuse (cross-platform)
// ============================================================================

/**
 * Factory function type for creating channels.
 * Allows different implementations (TLS, Snowflake, etc.)
 */
export type ChannelFactory<T extends ChannelConnection> = (peerInfo: PeerInfo) => Promise<T>;

/**
 * Function to check if a channel is still alive.
 * Different channel types may have different ways to detect dead connections.
 */
export type ChannelHealthCheck<T extends ChannelConnection> = (channel: T) => boolean;

/**
 * Default health check for TlsChannelConnection.
 */
export function isTlsChannelAlive(channel: TlsChannelConnection): boolean {
  if (!channel.socket) return false;
  return !channel.socket.destroyed && channel.socket.readable;
}

/**
 * Generic ChannelManager for connection reuse (cross-platform).
 *
 * Per tor-spec/channels.md: "Parties should usually reuse an existing channel
 * rather than opening a new channel to the same relay."
 *
 * ## Safety of Channel Reuse
 *
 * Channel reuse is SAFE because:
 * - Channels are keyed by relay IDENTITY (RSA ID digest), not IP/port
 * - The relay proved its identity during the TLS handshake (CERTS cell)
 * - Stream isolation (proposal 171) happens at the CIRCUIT level, not channel level
 * - Multiple isolated circuits can and should share the same channel
 *
 * This matches Arti's `ChanMgr` which uses `by_all_ids(target)` to find channels.
 *
 * ## Architecture
 *
 * ```
 * Channel (TLS to relay)
 *   ├── Circuit A (isolated: SOCKS user=alice)
 *   │     ├── Stream 1 (example.com:80)
 *   │     └── Stream 2 (example.com:443)
 *   ├── Circuit B (isolated: SOCKS user=bob)
 *   │     └── Stream 3 (other.com:80)
 *   └── Circuit C (directory circuit)
 *         └── Stream 4 (consensus fetch)
 * ```
 *
 * Works with any ChannelConnection subclass (TLS, Snowflake, etc.)
 */
export class ChannelManager<T extends ChannelConnection> {
  /** Cache of active channels, keyed by RSA identity digest (hex) */
  private channels = new Map<string, T>();
  private readonly factory: ChannelFactory<T>;
  private readonly isAlive: ChannelHealthCheck<T>;

  /**
   * Create a new channel manager.
   *
   * @param factory - Function to create new channels
   * @param isAlive - Function to check if a channel is still usable (default: always true)
   */
  constructor(factory: ChannelFactory<T>, isAlive?: ChannelHealthCheck<T>) {
    this.factory = factory;
    this.isAlive = isAlive ?? (() => true);
  }

  /**
   * Get an existing channel to a relay, or create a new one.
   *
   * @param peerInfo - The relay to connect to
   * @returns An existing or new channel
   */
  async getOrCreate(peerInfo: PeerInfo): Promise<T> {
    const key = peerInfo.rsaIdDigest.toString('hex');

    // Check for existing channel
    const existing = this.channels.get(key);
    if (existing && this.isAlive(existing)) {
      return existing;
    }

    // Remove dead channel if exists
    if (existing) {
      this.channels.delete(key);
    }

    // Create new channel
    const channel = await this.factory(peerInfo);

    // Cache the channel
    this.channels.set(key, channel);

    return channel;
  }

  /**
   * Get an existing channel without creating a new one.
   */
  get(rsaIdDigest: Buffer): T | undefined {
    const key = rsaIdDigest.toString('hex');
    const channel = this.channels.get(key);
    if (channel && this.isAlive(channel)) {
      return channel;
    }
    return undefined;
  }

  /**
   * Add an externally-created channel to the cache.
   * Useful when a channel is created outside the manager (e.g., bootstrap).
   */
  add(rsaIdDigest: Buffer, channel: T): void {
    const key = rsaIdDigest.toString('hex');
    this.channels.set(key, channel);
  }

  /**
   * Remove a specific channel from the cache.
   * Call this when a channel becomes unusable.
   */
  remove(channel: T): void {
    for (const [key, cached] of this.channels.entries()) {
      if (cached === channel) {
        this.channels.delete(key);
        break;
      }
    }
  }

  /**
   * Remove a channel by peer identity.
   */
  removeByPeer(rsaIdDigest: Buffer): void {
    const key = rsaIdDigest.toString('hex');
    this.channels.delete(key);
  }

  /**
   * Destroy all cached channels.
   */
  destroyAll(): void {
    for (const channel of this.channels.values()) {
      try {
        channel.destroy();
      } catch {
        // Ignore errors during cleanup
      }
    }
    this.channels.clear();
  }

  /**
   * Get the number of cached channels.
   */
  get size(): number {
    return this.channels.size;
  }

  /**
   * Check if a channel exists for a given peer.
   */
  has(rsaIdDigest: Buffer): boolean {
    const key = rsaIdDigest.toString('hex');
    const channel = this.channels.get(key);
    return channel !== undefined && this.isAlive(channel);
  }

  /**
   * Iterate over all cached channels.
   */
  *values(): IterableIterator<T> {
    yield* this.channels.values();
  }
}

/**
 * Type alias for TLS channel manager (Node.js).
 */
export type TlsChannelManager = ChannelManager<TlsChannelConnection>;

/**
 * Create a channel manager for Node.js TLS connections.
 *
 * In Node.js mode, each relay can have its own TLS connection.
 * The manager creates new connections on demand and reuses existing ones.
 */
export function createTlsChannelManager(): TlsChannelManager {
  return new ChannelManager<TlsChannelConnection>(async (peerInfo: PeerInfo) => {
    const channel = new TlsChannelConnection();
    await channel.connectPeerInfo(peerInfo);
    return channel;
  }, isTlsChannelAlive);
}

export type NodejsPeerAddressInfo = {
  port: number;
  family: string;
  address: string;
};

export function nodejsPeerAddressToNetInfo(
  peerAddressInfo: NodejsPeerAddressInfo | undefined
): NetInfoAddress | undefined {
  if (!peerAddressInfo) return undefined;
  const type =
    peerAddressInfo.family === 'IPv4'
      ? AddressTypes.IPv4
      : peerAddressInfo.family === 'IPv6'
        ? AddressTypes.IPv6
        : undefined;
  if (type === undefined) {
    throw new Error(`Unknown peer address family: ${peerAddressInfo.family}`);
  }
  return {
    address: peerAddressInfo.address,
    type,
  };
}
