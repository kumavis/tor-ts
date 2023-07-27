import { EventEmitter } from 'node:events';
import tls from 'node:tls';
import crypto from 'node:crypto';

import { secp256k1 } from '@noble/curves/secp256k1';
import {
  aes_128_ctr
} from '@noble/ciphers/webcrypto/aes';

import type { KeyInfo } from './profiles';
import {
  makeRandomServerName,
} from './tls';
import {
  validateCertsCellForIdentities,
} from './cert';
import type {
  RsaId,
} from './cert';
import {
  MessageCells,
  serializeCommand,
  readCellsFromData,
  AddressTypes,
  circuitIdLengthForProtocolVersion,
} from './messaging';
import type {
  MessageCell,
  NetInfoAddress,
} from './messaging';
import { sha256, sha1, deferred } from './util'
import { knownGuards } from './guard-nodes';
import { dangerouslyLookupOnionKey, getRandomDirectoryAuthority } from './directory';
import {
  makeCreate2ClientHandshakeForNtor,
  parseCreate2ServerHandshakeForNtor,
  getKeySeedFromNtorServerHandshake,
  KDF_RFC5869,
} from './ntor';
import {
  RelayCells,
  serializeExtend2,
} from './relay-cell'

const KEY_LEN = 16;
const defaultLinkSupportedVersions = [3, 4, 5];

export class ChannelConnection {
  
  isInitiator: boolean;
  incommingCommands: EventEmitter;
  state: {
    linkProtocolVersion: number | undefined;
    handShakeInProgress: boolean;
  };
  peerConnectionDetails?: {
    cert: tls.DetailedPeerCertificate,
    addressInfo: NodejsPeerAddressInfo,
  }
  peerIdentity?: {
    rsaId: RsaId;
    rsaIdDigest: Buffer;
    ed25519Id: Buffer
  }
  _clientHandshakeDigestData: never[];
  _serverHandshakeDigestData: never[];
  _incommingHandshakeDigestData: any;
  _outgoingHandshakeDigestData: any;

  constructor ({
    isInitiator = true,
  } = {}) {
    this.isInitiator = isInitiator;
    this.incommingCommands = new EventEmitter();
    this.state = {
      linkProtocolVersion: undefined,
      handShakeInProgress: true,
    }
    this._clientHandshakeDigestData = [];
    this._serverHandshakeDigestData = [];
    this._incommingHandshakeDigestData = this.isInitiator ? this._clientHandshakeDigestData : this._serverHandshakeDigestData;
    this._outgoingHandshakeDigestData = this.isInitiator ? this._serverHandshakeDigestData : this._clientHandshakeDigestData;
  }

  async performHandshake () {
    // TODO: use NETINFO timestamp to determine clock skew
    const now = Date.now()
    const clockSkew = 0;

    const handshakePromise = this.promiseForHandshake();

    const supportedVersions = defaultLinkSupportedVersions;
    if (!this.peerConnectionDetails) {
      throw new Error('peerConnectionDetails is undefined')
    }
    const peerCert = this.peerConnectionDetails.cert.raw;
    const peerAddressInfo = this.peerConnectionDetails.addressInfo;

    // need to do this synchronously so subsequent messages are parsed correctly based on the protocol version
    this.incommingCommands.once('VERSIONS', (versionsCell: MessageCell) => {
      // determine shared link protocol version
      console.log('supported versions:', supportedVersions, versionsCell.message.versions)
      const linkProtocolVersion = getHighestSharedNumber(supportedVersions, versionsCell.message.versions)
      if (linkProtocolVersion === undefined) {
        throw new Error('No shared link protocol version')
      }
      this.state.linkProtocolVersion = linkProtocolVersion
      console.log('VERSIONS: set linkProtocolVersion', linkProtocolVersion)
    })
    // send our handshake intro
    this.sendMessage(MessageCells.VERSIONS, { versions: supportedVersions })

    // receive their handshake intro
    const { certsCell } = await handshakePromise;

    // sha256 hash of (DER-encoded) peer certificate for this connection
    const peerCertSha256 = sha256(peerCert);
    const {
      rsaId,
      ed25519Id,
    } = validateCertsCellForIdentities(certsCell.message, peerCertSha256, now, clockSkew);
    const rsaIdDigest = sha1(rsaId.export({ type: 'pkcs1', format: 'der' }));
    this.peerIdentity = { rsaId, rsaIdDigest, ed25519Id };

    this.sendMessage(MessageCells.NETINFO, {
      //   Clients SHOULD send "0" as their timestamp, to
      //  avoid fingerprinting.
      time: 0,
      otherAddress: nodejsPeerAddressToNetInfo(peerAddressInfo),
      addresses: [],
    })
  }

  async createCircuit () {
    const peerRsaIdDigest = this.peerIdentity.rsaIdDigest
    // lookup onion key
    // const directoryAuthority = await getRandomDirectoryAuthority()
    // for chutney debugging
    const directoryAuthority = {
      dir_address: '127.0.0.0:7000',
    }
    const peerOnionKey = await dangerouslyLookupOnionKey(directoryAuthority.dir_address, peerRsaIdDigest);
    // temporary fake key
    // const ownOnionKey = crypto.randomBytes(32);
    const clientNtorEphemeralKeyPrivate = secp256k1.utils.randomPrivateKey();
    const clientNtorEphemeralKeyPublic = secp256k1.getPublicKey(clientNtorEphemeralKeyPrivate);

    const circuitId = createRandomCircuitId(this.state.linkProtocolVersion, this.isInitiator);

    // create listener for circuit CREATED2/DESTROY
    // TODO: need to retain or reopen DESTROY listener if CREATED2 is received first
    const { promise: createdP, resolve, reject } = deferred<MessageCell>();
    const checkCreated = (cell: MessageCell) => {
      if (circuitId.equals(cell.circId)) {
        this.incommingCommands.off('CREATED2', checkCreated);
        this.incommingCommands.off('DESTROY', checkDestroyed);
        resolve(cell);
      }
    }
    this.incommingCommands.on('CREATED2', checkCreated)
    const checkDestroyed = (cell: MessageCell) => {
      if (circuitId.equals(cell.circId)) {
        this.incommingCommands.off('CREATED2', checkCreated);
        this.incommingCommands.off('DESTROY', checkDestroyed);
        reject(new Error(`Circuit destroyed: reason #${cell.message.reason}`));
      }
    }
    this.incommingCommands.on('DESTROY', checkDestroyed)
    // submit create
    const clientHandshake = makeCreate2ClientHandshakeForNtor({
      ownOnionKey: clientNtorEphemeralKeyPublic,
      peerOnionKey,
      peerRsaIdDigest,
    })
    this.sendMessage(MessageCells.CREATE2, {
      circuitId,
      handshake: clientHandshake,
    })
    const { message: { handshake: serverHandshake } } = await createdP;
    const { serverNtorEphemeralKeyPublic, serverNtorAuth } = parseCreate2ServerHandshakeForNtor(serverHandshake);

    // generate Kf_1, Kb_1
    const keySeed = getKeySeedFromNtorServerHandshake({
      clientNtorEphemeralKeyPrivate,
      clientNtorEphemeralKeyPublic,
      serverNtorEphemeralKeyPublic,
      serverNtorIdentityKeyPublic: peerOnionKey,
      serverRsaIdentityKeyDigest: peerRsaIdDigest,
      serverNtorAuth,
    })
    const keyMaterial = KDF_RFC5869(keySeed, KEY_LEN * 2);
    // we use 128-bit AES in counter mode, with an IV of all 0 bytes.
    const IV = Buffer.alloc(16)
    const forwardKey = aes_128_ctr(keyMaterial.subarray(0, KEY_LEN), IV)
    const backwardKey = aes_128_ctr(keyMaterial.subarray(KEY_LEN, 2*KEY_LEN), IV)

    // extend to next hop
    // TODO: get linkSpecifiers and generate handshake for next hop
    const extend2PayloadPlaintext = serializeExtend2({ linkSpecifiers, handshake })
    const extend2PayloadEncrypted = Buffer.from(await forwardKey.encrypt(extend2PayloadPlaintext))
    this.sendMessage(MessageCells.RELAY, {
      circuitId,
      relayCommand: RelayCells.EXTEND2,
      streamId: 1,
      // this should be a running digest
      digest: Buffer.alloc(4),
      data: extend2PayloadEncrypted,
    })
  }
  async promiseForHandshake (): Promise<any> {
    const [versionsCell, certsCell, authChallengeCell] = await receiveEvents(['VERSIONS', 'CERTS', 'AUTH_CHALLENGE'], this.incommingCommands)
    return { versionsCell, certsCell, authChallengeCell };
  }
  onData (data: Buffer): void {
    console.log(`< received data (${data.length} bytes)`)
    const { handShakeInProgress } = this.state
    // TODO: dont read cells until you've seen the minimum number of bytes for a cell
    // TODO: retain unused data
    for (const cell of readCellsFromData(data, () => this.state.linkProtocolVersion)) {
      if (handShakeInProgress) {
        this._incommingHandshakeDigestData.push(cell.data);
      }
      console.log(`<< received ${cell.commandName} (${cell.data.length} bytes)`)
      this.incommingCommands.emit(cell.commandName, cell);
    }  
  }
  sendMessage (messageType: number, messageParams: any): void {
    const { handShakeInProgress } = this.state
    const serializedCell = serializeCommand(messageType, messageParams, this.state.linkProtocolVersion)
    console.log(`>> sending ${MessageCells[messageType]} (${serializedCell.length} bytes)`)
    if (handShakeInProgress) {
      this._outgoingHandshakeDigestData.push(serializedCell);
    }
    this.sendData(serializedCell);
  }
  // virtual - override
  sendData(_serializedCell: any) {
    throw new Error("Method not implemented.");
  }
  receiveEvent (eventName: string): Promise<any> {
    return receiveEvent(eventName, this.incommingCommands)
  }
  receiveEvents (eventNames: Array<string>): Promise<any[]> {
    return receiveEvents(eventNames, this.incommingCommands)
  }
}

export class TlsChannelConnection extends ChannelConnection {
  socket?: tls.TLSSocket;

  async connect (server: { ip: string, port: number }, additonalOptions: { localPort: number }) {
    const options = {
      servername: makeRandomServerName(),
      rejectUnauthorized: false,
      ...additonalOptions,
    }
    const socket = tls.connect(server.port, server.ip, options);
    this.socket = socket;
    const socketReadyP = new Promise<void>((resolve) => {
      socket.once('secureConnect', resolve);
    });
    socket.on('data', (data) => {
      this.onData(data)
    });
    socket.on('end',() => { console.log('end') });
    socket.on('close',() => { console.log('close') });
    socket.on('error', (err) => { console.log('error', err) });
    await socketReadyP;
    // perform handshake
    this.peerConnectionDetails = {
      cert: socket.getPeerCertificate(true),
      addressInfo: socket.address() as NodejsPeerAddressInfo,
    }
  }

  sendData (data: Buffer) {
    console.log(`> sending data (${data.length} bytes)`)
    if (!this.socket) {
      throw new Error('socket is undefined')
    }
    this.socket.write(data)
  }
}

export async function testHandshake ({ keyInfo }: { keyInfo: KeyInfo }) {
  const channelConnection = new TlsChannelConnection({ isInitiator: true })
  await testConnectToKnownNode({ channelConnection, keyInfo })
}

async function testConnectToKnownNode ({ channelConnection, keyInfo }: { channelConnection: TlsChannelConnection, keyInfo: KeyInfo }) {
  // select guard and connect
  // const randomGuard = knownGuards[Math.floor(Math.random()*knownGuards.length)]
  // const randomGuard = ['109.105.109.162', 60784]

  // for chutney debugging
  const randomGuard = ['127.0.0.1', 5004]
  const server = {
    ip: randomGuard[0] as string,
    port: randomGuard[1] as number,
  }
  await channelConnection.connect(server, {
    // for chutney debugging
    localPort: 12345
  })
  console.log('connected')

  await channelConnection.performHandshake()
  console.log('handshake complete')

  await channelConnection.createCircuit()
  console.log('circuit created')
}

function receiveEvent (eventName: string, eventEmitter: EventEmitter): Promise<any> {
  return new Promise((resolve) => {
    eventEmitter.once(eventName, resolve);
  });
}

function receiveEvents (eventNames: Array<string>, eventEmitter: EventEmitter): Promise<any> {
  return Promise.all(eventNames.map((eventName) => {
    return receiveEvent(eventName, eventEmitter);
  }));
}

function getHighestSharedNumber (listA: Array<number>, listB: Array<number>): number | undefined {
  return listB.reduce((highestNumber: number | undefined, number: number) => {
    if (highestNumber === undefined) {
      return number
    }
    if (listA.includes(number) && number > highestNumber) {
      return number
    }
    return highestNumber
  }, undefined)
}

export type NodejsPeerAddressInfo = {
  port: number,
  family: string,
  address: string,
}

export function nodejsPeerAddressToNetInfo (peerAddressInfo: NodejsPeerAddressInfo | undefined): NetInfoAddress | undefined {
  if (!peerAddressInfo) return undefined;
  return {
    type: AddressTypes[peerAddressInfo.family],
    address: peerAddressInfo.address,
  }
}

function createRandomCircuitId (protocolVersion: number, isInitiator: boolean): Buffer {
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
    randomId[0] |= 0x80;
  }
  return randomId;
}