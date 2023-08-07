import { EventEmitter } from 'node:events';
import tls from 'node:tls';
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
  serializeCellWithPayload,
  linkSpecifierToAddressAndPort,
} from './messaging';
import type {
  MessageCell,
  AddressAndPort,
  CellVersions,
  CellNetInfo,
  NetInfoAddress,
} from './messaging';
import { sha256, sha1 } from './util'
import { PeerInfo } from './circuit';

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
      const linkProtocolVersion = getHighestSharedNumber(supportedVersions, versionsCell.message.versions)
      if (linkProtocolVersion === undefined) {
        throw new Error('No shared link protocol version')
      }
      this.state.linkProtocolVersion = linkProtocolVersion
    })
    // send our handshake intro
    this.sendVersions({ versions: supportedVersions })

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

    this.sendNetInfo({
      //   Clients SHOULD send "0" as their timestamp, to
      //  avoid fingerprinting.
      time: 0,
      otherAddress: nodejsPeerAddressToNetInfo(peerAddressInfo),
      addresses: [],
    })
    this.state.handShakeInProgress = false
  }
  sendVersions (versionsCell: CellVersions): void {
    this.sendMessage(MessageCells.VERSIONS, versionsCell)
  }
  sendNetInfo (netInfoCell: CellNetInfo): void {
    this.sendMessage(MessageCells.NETINFO, netInfoCell)
  }
  async promiseForHandshake (): Promise<any> {
    const [versionsCell, certsCell, authChallengeCell] = await receiveEvents(['VERSIONS', 'CERTS', 'AUTH_CHALLENGE'], this.incommingCommands)
    return { versionsCell, certsCell, authChallengeCell };
  }
  onData (data: Buffer): void {
    // console.log(`< received data (${data.length} bytes)`)
    const { handShakeInProgress } = this.state
    // TODO: dont read cells until you've seen the minimum number of bytes for a cell
    // TODO: retain unused data
    for (const cell of readCellsFromData(data, () => this.state.linkProtocolVersion)) {
      if (handShakeInProgress) {
        this._incommingHandshakeDigestData.push(cell.data);
      }
      // console.log(`<< received ${cell.commandName} (${cell.data.length} bytes)`)
      this.incommingCommands.emit(cell.commandName, cell);
      this.incommingCommands.emit('*', cell);
    }  
  }
  sendMessage (messageType: number, messageParams: any): void {
    const { handShakeInProgress } = this.state
    const serializedCell = serializeCommand(messageType, messageParams, this.state.linkProtocolVersion)
    // console.log(`>> sending ${MessageCells[messageType]} (${serializedCell.length} bytes)`)
    if (handShakeInProgress) {
      this._outgoingHandshakeDigestData.push(serializedCell);
    }
    this.sendData(serializedCell);
  }
  sendMessageWithPayload (circuitId: Buffer, messageType: number, payloadBytes: Buffer): void {
    const { handShakeInProgress } = this.state
    const serializedCell = serializeCellWithPayload(circuitId, messageType, payloadBytes)
    // console.log(`>> sending ${MessageCells[messageType]} (${serializedCell.length} bytes on ${circuitId.toString('hex')})`)
    // console.log(`>> ${serializedCell.toString('hex')}`)
    if (handShakeInProgress) {
      this._outgoingHandshakeDigestData.push(serializedCell);
    }
    this.sendData(serializedCell);
  }
  receiveEvent (eventName: string): Promise<any> {
    return receiveEvent(eventName, this.incommingCommands)
  }
  receiveEvents (eventNames: Array<string>): Promise<any[]> {
    return receiveEvents(eventNames, this.incommingCommands)
  }
  subscribeCircuit (circuitId: Buffer, eventName: string, handler: Function): () => void {
    const listener = (message: MessageCell) => {
      if (!circuitId.equals(message.circId)) return
      handler(message)
    }
    this.incommingCommands.on(eventName, listener)
    const unsubscribe = () => {
      this.incommingCommands.off(eventName, listener)  
    }
    return unsubscribe
  }
  getProtocolVersion (): number {
    return this.state.linkProtocolVersion
  }
  // virtual - override
  sendData(_serializedCell: any) {
    throw new Error("virtual method 'sendData' not implemented.");
  }
}

export class TlsChannelConnection extends ChannelConnection {
  socket?: tls.TLSSocket;

  async connectPeerInfo (gatewayPeerInfo: PeerInfo, additonalOptions?: { localPort: number }) {
    return this.connect(
      linkSpecifierToAddressAndPort(gatewayPeerInfo.linkSpecifiers[0]),
      additonalOptions
    )
  }

  async connect (server: AddressAndPort, additonalOptions?: { localPort: number }) {
    const tlsOptions = {
      servername: makeRandomServerName(),
      rejectUnauthorized: false,
      ...additonalOptions,
    }
    const socket = tls.connect(server.port, server.ip, tlsOptions);
    this.socket = socket;
    const socketReadyP = new Promise<void>((resolve) => {
      socket.once('secureConnect', resolve);
    });
    socket.on('data', (data) => {
      this.onData(data)
    });
    // socket.on('end',() => { console.log('end') });
    // socket.on('close',() => { console.log('close') });
    // socket.on('error', (err) => { console.log('error', err) });
    await socketReadyP;
    // perform handshake
    this.peerConnectionDetails = {
      cert: socket.getPeerCertificate(true),
      addressInfo: socket.address() as NodejsPeerAddressInfo,
    }
    await this.performHandshake()
  }

  sendData (data: Buffer) {
    // console.log(`> sending data (${data.length} bytes)`)
    if (!this.socket) {
      throw new Error('socket is undefined')
    }
    this.socket.write(data)
  }
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
    address: peerAddressInfo.address,
    type: AddressTypes[peerAddressInfo.family],
  }
}
