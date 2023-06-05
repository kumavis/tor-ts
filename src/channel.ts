import { EventEmitter } from 'node:events';
import tls from 'node:tls';
import crypto from 'node:crypto';

import type { KeyInfo } from './profiles';
import {
  makeRandomServerName,
} from './tls';
import {
  validateCertsCellForIdentities,
} from './cert';
import {
  messageCells,
  serializeCommand,
  readCellsFromData,
  AddressTypes,
  circuitIdLengthForProtocolVersion,
} from './messaging';
import type {
  MessageCell,
  NetInfoAddress,
} from './messaging';
import { sha256, sha1 } from './util'
import { knownGuards } from './guard-nodes';
import { makeCreate2CellForNtor } from './ntor';
import { dangerouslyLookupOnionKey, getRandomDirectoryAuthority } from './directory';

const defaultLinkSupportedVersions = [3, 4, 5];

export class ChannelConnection {
  
  isInitiator: boolean;
  incommingCommands: any;
  state: {
    linkProtocolVersion: number | undefined;
    handShakeInProgress: boolean;
  };
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
  onData (data: Buffer): void {
    const { handShakeInProgress } = this.state
    for (const cell of readCellsFromData(data, () => this.state.linkProtocolVersion)) {
      if (handShakeInProgress) {
        this._incommingHandshakeDigestData.push(cell.data);
      }
      console.log('event', cell.commandName)
      this.incommingCommands.emit(cell.commandName, cell);
    }  
  }
  sendMessage (messageType: number, messageParams: any): void {
    const { handShakeInProgress } = this.state
    const serializedCell = serializeCommand(messageType, messageParams, this.state.linkProtocolVersion)
    if (handShakeInProgress) {
      this._outgoingHandshakeDigestData.push(serializedCell);
    }
    
    this.sendData(serializedCell);
  }
  sendData(_serializedCell: any) {
    throw new Error("Method not implemented.");
  }
  async promiseForHandshake (): Promise<any> {
    // TODO: should fail if any of these are repeated
    const [versionsCell, certsCell, authChallengeCell] = await receiveEvents(['VERSIONS', 'CERTS', 'AUTH_CHALLENGE'], this.incommingCommands)
    return { versionsCell, certsCell, authChallengeCell };
  }
  receiveEvents (eventNames: Array<string>): Promise<any[]> {
    return receiveEvents(eventNames, this.incommingCommands)
  }
}

export async function testHandshake ({ keyInfo }: { keyInfo: KeyInfo }) {
  const channelConnection = new ChannelConnection({ isInitiator: true })
  
  // connection.incommingCommands.once('NETINFO', (cell: MessageCell) => {
  //   const message = cell.message as CellNetInfo;
  //   console.log(`NETINFO: other address: ${message.otherAddress}`, message);
  //   for (const address of message.addresses) {
  //     console.log(`  ${address}`)
  //   }
  // })

  
  // test handshake
  // await testHandshakeFixture({ connection, keyInfo })
  await testConnectToKnownNode({ channelConnection, keyInfo })

}

async function testConnectToKnownNode ({ channelConnection, keyInfo }: { channelConnection: ChannelConnection, keyInfo: KeyInfo }) {
  // select guard and connect
  const randomGuard = knownGuards[Math.floor(Math.random()*knownGuards.length)]
  // const randomGuard = ['109.105.109.162', 60784]
  const server = {
    ip: randomGuard[0] as string,
    port: randomGuard[1] as number,
  }
  const options = {
    servername: makeRandomServerName(),
    rejectUnauthorized: false,
  }
  let socket = tls.connect(server.port, server.ip, options);
  const socketReadyP = new Promise<void>((resolve) => {
    socket.once('secureConnect', resolve);
  });

  // wire up connection to socket
  channelConnection.sendData = (data) => socket.write(data)
  socket.on('data', (data) => {
    channelConnection.onData(data)
  });
  // connection.sendData = (data) => {
  //   console.log(`out-> ${data.toString('hex')}`)
  //   socket.write(data)
  // }
  // socket.on('data', (data) => {
  //   console.log(`in<- ${data.toString('hex')}`)
  //   connection.onData(data)
  // });
  socket.on('end',() => { console.log('end') });
  socket.on('close',() => { console.log('close') });
  socket.on('error', (err) => { console.log('error', err) });
  await socketReadyP

  // perform handshake
  const peerCert = socket.getPeerCertificate(true);
  const peerAddressInfo = socket.address() as NodejsPeerAddressInfo;
  await performHandshake(channelConnection, keyInfo, peerCert.raw, defaultLinkSupportedVersions, peerAddressInfo)
  console.log('handshake complete')
  const peerIdentity = channelConnection.identity;


  // lookup onion key
  const directoryAuthority = await getRandomDirectoryAuthority()
  const peerOnionKey = await dangerouslyLookupOnionKey(directoryAuthority.dir_address, peerIdentity.rsaIdDigest);

  console.log('sending CREATE2')
  // circuitId length is variable based on protocol version
  const circuitId = randomCircuitIdForVersion(channelConnection.state.linkProtocolVersion);
  const ownOnionKey = Buffer.alloc(32);
  channelConnection.sendMessage(messageCells.CREATE2, {
    circuitId,
    ...makeCreate2CellForNtor(
      ownOnionKey,
      peerOnionKey,
      peerIdentity.rsaIdDigest,
    )
  })
}

export async function performHandshake (
  channelConnection: ChannelConnection,
  keyInfo: KeyInfo,
  peerCert: Buffer,
  supportedVersions: Array<number> = defaultLinkSupportedVersions,
  peerAddressInfo?: NodejsPeerAddressInfo
) {
  // TODO: use NETINFO timestamp to determine clock skew
  const now = Date.now()
  const clockSkew = 0;

  const handshakePromise = channelConnection.promiseForHandshake();

  // need to do this synchronously so subsequent messages are parsed correctly based on the protocol version
  channelConnection.incommingCommands.once('VERSIONS', (versionsCell: MessageCell) => {
    // determine shared link protocol version
    console.log('supported versions:', supportedVersions, versionsCell.message.versions)
    const linkProtocolVersion = getHighestSharedNumber(supportedVersions, versionsCell.message.versions)
    if (linkProtocolVersion === undefined) {
      throw new Error('No shared link protocol version')
    }
    channelConnection.state.linkProtocolVersion = linkProtocolVersion
    console.log('VERSIONS: set linkProtocolVersion', linkProtocolVersion)
  })
  // send our handshake intro
  channelConnection.sendMessage(messageCells.VERSIONS, { versions: supportedVersions })
  
  // receive their handshake intro
  const { certsCell } = await handshakePromise;

  // sha256 hash of (DER-encoded) peer certificate for this connection
  const peerCertSha256 = sha256(peerCert);
  const {
    rsaId,
    ed25519Id,
  } = validateCertsCellForIdentities(certsCell.message, peerCertSha256, now, clockSkew);
  const rsaIdDigest = sha1(rsaId.export({ type: 'pkcs1', format: 'der' }));
  channelConnection.identity = { rsaId, rsaIdDigest, ed25519Id };

  // console.log('AUTH_CHALLENGE: accepted challenge methods');
  // for (const type of authChallengeCell.message.methods) {
  //   console.log(`  ${getAuthTypeDescription(type)}`)
  // }

  // If it does not want to authenticate, it MUST
  // send a NETINFO cell.  
  // If it does want to authenticate, it MUST send a
  //  CERTS cell, an AUTHENTICATE cell (4.4), and a NETINFO.
  // const certs = certsFromKeyInfo({ keyInfo });
  // connection.sendMessage(messageCells.CERTS, { certs });

  // Complete handshake by sending NETINFO
  console.log('sending NETINFO')
  channelConnection.sendMessage(messageCells.NETINFO, {
    //   Clients SHOULD send "0" as their timestamp, to
    //  avoid fingerprinting.
    time: 0,
    otherAddress: nodejsPeerAddressToNetInfo(peerAddressInfo),
    addresses: [],
  })
}

function receiveEvents (eventNames: Array<string>, eventEmitter: EventEmitter): Promise<any> {
  return Promise.all(eventNames.map((eventName) => {
    return new Promise((resolve) => {
      eventEmitter.once(eventName, resolve);
    });
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

function randomCircuitIdForVersion (protocolVersion: number) {
  if (protocolVersion === undefined) {
    throw new Error('protocolVersion is undefined');
  }
  const circuitIdLength = circuitIdLengthForProtocolVersion(protocolVersion);
  return crypto.randomBytes(circuitIdLength);
}