import { EventEmitter } from 'events';
import tls from 'node:tls';
import type { KeyInfo } from './profiles';
import {
  getAuthTypeDescription,
  makeRandomServerName,
} from './tls';
import {
  validateCertsCellForIdentities,
  getCertDescription,
} from './cert';
import {
  messageCells,
  serializeCommand,
  readCellsFromData,
  AddressTypes,
} from './messaging';
import type {
  MessageCell,
  CellNetInfo,
  Certificate,
} from './messaging';
import { sha256 } from './util'

const defaultLinkSupportedVersions = [3, 4, 5];

export class Connection {
  
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
    const serializedCell = serializeCommand(messageType, messageParams)
    if (handShakeInProgress) {
      this._outgoingHandshakeDigestData.push(serializedCell);
    }
    
    this.sendData(serializedCell);
  }
  sendData(_serializedCell: any) {
    throw new Error("Method not implemented.");
  }
  promiseForHandshake (): Promise<any> {
    // TODO: should fail if any of these are repeated
    const handshakePromise = receiveEvents(['VERSIONS', 'CERTS', 'AUTH_CHALLENGE'], this.incommingCommands)
    return handshakePromise;
  }
  receiveEvents (eventNames: Array<string>): Promise<any[]> {
    return receiveEvents(eventNames, this.incommingCommands)
  }
}

export async function testHandshake ({ keyInfo }: { keyInfo: KeyInfo }) {
  const connection = new Connection({ isInitiator: true })
  
  // connection.incommingCommands.once('NETINFO', (cell: MessageCell) => {
  //   const message = cell.message as CellNetInfo;
  //   console.log(`NETINFO: other address: ${message.otherAddress}`, message);
  //   for (const address of message.addresses) {
  //     console.log(`  ${address}`)
  //   }
  // })

  
  // test handshake
  // await testHandshakeFixture({ connection, keyInfo })
  await testConnectToKnownNode({ connection, keyInfo })

}

type PeerAddressInfo = {
  port: number,
  family: string,
  address: string,
}

async function testConnectToKnownNode ({ connection, keyInfo }: { connection: Connection, keyInfo: KeyInfo }) {
  const server = {
    ip: '93.180.157.154',
    port: 9001,
  }
  const options = {
    servername: makeRandomServerName(),
    rejectUnauthorized: false,
  }
  const socket = tls.connect(server.port, server.ip, options, function() {
    const peerCert = socket.getPeerCertificate();
    // console.log('peerCertRaw', peerCert.raw.toString('ascii'))
    const linkProtocolSupportedVersions = [3, 4, 5];
    const peerAddressInfo = socket.address() as PeerAddressInfo;
    // { port: 12346, family: 'IPv4', address: '127.0.0.1' }.
    performHandshake(connection, keyInfo, peerCert.raw, linkProtocolSupportedVersions, peerAddressInfo)
  });
  connection.sendData = (data) => socket.write(data)
  socket.on('data', (data) => {
    connection.onData(data)
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
}

export async function performHandshake (connection: Connection, keyInfo: KeyInfo, peerCert: Buffer, supportedVersions: Array<number> = defaultLinkSupportedVersions, peerAddressInfo?: PeerAddressInfo) {
  // TODO: use NETINFO timestamp to determine clock skew
  const now = Date.now()
  const clockSkew = 0;

  const handshakePromise = connection.promiseForHandshake();

  // need to do this synchronously so subsequent messages are parsed correctly based on the version
  connection.incommingCommands.once('VERSIONS', (versionsCell: MessageCell) => {
    // determine shared link protocol version
    console.log('supported versions:', supportedVersions, versionsCell.message.versions)
    const linkProtocolVersion = getHighestSharedNumber(supportedVersions, versionsCell.message.versions)
    if (linkProtocolVersion === undefined) {
      throw new Error('No shared link protocol version')
    }
    connection.state.linkProtocolVersion = linkProtocolVersion
    console.log('VERSIONS: set linkProtocolVersion', linkProtocolVersion)
  })
  // send our handshake intro
  connection.sendMessage(messageCells.VERSIONS, { versions: supportedVersions })
  
  // receive their handshake intro
  const [_versionsCell, certsCell, authChallengeCell] = await handshakePromise;

  // sha256 hash of (DER-encoded) peer certificate for this connection
  const peerCertSha256 = sha256(peerCert);
  // console.log('peerCertSha256', peerCertSha256.toString('hex'))
  const {
    rsaId,
    ed25519Id,
  } = validateCertsCellForIdentities(certsCell.message, peerCertSha256, now, clockSkew);

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
  // console.log('sending netinfo')

  const otherAddress = peerAddressInfo ? {
    type: AddressTypes[peerAddressInfo.family],
    address: peerAddressInfo.address ? Buffer.from(peerAddressInfo.address, 'ascii') : Buffer.alloc(4),
  } : {
    type: 0,
    address: Buffer.alloc(4),
  };
  connection.sendMessage(messageCells.NETINFO, {
    //   Clients SHOULD send "0" as their timestamp, to
    //  avoid fingerprinting.
    time: 0,
    otherAddress,
    addresses: [],
  })
}



function certsFromKeyInfo({ keyInfo }: { keyInfo: KeyInfo }) {
  const certs: Certificate[] = [];

  // To authenticate the initiator as having an RSA identity key only,
  // the responder MUST check the following:

  //   * The CERTS cell contains exactly one CertType 3 "AUTH" certificate.
  //   * The CERTS cell contains exactly one CertType 2 "ID" certificate.
  //   * Both certificates have validAfter and validUntil dates that
  //     are not expired.
  //   * The certified key in the AUTH certificate is a 1024-bit RSA key.
  //   * The certified key in the ID certificate is a 1024-bit RSA key.
  //   * The certified key in the ID certificate was used to sign both
  //     certificates.
  //   * The auth certificate is correctly signed with the key in the
  //     ID certificate.
  //   * The ID certificate is correctly self-signed.

  certs.push({
    type: 3,
    body: keyInfo.pubkey,
  })
  certs.push({
    type: 2,
    body: keyInfo.pubid,
  })
  return certs
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