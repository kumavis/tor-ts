import { x25519 } from '@noble/curves/ed25519';
import {
  aes_128_ctr
} from '@noble/ciphers/webcrypto/aes';
import crypto from 'node:crypto';

import { ChannelConnection } from "./channel";
import {
  MessageCell,
  MessageCells as MessageCellType,
  CellRelay,
  Create2ClientHandshake,
  Create2ServerHandshake,
  CellCreated2,
  serializeCommand,
  serializeRelayCellPayload,
} from './messaging';
import type { CellDestroy, LinkSpecifier } from './messaging'
import {
  makeCreate2ClientHandshakeForNtor,
  parseCreate2ServerHandshakeForNtor,
  getKeySeedFromNtorServerHandshake,
  KDF_RFC5869,
  HmacSha256,
  NtorServerHandshake,
} from './ntor';
import {
  RelayCell,
  serializeExtend2,
} from './relay-cell'
import { BytesReader, deferred } from './util';

const KEY_LEN = 16;
const HASH_LEN = 20;

type HopKey = {
  encrypt(message: Buffer): Uint8Array;
  decrypt(message: Buffer): Uint8Array;
}

export type PeerInfo = {
  onionKey: Buffer;
  rsaIdDigest: Buffer;
  linkSpecifiers: Array<LinkSpecifier>;
}

class Hop {
  circuitId: Buffer;
  peerInfo: PeerInfo;
  ntorEphemeralKeyPrivate: Buffer;
  ntorEphemeralKeyPublic: Buffer;
  forwardDigest: Buffer;
  backwardDigest: Buffer;
  forwardKey: HopKey;
  backwardKey: HopKey;
  handshakePromiseKit = deferred<void>()
  async sendRelayMessage (streamId: number, messageType: RelayCell, data: Buffer) {
    throw new Error('virtual sendRelayMessage method')
  }
  async sendHandshake (_handshake: Create2ClientHandshake) {
    throw new Error('virtual sendHandshake method')
  }
  async performHandshake () {
    this.ntorEphemeralKeyPrivate = Buffer.from(x25519.utils.randomPrivateKey())
    this.ntorEphemeralKeyPublic = Buffer.from(x25519.getPublicKey(this.ntorEphemeralKeyPrivate))
    const clientHandshake = makeCreate2ClientHandshakeForNtor({
      ownOnionKey: this.ntorEphemeralKeyPublic,
      peerOnionKey: this.peerInfo.onionKey,
      peerRsaIdDigest: this.peerInfo.rsaIdDigest,
    })
    await this.sendHandshake(clientHandshake)
    await this.handshakePromiseKit.promise
  }
  receiveCreated2Handshake (handshake: NtorServerHandshake) {
    const { serverNtorEphemeralKeyPublic, serverNtorAuth } = handshake
    // generate Kf_1, Kb_1
    const keySeed = getKeySeedFromNtorServerHandshake({
      clientNtorEphemeralKeyPrivate: this.ntorEphemeralKeyPrivate,
      clientNtorEphemeralKeyPublic: this.ntorEphemeralKeyPublic,
      serverNtorIdentityKeyPublic: this.peerInfo.onionKey,
      serverRsaIdentityKeyDigest: this.peerInfo.rsaIdDigest,
      serverNtorEphemeralKeyPublic,
      serverNtorAuth,
    })
    const keyMaterial = new BytesReader(KDF_RFC5869(keySeed, 2 * HASH_LEN + 2 * KEY_LEN));
    this.forwardDigest = keyMaterial.readBytes(HASH_LEN)
    this.backwardDigest = keyMaterial.readBytes(HASH_LEN)
    // we use 128-bit AES in counter mode, with an IV of all 0 bytes.
    const IV = Buffer.alloc(16)
    this.forwardKey = aes_128_ctr(keyMaterial.readBytes(KEY_LEN), IV)
    this.backwardKey = aes_128_ctr(keyMaterial.readBytes(KEY_LEN), IV)
    console.log('established keys')
    this.handshakePromiseKit.resolve()
  }
  receiveRelayMessage (message: CellRelay) {
    // TODO: review this
    // decrypt
    const decryptedMessage = Buffer.from(this.backwardKey.decrypt(message.data))
    // TODO: check if this message is for here
    // pass onward
    // this.sendRelayMessage(this.circuitId, message.relayCommand, decryptedMessage)
    console.log('received relay message')
  }
}

class ChannelHop extends Hop {
  channel: ChannelConnection;
  async sendHandshake(handshake: Create2ClientHandshake): Promise<void> {
    this.channel.sendMessage(MessageCellType.CREATE2, {
      circuitId: this.circuitId,
      handshake,
    })
  }
  async sendRelayMessage (streamId: number, messageType: RelayCell, data: Buffer) {
    const relayCellPayload = serializeRelayCellPayload({
      streamId,
      relayCommand: messageType,
      // TODO: this should be a running digest
      /////////////////////////////////////////////////////////////////////////////////////////////
      // THE FAILURE IS HERE: digest is wrong
      /////////////////////////////////////////////////////////////////////////////////////////////
      digest: this.forwardDigest,
      data,
    })
    // relay cell (circuitId, commandCode, cellPayload)
    // relay cell payload (relay subcommand, recognized, streamId, digest....) <-- encrypt here
    // relay cell payload data (extend2 handshake data)
    const encryptedPayload = Buffer.from(await this.forwardKey.encrypt(relayCellPayload))
    this.channel.sendMessageWithPayload(this.circuitId, MessageCellType.RELAY, encryptedPayload)
  }
}

class RelayedHop extends Hop {
  previousHop: Hop;
  linkProtocolVersion: number;
  async sendHandshake(handshake: Create2ClientHandshake): Promise<void> {
    // TODO: include ed25519 linkSpecifiers if available
    const extend2PayloadPlaintext = serializeExtend2({
      linkSpecifiers: this.peerInfo.linkSpecifiers,
      handshake,
    })
    // we dont encypt this message here because we haven't established keys yet
    this.previousHop.sendRelayMessage(0, RelayCell.EXTEND2, extend2PayloadPlaintext)
  }
  async sendRelayMessage (streamId: number, messageType: RelayCell, data: Buffer) {
    // encrypt
    const encryptedMessage = Buffer.from(await this.forwardKey.encrypt(data))
    // pass onward
    this.previousHop.sendRelayMessage(streamId, messageType, encryptedMessage)
  }
}

export class Circuit {
  hops: Array<Hop> = [];
  unsubscribeFromChannel?: () => void;

  constructor ({
    path,
    channel,
  }: {
    path: Array<PeerInfo>,
    channel: ChannelConnection,
  }) {
    // select circuitId
    const protocolVersion = channel.getProtocolVersion()
    const circuitId = createRandomCircuitId(protocolVersion, true)
    // setup hops
    const channelHop = new ChannelHop()
    channelHop.channel = channel
    channelHop.peerInfo = path[0]
    channelHop.circuitId = circuitId
    this.hops.push(channelHop)
    for (let i = 1; i < path.length; i++) {
      const relayPeerInfo = path[i]
      const relayedHop = new RelayedHop()
      relayedHop.peerInfo = relayPeerInfo
      relayedHop.previousHop = this.hops[i - 1]
      relayedHop.circuitId = circuitId
      this.hops.push(relayedHop)
    }
    // listen for messages
    this.unsubscribeFromChannel = channel.subscribeCircuit(circuitId, '*', (message: MessageCell) => {
      this.receiveMessage(message)
    })
  }

  async connect () {
    const channelHop = this.hops[0]
    console.log('> circuit 0 handshake')
    await channelHop.performHandshake()
    console.log('< circuit 0 handshake')

    console.log('> circuit 1 handshake')
    await this.hops[1].performHandshake()
    console.log('< circuit 1 handshake')

  }

  get firstHop () {
    return this.hops[0]
  }
  get lastHop () {
    return this.hops[this.hops.length - 1]
  }

  receiveMessage (message: MessageCell) {
    switch (message.command) {
      // case MessageCellType.RELAY:
      //   this.receiveRelayMessage(message.message as CellRelay)
      //   break;
      case MessageCellType.CREATED2:
        const created2Message = message.message as CellCreated2
        const serverHandshake = parseCreate2ServerHandshakeForNtor(created2Message.handshake)
        this.firstHop.receiveCreated2Handshake(serverHandshake)
        break;
      case MessageCellType.DESTROY:
        const destroyMessage = message.message as CellDestroy
        console.log('! got destroy', destroyMessage)
        // this.receiveDestroyMessage(message.message as CellDestroy)
        break;
      default:
        throw new Error(`Circuit received unknown message type: ${message.command}`)
    }
  }

  receiveRelayMessage (relayMessage: CellRelay) {
    this.firstHop.receiveRelayMessage(relayMessage);
  }

  destroy () {
    if (this.unsubscribeFromChannel) {
      this.unsubscribeFromChannel()
    }
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

export function circuitIdLengthForProtocolVersion (protocolVersion: number | undefined): number {
  // CIRCID_LEN is 2 for link protocol versions 1, 2, and 3.  CIRCID_LEN
  // is 4 for link protocol version 4 or higher.  The first VERSIONS cell,
  // and any cells sent before the first VERSIONS cell, always have
  // CIRCID_LEN == 2 for backward compatibility.

  // for the "any cells sent before the first VERSIONS cell" case, we use an undefined protocol
  // version
  return protocolVersion && protocolVersion >= 4 ? 4 : 2;
}
