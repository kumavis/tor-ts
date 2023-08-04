import { x25519 } from '@noble/curves/ed25519';
import { makeAes128CtrKey } from './aes'
import crypto from 'node:crypto';

import { ChannelConnection } from "./channel";
import {
  MessageCell,
  MessageCells as MessageCellType,
  CellCreated2,
  serializeRelayCellPayload,
  setRelayCellIntegrity,
  checkRelayCellRecognized,
  parseRelayCellPayload,
  parseCreate2Cell,
} from './messaging';
import type { CellDestroy, CellRelayUnparsed, LinkSpecifier } from './messaging'
import {
  makeCreate2ClientHandshakeForNtor,
  parseCreate2ServerHandshakeForNtor,
  getKeySeedFromNtorServerHandshake,
  KDF_RFC5869,
  NtorServerHandshake,
} from './ntor';
import {
  RelayCell,
  serializeExtend2,
} from './relay-cell'
import { BytesReader, deferred, sha1 } from './util';

const KEY_LEN = 16;
const HASH_LEN = 20;

type HopKey = {
  encrypt(message: Buffer): Promise<Uint8Array>;
  decrypt(message: Buffer): Promise<Uint8Array>;
}

export type PeerInfo = {
  onionKey: Buffer;
  rsaIdDigest: Buffer;
  linkSpecifiers: Array<LinkSpecifier>;
}

class Hop {
  isConnected = false;
  peerInfo: PeerInfo;
  ntorEphemeralKeyPrivate: Buffer;
  ntorEphemeralKeyPublic: Buffer;
  forwardDigest: Buffer;
  backwardDigest: Buffer;
  forwardKey: HopKey;
  backwardKey: HopKey;
  handshakePromiseKit = deferred<void>()

  async encryptForward (data: Buffer) {
    return Buffer.from(await this.forwardKey.encrypt(data))
  }
  async decryptBackward (data: Buffer) {
    return Buffer.from(await this.backwardKey.decrypt(data))
  }
  createClientHandshake () {
    this.ntorEphemeralKeyPrivate = Buffer.from(x25519.utils.randomPrivateKey())
    this.ntorEphemeralKeyPublic = Buffer.from(x25519.getPublicKey(this.ntorEphemeralKeyPrivate))
    const clientHandshake = makeCreate2ClientHandshakeForNtor({
      ownOnionKey: this.ntorEphemeralKeyPublic,
      peerOnionKey: this.peerInfo.onionKey,
      peerRsaIdDigest: this.peerInfo.rsaIdDigest,
    })
    return clientHandshake
  }
  async receiveCreated2Handshake (handshake: NtorServerHandshake) {
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
    this.forwardKey = await makeAes128CtrKey(keyMaterial.readBytes(KEY_LEN))
    this.backwardKey = await makeAes128CtrKey(keyMaterial.readBytes(KEY_LEN))
    this.isConnected = true
    this.handshakePromiseKit.resolve()
  }
  toString () {
    const port = this.peerInfo.linkSpecifiers[0].data.subarray(4).readInt16BE()
    return `hop:${port}`
  }
}

export class Circuit {
  channel: ChannelConnection;
  hops: Array<Hop> = [];
  unsubscribeFromChannel?: () => void;
  circuitId: Buffer;
  relayMessageCount: 0;

  constructor ({
    path,
    channel,
  }: {
    path: Array<PeerInfo>,
    channel: ChannelConnection,
  }) {
    this.channel = channel
    // select circuitId
    const protocolVersion = channel.getProtocolVersion()
    const circuitId = createRandomCircuitId(protocolVersion, true)
    this.circuitId = circuitId
    // setup hops
    for (let i = 0; i < path.length; i++) {
      const relayPeerInfo = path[i]
      const relayedHop = new Hop()
      relayedHop.peerInfo = relayPeerInfo
      this.hops.push(relayedHop)
    }
    // listen for messages
    this.unsubscribeFromChannel = channel.subscribeCircuit(circuitId, '*', (message: MessageCell) => {
      this.receiveMessage(message)
    })
  }

  get firstHop () {
    return this.hops[0]
  }
  get lastHop () {
    return this.hops[this.hops.length - 1]
  }

  async connect () {
    for (const hop of this.hops) {
      await this.performHandshakeForHop(hop)
    }
  }

  async performHandshakeForHop (hop: Hop) {
    if (hop.isConnected) {
      throw new Error('hop already connected during handshake attempt')
    }
    const clientHandshake = hop.createClientHandshake()
    if (hop === this.firstHop) {
      // this is our first hop - just a create2
      this.channel.sendMessage(MessageCellType.CREATE2, {
        circuitId: this.circuitId,
        handshake: clientHandshake,
      })
    } else {
      // extending the relay - send extend2 to previous hop
      const handshakeHopIndex = this.hops.indexOf(hop)
      const targetHop = this.hops[handshakeHopIndex - 1]
      const extend2PayloadPlaintext = serializeExtend2({
        linkSpecifiers: hop.peerInfo.linkSpecifiers,
        handshake: clientHandshake,
      })
      // i expect to abstract this into a function
      const relayCellPayload = serializeRelayCellPayload({
        streamId: 0,
        relayCommand: RelayCell.EXTEND2,
        data: extend2PayloadPlaintext,
      })
      await this.sendRelayMessageToHop(relayCellPayload, targetHop)
    }
    // wait until handshake response has been received
    await hop.handshakePromiseKit.promise
  }

  async sendRelayMessageToHop (relayCellPayload: Buffer, targetHop: Hop) {
    const targetHopIndex = this.hops.indexOf(targetHop)
    const backHops = this.hops.slice(0, targetHopIndex + 1).reverse()
    // update the forwardDigest and set the integrity
    targetHop.forwardDigest = sha1(targetHop.forwardDigest, relayCellPayload)
    const integrity = targetHop.forwardDigest.subarray(0, 4)
    setRelayCellIntegrity(relayCellPayload, integrity)
    // encrypt
    let currentPayload = relayCellPayload
    for (const backHop of backHops) {
      currentPayload = await backHop.encryptForward(currentPayload)
    }
    // send over channel
    this.relayMessageCount++
    const relayType = this.relayMessageCount > 8 ? MessageCellType.RELAY : MessageCellType.RELAY_EARLY
    this.channel.sendMessageWithPayload(this.circuitId, relayType, currentPayload)
  }

  receiveMessage (message: MessageCell) {
    switch (message.command) {
      case MessageCellType.RELAY:
        this.receiveRelayMessage(message.message as CellRelayUnparsed)
        break;
      case MessageCellType.CREATED2:
        const created2Message = message.message as CellCreated2
        const serverHandshake = parseCreate2ServerHandshakeForNtor(created2Message.handshake)
        this.firstHop.receiveCreated2Handshake(serverHandshake)
        break;
      case MessageCellType.DESTROY:
        const destroyMessage = message.message as CellDestroy
        console.warn('! got destroy', destroyMessage)
        // this.receiveDestroyMessage(message.message as CellDestroy)
        break;
      default:
        throw new Error(`Circuit received unknown message type: ${message.command}`)
    }
  }

  async receiveRelayMessage (relayMessage: CellRelayUnparsed) {
    // decrypt and identify target hop
    let currentPayload = relayMessage.payload
    let targetHop: Hop
    for (const hop of this.hops) {
      if (!hop.isConnected) continue
      currentPayload = Buffer.from(await hop.decryptBackward(currentPayload))
      const looksRecognized = checkRelayCellRecognized(currentPayload)
      if (looksRecognized) {
        targetHop = hop
        const targetHopIndex = this.hops.indexOf(targetHop)
        // TODO: check digest
        // TODO: update backward digest
        break
      }
    }
    if (!targetHop) {
      console.warn('did not find matching hop for relay message')
      return
    }
    // parse and process relay message
    const relayCell = parseRelayCellPayload(currentPayload)
    switch (relayCell.relayCommand) {
      case RelayCell.EXTENDED2: {
        const create2Cell = parseCreate2Cell(relayCell.data)
        const handshake = parseCreate2ServerHandshakeForNtor(create2Cell.handshake)
        const targetHopIndex = this.hops.indexOf(targetHop)
        const nextHop = this.hops[targetHopIndex + 1]
        nextHop.receiveCreated2Handshake(handshake)
        return
      }
      default: {
        throw new Error(`Hop received unknown relay message type ${relayCell.relayCommand}`)
      }
    }

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
