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
  serializeCellWithPayload,
  readCellsFromData,
  RELAY_PAYLOAD_LEN,
  chunkDataForRelayDataCells,
} from './messaging';
import type { CellDestroy, CellRelay, CellRelayUnparsed, LinkSpecifier } from './messaging'
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
import { BytesReader, deferred } from './util';
import EventEmitter from 'node:events';

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
  forwardDigest = crypto.createHash('sha1');
  backwardDigest = crypto.createHash('sha1');
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
    this.forwardDigest.update(keyMaterial.readBytes(HASH_LEN))
    this.backwardDigest.update(keyMaterial.readBytes(HASH_LEN))
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

export class CircuitStream extends EventEmitter {
  streamId: number
  destroyed = false
  connectionPromiseKit = deferred<void>()
  write: (data: Buffer) => Promise<void>
  close () {
    this.destroy()
  }
  destroy (err?: Error) {
    this.connectionPromiseKit.reject(err)
    this.destroyed = true
    this.emit('end', err)
  }
}

export class Circuit {
  channel: ChannelConnection
  hops: Array<Hop> = []
  unsubscribeFromChannel?: () => void
  circuitId: Buffer
  relayMessageCount = 0
  lastStreamId = 0
  streams: Array<CircuitStream> = []

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
      await this.sendRelayMessage({
        streamId: 0,
        relayCommand: RelayCell.EXTEND2,
        data: extend2PayloadPlaintext,
      }, targetHop)
    }
    // wait until handshake response has been received
    await hop.handshakePromiseKit.promise
  }

  async sendRelayMessage (relayCell: CellRelay, targetHop: Hop = this.lastHop) {
    const relayCellPayload = serializeRelayCellPayload(relayCell)
    const targetHopIndex = this.hops.indexOf(targetHop)
    // update the forwardDigest and set the integrity
    targetHop.forwardDigest.update(relayCellPayload)
    const integrity = targetHop.forwardDigest.copy().digest().subarray(0, 4)
    setRelayCellIntegrity(relayCellPayload, integrity)
    // encrypt
    let currentPayload = relayCellPayload
    const backHops = this.hops.slice(0, targetHopIndex + 1).reverse()
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
        this.streams.forEach(stream => {
          stream.destroy()
        })
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
    const { streamId, relayCommand, data } = relayCell
    const stream = streamId === 0 ? undefined : this.streams.find(stream => stream.streamId === streamId)
    switch (relayCommand) {
      case RelayCell.EXTENDED2: {
        const create2Cell = parseCreate2Cell(data)
        const handshake = parseCreate2ServerHandshakeForNtor(create2Cell.handshake)
        const targetHopIndex = this.hops.indexOf(targetHop)
        const nextHop = this.hops[targetHopIndex + 1]
        nextHop.receiveCreated2Handshake(handshake)
        return
      }
      case RelayCell.CONNECTED: {
        stream.connectionPromiseKit.resolve()
        return
      }
      case RelayCell.DATA: {
        console.log(`got ${data.length} bytes of data for stream ${streamId}`)
        // console.log(data.toString('hex'))
        stream.emit('data', data)
        return
      }
      case RelayCell.END: {
        const reason = data[0]
        console.warn('! got end', reason)
        if (reason === 2) {
          // ended normally
          stream.end()
          return
        }
        stream.destroy(new Error(`stream ended: ${reason}`))
        return
      }
      default: {
        throw new Error(`Hop received unknown relay message type ${relayCommand}`)
      }
    }
  }

  async writeToStream (stream: CircuitStream, data: Buffer) {
    const { streamId, destroyed } = stream
    if (destroyed) {
      throw new Error('stream is destroyed')
    }
    for (const chunk of chunkDataForRelayDataCells(data)) {
      console.log(`writing ${chunk.length} bytes to stream ${streamId}`)
      const relayCell = {
        streamId,
        relayCommand: RelayCell.DATA,
        data: chunk,
      }
      await this.sendRelayMessage(relayCell)
    }
  }

  async open (desination: string): Promise<CircuitStream> {
    const streamId = ++this.lastStreamId
    const stream = new CircuitStream()
    stream.streamId = streamId
    stream.write = async (data: Buffer) => {
      await this.writeToStream(stream, data)
    }
    this.streams.push(stream)
    console.log(`opening stream ${streamId} to ${desination}`)

    // RELAY_BEGIN
    //   ADDRPORT [nul-terminated string]
    //   FLAGS    [4 bytes]
    const flagsData = Buffer.alloc(4)
    const data = Buffer.concat([
      Buffer.from(desination, 'ascii'),
      Buffer.from([0x00]),
      flagsData,
    ])
    await this.sendRelayMessage({
      streamId,
      relayCommand: RelayCell.BEGIN,
      data,
    })
    await stream.connectionPromiseKit.promise
    return stream
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
