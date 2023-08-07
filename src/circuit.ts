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
  RelayEndReasons,
  RelayEndReasonNames,
  serializeExtend2,
} from './relay-cell'
import { BytesReader, deferred } from './util';
import EventEmitter from 'node:events';
import { ReadableStream, WritableStream } from 'stream/web';

const KEY_LEN = 16;
const HASH_LEN = 20;

type HopKey = {
  encrypt(message: Buffer): Promise<Uint8Array>;
  decrypt(message: Buffer): Promise<Uint8Array>;
}

interface Cipher {
  key: HopKey,
  digest: crypto.Hash,
}

class CipherPair {
  forward: Cipher
  backward: Cipher
  constructor (forward: Cipher, backward: Cipher) {
    this.forward = forward
    this.backward = backward
  }
}

class Tor1Cipher implements Cipher {
  key: HopKey
  digest: crypto.Hash
  constructor (key: HopKey, digest: crypto.Hash) {
    this.key = key
    this.digest = digest
  }
}

export type PeerInfo = {
  onionKey: Buffer;
  rsaIdDigest: Buffer;
  linkSpecifiers: Array<LinkSpecifier>;
}

class Hop {
  isConnected = false;
  peerInfo: PeerInfo;
  handshakePromiseKit = deferred<void>()
  cipherPair: CipherPair;

  ntorEphemeralKeyPrivate: Buffer;
  ntorEphemeralKeyPublic: Buffer;

  async encryptForward (data: Buffer) {
    return Buffer.from(await this.cipherPair.forward.key.encrypt(data))
  }
  async decryptBackward (data: Buffer) {
    return Buffer.from(await this.cipherPair.backward.key.decrypt(data))
  }
  async witnessForwardPayload (relayCellPayload: Buffer) {
    // update the forwardDigest and set the integrity
    this.cipherPair.forward.digest.update(relayCellPayload)
    const integrity = this.cipherPair.forward.digest.copy().digest().subarray(0, 4)
    return integrity
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
    const keyMaterial = KDF_RFC5869(keySeed, 2 * HASH_LEN + 2 * KEY_LEN)
    this.cipherPair = makeTor1CipherPairFromKeyMaterial(keyMaterial)
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
  destination: string
  destroyed = false
  connectionPromiseKit = deferred<void>()
  source: ReadableStream
  sink: WritableStream
  constructor () {
    super()
    const { source, sink } = createSourceAndSinkForCircuit(this)
    this.source = source
    this.sink = sink
  }
  write: (data: Buffer) => Promise<void>
  close () {
    this.destroy()
  }
  destroy (err?: Error) {
    if (err) this.connectionPromiseKit.reject(err)
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
    const integrity = await targetHop.witnessForwardPayload(relayCellPayload)
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
        const err = new Error(`circuit destroyed: ${destroyMessage.reason}`)
        this.streams.forEach(stream => {
          stream.destroy(err)
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
        const reasonName = RelayEndReasonNames[reason]
        if (reason === RelayEndReasons.REASON_DONE) {
          // ended normally
          stream.close()
          return
        }
        console.warn(`Got ungraceful end for stream ${streamId} with reason ${reasonName}`)
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

  // TODO: delete?
  async open (desination: string): Promise<CircuitStream> {
    const stream = this.createStream(desination)
    await this.performStreamHandshake(stream)
    return stream
  }

  openStream (desination: string): CircuitStream {
    const stream = this.createStream(desination)
    // kick off handshake, but dont wait for it
    this.performStreamHandshake(stream)
    return stream
  }

  createStream (desination: string): CircuitStream {
    const streamId = ++this.lastStreamId
    const stream = new CircuitStream()
    stream.streamId = streamId
    stream.destination = desination
    // TODO better to use event emitter so its self-contained?
    stream.write = async (data: Buffer) => {
      await stream.connectionPromiseKit.promise
      await this.writeToStream(stream, data)
    }
    this.streams.push(stream)
    return stream
  }

  async performStreamHandshake (stream: CircuitStream): Promise<void> {
    const { streamId, destination } = stream
    console.log(`opening stream ${streamId} to ${destination}`)
    // RELAY_BEGIN
    //   ADDRPORT [nul-terminated string]
    //   FLAGS    [4 bytes]
    const flagsData = Buffer.alloc(4)
    const data = Buffer.concat([
      Buffer.from(destination, 'ascii'),
      Buffer.from([0x00]),
      flagsData,
    ])
    await this.sendRelayMessage({
      streamId,
      relayCommand: RelayCell.BEGIN,
      data,
    })
    await stream.connectionPromiseKit.promise
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

function createSourceAndSinkForCircuit (circuitStream: CircuitStream) {
  // stream consumer can write to this
  // and it gets forwarded to the circuit
  const sink = new WritableStream({
    write: (chunk) => {
      circuitStream.write(chunk)
    },
    close: () => {
      circuitStream.close()
    },
    abort: (err) => {
      circuitStream.destroy(err)
    },
  })
  // stream consumer can read from this
  // and it gets data forwarded from the circuit
  const source = new ReadableStream({
    start: (controller) => {
      circuitStream.on('data', (data) => {
        controller.enqueue(data)
      })
      circuitStream.on('end', () => {
        controller.close()
      })
    },
    cancel: () => {
      circuitStream.destroy()
    },
  })
  return { source, sink }
}

function makeTor1CipherPairFromKeyMaterial (keyMaterial: Buffer) {
  const keyMaterialReader = new BytesReader(keyMaterial)
  const forwardDigest = crypto.createHash('sha1');
  const backwardDigest = crypto.createHash('sha1');
  forwardDigest.update(keyMaterialReader.readBytes(HASH_LEN))
  backwardDigest.update(keyMaterialReader.readBytes(HASH_LEN))
  // we use 128-bit AES in counter mode, with an IV of all 0 bytes.
  const forwardKey = makeAes128CtrKey(keyMaterialReader.readBytes(KEY_LEN))
  const backwardKey = makeAes128CtrKey(keyMaterialReader.readBytes(KEY_LEN))
  return new CipherPair(
    new Tor1Cipher(forwardKey, forwardDigest),
    new Tor1Cipher(backwardKey, backwardDigest),
  )
}
