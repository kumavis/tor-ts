import { secp256k1 } from '@noble/curves/secp256k1';
import {
  aes_128_ctr
} from '@noble/ciphers/webcrypto/aes';

import { ChannelConnection } from "./channel";
import {
  MessageCells,
  Create2ClientHandshake,
  Create2ServerHandshake,
} from './messaging';
import {
  makeCreate2ClientHandshakeForNtor,
  parseCreate2ServerHandshakeForNtor,
  getKeySeedFromNtorServerHandshake,
  KDF_RFC5869,
} from './ntor';
import {
  RelayCell,
  serializeExtend2,
} from './relay-cell'

const KEY_LEN = 16;

type HopKey = {
  encrypt(message: Buffer): Uint8Array;
}

type PeerInfo = {
  onionKey: Buffer;
  rsaIdDigest: Buffer;
  // TODO: linkSpecifiers type
  linkSpecifiers: any;
}

class Hop {
  circuitId: Buffer;
  peerInfo: PeerInfo;
  ntorEphemeralKeyPrivate: Buffer;
  ntorEphemeralKeyPublic: Buffer;
  forwardKey: HopKey;
  backwardKey: HopKey;
  async sendRelayMessage (messageType: RelayCell, message: Buffer) {
    throw new Error('virtual sendRelayMessage method')
  }
  async sendHandshake (handshake: Create2ClientHandshake) {
    throw new Error('virtual sendHandshake method')
  }
  async prepareHandshake () {
    // !!! TODO: wrong cipher? should be curve25519?
    this.ntorEphemeralKeyPrivate = secp256k1.utils.randomPrivateKey();
    this.ntorEphemeralKeyPublic = secp256k1.getPublicKey(this.ntorEphemeralKeyPrivate);
    const clientHandshake = makeCreate2ClientHandshakeForNtor({
      ownOnionKey: this.ntorEphemeralKeyPublic,
      peerOnionKey: this.peerInfo.onionKey,
      peerRsaIdDigest: this.peerInfo.rsaIdDigest,
    })
    await this.sendHandshake(clientHandshake)
  }
  receiveCreated2Handshake (serverNtorEphemeralKeyPublic: Buffer, serverNtorAuth: Buffer) {
    // generate Kf_1, Kb_1
    const keySeed = getKeySeedFromNtorServerHandshake({
      clientNtorEphemeralKeyPrivate: this.ntorEphemeralKeyPrivate,
      clientNtorEphemeralKeyPublic: this.ntorEphemeralKeyPublic,
      serverNtorIdentityKeyPublic: this.peerInfo.onionKey,
      serverRsaIdentityKeyDigest: this.peerInfo.rsaIdDigest,
      serverNtorEphemeralKeyPublic,
      serverNtorAuth,
    })
    const keyMaterial = KDF_RFC5869(keySeed, 2 * KEY_LEN);
    // we use 128-bit AES in counter mode, with an IV of all 0 bytes.
    const IV = Buffer.alloc(16)
    this.forwardKey = aes_128_ctr(keyMaterial.subarray(0, KEY_LEN), IV)
    this.backwardKey = aes_128_ctr(keyMaterial.subarray(KEY_LEN, 2 * KEY_LEN), IV)
  }
}

class ChannelHop extends Hop {
  channel: ChannelConnection;
  async sendRelayMessage (messageType: RelayCell, message: Buffer) {
    // encrypt
    const encryptedMessage = Buffer.from(await this.forwardKey.encrypt(message))
    // send over channel
    this.channel.sendMessage(MessageCells.RELAY, {
      circuitId: this.circuitId,
      relayCommand: messageType,
      streamId: 1,
      // this should be a running digest
      digest: Buffer.alloc(4),
      data: encryptedMessage,
    })
  }
  async sendHandshake(handshake: Create2ClientHandshake): Promise<void> {
    this.channel.sendMessage(MessageCells.CREATE2, {
      circuitId: this.circuitId,
      handshake,
    })
    // TODO: await response
  }
}

class RelayedHop extends Hop {
  previousHop: Hop;
  async sendRelayMessage (messageType: RelayCell, message: Buffer) {
    // encrypt
    const encryptedMessage = Buffer.from(await this.forwardKey.encrypt(message))
    // pass onward
    this.previousHop.sendRelayMessage(messageType, encryptedMessage)
  }
  async sendHandshake(handshake: Create2ClientHandshake): Promise<void> {
    //this.previousHop. sendExtend2, payload matches create2
    const extend2PayloadPlaintext = serializeExtend2({
      linkSpecifiers: this.peerInfo.linkSpecifiers,
      handshake,
    })
    this.sendRelayMessage(RelayCell.EXTEND2, extend2PayloadPlaintext)
  }
}

class Circuit {
  hops = Array<Hop>;


}

type RelayConnectionInfo = {}

function getStandardCircuitPath () {
  let gatewayRelay: RelayConnectionInfo;
  let routerRelay: RelayConnectionInfo;
  let exitRelay: RelayConnectionInfo;
  return {
    gatewayRelay,
    routerRelay,
    exitRelay,
  }
}

// choose relays
const {
  gatewayRelay,
  routerRelay,
  exitRelay,
} = await getStandardCircuitPath()

const channel = new Channel()
await channel.connect(gatewayRelay)

const circuit = new Circuit({
  path: [gatewayRelay, routerRelay, exitRelay],
  channel,
})
await circuit.connect()

// circuit.sendRequest()