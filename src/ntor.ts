import assert from 'node:assert'
import crypto from 'node:crypto'
import {
  HandshakeTypes,
} from './messaging';
import type {
  Create2Handshake,
} from './messaging';

// H(x,t) as HMAC_SHA256 with message x and key t.
// H_LENGTH  = 32.
// ID_LENGTH = 20.
// G_LENGTH  = 32
// PROTOID   = "ntor-curve25519-sha256-1"
// t_mac     = PROTOID | ":mac"
// t_key     = PROTOID | ":key_extract"
// t_verify  = PROTOID | ":verify"
// G         = The preferred base point for curve25519 ([9])
// KEYGEN()  = The curve25519 key generation algorithm, returning
//             a private/public keypair.
// m_expand  = PROTOID | ":key_expand"
// KEYID(A)  = A
// EXP(a, b) = The ECDH algorithm for establishing a shared secret.
const H_LENGTH = 32;
const ID_LENGTH = 20;
const G_LENGTH = 32;
const PROTOID = "ntor-curve25519-sha256-1";
const t_mac = PROTOID + ":mac";
const t_key = PROTOID + ":key_extract";
const t_verify = PROTOID + ":verify";
const m_expand = PROTOID + ":key_expand";

export function makeCreate2CellForNtor (ownOnionKey: Buffer, peerOnionKey: Buffer, peerIdDigest: Buffer): Create2Handshake {
  // NODEID      Server identity digest  [ID_LENGTH bytes]
  // KEYID       KEYID(B)                [H_LENGTH bytes]
  // CLIENT_KP   X                       [G_LENGTH bytes]
  assert.equal(peerIdDigest.length, ID_LENGTH, 'peer id digest length is not expected length')
  assert.equal(peerOnionKey.length, H_LENGTH, 'peer ntor onion key length is not expected length')
  assert.equal(ownOnionKey.length, G_LENGTH, 'own ntor onion key length is not expected length')
  
  return {
    type: HandshakeTypes.NTOR,
    data: Buffer.concat([
      // should be sha1 of rsa_id
      peerIdDigest,
      // should be peer ntor onion key
      // need to get from descriptors / netdoc
      peerOnionKey,
      // should be own curve25519 pubkey
      ownOnionKey,
    ]),
  }
}