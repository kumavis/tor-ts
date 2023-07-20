import assert from 'node:assert';
import {
  HandshakeTypes,
} from './messaging';
import type {
  Create2ClientHandshake,
  Create2ServerHandshake,
} from './messaging';
import {
  BytesReader,
} from './util';

// The "ntor" handshake

//   This handshake uses a set of DH handshakes to compute a set of
//   shared keys which the client knows are shared only with a particular
//   server, and the server knows are shared with whomever sent the
//   original handshake (or with nobody at all).  Here we use the
//   "curve25519" group and representation as specified in "Curve25519:
//   new Diffie-Hellman speed records" by D. J. Bernstein.

//   [The ntor handshake was added in Tor 0.2.4.8-alpha.]

//   In this section, define:

//     H(x,t) as HMAC_SHA256 with message x and key t.
//     H_LENGTH  = 32.
//     ID_LENGTH = 20.
//     G_LENGTH  = 32
//     PROTOID   = "ntor-curve25519-sha256-1"
//     t_mac     = PROTOID | ":mac"
//     t_key     = PROTOID | ":key_extract"
//     t_verify  = PROTOID | ":verify"
//     G         = The preferred base point for curve25519 ([9])
//     KEYGEN()  = The curve25519 key generation algorithm, returning
//                 a private/public keypair.
//     m_expand  = PROTOID | ":key_expand"
//     KEYID(A)  = A
//     EXP(a, b) = The ECDH algorithm for establishing a shared secret.

//   To perform the handshake, the client needs to know an identity key
//   digest for the server, and an ntor onion key (a curve25519 public
//   key) for that server. Call the ntor onion key "B".  The client
//   generates a temporary keypair:

//       x,X = KEYGEN()

//   and generates a client-side handshake with contents:

//       NODEID      Server identity digest  [ID_LENGTH bytes]
//       KEYID       KEYID(B)                [H_LENGTH bytes]
//       CLIENT_KP   X                       [G_LENGTH bytes]

//   The server generates a keypair of y,Y = KEYGEN(), and uses its ntor
//   private key 'b' to compute:

//     secret_input = EXP(X,y) | EXP(X,b) | ID | B | X | Y | PROTOID
//     KEY_SEED = H(secret_input, t_key)
//     verify = H(secret_input, t_verify)
//     auth_input = verify | ID | B | Y | X | PROTOID | "Server"

//   The server's handshake reply is:

//       SERVER_KP   Y                       [G_LENGTH bytes]
//       AUTH        H(auth_input, t_mac)    [H_LENGTH bytes]

//   The client then checks Y is in G^* [see NOTE below], and computes

//     secret_input = EXP(Y,x) | EXP(B,x) | ID | B | X | Y | PROTOID
//     KEY_SEED = H(secret_input, t_key)
//     verify = H(secret_input, t_verify)
//     auth_input = verify | ID | B | Y | X | PROTOID | "Server"

//   The client verifies that AUTH == H(auth_input, t_mac).

//   Both parties check that none of the EXP() operations produced the
//   point at infinity. [NOTE: This is an adequate replacement for
//   checking Y for group membership, if the group is curve25519.]

//   Both parties now have a shared value for KEY_SEED.  They expand this
//   into the keys needed for the Tor relay protocol, using the KDF
//   described in 5.2.2 and the tag m_expand.


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

export const NtorParams = {
  H_LENGTH,
  ID_LENGTH,
  G_LENGTH,
  PROTOID,
  t_mac,
  t_key,
  t_verify,
  m_expand,
}

export type NtorClientHandshake = {
  ownOnionKey: Buffer,
  peerOnionKey: Buffer,
  peerRsaIdDigest: Buffer,
}

export type NtorServerHandshake = {
  peerOnionKey: Buffer,
  auth: Buffer,
}

export function makeCreate2ClientHandshakeForNtor (handshake: NtorClientHandshake): Create2ClientHandshake {
  const { ownOnionKey, peerOnionKey, peerRsaIdDigest } = handshake;
  // NODEID      Server identity digest  [ID_LENGTH bytes]
  // KEYID       KEYID(B)                [H_LENGTH bytes]
  // CLIENT_KP   X                       [G_LENGTH bytes]
  assert.equal(peerRsaIdDigest.length, ID_LENGTH, 'peer id digest length is not expected length')
  assert.equal(peerOnionKey.length, H_LENGTH, 'peer ntor onion key length is not expected length')
  assert.equal(ownOnionKey.length, G_LENGTH, 'own ntor onion key length is not expected length')
  
  return {
    type: HandshakeTypes.NTOR,
    data: Buffer.concat([
      // should be sha1 of rsa_id
      peerRsaIdDigest,
      // should be peer ntor onion key
      // need to get from descriptors / netdoc
      peerOnionKey,
      // should be own curve25519 pubkey
      ownOnionKey,
    ]),
  }
}

export function parseCreate2ServerHandshakeForNtor (handshake: Create2ServerHandshake): NtorServerHandshake {
  const handshakeData = handshake.data;
  // SERVER_KP   Y                       [G_LENGTH bytes]
  // AUTH        H(auth_input, t_mac)    [H_LENGTH bytes]
  assert.equal(handshakeData.length, G_LENGTH + H_LENGTH, 'handshake length is not expected length')
  const reader = new BytesReader(handshakeData);
  const peerOnionKey = reader.readBytes(G_LENGTH);
  const auth = reader.readBytes(H_LENGTH);
  return { peerOnionKey, auth }
}