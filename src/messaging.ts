import assert from "node:assert";
import crypto from "node:crypto";
import { BytesReader, bufferFromUint, sha256 } from "./util";

//  PAYLOAD_LEN -- The longest allowable cell payload, in bytes. (509)
const PAYLOAD_LEN = 509

// The 'Command' field of a fixed-length cell holds one of the following
// values:

// 0 -- PADDING     (Padding)                 (See Sec 7.2)
// 1 -- CREATE      (Create a circuit)        (See Sec 5.1)
// 2 -- CREATED     (Acknowledge create)      (See Sec 5.1)
// 3 -- RELAY       (End-to-end data)         (See Sec 5.5 and 6)
// 4 -- DESTROY     (Stop using a circuit)    (See Sec 5.4)
// 5 -- CREATE_FAST (Create a circuit, no KP) (See Sec 5.1)
// 6 -- CREATED_FAST (Circuit created, no KP) (See Sec 5.1)
// 8 -- NETINFO     (Time and address info)   (See Sec 4.5)
// 9 -- RELAY_EARLY (End-to-end data; limited)(See Sec 5.6)
// 10 -- CREATE2    (Extended CREATE cell)    (See Sec 5.1)
// 11 -- CREATED2   (Extended CREATED cell)    (See Sec 5.1)
// 12 -- PADDING_NEGOTIATE   (Padding negotiation)    (See Sec 7.2)

// Variable-length command values are:  

// 7 -- VERSIONS    (Negotiate proto version) (See Sec 4)
// 128 -- VPADDING  (Variable-length padding) (See Sec 7.2)
// 129 -- CERTS     (Certificates)            (See Sec 4.2)
// 130 -- AUTH_CHALLENGE (Challenge value)    (See Sec 4.3)
// 131 -- AUTHENTICATE (Client authentication)(See Sec 4.5)
// 132 -- AUTHORIZE (Client authorization)    (Not yet used)

enum MessageCells {
  PADDING = 0,
  CREATE = 1,
  CREATED = 2,
  RELAY = 3,
  DESTROY = 4,
  CREATE_FAST = 5,
  CREATED_FAST = 6,
  NETINFO = 8,
  RELAY_EARLY = 9,
  CREATE2 = 10,
  CREATED2 = 11,
  PADDING_NEGOTIATE = 12,
  VERSIONS = 7,
  VPADDING = 128,
  CERTS = 129,
  AUTH_CHALLENGE = 130,
  AUTHENTICATE = 131,
  AUTHORIZE = 132,
}

const messageCellNames = {
  [MessageCells.PADDING]: 'PADDING',
  [MessageCells.CREATE]: 'CREATE',
  [MessageCells.CREATED]: 'CREATED',
  [MessageCells.RELAY]: 'RELAY',
  [MessageCells.DESTROY]: 'DESTROY',
  [MessageCells.CREATE_FAST]: 'CREATE_FAST',
  [MessageCells.CREATED_FAST]: 'CREATED_FAST',
  [MessageCells.NETINFO]: 'NETINFO',
  [MessageCells.RELAY_EARLY]: 'RELAY_EARLY',
  [MessageCells.CREATE2]: 'CREATE2',
  [MessageCells.CREATED2]: 'CREATED2',
  [MessageCells.PADDING_NEGOTIATE]: 'PADDING_NEGOTIATE',
  [MessageCells.VERSIONS]: 'VERSIONS',
  [MessageCells.VPADDING]: 'VPADDING',
  [MessageCells.CERTS]: 'CERTS',
  [MessageCells.AUTH_CHALLENGE]: 'AUTH_CHALLENGE',
  [MessageCells.AUTHENTICATE]: 'AUTHENTICATE',
  [MessageCells.AUTHORIZE]: 'AUTHORIZE',
}

// On a version 3 or
// higher connection, variable-length cells are indicated by a command
// byte equal to 7 ("VERSIONS"), or greater than or equal to 128.
const variableLengthCells = Object.values(MessageCells).filter((code: number) => code === 7 || code >= 123);

export const AddressTypes = {
  IPv4: 4,
  IPv6: 6,
}

// Recognized HTYPEs (handshake types) are:

// 0x0000  TAP  -- the original Tor handshake; see 5.1.3
// 0x0001  reserved
// 0x0002  ntor -- the ntor+curve25519+sha256 handshake; see 5.1.4

export const HandshakeTypes = {
  TAP: 0x0000,
  NTOR: 0x0002,
}

export type MessageCell = {
  data: Buffer,
  circId: Buffer,
  command: number,
  length: number,
  payloadBytes: Buffer,
  message: any,
  commandName: string,
}

export type CellVersions = {
  versions: number[]
};

export type Certificate = {
  type: number,
  body: Buffer,
}

export type CellCerts = {
  certs: Certificate[]
};

export type CellAuthenticate = {
  type: number,
  auth: Buffer,
};

export type CellCreate2 = {
  handshake: Create2ClientHandshake,
};

export type CellCreated2 = {
  handshake: Create2ServerHandshake,
};

export type CellDestroy = {
  reason: number,
};

export type CellAuthChallenge = {
  challenge: Buffer,
  methods: Array<number>,
};

export type CellNetInfo = {
  time: number,
  otherAddress: NetInfoAddress,
  addresses: Array<NetInfoAddress>,
};

export type NetInfoAddress = {
  address: string,
  type: number,
}

export type Create2ClientHandshake = {
  type: number,
  data: Buffer,
}

export type Create2ServerHandshake = {
  data: Buffer,
}

const cellParsers = {
  [MessageCells.VERSIONS]: (reader: BytesReader): CellVersions => {
    const versions = []
    for (let i = 0; i < reader.length; i += 2) {
      const version = reader.readUIntBE(2)
      versions.push(version)
    }
    return { versions }
  },
  [MessageCells.CERTS]: (reader: BytesReader): CellCerts => {
    // N: Number of certs in cell            [1 octet]
    // N times:
    //    CertType                           [1 octet]
    //    CLEN                               [2 octets]
    //    Certificate                        [CLEN octets]
    // Relevant certType values are:
    // 1: Link key certificate certified by RSA1024 identity
    // 2: RSA1024 Identity certificate, self-signed.
    // 3: RSA1024 AUTHENTICATE cell link certificate, signed with RSA1024 key.
    // 4: Ed25519 signing key, signed with identity key.
    // 5: TLS link certificate, signed with ed25519 signing key.
    // 6: Ed25519 AUTHENTICATE cell key, signed with ed25519 signing key.
    // 7: Ed25519 identity, signed with RSA identity.
    const certs = []
    const numCerts = reader.readUIntBE(1)
    for (let i = 0; i < numCerts; i++) {
      const type = reader.readUIntBE(1)
      const certLength = reader.readUIntBE(2)
      const body = reader.readBytes(certLength)
      certs.push({ type, body })
    }
    return { certs }
  },
  [MessageCells.AUTH_CHALLENGE]: (reader: BytesReader): CellAuthChallenge => {
    // Challenge [32 octets]
    // N_Methods [2 octets]
    // Methods   [2 * N_Methods octets]
    const challenge = reader.readBytes(32)
    const numMethods = reader.readUIntBE(2)
    const methods = []
    for (let i = 0; i < numMethods; i++) {
      const method = reader.readUIntBE(2)
      methods.push(method)
    }
    return { challenge, methods }
  },
  [MessageCells.NETINFO]: (reader: BytesReader): CellNetInfo => {
    //   TIME       (Timestamp)                     [4 bytes]
    //   OTHERADDR  (Other OR's address)            [variable]
    //      ATYPE   (Address type)                  [1 byte]
    //      ALEN    (Address length)                [1 byte]
    //      AVAL    (Address value in NBO)          [ALEN bytes]
    //   NMYADDR    (Number of this OR's addresses) [1 byte]
    //     NMYADDR times:
    //       ATYPE   (Address type)                 [1 byte]
    //       ALEN    (Address length)               [1 byte]
    //       AVAL    (Address value in NBO))        [ALEN bytes]

    // Recognized address types (ATYPE) are:

    //  [04] IPv4.
    //  [06] IPv6.
    // ALEN MUST be 4 when ATYPE is 0x04 (IPv4) and 16 when ATYPE is 0x06
    // (IPv6).
    const time = reader.readUIntBE(4)
    const otherAddress = readNetInfoAddress(reader)
    const numMyAddresses = reader.readUIntBE(1);
    const addresses = [];
    for (let j = 0; j < numMyAddresses; j++) {
      const address = readNetInfoAddress(reader)
      if (address !== undefined) {
        addresses.push(address);
      }
    }
    return { time, otherAddress, addresses };
  },
  [MessageCells.AUTHENTICATE]: (reader: BytesReader): CellAuthenticate => {
    // AuthType                              [2 octets]
    // AuthLen                               [2 octets]
    // Authentication                        [AuthLen octets]
    const type = reader.readUIntBE(2)
    const authLength = reader.readUIntBE(2)
    const auth = reader.readBytes(authLength)
    return { type, auth }
  },
  [MessageCells.DESTROY]: (reader: BytesReader): CellDestroy => {
    // The payload of a DESTROY and RELAY_TRUNCATED cell contains a single
    // octet, describing the reason that the circuit was
    // closed. RELAY_TRUNCATED cells, and DESTROY cells sent _towards the
    // client, should contain the actual reason from the list of error codes
    // below.  Reasons in DESTROY cell SHOULD NOT be propagated downward or
    // upward, due to potential side channel risk: An OR receiving a DESTROY
    // command should use the DESTROYED reason for its next cell. An OP
    // should always use the NONE reason for its own DESTROY cells.

    // The error codes are:
    //   0 -- NONE            (No reason given.)
    //   1 -- PROTOCOL        (Tor protocol violation.)
    //   2 -- INTERNAL        (Internal error.)
    //   3 -- REQUESTED       (A client sent a TRUNCATE command.)
    //   4 -- HIBERNATING     (Not currently operating; trying to save bandwidth.)
    //   5 -- RESOURCELIMIT   (Out of memory, sockets, or circuit IDs.)
    //   6 -- CONNECTFAILED   (Unable to reach relay.)
    //   7 -- OR_IDENTITY     (Connected to relay, but its OR identity was not
    //                         as expected.)
    //   8 -- CHANNEL_CLOSED  (The OR connection that was carrying this circuit
    //                         died.)
    //   9 -- FINISHED        (The circuit has expired for being dirty or old.)
    // 10 -- TIMEOUT         (Circuit construction took too long)
    // 11 -- DESTROYED       (The circuit was destroyed w/o client TRUNCATE)
    // 12 -- NOSUCHSERVICE   (Request for unknown hidden service)
    const reason = reader.readUIntBE(1)
    return { reason }
  },
  [MessageCells.CREATED2]: (reader: BytesReader): CellCreated2 => {
    // HLEN      (Server Handshake Data Len) [2 bytes]
    // HDATA     (Server Handshake Data)     [HLEN bytes]
    const handshakeLength = reader.readUIntBE(2)
    const handshakeData = reader.readBytes(handshakeLength)
    const handshake = {
      data: handshakeData,
    }
    return { handshake }
  },
}

const cellSerializers = {
  [MessageCells.VERSIONS]: ({ versions }: CellVersions) => {
    const payloadBytes = Buffer.alloc(versions.length * 2)
    versions.forEach((version, i) => {
      payloadBytes.writeUIntBE(version, i * 2, 2)
    })
    return payloadBytes
  },
  [MessageCells.CERTS]: ({ certs }: CellCerts) => {
    // N: Number of certs in cell            [1 octet]
    // N times:
    //    CertType                           [1 octet]
    //    CLEN                               [2 octets]
    //    Certificate                        [CLEN octets]
    const payloadBytes = Buffer.concat([
      Buffer.from([certs.length]),
      ...certs.map(({ type, body }) => {
        return Buffer.concat([
          bufferFromUint(1, type),
          bufferFromUint(2, body.length),
          body,
        ])
      }),
    ])
    return payloadBytes
  },
  [MessageCells.AUTHENTICATE]: ({
    type,
    auth,
  }: CellAuthenticate) => {
    // AuthType                              [2 octets]
    // AuthLen                               [2 octets]
    // Authentication                        [AuthLen octets]
    const payloadBytes = Buffer.concat([
        bufferFromUint(2, type),
        bufferFromUint(2, auth.length),
        auth,
    ])
    return payloadBytes
  },
  [MessageCells.NETINFO]: ({
    time,
    otherAddress,
    addresses,
  }: CellNetInfo) => {
    //   TIME       (Timestamp)                     [4 bytes]
    //   OTHERADDR  (Other OR's address)            [variable]
    //      ATYPE   (Address type)                  [1 byte]
    //      ALEN    (Address length)                [1 byte]
    //      AVAL    (Address value in NBO)          [ALEN bytes]
    //   NMYADDR    (Number of this OR's addresses) [1 byte]
    //     NMYADDR times:
    //       ATYPE   (Address type)                 [1 byte]
    //       ALEN    (Address length)               [1 byte]
    //       AVAL    (Address value in NBO))        [ALEN bytes]

    // Recognized address types (ATYPE) are:

    //  [04] IPv4.
    //  [06] IPv6.
    // ALEN MUST be 4 when ATYPE is 0x04 (IPv4) and 16 when ATYPE is 0x06
    // (IPv6).

    const payloadBytes = Buffer.concat([
      bufferFromUint(4, time),
      serializeNetInfoAddress(otherAddress),
      bufferFromUint(1, addresses.length),
      ...addresses.map((addressInfo) => {
        return serializeNetInfoAddress(addressInfo)
      }
    )])
    return payloadBytes
  },
  [MessageCells.CREATE2]: ({ handshake }: CellCreate2) => {
    // HTYPE     (Client Handshake Type)     [2 bytes]
    // HLEN      (Client Handshake Data Len) [2 bytes]
    // HDATA     (Client Handshake Data)     [HLEN bytes]
    const payloadBytes = Buffer.concat([
      bufferFromUint(2, handshake.type),
      bufferFromUint(2, handshake.data.length),
      handshake.data,
    ])
    return payloadBytes
  },
  [MessageCells.RELAY]: ({ relayCommand, streamId, digest, data }): Buffer => {
    // Relay command           [1 byte]
    // 'Recognized'            [2 bytes]
    // StreamID                [2 bytes]
    // Digest                  [4 bytes]
    // Length                  [2 bytes]
    // Data                    [Length bytes]
    // Padding                 [PAYLOAD_LEN - 11 - Length bytes]
    assert.equal(digest.length, 4)
    const payloadBytes = Buffer.concat([
      bufferFromUint(1, relayCommand),
      // When sending cells, the unencrypted 'recognized' MUST be set to zero.
      Buffer.alloc(2),
      bufferFromUint(2, streamId),
      digest,
      bufferFromUint(2, data.length),
      data,
      // SECURITY TODO
      // Implementations SHOULD fill this field with four zero-valued bytes, followed by as many
      // random bytes as will fit.  (If there are fewer than 4 bytes for padding,
      // then they should all be filled with zero.
      Buffer.alloc(PAYLOAD_LEN - 11 - data.length)
    ])
    return payloadBytes
  }

}

function serializeCell(commandCode: number, params: any, protocolVersion: number | undefined) {
  // On a version 1 connection, each cell contains the following
  // fields:

  //      CircID                                [CIRCID_LEN bytes]
  //      Command                               [1 byte]
  //      Payload (padded with padding bytes)   [PAYLOAD_LEN bytes]

  // On a version 2 or higher connection, all cells are as in version 1
  // connections, except for variable-length cells, whose format is:

  //      CircID                                [CIRCID_LEN octets]
  //      Command                               [1 octet]
  //      Length                                [2 octets; big-endian integer]
  //      Payload (some commands MAY pad)       [Length bytes]

  const cellSerializer = cellSerializers[commandCode]
  if (cellSerializer === undefined) {
    throw new Error(`Unable to serialize command code ${commandCode} (${getCommandName(commandCode)})`)
  }
  const circuitLength = circuitIdLengthForProtocolVersion(protocolVersion)
  const circuitId = params.circuitId || Buffer.alloc(circuitLength);
  if (params.circuitId) {
    assert.equal(params.circuitId.length, circuitLength, 'circuitId length is not expected length')
  }
  const cellData = [
    circuitId,
    bufferFromUint(1, commandCode),
  ];
  const payloadBytes = cellSerializer(params);
  const isVariableLength = variableLengthCells.includes(commandCode);
  if (isVariableLength) {
    cellData.push(
      bufferFromUint(2, payloadBytes.length)
    );
    cellData.push(payloadBytes);
  } else {
    cellData.push(payloadBytes);
    const paddingLength = PAYLOAD_LEN - payloadBytes.length;
    if (paddingLength > 0) {
      cellData.push(Buffer.alloc(paddingLength));
    }
  }
  return Buffer.concat(cellData);
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

function* readCellsFromData (data: Buffer, getVersion: ()=>number): Generator<MessageCell> {
  const { cell, extraData } = parseCell(data, getVersion());
  yield cell;
  if (extraData.length > 0) {
    yield* readCellsFromData(extraData, getVersion);
  }
}

function parseCell (data: Buffer, version: number | undefined): { cell: MessageCell, extraData: Buffer } {
  // On a version 1 connection, each cell contains the following
  // fields:

  //      CircID                                [CIRCID_LEN bytes]
  //      Command                               [1 byte]
  //      Payload (padded with padding bytes)   [PAYLOAD_LEN bytes]

  // On a version 2 or higher connection, all cells are as in version 1
  // connections, except for variable-length cells, whose format is:

  //      CircID                                [CIRCID_LEN octets]
  //      Command                               [1 octet]
  //      Length                                [2 octets; big-endian integer]
  //      Payload (some MessageCells MAY pad)       [Length bytes]

  let circId: Buffer;
  let commandCode: number;
  let payloadBytes: Buffer;
  let extraData: Buffer;
  let decodedCell: MessageCell

  try {
    const reader = new BytesReader(data);
    const circIdLength = circuitIdLengthForProtocolVersion(version);
    circId = reader.readBytes(circIdLength);
    commandCode = reader.readUIntBE(1);
    let length = PAYLOAD_LEN;
    if (variableLengthCells.includes(commandCode)) {
      length = reader.readUIntBE(2);
    }
    payloadBytes = reader.readBytes(length, { allowShorter: true });
    const payloadReader = new BytesReader(payloadBytes);
    extraData = reader.readRemainder();
    decodedCell = {
      data: data.slice(0, data.length - extraData.length),
      circId,
      command: commandCode,
      length,
      payloadBytes,
      message: undefined,
      commandName: getCommandName(commandCode),
    };
    const commandParser = cellParsers[commandCode];
    if (commandParser !== undefined) {
      decodedCell.message = commandParser(payloadReader);
    }
    return { cell: decodedCell, extraData };
  } catch (err) {
    let message = `Error parsing cell: "${err.message}"`;
    if (circId !== undefined) {
      message += ` (circuit id ${circId.toString('hex')})`;
    }
    if (commandCode !== undefined) {
      message += ` (command code ${commandCode} = ${getCommandName(commandCode)})`;
    }
    throw new Error(message, { cause: err })
  }
  
}

function getCommandName (commandCode: number): string {
  const commandCodeHex = `0x${commandCode.toString(16)}`
  return messageCellNames[commandCode] || `<UNKNOWN:${commandCode}|${commandCodeHex}>`
}

function readNetInfoAddress (reader: BytesReader): NetInfoAddress {
  //   ATYPE   (Address type)                  [1 byte]
  //   ALEN    (Address length)                [1 byte]
  //   AVAL    (Address value in NBO)          [ALEN bytes]
  const type = reader.readUIntBE(1)
  const length = reader.readUIntBE(1)
  const addressBytes = reader.readBytes(length)
  const address = parseIpAddress(addressBytes, type);
  if (type === 4 && length === 4) {
    return { address, type }
  }
  if (type === 6 && length === 16) {
    return { address, type }
  }
  throw new Error(`Invalid address type ${type} or length ${length}`)
}

function serializeNetInfoAddress (netInfoAddress: NetInfoAddress | undefined): Buffer {
  if (!netInfoAddress) {
    // return empty
    return Buffer.concat([
      bufferFromUint(1, 0),
      bufferFromUint(1, 4),
      Buffer.alloc(4),
    ])
  }
  const { address, type } = netInfoAddress;
  const length = type === AddressTypes.IPv4 ? 4 : 16
  return Buffer.concat([
    bufferFromUint(1, type),
    bufferFromUint(1, length),
    // allow empty address ?
    ipAddressToBuffer(address, type),
  ])
}

function parseIpAddress (address: Buffer, type: number): string {
  if (type === AddressTypes.IPv4) {
    return address.join('.');
  } else if (type === AddressTypes.IPv6) {
    return address.join(':');
  } else {
    throw new Error(`Invalid address type ${type}`)
  }
}

function ipAddressToBuffer (ipAddress: string, type: number): Buffer {
  if (type === AddressTypes.IPv4) {
    const parts = ipAddress.split('.');
    if (parts.length !== 4) {
      throw new Error(`Invalid IP address ${ipAddress}`)
    }
    const bytes = parts.map(part => parseInt(part, 10));
    return Buffer.from(bytes);
  } else if (type === AddressTypes.IPv6) {
    const parts = ipAddress.split(':');
    if (parts.length !== 8) {
      throw new Error(`Invalid IP address ${ipAddress}`)
    }
    const bytes = parts.map(part => parseInt(part, 16));
    return Buffer.from(bytes);
  } else {
    throw new Error(`Invalid address type ${type}`)
  }
}

function buildAuthenticateCell ({
  type,
  serverHandshakeDigestData,
  clientHandshakeDigestData,
  serverRsa1024Key,
  clientRsa1024Key,
  responderTlsLinkCert,
}: {
  type: number,
  serverHandshakeDigestData: Array<Buffer>,
  clientHandshakeDigestData: Array<Buffer>,
  serverRsa1024Key: Buffer,
  clientRsa1024Key: Buffer,
  responderTlsLinkCert: Buffer,
}) {

  // If AuthType is 1 (meaning "RSA-SHA256-TLSSecret"), then the
  // Authentication field of the AUTHENTICATE cell contains the following:

  //     TYPE: The characters "AUTH0001" [8 octets]
  //     CID: A SHA256 hash of the initiator's RSA1024 identity key [32 octets]
  //     SID: A SHA256 hash of the responder's RSA1024 identity key [32 octets]
  //     SLOG: A SHA256 hash of all bytes sent from the responder to the
  //       initiator as part of the negotiation up to and including the
  //       AUTH_CHALLENGE cell; that is, the VERSIONS cell, the CERTS cell,
  //       the AUTH_CHALLENGE cell, and any padding cells.  [32 octets]
  //     CLOG: A SHA256 hash of all bytes sent from the initiator to the
  //       responder as part of the negotiation so far; that is, the
  //       VERSIONS cell and the CERTS cell and any padding cells. [32
  //       octets]
  //     SCERT: A SHA256 hash of the responder's TLS link certificate. [32
  //       octets]
  //     TLSSECRETS: A SHA256 HMAC, using the TLS master secret as the
  //       secret key, of the following:
  //         - client_random, as sent in the TLS Client Hello
  //         - server_random, as sent in the TLS Server Hello
  //         - the NUL terminated ASCII string:
  //           "Tor V3 handshake TLS cross-certification"
  //        [32 octets]
  //     RAND: A 24 byte value, randomly chosen by the initiator.  (In an
  //       imitation of SSL3's gmt_unix_time field, older versions of Tor
  //       sent an 8-byte timestamp as the first 8 bytes of this field;
  //       new implementations should not do that.) [24 octets]
  //     SIG: A signature of a SHA256 hash of all the previous fields
  //       using the initiator's "Authenticate" key as presented.  (As
  //       always in Tor, we use OAEP-MGF1 padding; see tor-spec.txt
  //       section 0.3.)
  //        [variable length]
  if (type !== 1) {
    throw new Error('Only type 1 AUTHENTICATE supported')
  }

  const TYPE = Buffer.from('AUTH001', 'utf8');
  const CID = Buffer.from(sha256(clientRsa1024Key));
  const SID = Buffer.from(sha256(serverRsa1024Key));
  const SLOG = Buffer.from(
    sha256(
      Buffer.concat(serverHandshakeDigestData)
    )
  );
  const CLOG = Buffer.from(
    sha256(
      Buffer.concat(clientHandshakeDigestData)
    )
  );
  const SCERT = Buffer.from(sha256(responderTlsLinkCert));
  // TODO: hmac with tls master secret
  const TLSSECRETS = Buffer.from([])
  const RAND = crypto.randomBytes(24);
  const unsignedSection = Buffer.concat([
    TYPE,
    CID,
    SID,
    SLOG,
    CLOG,
    SCERT,
    TLSSECRETS,
    RAND,
  ]);
  // TODO: sign
  const unsignedSectionHash = Buffer.from(sha256(unsignedSection));
  const sig = Buffer.from([]);
  const signedSection = Buffer.concat([
    unsignedSection,
    sig,
  ]);
  return signedSection
}

export {
  MessageCells,
  messageCellNames,
  readCellsFromData,
  serializeCell as serializeCommand,
};