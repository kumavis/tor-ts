import * as crypto from "node:crypto";

const sha256 = (data: Buffer): Buffer => {
	return crypto.createHmac('sha256', data).digest();
}

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

const messageCells = {
	PADDING: 0,
	CREATE: 1,
	CREATED: 2,
	RELAY: 3,
	DESTROY: 4,
	CREATE_FAST: 5,
	CREATED_FAST: 6,
	NETINFO: 8,
	RELAY_EARLY: 9,
	CREATE2: 10,
	CREATED2: 11,
	PADDING_NEGOTIATE: 12,
	VERSIONS: 7,
	VPADDING: 128,
	CERTS: 129,
	AUTH_CHALLENGE: 130,
	AUTHENTICATE: 131,
	AUTHORIZE: 132,
}

const messageCellNames = {
	[messageCells.PADDING]: 'PADDING',
	[messageCells.CREATE]: 'CREATE',
	[messageCells.CREATED]: 'CREATED',
	[messageCells.RELAY]: 'RELAY',
	[messageCells.DESTROY]: 'DESTROY',
	[messageCells.CREATE_FAST]: 'CREATE_FAST',
	[messageCells.CREATED_FAST]: 'CREATED_FAST',
	[messageCells.NETINFO]: 'NETINFO',
	[messageCells.RELAY_EARLY]: 'RELAY_EARLY',
	[messageCells.CREATE2]: 'CREATE2',
	[messageCells.CREATED2]: 'CREATED2',
	[messageCells.PADDING_NEGOTIATE]: 'PADDING_NEGOTIATE',
	[messageCells.VERSIONS]: 'VERSIONS',
	[messageCells.VPADDING]: 'VPADDING',
	[messageCells.CERTS]: 'CERTS',
	[messageCells.AUTH_CHALLENGE]: 'AUTH_CHALLENGE',
	[messageCells.AUTHENTICATE]: 'AUTHENTICATE',
	[messageCells.AUTHORIZE]: 'AUTHORIZE',
}

const variableLengthCells = [
	messageCells.VERSIONS,
	messageCells.VPADDING,
	messageCells.CERTS,
	messageCells.AUTH_CHALLENGE,
	messageCells.AUTHENTICATE,
	messageCells.AUTHORIZE,
];

export type MessageCell = {
	data: Buffer,
	circId: number,
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

export type CellAuthChallenge = {
	challenge: Buffer,
	methods: Array<number>,
};

export type CellNetInfo = {
	time: number,
	otherAddress: NetInfoAddress | undefined,
	addresses: Array<NetInfoAddress>,
};

const cellParsers = {
	[messageCells.VERSIONS]: (reader: BytesReader): CellVersions => {
		const versions = []
		for (let i = 0; i < reader.length; i += 2) {
			const version = reader.readUIntBE(2)
			versions.push(version)
		}
		return { versions }
	},
	[messageCells.CERTS]: (reader: BytesReader): CellCerts => {
		// N: Number of certs in cell            [1 octet]
		// N times:
		// 	 CertType                           [1 octet]
		// 	 CLEN                               [2 octets]
		// 	 Certificate                        [CLEN octets]
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
	[messageCells.AUTH_CHALLENGE]: (reader: BytesReader): CellAuthChallenge => {
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
	[messageCells.NETINFO]: (reader: BytesReader): CellNetInfo => {
		// 	TIME       (Timestamp)                     [4 bytes]
		// 	OTHERADDR  (Other OR's address)            [variable]
		// 		 ATYPE   (Address type)                  [1 byte]
		// 		 ALEN    (Address length)                [1 byte]
		// 		 AVAL    (Address value in NBO)          [ALEN bytes]
		// 	NMYADDR    (Number of this OR's addresses) [1 byte]
		// 		NMYADDR times:
		// 			ATYPE   (Address type)                 [1 byte]
		// 			ALEN    (Address length)               [1 byte]
		// 			AVAL    (Address value in NBO))        [ALEN bytes]

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
	[messageCells.AUTHENTICATE]: (reader: BytesReader): CellAuthenticate => {
		// AuthType                              [2 octets]
		// AuthLen                               [2 octets]
		// Authentication                        [AuthLen octets]
		const type = reader.readUIntBE(2)
		const authLength = reader.readUIntBE(2)
		const auth = reader.readBytes(authLength)
		return { type, auth }
	},
}

const cellSerializers = {
	[messageCells.VERSIONS]: ({ versions }: CellVersions) => {
		const payloadBytes = Buffer.alloc(versions.length * 2)
		versions.forEach((version, i) => {
			payloadBytes.writeUIntBE(version, i * 2, 2)
		})
		return payloadBytes
	},
	[messageCells.CERTS]: ({ certs }: CellCerts) => {
		// N: Number of certs in cell            [1 octet]
		// N times:
		// 	 CertType                           [1 octet]
		// 	 CLEN                               [2 octets]
		// 	 Certificate                        [CLEN octets]
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
	[messageCells.AUTHENTICATE]: ({
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
	}
}

function serializeCell(commandCode: number, params: any) {
	// On a version 1 connection, each cell contains the following
	// fields:

	// 		 CircID                                [CIRCID_LEN bytes]
	// 		 Command                               [1 byte]
	// 		 Payload (padded with padding bytes)   [PAYLOAD_LEN bytes]

	// On a version 2 or higher connection, all cells are as in version 1
	// connections, except for variable-length cells, whose format is:

	// 		 CircID                                [CIRCID_LEN octets]
	// 		 Command                               [1 octet]
	// 		 Length                                [2 octets; big-endian integer]
	// 		 Payload (some commands MAY pad)       [Length bytes]

	const cellSerializer = cellSerializers[commandCode]
	if (cellSerializer === undefined) {
		throw new Error(`Unable to serialize command code ${commandCode} (${getCommandName(commandCode)})`)
	}
	const circuitId = params.circuitId || 0;
	const cellData = [
		bufferFromUint(2, circuitId),
		bufferFromUint(1, commandCode),
	];
	const payloadBytes = cellSerializer(params);
	const isVariableLength = variableLengthCells.includes(commandCode);
	if (isVariableLength) {
		cellData.push(
			bufferFromUint(2, payloadBytes.length)
		);
	}
	cellData.push(payloadBytes);
	return Buffer.concat(cellData);
}

function bufferFromUint (length: number, value: number) {
	const data = Buffer.alloc(length);
	data.writeUintBE(value, 0, length);
	return data;
}

function* readCellsFromData (data: Buffer): Generator<MessageCell> {
	const { cell, extraData } = parseCell(data);
	yield cell;
	if (extraData.length > 0) {
		yield* readCellsFromData(extraData);
	}
}

function parseCell (data: Buffer): { cell: MessageCell, extraData: Buffer } {
	// On a version 1 connection, each cell contains the following
	// fields:

	// 		 CircID                                [CIRCID_LEN bytes]
	// 		 Command                               [1 byte]
	// 		 Payload (padded with padding bytes)   [PAYLOAD_LEN bytes]

	// On a version 2 or higher connection, all cells are as in version 1
	// connections, except for variable-length cells, whose format is:

	// 		 CircID                                [CIRCID_LEN octets]
	// 		 Command                               [1 octet]
	// 		 Length                                [2 octets; big-endian integer]
	// 		 Payload (some messageCells MAY pad)       [Length bytes]

	const reader = new BytesReader(data);
	const circId = reader.readUIntBE(2);
	const commandCode = reader.readUIntBE(1);
  //  PAYLOAD_LEN -- The longest allowable cell payload, in bytes. (509)
	let length = 509;
	if (variableLengthCells.includes(commandCode)) {
		length = reader.readUIntBE(2);
	}
	const payloadBytes = reader.readBytes(length)
	const payloadReader = new BytesReader(payloadBytes);
	const extraData = reader.readRemainder();
	const decodedCell: MessageCell = {
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
}

function getCommandName (commandCode: number): string {
	return messageCellNames[commandCode] || `<UNKNOWN:${commandCode}>`
}

export type NetInfoAddress = {
	address: Buffer,
	type: number,
}

const readNetInfoAddress = (reader: BytesReader): NetInfoAddress | undefined => {
	// 	ATYPE   (Address type)                  [1 byte]
	// 	ALEN    (Address length)                [1 byte]
	// 	AVAL    (Address value in NBO)          [ALEN bytes]
	const type = reader.readUIntBE(1)
	const length = reader.readUIntBE(1)
	const address = reader.readBytes(length)
	if (type === 4 && length === 4) {
		return { address, type }
	}
	if (type === 6 && length === 16) {
		return { address, type }
	}
	return undefined;
}

class BytesReader {
	data: Buffer;
	offset: number;
	constructor (data: Buffer) {
		this.data = data;
		this.offset = 0;
	}
	readUIntBE (length: number) {
		const value = this.data.readUIntBE(this.offset, length);
		this.offset += length;
		return value
	}
	readBytes (length: number) {
		const bytes = this.data.slice(this.offset, this.offset + length);
		this.offset += length;
		return bytes
	}
	readRemainder () {
		const bytes = this.data.slice(this.offset);
		return bytes;
	}
	get length () {
		return this.data.length
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

	// 		TYPE: The characters "AUTH0001" [8 octets]
	// 		CID: A SHA256 hash of the initiator's RSA1024 identity key [32 octets]
	// 		SID: A SHA256 hash of the responder's RSA1024 identity key [32 octets]
	// 		SLOG: A SHA256 hash of all bytes sent from the responder to the
	// 			initiator as part of the negotiation up to and including the
	// 			AUTH_CHALLENGE cell; that is, the VERSIONS cell, the CERTS cell,
	// 			the AUTH_CHALLENGE cell, and any padding cells.  [32 octets]
	// 		CLOG: A SHA256 hash of all bytes sent from the initiator to the
	// 			responder as part of the negotiation so far; that is, the
	// 			VERSIONS cell and the CERTS cell and any padding cells. [32
	// 			octets]
	// 		SCERT: A SHA256 hash of the responder's TLS link certificate. [32
	// 			octets]
	// 		TLSSECRETS: A SHA256 HMAC, using the TLS master secret as the
	// 			secret key, of the following:
	// 				- client_random, as sent in the TLS Client Hello
	// 				- server_random, as sent in the TLS Server Hello
	// 				- the NUL terminated ASCII string:
	// 					"Tor V3 handshake TLS cross-certification"
	// 			 [32 octets]
	// 		RAND: A 24 byte value, randomly chosen by the initiator.  (In an
	// 			imitation of SSL3's gmt_unix_time field, older versions of Tor
	// 			sent an 8-byte timestamp as the first 8 bytes of this field;
	// 			new implementations should not do that.) [24 octets]
	// 		SIG: A signature of a SHA256 hash of all the previous fields
	// 			using the initiator's "Authenticate" key as presented.  (As
	// 			always in Tor, we use OAEP-MGF1 padding; see tor-spec.txt
	// 			section 0.3.)
	// 			 [variable length]
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
	messageCells,
	messageCellNames,
  readCellsFromData,
  serializeCell as serializeCommand,
};