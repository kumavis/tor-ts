import { EventEmitter } from 'events';
import * as tls from 'tls';
import type { KeyInfo } from './profiles.js';
import {
	clientTlsOptionsFromKeyInfo,
	validateCertsForEd25519Identity,
	getCertDescription,
	getAuthTypeDescription,
} from './tls.ts';

import {
	messageCells,
	serializeCommand,
	readCellsFromData,
} from './messaging.ts';
import type {
	MessageCell,
	CellNetInfo,
	Certificate,
} from './messaging.ts';

class Connection {
	
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
		for (const cell of readCellsFromData(data)) {
			if (handShakeInProgress) {
				this._incommingHandshakeDigestData.push(cell.data);
			}
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
	sendData(serializedCell: any) {
		throw new Error("Method not implemented.");
	}
	promiseForHandshake (): Promise<any> {
		// TODO: should fail if any of these are repeated
		const handshakePromise = receiveEvents(['VERSIONS', 'CERTS', 'AUTH_CHALLENGE'], this.incommingCommands)
		return handshakePromise;
	}
}

export async function testHandshake ({ keyInfo }: { keyInfo: KeyInfo }) {
	const connection = new Connection({ isInitiator: true })
	
	connection.incommingCommands.once('NETINFO', (cell: MessageCell) => {
		const message = cell.message as CellNetInfo;
		console.log(`NETINFO: other address: ${cell.message.otherAddress}`, cell.message);
		for (const address of cell.message.addresses) {
			console.log(`  ${address}`)
		}
	})

	
	// test handshake
	// await testHandshakeFixture({ connection, keyInfo })
	await testConnectToKnownNode({ connection, keyInfo })

}

async function testHandshakeFixture ({ connection, keyInfo }: { connection: Connection, keyInfo: KeyInfo }) {
	connection.sendData = (data) => console.log(`send: ${data.toString('hex')}`)
	const handshakeP = performHandshake({ connection, keyInfo })
	const data = Buffer.from('000007000600030004000500008105a20501023f3082023b308201a4a00302010202086563efa7b2001cda300d06092a864886f70d01010b0500301d311b301906035504030c127777772e74627874786d6c36616a2e636f6d301e170d3232303830393030303030305a170d3233303333313233353935395a301f311d301b06035504030c147777772e796c666667796562636e73322e6e657430820122300d06092a864886f70d01010105000382010f003082010a0282010100dd5bde4282f071eb5a9fca2a1471dff98ee7fa83a8eb3ace838853fca2d2ad3e37bd86e182d2941da93cabcb2e41b1626c8b8f5c8c66f4ce161d5d9a03d631d9acab2d70622b3c2efa6016721d5b8377e80724dbd06d93a73dd33a0b12dd6b78ac1a8310c8bf77f3382aaf4396e820e6ad7bac7f191184f5f6cbda0d40bd6bbe4f818102aeccf07d5359ad749de57470e71e9e41a6e962a75851440abb2d765ae3c72fdb732db00aed81f4fbb2466b533608380afb5c3e0f8e403fd34c173f53beeb3c39a7c76f1eec0b87aadb654ba8b9407fdc26b428b8bfd93917dc08c6dead3baee70896bb2a3e908cda0676b36c9fa15d1edf57f939052fe0474ccee8eb0203010001300d06092a864886f70d01010b050003818100afdbf617e5b17803cce2fe7ee0e4aafe1389f789be053d6e2650de63da31d7a634989131404cce9fc379354c13fd0bcb6f507c2740e32154ae4cf336bd1ba2ee4b788eab560318c5abb47c33833be2637e509fdaaeab534279366d17bf9b4214644651eb0c002c3b620e1903b51d963633d1ce3a9055fc0d97bef32f3738155b0201ba308201b63082011fa003020102020900f6fecb839315ec83300d06092a864886f70d01010b0500301d311b301906035504030c127777772e74627874786d6c36616a2e636f6d301e170d3232303632303030303030305a170d3233303632303030303030305a301d311b301906035504030c127777772e74627874786d6c36616a2e636f6d30819f300d06092a864886f70d010101050003818d0030818902818100d1b298f5d0d3a879a039484de926fd75ca613ff20dea69f70310f60b74d52d4c5c27e3148d012cc73133b013bcee0ae6f3833d101e8acd4a9e880ec2bb57283e5c53bb36842ab8934c7083ca4ae2b83bd7109ef7f0c5ac758dbcdec3a46c20c80d392a6a13248e48682ad3fa0e6e7c13b8a90b8bf9d4788e6315ec47e85124b50203010001300d06092a864886f70d01010b0500038181004b14fde4c8ffcc2faadacba490ccc4ccbf699766438d364b54c632fd80f54e1bd1a3e0a9a9485fdd750fa82306c4be8bb563760bd5f17f50d2f35e80801468905a4bc615865765aa62b808da0e1ea41487d8ea4b050ef7592ef3fd841bbab294f8b5946caea96e559e9e699e5bfba673b76b24de8d2c159e7fdd947360ac8f9c04008c01040007206f011c4d1d00524b0b7a88d77417016e67eabb5187fb19a560cd133f8f2e34d7323b010020040078d5dcbcbaaed604ed4174b883496e4a75864fe336d8989abb9f033d9d13ad1f50d36fe057c3a6399b4983919e976e5f2154dd265da2c2c6a4b2014a1803d3358219016f3a3244be5a38d1bd6defa9ce50f2b61a9cbb0cde5b249921476d2206050068010500071c5603119833c0b82be368c41df5cec65ce7de44611cefc29573105e11ed36d7d2bad20000646fa191fd5ae34c4116e6dc1d929999eac6c1fbdde688bf50c6decbca32c9f3c9e94cf5c4b0a2ae350f0f0835f212e00c015a8d9a0b3668eb917c53364e0b0700a578d5dcbcbaaed604ed4174b883496e4a75864fe336d8989abb9f033d9d13ad1f00072cce803bfbf07ad8e9d90b33af7a1dad4badf4505517d92545b370efed4d8028199c6ed96069d48d34e3265b3d2c5a5b392eb120198fbb86fda364451cf38658ef45a907d86a8ac814e9ccf2ad7628f5ae2ef893291e03cde85387b5189ae7bf5e86e0ab4d0be8cbe60d6925babf4d875db8b4e5f4237dbcac367e048c793da8f9ecd00000820026f4b46fd886002b8cbc1bf82fd29ae74e3965f47c96d43eec58d870e9e414c1a200020001000300000863fbd3210404c0fcd4290204045db49d9a06102a0011580003000000000000000002ae000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000','hex')
	connection.onData(data)
	await handshakeP
}

async function testConnectToKnownNode ({ connection, keyInfo }: { connection: Connection, keyInfo: KeyInfo }) {
	const server = {
		ip: '93.180.157.154',
		// fing: 'B198C0B4B8C551F174FBB841A172616E3DB3124D',
		port: 9001,
		// band: '10702338',
		// o_modulus: 'd394335f7605853b76f8bd636100fcb4c68499fc98ca05240a0f11dda7f1102bacb4197f4f8206e38235938834a21032bc1fac7f31c6fd6401ae73833457f76b78fcfde98480e890e1aee9a6fa077c2a632d298dcdcfc659c3614bb42dfa53dd81ff22e7c05056fe2e4ceb506908b4123cd7b4e352b45061a4f88d9da48583ab'
	}

	const options = clientTlsOptionsFromKeyInfo(keyInfo);
	const socket = tls.connect(server.port, server.ip, options, function() {
		console.log('connect')
		performHandshake({ connection, keyInfo })
	});
	connection.sendData = (data) => socket.write(data)
	socket.on('data', (data) => {
		connection.onData(data)
	});
	socket.on('end',() => { console.log('end') });
	socket.on('close',() => { console.log('close') });
	socket.on('error', (err) => { console.log('error', err) });
}

async function performHandshake ({ connection, keyInfo }: { connection: Connection, keyInfo: KeyInfo }) {
	// TODO: use NETINFO timestamp to determine clock skew
	const linkProtocolSupportedVersions = [3];
	const handshakePromise = connection.promiseForHandshake();
	// send our handshake intro
	connection.sendMessage(messageCells.VERSIONS, { versions: linkProtocolSupportedVersions })
	
	// receive their handshake intro
	const [versionsCell, certsCell, authChallengeCell] = await handshakePromise;
	// determine shared link protocol version
	console.log('supported versions:', linkProtocolSupportedVersions, versionsCell.message.versions)
	const linkProtocolVersion = getHighestSharedNumber(linkProtocolSupportedVersions, versionsCell.message.versions)
	if (linkProtocolVersion === undefined) {
		throw new Error('No shared link protocol version')
	}
	connection.state.linkProtocolVersion = linkProtocolVersion
	console.log('VERSIONS: set linkProtocolVersion', linkProtocolVersion)
	// get certs
	console.log('CERTS: got certs');
	for (const { type, cert } of certsCell.message.certs) {
		console.log(`  #${type} ${getCertDescription(type)}`)
	}
	validateCertsForEd25519Identity(certsCell.message)

	console.log('AUTH_CHALLENGE: accepted challenge methods');
	for (const type of authChallengeCell.message.methods) {
		console.log(`  ${getAuthTypeDescription(type)}`)
	}
	// If it does not want to authenticate, it MUST
	// send a NETINFO cell.  
	// If it does want to authenticate, it MUST send a
  //  CERTS cell, an AUTHENTICATE cell (4.4), and a NETINFO.
	const certs = certsFromKeyInfo({ keyInfo });
	connection.sendMessage(messageCells.CERTS, { certs });
}



function certsFromKeyInfo({ keyInfo }: { keyInfo: KeyInfo }) {
	const certs: Certificate[] = [];

	// To authenticate the initiator as having an RSA identity key only,
	// the responder MUST check the following:

	// 	* The CERTS cell contains exactly one CertType 3 "AUTH" certificate.
	// 	* The CERTS cell contains exactly one CertType 2 "ID" certificate.
	// 	* Both certificates have validAfter and validUntil dates that
	// 		are not expired.
	// 	* The certified key in the AUTH certificate is a 1024-bit RSA key.
	// 	* The certified key in the ID certificate is a 1024-bit RSA key.
	// 	* The certified key in the ID certificate was used to sign both
	// 		certificates.
	// 	* The auth certificate is correctly signed with the key in the
	// 		ID certificate.
	// 	* The ID certificate is correctly self-signed.

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