import * as crypto from 'node:crypto';
import * as assert from 'node:assert';
import { pki } from 'node-forge';
import type { KeyInfo } from './profiles.ts';
import type { CellCerts } from './messaging.ts';
import * as forge from 'node-forge';

const Rand = function (length: number): Buffer {
	return crypto.randomBytes(length);
};

const randomHexId = function (): string {
	return Rand(Math.floor(Math.random()*20+4)).toString('hex')
};

const createIdLinkTLSCertFromKeyInfo = function(keyInfo: KeyInfo, format: string, date: Date, subject: string, issuer: string, cert: any=undefined) {
	let publicKey = pki.publicKeyFromPem(keyInfo.pubkey.toString('utf8'));
	let privateKey = pki.privateKeyFromPem(keyInfo.privkey.toString('utf8'));
	if (!cert) {
		cert = pki.createCertificate();
		cert.serialNumber='00cc3f3ee26d9a574e';
		//stupid openssl X509 stuff - see https://icinga.com/2017/08/30/advisory-for-ssl-problems-with-leading-zeros-on-openssl-1-1-0/ and https://github.com/openssl/openssl/issues/7134 and https://github.com/digitalbazaar/forge/issues/349
		//won't fix, see if fingerprinting issues
		let date2 = new Date(date.valueOf());
		date2.setHours(date2.getHours() - 2);
		cert.validity.notBefore = date2;
		cert.validity.notAfter = new Date(cert.validity.notBefore.valueOf());
		cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 1);
		let attrs = [{
			name: 'commonName',
			value: subject||(`www.${randomHexId()}.com`)
		}];
		let attri = [{
			name: 'commonName',
			value: issuer||(`www.${randomHexId()}.com`)
		}];
		cert.setSubject(attrs);
		cert.setIssuer(attri);
	};
	cert.publicKey = publicKey;
	cert.sign(privateKey);
	let pem = pki.certificateToPem(cert);
	if (format==='pem') {
		return pem;
	} else if (format==='der') {
		// if (!forge_buffers) {
		// 	return pki.pemToDer(pem).data.toString('hex');
		// } else {
			return pki.pemToDer(pem).toHex();
		// };
	} else {
		return cert;
	};
};

export const clientTlsOptionsFromKeyInfo = function(keyInfo: KeyInfo) {
	let servername = `www.${randomHexId()}.net`;
	let issuer = `www.${randomHexId()}.com`;
	let options = {
		key: keyInfo.privkey,
		cert: createIdLinkTLSCertFromKeyInfo(keyInfo, 'pem', new Date(), servername, issuer),
		servername: servername,
		rejectUnauthorized: false
	};
	return options
};


const authTypeDescriptions: Record<number, string> = {
	1: 'RSA-SHA256-TLSSecret',
	// 2: '<reserved auth type>',
	3: 'Ed25519-SHA256-RFC5705',
}

export const getAuthTypeDescription = (type: number): string => {
	return authTypeDescriptions[type] || `Unknown auth type ${type}`
}

const certDescriptions: Record<number, string> = {
	1: 'Link key certificate certified by RSA1024 identity',
	2: 'RSA1024 Identity certificate, self-signed.',
	3: 'RSA1024 AUTHENTICATE cell link certificate, signed with RSA1024 key.',
	4: 'Ed25519 signing key, signed with identity key.',
	5: 'TLS link certificate, signed with ed25519 signing key.',
	6: 'Ed25519 AUTHENTICATE cell key, signed with ed25519 signing key.',
	7: 'Ed25519 identity, signed with RSA identity.',
};

export function getCertDescription (certType: number): string {
	return certDescriptions[certType] || 'Unknown'
}


// const derToPem = (derData: Buffer): Buffer => {
// 	// const type = derData[0];
// 	// const length = derData[1];
// 	// const body = derData.slice(2, 2 + length);
// 	const body = derData;
// 	const pemBody = body.toString('base64');
// 	const pem = Buffer.from(`-----BEGIN CERTIFICATE-----\n${pemBody}\n-----END CERTIFICATE-----`);
// 	return pem;
// }

const derToPem = (derData: Buffer): Buffer => {
	// const certString = derData.toString('binary');
	// const obj = forge.asn1.fromDer(certString, { parseAllBytes: false });
	// console.log({ asn1: obj })
	// const cert = forge.pki.certificateFromAsn1(obj);
	// // convert a Forge certificate to PEM
	// const pem = pki.certificateToPem(cert);
	// return Buffer.from(pem);

	const pemBody = derData.toString('base64').match(/.{1,64}/g)!.join('\n');
	const pem = `-----BEGIN CERTIFICATE-----\n${pemBody}\n-----END CERTIFICATE-----\n`;
	console.log(forge.pem.decode(Buffer.from(pem).toString('binary')))
	return Buffer.from(pem);

	// const { createPublicKey } = crypto;

	//         // Create a public key object from the DER
	// 				const publicKeyInput = {
  //           key: derData,
  //           format: 'der',
  //           type: 'pkcs1',
  //       } as crypto.PublicKeyInput;
	// 			console.log({publicKeyInput})
  //       const publicKey = createPublicKey(publicKeyInput);
	// 			console.log({publicKey})
  //       // Export the public key to PEM
  //       const pem = publicKey.export({ type: 'spki', format: 'pem' });
	// 			console.log({pem})
	// 			if (typeof pem === 'string') {
	// 				return Buffer.from(pem);
	// 			}
	// 			return pem;
}

export const parseCert = (certBody: Buffer): void => {
	// const pem = derToPem(certBody);
	// // return new crypto.X509Certificate(pem)
	// // return new crypto.X509Certificate(certBody)
	// // convert a Forge certificate from PEM
	// var cert = forge.pki.certificateFromPem(pem.toString('binary'));
	// const cert = forge.pki.certificateFromPem(certBody.toString('binary'));
	const certString = certBody.toString('binary');
	const asn1Obj = forge.asn1.fromDer(certString, { parseAllBytes: false });
	console.log({forgeAsn1: asn1Obj})
	const cert = forge.pki.certificateFromAsn1(asn1Obj);
	console.log({forgeCert:cert})
}

export const validateCertsForEd25519Identity = ({ certs }: CellCerts): void => {
	// To authenticate the responder as having a given Ed25519,RSA identity key
	// combination, the initiator MUST check the following.

	// 	* The CERTS cell contains exactly one CertType 2 "ID" certificate.
	assert(certs.filter((cert) => cert.type === 2).length === 1);
	// 	* The CERTS cell contains exactly one CertType 4 Ed25519
	// 		"Id->Signing" cert.
	assert(certs.filter((cert) => cert.type === 4).length === 1);
	// 	* The CERTS cell contains exactly one CertType 5 Ed25519
	// 		"Signing->link" certificate.
	assert(certs.filter((cert) => cert.type === 5).length === 1);
	// 	* The CERTS cell contains exactly one CertType 7 "RSA->Ed25519"
	// 		cross-certificate.
	assert(certs.filter((cert) => cert.type === 7).length === 1);
	// 	* All X.509 certificates above have validAfter and validUntil dates;
	// 		no X.509 or Ed25519 certificates are expired.
	// const certObjs = certs.map((cert) => {
	// 	console.log(cert)
	// 	// console.log(cert.body.toString('utf8'))
	// 	return new crypto.X509Certificate(derToPem(cert.body))
	// 	// var asnObj = forge.asn1.fromDer(derKey);
	// 	// var asn1Cert = forge.pki.certificateFromAsn1(asnObj);
	// 	// return forge.pki.certificateToPem(asn1Cert);
	// });
	// console.log(certObjs)

	// 	* All certificates are correctly signed.
	// 	* The certified key in the Signing->Link certificate matches the
	// 		SHA256 digest of the certificate that was used to
	// 		authenticate the TLS connection.
	// 	* The identity key listed in the ID->Signing cert was used to
	// 		sign the ID->Signing Cert.
	// 	* The Signing->Link cert was signed with the Signing key listed
	// 		in the ID->Signing cert.
	// 	* The RSA->Ed25519 cross-certificate certifies the Ed25519
	// 		identity, and is signed with the RSA identity listed in the
	// 		"ID" certificate.
	// 	* The certified key in the ID certificate is a 1024-bit RSA key.
	// 	* The RSA ID certificate is correctly self-signed.
}

