import * as crypto from 'node:crypto';
import * as forge from 'node-forge';
import type { KeyInfo } from './profiles';

const Rand = function (length: number): Buffer {
	return crypto.randomBytes(length);
};

const randomHexId = function (): string {
	return Rand(Math.floor(Math.random()*20+4)).toString('hex')
};

const createIdLinkTLSCertFromKeyInfo = function(keyInfo: KeyInfo, format: string, date: Date, subject: string, issuer: string, cert: any=undefined) {
	let publicKey = forge.pki.publicKeyFromPem(keyInfo.pubkey.toString('utf8'));
	let privateKey = forge.pki.privateKeyFromPem(keyInfo.privkey.toString('utf8'));
	if (!cert) {
		cert = forge.pki.createCertificate();
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
	let pem = forge.pki.certificateToPem(cert);
	if (format==='pem') {
		return pem;
	} else if (format==='der') {
		return forge.pki.pemToDer(pem).toHex();
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
