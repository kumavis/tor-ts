import * as crypto from 'crypto';
import { pki } from 'node-forge';
import type { KeyInfo } from './profiles.ts';

const Rand = function (length: number): Buffer {
	return crypto.randomBytes(length);
};

const createIdLinkTLSCertFromKeyInfo=function(keyInfo: KeyInfo, format: string, date: Date, subject: string, issuer: string, cert: any=undefined) {
	let publicKey = pki.publicKeyFromPem(keyInfo.pubkey.toString('utf8'));
	let privateKey = pki.privateKeyFromPem(keyInfo.privkey.toString('utf8'));
	if (!cert) {
		cert = pki.createCertificate();
		cert.serialNumber='00cc3f3ee26d9a574e';
		//stupid openssl X509 stuff - see https://icinga.com/2017/08/30/advisory-for-ssl-problems-with-leading-zeros-on-openssl-1-1-0/ and https://github.com/openssl/openssl/issues/7134 and https://github.com/digitalbazaar/forge/issues/349
		//won't fix, see if fingerprinting issues
		let date2=new Date(date.valueOf());
		date2.setHours(date2.getHours() - 2);
		cert.validity.notBefore = date2;
		cert.validity.notAfter = new Date(cert.validity.notBefore.valueOf());
		cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 1);
		let attrs = [{
			name: 'commonName',
			value: subject||('www.'+Rand(Math.floor(Math.random()*20+4)).toString('hex')+'.com')
		}];
		let attri = [{
			name: 'commonName',
			value: issuer||('www.'+Rand(Math.floor(Math.random()*20+4)).toString('hex')+'.com')
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

export const client_tls_options_fromKeyInfo= function(keyInfo: KeyInfo) {
	let servername='www.'+Rand(Math.floor(Math.random()*20+4)).toString('hex')+'.net';
	let issuer='www.'+Rand(Math.floor(Math.random()*20+4)).toString('hex')+'.com';
	let options = {
		key: keyInfo.privkey,
		cert: createIdLinkTLSCertFromKeyInfo(keyInfo,'pem',new Date(),servername,issuer),
		servername: servername,
		rejectUnauthorized: false
	};
	return options
};
