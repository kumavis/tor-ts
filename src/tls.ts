import crypto from 'node:crypto';

const Rand = function (length: number): Buffer {
	return crypto.randomBytes(length);
};

const randomHexId = function (): string {
	return Rand(Math.floor(Math.random()*20+4)).toString('hex')
};

export const makeRandomServerName = (): string => {
	return `www.${randomHexId()}.net`;
};

const authTypeDescriptions: Record<number, string> = {
	1: 'RSA-SHA256-TLSSecret',
	// 2: '<reserved auth type>',
	3: 'Ed25519-SHA256-RFC5705',
}

export const getAuthTypeDescription = (type: number): string => {
	return authTypeDescriptions[type] || `Unknown auth type ${type}`
}
