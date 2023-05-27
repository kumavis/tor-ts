declare module 'node-forge' {
	export const pki: {
		publicKeyFromPem(pem: string): any;
		privateKeyFromPem(pem: string): any;
		createCertificate(): any;
		certificateToPem(cert: any): string;
		pemToDer(pem: string): any;
	}
}
