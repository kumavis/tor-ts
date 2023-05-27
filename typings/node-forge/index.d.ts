declare module 'node-forge' {
  export const pki: {
    publicKeyFromPem(pem: string): any;
    privateKeyFromPem(pem: string): any;
    createCertificate(): any;
    certificateToPem(cert: any): string;
    certificateFromPem(pem: string): any;
    certificateFromAsn1(obj: any): any;
    pemToDer(pem: string): any;
  }
  export const asn1: {
    fromDer(der: string, opts?: any): any;
  }
  export const pem: {
    decode(pem: string): any;
  }
}
