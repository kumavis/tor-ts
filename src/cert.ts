import crypto from 'node:crypto';
import assert from 'node:assert';
import type { CellCerts } from './messaging';
import { BytesReader, sha256 } from './util';
import * as ed from '@noble/ed25519';
import { sha512 } from '@noble/hashes/sha512';

// enable synchronous ed25519 methods
ed.etc.sha512Sync = (...m) => sha512(ed.etc.concatBytes(...m));

type Ed25519CertificateExtension = {
  type: number;
  flags: number;
  data: Buffer;
}

type Ed25519Certificate = {
  version: number;
  type: number;
  expirationHours: number;
  keyType: number;
  key: Buffer;
  extensions: Array<Ed25519CertificateExtension>;
  signature: Buffer;
  signedWith: Buffer | null;
  text: Buffer;
}

export const CertTypes = {
	/// TLS link key, signed with RSA identity. X.509 format. (Obsolete)
	TLS_LINK_X509: 0x01,
	/// Self-signed RSA identity certificate. X.509 format. (Legacy)
	RSA_ID_X509: 0x02,
	/// RSA lnk authentication key signed with RSA identity
	/// key. X.509 format. (Obsolete)
	LINK_AUTH_X509: 0x03,

	/// Identity verifying a signing key, directly.
	IDENTITY_V_SIGNING: 0x04,

	/// Signing key verifying a TLS certificate by digest.
	SIGNING_V_TLS_CERT: 0x05,

	/// Signing key verifying a link authentication key.
	SIGNING_V_LINK_AUTH: 0x06,

	/// RSA identity key certifying an Ed25519 identity key. RSA
	/// crosscert format. (Legacy)
	RSA_ID_V_IDENTITY: 0x07,

	/// For onion services: short-term descriptor signing key
	/// (`KP_hs_desc_sign`), signed with blinded onion service identity
	/// (`KP_hs_blind_id`).
	HS_BLINDED_ID_V_SIGNING: 0x08,

	/// For onion services: Introduction point authentication key
	/// (`KP_hs_ipt_sid`), signed with short term descriptor signing key
	/// (`KP_hs_desc_sign`).
	///
	/// This one is, sadly, a bit complicated. In the original specification
	/// it was meant to be a cross-certificate, where the signature would be
	/// _on_ the descriptor signing key, _signed with_ the intro TID key.
	/// But we got it backwards in the C Tor implementation, and now, for
	/// compatibility, we are stuck doing it backwards in the future.
	///
	/// If we find in the future that it is actually important to
	/// cross-certify these keys (as originally intended), then we should
	/// add a new certificate type, and put the new certificate in the onion
	/// service descriptor.
	HS_IP_V_SIGNING: 0x09,

	/// An ntor key converted to a ed25519 key, cross-certifying an
	/// identity key.
	NTOR_CC_IDENTITY: 0x0A,

	/// For onion services: Ntor encryption key (`KP_hss_ntor`),
	/// converted to ed25519, signed with the descriptor signing key
	/// (`KP_hs_desc_sign`).
	///
	/// As with [`HS_IP_V_SIGNING`](CertType::HS_IP_V_SIGNING), this
	/// certificate type is backwards.  In the original specification it was
	/// meant to be a cross certificate, with the signing and signed keys
	/// reversed.
	HS_IP_CC_SIGNING: 0x0B,
}

const certDescriptions: Record<number, string> = {
	[CertTypes.TLS_LINK_X509]: 'Link key certificate certified by RSA1024 identity',
	[CertTypes.RSA_ID_X509]: 'RSA1024 Identity certificate, self-signed.',
	[CertTypes.LINK_AUTH_X509]: 'RSA1024 AUTHENTICATE cell link certificate, signed with RSA1024 key.',
	[CertTypes.IDENTITY_V_SIGNING]: 'Ed25519 signing key, signed with identity key.',
	[CertTypes.SIGNING_V_TLS_CERT]: 'TLS link certificate, signed with ed25519 signing key.',
	[CertTypes.SIGNING_V_LINK_AUTH]: 'Ed25519 AUTHENTICATE cell key, signed with ed25519 signing key.',
	[CertTypes.RSA_ID_V_IDENTITY]: 'Ed25519 identity, signed with RSA identity.',
};

export function getCertDescription (type: number): string {
	return certDescriptions[type] || 'Unknown'
}

/// Identifiers for the type of key or object getting signed.
const KeyTypes = {
  /// Identifier for an Ed25519 key.
  ED25519_KEY: 0x01,
  /// Identifier for the SHA256 of an DER-encoded RSA key.
  SHA256_OF_RSA: 0x02,
  /// Identifies the SHA256 of an X.509 certificate.
  SHA256_OF_X509: 0x03,

  // 08 through 09 and 0B are used for onion services.  They
  // probably shouldn't be, but that's what Tor does.
  // TODO hs: Add these types.
}

/// Extension identifiers for extensions in certificates.
const ExtensionTypes = {
  /// Extension indicating an Ed25519 key that signed this certificate.
  ///
  /// Certificates do not always contain the key that signed them.
  SIGNED_WITH_ED25519_KEY: 0x04,
}

export function parseEd25519Certificate (certBody: Buffer): Ed25519Certificate {
  const reader = new BytesReader(certBody);
  // VERSION         [1 Byte]
  // CERT_TYPE       [1 Byte]
  // EXPIRATION_DATE [4 Bytes]
  // CERT_KEY_TYPE   [1 byte]
  // CERTIFIED_KEY   [32 Bytes]
  // N_EXTENSIONS    [1 byte]
  // EXTENSIONS      [N_EXTENSIONS times]
  // SIGNATURE       [64 Bytes]

  const version = reader.readUIntBE(1)
  if (version !== 1) {
    throw new Error(`Unrecognized certificate version: ${version}`)
  }

  const type = reader.readUIntBE(1)
  const expirationHours = reader.readUIntBE(4)
  let keyType = reader.readUIntBE(1)

  // This is a workaround for a tor bug: the key type is
  // wrong. It was fixed in tor#40124, which got merged into Tor
  // 0.4.5.x and later.
  if (type === CertTypes.SIGNING_V_TLS_CERT && keyType === KeyTypes.ED25519_KEY) {
    keyType = KeyTypes.SHA256_OF_X509;
  }

  // parse key?
  const key = reader.readBytes(32)

  const nExtensions = reader.readUIntBE(1);
  const extensions = new Array(nExtensions);
  for (let index = 0; index < nExtensions; index++) {
    // ExtLength [2 bytes]
    // ExtType   [1 byte]
    // ExtFlags  [1 byte]
    // ExtData   [ExtLength bytes]
    const length = reader.readUIntBE(2);
    const extension = {
      type: reader.readUIntBE(1),
      flags: reader.readUIntBE(1),
      data: reader.readBytes(length),
    }
    // parse extension?
    extensions[index] = extension;
  }
  const signatureOffset = reader.offset;
  const signature = reader.readBytes(64);

  // verify exhausted
  if (!reader.isExhausted()) {
    throw new Error('Extra bytes at end of certificate');
  }

  const keyExtension = extensions.find(({ type }) => type === ExtensionTypes.SIGNED_WITH_ED25519_KEY);
  let signedWith;
  if (keyExtension) {
    signedWith = keyExtension.data;
  }

  const text = certBody.slice(0, signatureOffset);

  const cert = {
    version,
    type,
    expirationHours,
    keyType,
    key,
    extensions,
    signature,
    signedWith,
    text,
  };

  return cert
}

type Signature = {
  key: Buffer;
  signature: Buffer;
  text: Buffer;
}

export type RsaId = crypto.KeyObject;

export const validateCertsCellForIdentities = (certsCell: CellCerts, peerCertSha256: Buffer, now: number, clockSkew: number): {
  rsaId: RsaId,
  ed25519Id: Buffer,
} => {
	// To authenticate the responder as having a given Ed25519,RSA identity key
	// combination, the initiator MUST check the following.

  const { certs } = certsCell;
	// 	* The CERTS cell contains exactly one CertType 2 "ID" certificate.
	assert(certs.filter(({ type }) => type === CertTypes.RSA_ID_X509).length === 1, 'The CERTS cell contains exactly one CertType 2 "ID" certificate.');
	// 	* The CERTS cell contains exactly one CertType 4 Ed25519
	// 		"Id->Signing" cert.
	assert(certs.filter(({ type }) => type === CertTypes.IDENTITY_V_SIGNING).length === 1, 'The CERTS cell contains exactly one CertType 4 Ed25519 "Id->Signing" cert.');
	// 	* The CERTS cell contains exactly one CertType 5 Ed25519
	// 		"Signing->link" certificate.
	assert(certs.filter(({ type }) => type === CertTypes.SIGNING_V_TLS_CERT).length === 1, 'The CERTS cell contains exactly one CertType 5 Ed25519 "Signing->link" certificate.');
	// 	* The CERTS cell contains exactly one CertType 7 "RSA->Ed25519"
	// 		cross-certificate.
	assert(certs.filter(({ type }) => type === CertTypes.RSA_ID_V_IDENTITY).length === 1, 'The CERTS cell contains exactly one CertType 7 "RSA->Ed25519" cross-certificate.');
	// 	* All X.509 certificates above have validAfter and validUntil dates;
	// 		no X.509 or Ed25519 certificates are expired.

	// We need to check the following lines of authentication:
	//
	// First, to bind the ed identity to the channel.
	//    peer.ed_identity() matches the key in...
	//    IDENTITY_V_SIGNING cert, which signs...
	//    SIGNING_V_TLS_CERT cert, which signs peer_cert.
	//
	// Second, to bind the rsa identity to the ed identity:
	//    peer.rsa_identity() matches the key in...
	//    the x.509 RSA identity certificate (type 2), which signs...
	//    the RSA->Ed25519 crosscert (type 7), which signs...
	//    peer.ed_identity().

	const idSkCertContainer = certs.find(({ type }) => type === CertTypes.IDENTITY_V_SIGNING)
  if (!idSkCertContainer) {
    throw new Error(`Missing identity->signing cert`)
  }
  const idSk = parseEd25519Certificate(idSkCertContainer.body);

	const skTlsCertContainer = certs.find(({ type }) => type === CertTypes.SIGNING_V_TLS_CERT)
  if (!skTlsCertContainer) {
    throw new Error(`Missing signing->TLS cert`)
  }
  const skTls = parseEd25519Certificate(skTlsCertContainer.body);

	const sigs: Signature[] = [];

	// Part 1: validate ed25519 stuff.
	//
	// (We are performing our timeliness checks now, but not inspecting them
	// until later in the function, so that we can distinguish failures that
	// might be caused by clock skew from failures that are definitely not
	// clock skew.)


  const idSkSig = {
    key: idSk.signedWith,
    signature: idSk.signature,
    text: idSk.text,
  }
  sigs.push(idSkSig);
  // check timeliness
  verifyTimeliness(idSk.expirationHours, now, clockSkew)

  // Take the identity key from the identity->signing cert
  const identityKey = idSk.signedWith;
  if (!identityKey) {
    throw new Error(`Missing identity key in identity->signing cert`)
  }
  // Take the signing key from the identity->signing cert
  const signingKey = idSk.key;
  if (!signingKey) {
    throw new Error(`Bad key type in identity->signing cert`)
  }

  // Now look at the signing->TLS cert and check it against the
  // peer certificate.

  // KeyUnknownCert.should_be_signed_with
  if (skTls.signedWith && !keysMatch(skTls.signedWith, signingKey)) {
    throw new Error(`Certificate mistmatch`)
  }
  const skTlsSig = {
    key: signingKey,
    signature: skTls.signature,
    text: skTls.text,
  }
  sigs.push(skTlsSig);
  // check timeliness
  verifyTimeliness(skTls.expirationHours, now, clockSkew)

  if (!keysMatch(peerCertSha256, skTls.key)) {
    throw new Error(`Peer cert did not authenticate TLS cert`)
  }

  // Verify the ed25519 certificates in this handshake.
  sigs.forEach(({ key, signature, text }) => {
    const verified = ed.verify(signature, text, key);
    if (verified !== true) {
      throw new Error(`Invalid ed25519 signature in handshake`)
    }
  });


  // Part 2: validate rsa stuff.

  // What is the RSA identity key, according to the X.509 certificate
  // in which it is self-signed?
  //
  // (We don't actually check this self-signed certificate, and we use
  // a kludge to extract the RSA key)
  // let pkrsa = c
  //     .cert_body(CertType::RSA_ID_X509)
  //     .and_then(ll::util::x509_extract_rsa_subject_kludge)
  //     .ok_or_else(|| Error::HandshakeProto("Couldn't find RSA identity key".into()))?;
	const pkrsaCertContainer = certs.find(({ type }) => type === CertTypes.RSA_ID_X509)
  if (!pkrsaCertContainer) {
    throw new Error(`Missing RSA identity cert`)
  }
  const pkrsaCert = parseRsaX509Certificate(pkrsaCertContainer.body);

  // Now verify the RSA identity -> Ed Identity crosscert.
  //
  // This proves that the RSA key vouches for the Ed key.  Note that
  // the Ed key does not vouch for the RSA key: The RSA key is too
  // weak.
  // let rsa_cert = c
  //     .cert_body(CertType::RSA_ID_V_IDENTITY)
  //     .ok_or_else(|| Error::HandshakeProto("No RSA->Ed crosscert".into()))?;
  const rsaCrossCertContainer = certs.find(({ type }) => type === CertTypes.RSA_ID_V_IDENTITY)
  if (!rsaCrossCertContainer) {
    throw new Error(`Missing RSA->Ed crosscert signature`)
  }
  const rsaCrossCert = parseRsaCrossCertificate(rsaCrossCertContainer.body);
  
  // let rsa_cert = tor_cert::rsa::RsaCrosscert::decode(rsa_cert)
  //     .map_err(|e| Error::from_bytes_err(e, "RSA identity cross-certificate"))?
  //     .check_signature(&pkrsa)
  //     .map_err(|_| Error::HandshakeProto("Bad RSA->Ed crosscert signature".into()))?;
  // let (rsa_cert_timeliness, rsa_cert) = check_timeliness(rsa_cert, now, self.clock_skew);

  // >>>>>>> SECURITY TODO: fix checking rsa signature <<<<<<<<<<<<<<<<<<<<

  // if (rsaCrossCert.checkSignature(pkrsaCert.publicKey) !== true) {
  //   throw new Error(`Bad RSA->Ed crosscert signature`)
  // }
  // check timeliness
  verifyTimeliness(rsaCrossCert.expirationHours, now, clockSkew)

  // if !rsa_cert.subject_key_matches(identity_key) {
  //     return Err(Error::HandshakeProto(
  //         "RSA->Ed crosscert certifies incorrect key".into(),
  //     ));
  // }
  if (!keysMatch(rsaCrossCert.ed25519Key, identityKey)) {
    throw new Error(`RSA->Ed crosscert certifies incorrect key`)
  }

  // let rsa_id = pkrsa.to_rsa_identity();
  const rsaId = pkrsaCert.publicKey;


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

  return {
    rsaId,
    ed25519Id: identityKey,
  }
}

function convertDERtoPEM (derData: Buffer): Buffer {
  // Base64 encode and split into lines of 64 characters
  const base64 = derData.toString('base64');
  const base64Lines = base64.match(/.{1,64}/g)!.join('\n');
  const pemData = Buffer.from(
    '-----BEGIN CERTIFICATE-----\n' +
    base64Lines +
    '\n-----END CERTIFICATE-----\n'
  );
  return pemData;
}

function parseRsaX509Certificate (certBody: Buffer) {
  // const asn1Obj = forge.asn1.fromDer(certBody.toString('binary'))
  // const cert = forge.pki.certificateFromAsn1(asn1Obj);
  // console.log({ forgeCert: cert })
  // return cert
  return new crypto.X509Certificate(convertDERtoPEM(certBody));
}

export type CrossCertificate = {
  ed25519Key: Buffer;
  expirationHours: number;
  signature: Buffer;
  digest: Buffer;
  checkSignature (publicKey: RsaId): boolean;
}

const RsaCrossCertPrefix = Buffer.from('Tor TLS RSA/Ed25519 cross-certificate');

function parseRsaCrossCertificate (certBody: Buffer): CrossCertificate {
  const bytesReader = new BytesReader(certBody);
  // ED25519_KEY                       [32 bytes]
  // EXPIRATION_DATE                   [4 bytes]
  // SIGLEN                            [1 byte]
  // SIGNATURE                         [SIGLEN bytes]
  const ed25519Key = bytesReader.readBytes(32);
  const expirationHours = bytesReader.readUIntBE(4);
  const sigLen = bytesReader.readUIntBE(1);
  const signature = bytesReader.readBytes(sigLen);
  const signedPortion = certBody.slice(0, 36);
  const digest = sha256(
    RsaCrossCertPrefix,
    signedPortion,
  )

  return {
    ed25519Key,
    expirationHours,
    signature,
    digest,
    checkSignature (publicKey: RsaId): boolean {
      const verifier = crypto.createVerify('RSA-SHA256');
      // // verifier.update(Buffer.concat([RsaCrossCertPrefix, signedPortion]));
      verifier.update(RsaCrossCertPrefix);
      verifier.update(signedPortion);
      verifier.end();
      // console.log({
      //   digest: digest.toString('hex'),
      //   signature: signature.toString('hex'),
      //   publicKey: publicKey.export({ type: 'spki', format: 'der' }).toString('hex')
      // })
      return verifier.verify(publicKey, signature)
      // need to verify digest not signedPortion
      // return crypto.verify(null, digest, publicKey, signature)
      // forge.pki.rsa.setPublicKey(publicKey);
      // const asn1Obj = forge.asn1.fromDer(_publicKey.export({ type: 'pkcs1', format: 'der' }).toString('binary'))
      // const publicKey = forge.pki.publicKeyFromAsn1(asn1Obj)
      // return publicKey.verify(digest.toString('binary'), signature.toString('binary'));
    }
  }
}

const hoursToMs = (hours: number): number => hours * (60 * 60 * 1000);

function verifyTimeliness(expirationHours: number, now: number, clockSkewMs: number = 0) {
  const expirationMs = hoursToMs(expirationHours);
  const expiredByMs = now - expirationMs;
  if (expiredByMs > clockSkewMs) {
    throw new Error(`Certificate expired by ${expiredByMs}ms`)
  }
}

function keysMatch (keyA: Buffer, keyB: Buffer): boolean {
  return keyA === keyB || Buffer.prototype.equals.call(keyA, keyB)
}

export function logCerts (certsCell) {
  const { certs } = certsCell;
  console.log('CERTS: got certs');
  for (const { type, body } of certs) {
    console.log(`  #${type} ${getCertDescription(type)}`)
    if ([CertTypes.IDENTITY_V_SIGNING, CertTypes.SIGNING_V_TLS_CERT].includes(type)) {
      const cert = parseEd25519Certificate(body)
      console.log('    version:', cert.version)
      console.log('    type:', cert.type)
      console.log('    expirationHours:', cert.expirationHours)
      console.log('    keyType:', cert.keyType)
      console.log('    key:', cert.key.toString('hex'))
      console.log(`    extensions: (${cert.extensions.length})`)
      for (const { type, flags, data } of cert.extensions) {
        console.log(`      type=${type}`)
        console.log(`      flags=${flags}`)
        console.log(`      data=${data.toString('hex')}`)
      }
      console.log('    signature:', cert.signature.toString('hex'))
      console.log('    signedWith:', cert.signedWith?.toString('hex'))
      console.log('    text:', cert.text.toString('hex'))
    }
  }
}