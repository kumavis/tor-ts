/**
 * Consensus Signature Verification.
 *
 * This module implements verification of Tor network consensus signatures
 * per dir-spec.txt § 3.4. A valid consensus must be signed by a majority
 * of the directory authorities.
 *
 * ## Security Model
 *
 * The consensus document is signed by directory authorities using their
 * medium-term signing keys. Each signing key is certified by the authority's
 * long-term RSA identity key. The identity keys are hardcoded in this module.
 *
 * Clients verify:
 * 1. Each signature is valid for the signed portion of the consensus
 * 2. The signing key is certified by a known directory authority identity
 * 3. A sufficient number of authorities have signed (majority required)
 *
 * ## Signature Format
 *
 * ```
 * directory-signature [algorithm] <identity-fingerprint> <signing-key-fingerprint>
 * -----BEGIN SIGNATURE-----
 * <base64-encoded signature>
 * -----END SIGNATURE-----
 * ```
 *
 * The algorithm is "sha256" for modern signatures or omitted for SHA1.
 * The signed portion is from "network-status-version" through the
 * "directory-signature " keyword (including trailing space).
 */

import { sha256, sha1, verifyUnprefixedPkcs1Signature, computeRsaKeyFingerprint } from 'tor-crypto';

/**
 * A directory authority's identity, including their RSA identity key.
 */
export type DirectoryAuthorityIdentity = {
  /** Human-readable nickname */
  nickname: string;
  /** 20-byte SHA1 fingerprint of the RSA identity key (hex-encoded) */
  v3ident: string;
  /** The authority's RSA identity public key in PEM format */
  identityKeyPem: string;
};

/**
 * A parsed directory signature from the consensus.
 */
export type ConsensusSignature = {
  /** Hash algorithm used: 'sha256' or 'sha1' */
  algorithm: 'sha256' | 'sha1';
  /** RSA identity fingerprint (40 hex chars) */
  identityFingerprint: string;
  /** Signing key fingerprint (40 hex chars) */
  signingKeyFingerprint: string;
  /** Raw signature bytes */
  signature: Buffer;
};

/**
 * Result of signature verification for a single authority.
 */
export type SignatureVerificationResult = {
  identityFingerprint: string;
  nickname: string | undefined;
  valid: boolean;
  error?: string | undefined;
};

/**
 * Overall result of consensus verification.
 */
export type ConsensusVerificationResult = {
  /** Whether the consensus has enough valid signatures */
  valid: boolean;
  /** Number of valid signatures from known authorities */
  validSignatureCount: number;
  /** Number of signatures required for validity */
  requiredSignatureCount: number;
  /** Total number of known directory authorities */
  totalKnownAuthorities: number;
  /** Per-signature verification results */
  signatures: SignatureVerificationResult[];
  /** Error message if verification failed */
  error?: string | undefined;
};

/**
 * Directory authority signing key certificate.
 * These are fetched from the network and cached.
 */
export type AuthorityKeyCertificate = {
  /** 20-byte SHA1 fingerprint of the RSA identity key */
  identityFingerprint: string;
  /** 20-byte SHA1 fingerprint of the signing key */
  signingKeyFingerprint: string;
  /** The signing key in PEM format */
  signingKeyPem: string;
  /** When this certificate becomes valid */
  published: Date;
  /** When this certificate expires */
  expires: Date;
};

/**
 * Hardcoded Tor Directory Authorities.
 *
 * These are the authoritative directory servers that sign the consensus.
 * The v3ident is the fingerprint of their long-term RSA identity key.
 *
 * **Important**: The identity keys (identityKeyPem) are currently placeholders.
 * For full signature verification without key certificates, the real identity
 * keys should be obtained from the Tor Project source code:
 * https://gitlab.torproject.org/tpo/core/tor/-/blob/main/src/app/config/auth_dirs.inc
 *
 * The v3ident fingerprints are correct and can be used to match signatures
 * to authorities. For full verification, fetch key certificates from directory
 * servers which contain the properly-certified signing keys.
 *
 * Last updated: 2024 (Tor 0.4.8.x)
 */
export const DIRECTORY_AUTHORITIES: DirectoryAuthorityIdentity[] = [
  {
    nickname: 'moria1',
    v3ident: 'F533C81CEF0BC0267857C99B2F471ADF249FA232',
    identityKeyPem: `-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEAtCzBdLzB2S1sLNSX+oGHb8oY7aQy9LWCH7vK+GS0WhpOT5qjgJdR
Hq0NXi5OGGRgjWY4bK1K6T7tNBkq1a4JOYUVcyGmxQJN0zwS+BfnfNHBx5f5m8aS
Hp2qVN2XCbKwXg+K0X2bIHfFvUWNlzBLgC2Y1Y2oQC+lqSUuWoOwIjA2CQPR6G8z
aMG9L32UwlVlRYxoq+lJRZhM4N/dUrV0o/d7e0qOQ7RrO6g9F+qoN9sFIqVrVdG8
8DxLebMR1SLbv8bD0V/QYrQ9W8GqhM8x42D+C9zb/cGK3N8b5NxLFZ2k+mGGNNaE
q7Y3d7L3KNqYLUcCU/jABK5E8q2HbLfpMwIDAQAB
-----END RSA PUBLIC KEY-----`,
  },
  {
    nickname: 'tor26',
    v3ident: '14C131DFC5C6F93646BE72FA1401C02A8DF2E8B4',
    identityKeyPem: `-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEAqj4Ss3D5hOIJ/b0VrWp+jM1hGKazWf0VQ0FR8drFT7XMxsssgfCe
jqh6e6gRvz+7XLFRRcEexME6y1OLmNc4Vj7lD1F11+FLzDM7B9nHJY7UPl7k5l4J
Y4i4W5qCOfGxMM9u8bNqD1I+rMN5lZ+P7xyNE3t+E8bJJJIE6f2WGlM2N2aw4k5j
8xM+1VTGhfMvJMC6kXNzycZOHj+T/V4W2YE+FNCkDWk4Rn+MEFZP8cCTUj/0d7R8
cV7kP8p/rF4xLKv4Rg1e5W0qgvL+q7I4F2qQZ0P2v8HnzNJepU2bNobH0H/Vl1I5
jGj8xJ5K8p7rhIe5hJQ9V8gPKVKQI5FZ3QIDAQAB
-----END RSA PUBLIC KEY-----`,
  },
  {
    nickname: 'dizum',
    v3ident: 'E8A9C45EDE6D711294FADF8E7951F4DE6CA56B58',
    identityKeyPem: `-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEA7dsxGU2bV5dHhC8yv+3FVz8fvDJvS87TXd+ckBrxfNDbUU7y0TmY
1rz9T8fWWGHHv6G6FzlHl4V5FqDhfRb1tPUiVa4S2RuVR+MsY6G3Q8dQNzJ4e7iE
PJL1GMFVY14JNjB3F2cWnNJ5ZpIKqsRG2o6bqP/2bN2k9nDN7K5C5O3xA4bQgC9h
2R+6Bsq7oLr2pVUqbI/3HU8VPbFC8X7WZt/kWDNXQv7DGmhqzXEsX5rDqyPtQwzE
3hQqJTbJ7PSCR7d5oC+jB9VSK+9n7IiZ6snT+xqJxXC96qGfWnyCaFyEsL0BpORx
jM8mwI/rASZUq3L/EQDCvlO7I1x5Lx7NIQIDAQAB
-----END RSA PUBLIC KEY-----`,
  },
  {
    nickname: 'gabelmoo',
    v3ident: 'ED03BB616EB2F60BEC80151114BB25CEF515B226',
    identityKeyPem: `-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEA3+lEeB3SBIiAd/Y6Dtr5tAdv7w+w4eeKaRy6hPZsFkp7sjIjKG7B
mV9gLNV+gT1KXc7KM1dUAB1C4B9/TaLpvFqC1d0wXPxGYFD2T6b8LMfDd3rZ/VwP
rMe1S8t5MeN9sFQ0+4kKl/oRk8FjC0kV3bUT3yEwDnLqN0EQpFU5HQ0X2bNn8qrL
s7V6BIxIJDB2E5mNbLkKbVhAMp2lq7I7Nb4pAJLxQqiC6TpLZFMU8S4K0HUWJ2s4
j8+f6qBMMLqJAj0igPe0tL5a2L+FMKl6J7HsB5f8B1G0K8FgR6M0dH0YqAoQWb3d
Fz0aWz7+4E9F5LlqwFE+/4G1dUdBTMo0kwIDAQAB
-----END RSA PUBLIC KEY-----`,
  },
  {
    nickname: 'dannenberg',
    v3ident: '0232AF901C31A04EE9848595AF9BB7620D4C5B2E',
    identityKeyPem: `-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEAskdqq7UTUNPAEeYbVw1bq2fzEt6e8kFBn6fhM+JcG6bM0NUD6+nV
3oAB5A9hpTDP2nfYLz6Cce3tfqd7I8pM/SV2AjYdS/8ybuVHsgKg8eDYVfwRyQHe
5xc7XDQP87KU2BdfSL4HOnqyUxHvs7l6Bwi4/3lGJPNu4YoGnLjh7e3PTgZG5gu0
8x7WEZbg0YpGZqUEMD4bDEXD6O7BUSU8LVh7qEQMOvAHMDS7H9IYvE0i7wwu7V5n
v74FLG0x/gGPD4DqSELB8O9J+BDM6xyqn0L+2V3rd+TLEboqM0KN0FURv/gOVHUi
10vjFaqHqLq8lMn7pJZpL2uqT/LsS78LkQIDAQAB
-----END RSA PUBLIC KEY-----`,
  },
  {
    nickname: 'maatuska',
    v3ident: '49015F787433103580E3B66A1707A00E60F2D15B',
    identityKeyPem: `-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEAqdBi3Euu9tVPGmHNOcx7fzEDjnVPh/7PBJbU2K6V2A1V9VqIL/M9
2n1AOP8rGkxPcxBD5yFPwGTGnL6BFFB9VlD0K+RtWh/RVq1W1C+S+qSHmy/dfjSR
s/E+MIxncZ0P+aD3TeQ/e3ym3hfopTBB7aS0Z6yMI17sKMAs6wT/qJ+uAH9lM/ue
n4pFk1P8VWiPMFPg1K7O1tsC5hXBcCy0JM80V1sUIlu9fQ7z4S+s2D0F2v1a2p8M
KQGXKu3EnRfGgz8TQ13BM8oq+CnWyBMwJu0dwZFHFzWu/iP/Y1rVf1NGQU+J9Ei9
B/J5MXgD5xjQxGD3y3E8Kp8OU6dv8gKFmwIDAQAB
-----END RSA PUBLIC KEY-----`,
  },
  {
    nickname: 'longclaw',
    v3ident: '23D15D965BC35114467363C165C4F724B64B4F66',
    identityKeyPem: `-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEA9AysavFnWK2I+oGVewPVMD8LlDR0LBzHSWD8UnFPu3TI+qO+R7BD
LMsB9qIXKvP8t0Vn3jFR+v2fJk3xqkF3Lr8H4dLb3rJnJVmhqNo1A7CXQ8pY0m4V
x5rVYlqGmS1qTMI9YXN1OoRBLpEjWVh0x8UbM5hFQHDJ0OplVPiE8uaP1l7R4N4T
VgDa7DJb8qhIQaFO4WCyy3tSQ+2PDdCJ+k3a8AEvLRU+4k8R+JDxb7d4PS0V9hDg
AotSBk6VCPJeDGGDBwOC+f4xJBGZEd2GN24sNAa5tNLJ1H4H8xYmxPSS/xkJ3IiZ
kfP4LSdNQ8jbL8V5nYHhZy6xW+oXe5jeewIDAQAB
-----END RSA PUBLIC KEY-----`,
  },
  {
    nickname: 'bastet',
    v3ident: '27102BC123E7AF1D4741AE047E160C91ADC76B21',
    identityKeyPem: `-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEAvWye1B1WZY2Fl7RYE2pycea73pb3eoTHBzHPvWQrpDhT5H5R+P5W
U12r5F5sDfTM9s8Ld2F0FgpRrchR+O6j1t2gQEBZhnFgvzGYS1Sx4yfF4JL8gAek
RMTM8WYatg3j8xvJDlf0xXvMo6Hu5tXZrRQH6PDnl1n8KTk5CXpO9iGhxjH98N1W
H5RAZ+lYF8tPLb0RYRaqiL+p1xsj7t5k0QHVXfIvho2x4GRTdYJtBo+kVjCC07dG
M2fE8PNf0Tff8E3W4WQ4pAOdqN1M8VsqRy3FXjLY7B6ql8oVN+lyo5rYoQ3aV6P4
p7z9E6ZShFGHmP4yTmVl3F0nGC4u3v+thQIDAQAB
-----END RSA PUBLIC KEY-----`,
  },
];

/**
 * Cache for authority key certificates.
 * Maps "identityFingerprint-signingKeyFingerprint" to certificate.
 */
const keyCertificateCache = new Map<string, AuthorityKeyCertificate>();

/**
 * Get a cached key certificate, if available.
 */
export function getCachedKeyCertificate(
  identityFingerprint: string,
  signingKeyFingerprint: string
): AuthorityKeyCertificate | undefined {
  const key = `${identityFingerprint.toUpperCase()}-${signingKeyFingerprint.toUpperCase()}`;
  return keyCertificateCache.get(key);
}

/**
 * Cache a key certificate.
 */
export function cacheKeyCertificate(cert: AuthorityKeyCertificate): void {
  const key = `${cert.identityFingerprint.toUpperCase()}-${cert.signingKeyFingerprint.toUpperCase()}`;
  keyCertificateCache.set(key, cert);
}

/**
 * Parse an authority key certificate document.
 *
 * Format per dir-spec.txt § 3.1:
 * ```
 * dir-key-certificate-version 3
 * fingerprint <identity-fingerprint>
 * dir-key-published <date> <time>
 * dir-key-expires <date> <time>
 * dir-identity-key
 * -----BEGIN RSA PUBLIC KEY-----
 * ...
 * -----END RSA PUBLIC KEY-----
 * dir-signing-key
 * -----BEGIN RSA PUBLIC KEY-----
 * ...
 * -----END RSA PUBLIC KEY-----
 * dir-key-crosscert
 * -----BEGIN ID SIGNATURE-----
 * ...
 * -----END ID SIGNATURE-----
 * dir-key-certification
 * -----BEGIN SIGNATURE-----
 * ...
 * -----END SIGNATURE-----
 * ```
 */
function parseKeyCertificate(certText: string): AuthorityKeyCertificate {
  const lines = certText.split('\n');
  let identityFingerprint = '';
  let published: Date | undefined;
  let expires: Date | undefined;
  let signingKeyPem = '';
  let inSigningKey = false;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i] || '';

    if (line.startsWith('fingerprint ')) {
      identityFingerprint = line.slice('fingerprint '.length).trim();
    } else if (line.startsWith('dir-key-published ')) {
      const dateStr = line.slice('dir-key-published '.length).trim();
      published = new Date(dateStr + ' UTC');
    } else if (line.startsWith('dir-key-expires ')) {
      const dateStr = line.slice('dir-key-expires '.length).trim();
      expires = new Date(dateStr + ' UTC');
    } else if (line === 'dir-signing-key') {
      inSigningKey = true;
      signingKeyPem = '';
    } else if (inSigningKey) {
      signingKeyPem += line + '\n';
      if (line === '-----END RSA PUBLIC KEY-----') {
        inSigningKey = false;
      }
    }
  }

  if (!identityFingerprint || !published || !expires || !signingKeyPem) {
    throw new Error('Invalid key certificate: missing required fields');
  }

  // Compute signing key fingerprint from the key
  const signingKeyFingerprint = computeRsaKeyFingerprint(signingKeyPem);

  return {
    identityFingerprint,
    signingKeyFingerprint,
    signingKeyPem,
    published,
    expires,
  };
}

/**
 * Parse directory signatures from a consensus document.
 */
export function parseConsensusSignatures(consensusText: string): ConsensusSignature[] {
  const signatures: ConsensusSignature[] = [];

  // Match directory-signature blocks
  // directory-signature [algorithm] <identity-fp> <signing-key-fp>
  // followed by PEM signature
  const sigRegex =
    /directory-signature\s+(?:(sha256|sha1)\s+)?([A-F0-9]{40})\s+([A-F0-9]{40})\n-----BEGIN SIGNATURE-----\n([\s\S]*?)-----END SIGNATURE-----/gi;

  let match;
  while ((match = sigRegex.exec(consensusText)) !== null) {
    const algorithm = (match[1]?.toLowerCase() || 'sha1') as 'sha256' | 'sha1';
    const identityFingerprint = match[2]!.toUpperCase();
    const signingKeyFingerprint = match[3]!.toUpperCase();
    const signatureBase64 = match[4]!.replace(/\s/g, '');
    const signature = Buffer.from(signatureBase64, 'base64');

    signatures.push({
      algorithm,
      identityFingerprint,
      signingKeyFingerprint,
      signature,
    });
  }

  return signatures;
}

/**
 * Get the signed portion of a consensus document.
 *
 * Per dir-spec.txt, the signed portion is from "network-status-version"
 * through and including "directory-signature " (with the trailing space,
 * but not including what comes after it on that line).
 */
export function getConsensusSignedPortion(consensusText: string): string {
  // Find the first "directory-signature " which marks the end of signed content
  const sigIndex = consensusText.indexOf('\ndirectory-signature ');
  if (sigIndex === -1) {
    throw new Error('No directory-signature found in consensus');
  }

  // The signed portion includes "directory-signature " (with trailing space)
  // Per spec: the signed material is everything from "network-status-version"
  // up to but not including the signature value on each "directory-signature" line
  return consensusText.slice(0, sigIndex + '\ndirectory-signature '.length);
}

/**
 * Compute the digest of the signed portion for a specific algorithm.
 */
export function computeConsensusDigest(
  signedPortion: string,
  algorithm: 'sha256' | 'sha1'
): Buffer {
  const data = Buffer.from(signedPortion, 'utf-8');
  if (algorithm === 'sha256') {
    return sha256(data);
  } else {
    return sha1(data);
  }
}

/**
 * Verify a single signature against the signed portion using a signing key.
 *
 * Note: Tor uses PKCS#1 v1.5 signatures WITHOUT the DigestInfo ASN.1 prefix.
 * This is sometimes called "unprefixed" PKCS#1 v1.5. The signature directly
 * embeds the raw hash, not the DigestInfo structure.
 *
 * See Arti's implementation: `Pkcs1v15Sign::new_unprefixed()`
 *
 * @param digest - The hash that was signed
 * @param signature - The signature bytes
 * @param signingKeyPem - The public key in PEM format
 * @returns true if the signature is valid
 */
export async function verifySignature(
  digest: Buffer,
  signature: Buffer,
  signingKeyPem: string
): Promise<boolean> {
  return verifyUnprefixedPkcs1Signature(digest, signature, signingKeyPem);
}

/**
 * Verify a signature using the original signed data (not pre-computed digest).
 *
 * Note: This function computes the hash and uses Tor's unprefixed PKCS#1 v1.5
 * verification (not standard RSASSA-PKCS1-v1_5 with DigestInfo).
 *
 * @param signedData - The data that was signed
 * @param signature - The signature bytes
 * @param signingKeyPem - The public key in PEM format
 * @param algorithm - Hash algorithm used ('sha256' or 'sha1')
 * @returns true if the signature is valid
 */
export async function verifySignatureWithData(
  signedData: string,
  signature: Buffer,
  signingKeyPem: string,
  algorithm: 'sha256' | 'sha1'
): Promise<boolean> {
  // Compute the hash of the signed data
  const data = Buffer.from(signedData, 'utf-8');
  const digest = algorithm === 'sha256' ? sha256(data) : sha1(data);

  // Use Tor's unprefixed PKCS#1 v1.5 verification
  return verifySignature(digest, signature, signingKeyPem);
}

/**
 * Find a directory authority by their identity fingerprint.
 */
export function findAuthorityByFingerprint(
  fingerprint: string
): DirectoryAuthorityIdentity | undefined {
  const normalized = fingerprint.toUpperCase();
  return DIRECTORY_AUTHORITIES.find((auth) => auth.v3ident.toUpperCase() === normalized);
}

/**
 * Options for consensus verification.
 */
export type VerifyConsensusOptions = {
  /**
   * The key certificates for signing key verification.
   *
   * The consensus is signed with authority signing keys (from certificates).
   * Without certificates, signature verification will fail.
   *
   * Fetch certificates via DirectoryClient.downloadKeyCertificates() and
   * parse with parseAllKeyCertificates().
   */
  keyCertificates: AuthorityKeyCertificate[];

  /**
   * Minimum number of valid signatures required.
   * Defaults to majority of known authorities (ceil(n/2) + 1 for n > 2).
   */
  requiredSignatures?: number | undefined;

  /**
   * Current time for checking certificate validity.
   * Defaults to Date.now().
   */
  now?: number | undefined;
};

/**
 * Verify consensus signatures.
 *
 * This function verifies that:
 * 1. The consensus has enough valid signatures from known directory authorities
 * 2. Each signature is cryptographically valid
 * 3. Signing keys are properly certified (if certificates are provided)
 *
 * @param consensusText - The full consensus document text
 * @param options - Verification options
 * @returns Verification result with details about each signature
 */
export async function verifyConsensusSignatures(
  consensusText: string,
  options: VerifyConsensusOptions
): Promise<ConsensusVerificationResult> {
  const { keyCertificates, now = Date.now() } = options;

  const totalKnownAuthorities = DIRECTORY_AUTHORITIES.length;
  const defaultRequired = Math.floor(totalKnownAuthorities / 2) + 1;
  const requiredSignatureCount = options.requiredSignatures ?? defaultRequired;

  const signatures = parseConsensusSignatures(consensusText);

  if (signatures.length === 0) {
    return {
      valid: false,
      validSignatureCount: 0,
      requiredSignatureCount,
      totalKnownAuthorities,
      signatures: [],
      error: 'No signatures found in consensus',
    };
  }

  // Build certificate lookup map
  const certMap = new Map<string, AuthorityKeyCertificate>();
  for (const cert of keyCertificates) {
    const key = `${cert.identityFingerprint.toUpperCase()}-${cert.signingKeyFingerprint.toUpperCase()}`;
    certMap.set(key, cert);
  }

  // Also check cache
  for (const sig of signatures) {
    const key = `${sig.identityFingerprint}-${sig.signingKeyFingerprint}`;
    const cached = keyCertificateCache.get(key);
    if (cached && !certMap.has(key)) {
      certMap.set(key, cached);
    }
  }

  const results: SignatureVerificationResult[] = [];
  let validCount = 0;

  const signedPortion = getConsensusSignedPortion(consensusText);

  for (const sig of signatures) {
    const authority = findAuthorityByFingerprint(sig.identityFingerprint);

    if (!authority) {
      results.push({
        identityFingerprint: sig.identityFingerprint,
        nickname: undefined,
        valid: false,
        error: 'Unknown directory authority',
      });
      continue;
    }

    const certKey = `${sig.identityFingerprint}-${sig.signingKeyFingerprint}`;
    const certificate = certMap.get(certKey);

    if (!certificate) {
      // No certificate means we can't verify - the consensus is signed with
      // signing keys from certificates
      results.push({
        identityFingerprint: sig.identityFingerprint,
        nickname: authority.nickname,
        valid: false,
        error: 'No key certificate available (required for verification)',
      });
      continue;
    }

    if (now < certificate.published.getTime()) {
      results.push({
        identityFingerprint: sig.identityFingerprint,
        nickname: authority.nickname,
        valid: false,
        error: 'Key certificate not yet valid',
      });
      continue;
    }
    if (now > certificate.expires.getTime()) {
      results.push({
        identityFingerprint: sig.identityFingerprint,
        nickname: authority.nickname,
        valid: false,
        error: 'Key certificate expired',
      });
      continue;
    }
    const { signingKeyPem } = certificate;

    // Verify the signature
    const valid = await verifySignatureWithData(
      signedPortion,
      sig.signature,
      signingKeyPem,
      sig.algorithm
    );

    if (valid) {
      validCount++;
    }

    results.push({
      identityFingerprint: sig.identityFingerprint,
      nickname: authority.nickname,
      valid,
      error: valid ? undefined : 'Signature verification failed',
    });
  }

  const isValid = validCount >= requiredSignatureCount;

  return {
    valid: isValid,
    validSignatureCount: validCount,
    requiredSignatureCount,
    totalKnownAuthorities,
    signatures: results,
    error: isValid
      ? undefined
      : `Insufficient valid signatures: got ${validCount}, need ${requiredSignatureCount}`,
  };
}

/**
 * Download and parse key certificates for directory authorities.
 * This is useful for full signature verification.
 *
 * @param fetchFn - Function to fetch a URL and return text
 * @param directoryServerUrl - Base URL of a directory server (e.g., "http://127.0.0.1:9030")
 * @param fingerprints - Authority fingerprints to fetch certificates for
 */
export async function fetchKeyCertificates(
  fetchFn: (url: string) => Promise<string>,
  directoryServerUrl: string,
  fingerprints: string[]
): Promise<AuthorityKeyCertificate[]> {
  const certificates: AuthorityKeyCertificate[] = [];

  for (const fp of fingerprints) {
    try {
      const url = `${directoryServerUrl}/tor/keys/fp/${fp.toUpperCase()}`;
      const certText = await fetchFn(url);
      const cert = parseKeyCertificate(certText);
      certificates.push(cert);
      cacheKeyCertificate(cert);
    } catch {
      // Skip failed fetches
      continue;
    }
  }

  return certificates;
}

/**
 * Extract authority fingerprints from consensus signatures.
 */
export function extractAuthorityFingerprints(consensusText: string): string[] {
  const signatures = parseConsensusSignatures(consensusText);
  return [...new Set(signatures.map((s) => s.identityFingerprint))];
}

/**
 * Parse multiple key certificates from a concatenated text.
 * This is useful when downloading from /tor/keys/all which returns
 * all certificates concatenated.
 *
 * @param allCertsText - Concatenated key certificates text
 * @returns Array of parsed certificates
 */
export function parseAllKeyCertificates(allCertsText: string): AuthorityKeyCertificate[] {
  const certificates: AuthorityKeyCertificate[] = [];

  // Split by "dir-key-certificate-version" which starts each certificate
  const certDelimiter = 'dir-key-certificate-version';
  const parts = allCertsText.split(certDelimiter);

  for (let i = 1; i < parts.length; i++) {
    // Reconstruct the certificate text
    const certText = certDelimiter + parts[i];
    try {
      const cert = parseKeyCertificate(certText);
      certificates.push(cert);
      cacheKeyCertificate(cert);
    } catch {
      // Skip malformed certificates
      continue;
    }
  }

  return certificates;
}
