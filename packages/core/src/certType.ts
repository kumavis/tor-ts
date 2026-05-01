// Tor certificate types (verified core).
//
// Numeric tag identifying what a certificate certifies. Used inside
// CERTS link cells (tor-spec.txt §4.2) and v3 hidden-service
// descriptors (rend-spec-v3.txt). Mirrors `CertTypes` from
// `packages/tor/src/cert.ts`.
//
// 10 codes (0x01..0x0A) currently defined; 0x00 and codes ≥ 0x0B are
// unused / reserved.

type CertType =
  | { kind: 'TLS_LINK_X509' } //           0x01 — obsolete
  | { kind: 'RSA_ID_X509' } //             0x02 — legacy
  | { kind: 'LINK_AUTH_X509' } //          0x03 — obsolete
  | { kind: 'IDENTITY_V_SIGNING' } //      0x04
  | { kind: 'SIGNING_V_TLS_CERT' } //      0x05
  | { kind: 'SIGNING_V_LINK_AUTH' } //     0x06
  | { kind: 'RSA_ID_V_IDENTITY' } //       0x07 — legacy
  | { kind: 'HS_BLINDED_ID_V_SIGNING' } // 0x08
  | { kind: 'HS_IP_V_SIGNING' } //         0x09
  | { kind: 'NTOR_CC_IDENTITY' }; //       0x0a

/** @total */
function certTypeCode(c: CertType): bigint {
  switch (c.kind) {
    case 'TLS_LINK_X509':
      return 1n;
    case 'RSA_ID_X509':
      return 2n;
    case 'LINK_AUTH_X509':
      return 3n;
    case 'IDENTITY_V_SIGNING':
      return 4n;
    case 'SIGNING_V_TLS_CERT':
      return 5n;
    case 'SIGNING_V_LINK_AUTH':
      return 6n;
    case 'RSA_ID_V_IDENTITY':
      return 7n;
    case 'HS_BLINDED_ID_V_SIGNING':
      return 8n;
    case 'HS_IP_V_SIGNING':
      return 9n;
    case 'NTOR_CC_IDENTITY':
      return 10n;
  }
}

/** @total */
function certTypeFromCode(code: bigint): CertType | null {
  if (code === 1n) return { kind: 'TLS_LINK_X509' };
  if (code === 2n) return { kind: 'RSA_ID_X509' };
  if (code === 3n) return { kind: 'LINK_AUTH_X509' };
  if (code === 4n) return { kind: 'IDENTITY_V_SIGNING' };
  if (code === 5n) return { kind: 'SIGNING_V_TLS_CERT' };
  if (code === 6n) return { kind: 'SIGNING_V_LINK_AUTH' };
  if (code === 7n) return { kind: 'RSA_ID_V_IDENTITY' };
  if (code === 8n) return { kind: 'HS_BLINDED_ID_V_SIGNING' };
  if (code === 9n) return { kind: 'HS_IP_V_SIGNING' };
  if (code === 10n) return { kind: 'NTOR_CC_IDENTITY' };
  return null;
}

// ----------------------------------------------------------------------------
// Classifiers.
// ----------------------------------------------------------------------------

/**
 * X.509-format cert types (codes 1..3) are obsolete / legacy. The
 * Ed25519-based formats (codes 4..10) are the modern set.
 */
/** @total */
function isLegacyX509Cert(c: CertType): boolean {
  switch (c.kind) {
    case 'TLS_LINK_X509':
      return true;
    case 'RSA_ID_X509':
      return true;
    case 'LINK_AUTH_X509':
      return true;

    case 'IDENTITY_V_SIGNING':
      return false;
    case 'SIGNING_V_TLS_CERT':
      return false;
    case 'SIGNING_V_LINK_AUTH':
      return false;
    case 'RSA_ID_V_IDENTITY':
      return false;
    case 'HS_BLINDED_ID_V_SIGNING':
      return false;
    case 'HS_IP_V_SIGNING':
      return false;
    case 'NTOR_CC_IDENTITY':
      return false;
  }
}

/**
 * Hidden-service-specific cert types (codes 0x08, 0x09).
 */
/** @total */
function isHiddenServiceCert(c: CertType): boolean {
  switch (c.kind) {
    case 'HS_BLINDED_ID_V_SIGNING':
      return true;
    case 'HS_IP_V_SIGNING':
      return true;

    case 'TLS_LINK_X509':
      return false;
    case 'RSA_ID_X509':
      return false;
    case 'LINK_AUTH_X509':
      return false;
    case 'IDENTITY_V_SIGNING':
      return false;
    case 'SIGNING_V_TLS_CERT':
      return false;
    case 'SIGNING_V_LINK_AUTH':
      return false;
    case 'RSA_ID_V_IDENTITY':
      return false;
    case 'NTOR_CC_IDENTITY':
      return false;
  }
}
