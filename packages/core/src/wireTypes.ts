// Small Tor wire-format type vocabularies (verified core).
//
// Each of these is a discriminated union with a numeric wire code,
// mirroring an `as const` table in `packages/tor/src/messaging.ts`.
// Same shape as `messageCellType.ts` and `relayCommand.ts`: code-to-DU,
// DU-to-code, and a round-trip theorem in Spec/WireTypes.lean.
//
// Three vocabularies live in this one file because each is tiny:
//
//   * AddressTypes      - IP family discriminator used in NETINFO and
//                         RELAY_BEGIN cells (tor-spec.txt §6.2)
//   * LinkSpecifierTypes - link-spec format codes used inside EXTEND2
//                         (tor-spec.txt §5.1.2)
//   * HandshakeTypes    - circuit handshake variant used in CREATE2
//                         (tor-spec.txt §5.1.4)

// ============================================================================
// AddressTypes (tor-spec.txt §6.2 / RELAY_RESOLVED §6.4)
// ============================================================================

type AddressType = { kind: 'IPv4' } | { kind: 'IPv6' };

/** @total */
function addressTypeCode(a: AddressType): bigint {
  switch (a.kind) {
    case 'IPv4':
      return 4n;
    case 'IPv6':
      return 6n;
  }
}

/** @total */
function addressTypeFromCode(code: bigint): AddressType | null {
  if (code === 4n) return { kind: 'IPv4' };
  if (code === 6n) return { kind: 'IPv6' };
  return null;
}

// ============================================================================
// LinkSpecifierTypes (tor-spec.txt §5.1.2; used inside EXTEND2 cells)
// ============================================================================

type LinkSpecifierType =
  | { kind: 'TlsOverTcpIPv4' } // 0
  | { kind: 'TlsOverTcpIPv6' } // 1
  | { kind: 'LegacyId' } //       2
  | { kind: 'Ed25519Id' }; //     3

/** @total */
function linkSpecifierTypeCode(t: LinkSpecifierType): bigint {
  switch (t.kind) {
    case 'TlsOverTcpIPv4':
      return 0n;
    case 'TlsOverTcpIPv6':
      return 1n;
    case 'LegacyId':
      return 2n;
    case 'Ed25519Id':
      return 3n;
  }
}

/** @total */
function linkSpecifierTypeFromCode(code: bigint): LinkSpecifierType | null {
  if (code === 0n) return { kind: 'TlsOverTcpIPv4' };
  if (code === 1n) return { kind: 'TlsOverTcpIPv6' };
  if (code === 2n) return { kind: 'LegacyId' };
  if (code === 3n) return { kind: 'Ed25519Id' };
  return null;
}

// ============================================================================
// HandshakeTypes (tor-spec.txt §5.1.4)
// ============================================================================
//
// TAP and NTOR are the two surviving handshake types. FAST (code 1)
// was removed for current protocol versions; the `tor-ts` source
// likewise tracks only TAP and NTOR.

type HandshakeType = { kind: 'TAP' } | { kind: 'NTOR' };

/** @total */
function handshakeTypeCode(h: HandshakeType): bigint {
  switch (h.kind) {
    case 'TAP':
      return 0n;
    case 'NTOR':
      return 2n;
  }
}

/** @total */
function handshakeTypeFromCode(code: bigint): HandshakeType | null {
  if (code === 0n) return { kind: 'TAP' };
  if (code === 2n) return { kind: 'NTOR' };
  return null;
}
