// Tor message-cell types (verified core).
//
// A Tor link-layer message cell carries one command byte that
// determines the rest of the wire format (and crucially, whether the
// cell has a fixed 514-byte body or a variable-length body with an
// explicit length prefix). These are the outermost wire types — every
// link-layer byte that arrives ultimately gets dispatched on this
// command.
//
// Spec source: tor-spec.txt §3 (cells), §4 (negotiating versions). The
// existing definitions in `packages/tor/src/messaging.ts` are mirrored
// here as a discriminated union.
//
// Variable-length cells per tor-spec.txt §3 (line 80 of messaging.ts):
//
//     "On a version 3 or higher connection, variable-length cells are
//     indicated by a command byte equal to 7 ("VERSIONS"), or greater
//     than or equal to 128."
//
// That predicate is captured here as `isVariableLengthCell`, with a
// theorem in Spec/MessageCellType.lean characterizing exactly which
// constructors return `true`.

type MessageCellType =
  // Fixed-length, low range (codes 0..6)
  | { kind: 'PADDING' } // 0
  | { kind: 'CREATE' } // 1
  | { kind: 'CREATED' } // 2
  | { kind: 'RELAY' } // 3
  | { kind: 'DESTROY' } // 4
  | { kind: 'CREATE_FAST' } // 5
  | { kind: 'CREATED_FAST' } // 6

  // Variable-length in the low range (the only one)
  | { kind: 'VERSIONS' } // 7

  // Fixed-length, mid range (codes 8..12)
  | { kind: 'NETINFO' } // 8
  | { kind: 'RELAY_EARLY' } // 9
  | { kind: 'CREATE2' } // 10
  | { kind: 'CREATED2' } // 11
  | { kind: 'PADDING_NEGOTIATE' } // 12

  // Variable-length, high range (codes 128..132)
  | { kind: 'VPADDING' } // 128
  | { kind: 'CERTS' } // 129
  | { kind: 'AUTH_CHALLENGE' } // 130
  | { kind: 'AUTHENTICATE' } // 131
  | { kind: 'AUTHORIZE' }; // 132

// ----------------------------------------------------------------------------
// Wire-format encoding: numeric code <-> DU.
// ----------------------------------------------------------------------------

/** @total */
function messageCellTypeCode(t: MessageCellType): bigint {
  switch (t.kind) {
    case 'PADDING':
      return 0n;
    case 'CREATE':
      return 1n;
    case 'CREATED':
      return 2n;
    case 'RELAY':
      return 3n;
    case 'DESTROY':
      return 4n;
    case 'CREATE_FAST':
      return 5n;
    case 'CREATED_FAST':
      return 6n;
    case 'VERSIONS':
      return 7n;
    case 'NETINFO':
      return 8n;
    case 'RELAY_EARLY':
      return 9n;
    case 'CREATE2':
      return 10n;
    case 'CREATED2':
      return 11n;
    case 'PADDING_NEGOTIATE':
      return 12n;
    case 'VPADDING':
      return 128n;
    case 'CERTS':
      return 129n;
    case 'AUTH_CHALLENGE':
      return 130n;
    case 'AUTHENTICATE':
      return 131n;
    case 'AUTHORIZE':
      return 132n;
  }
}

/** @total */
function messageCellTypeFromCode(code: bigint): MessageCellType | null {
  if (code === 0n) return { kind: 'PADDING' };
  if (code === 1n) return { kind: 'CREATE' };
  if (code === 2n) return { kind: 'CREATED' };
  if (code === 3n) return { kind: 'RELAY' };
  if (code === 4n) return { kind: 'DESTROY' };
  if (code === 5n) return { kind: 'CREATE_FAST' };
  if (code === 6n) return { kind: 'CREATED_FAST' };
  if (code === 7n) return { kind: 'VERSIONS' };
  if (code === 8n) return { kind: 'NETINFO' };
  if (code === 9n) return { kind: 'RELAY_EARLY' };
  if (code === 10n) return { kind: 'CREATE2' };
  if (code === 11n) return { kind: 'CREATED2' };
  if (code === 12n) return { kind: 'PADDING_NEGOTIATE' };
  if (code === 128n) return { kind: 'VPADDING' };
  if (code === 129n) return { kind: 'CERTS' };
  if (code === 130n) return { kind: 'AUTH_CHALLENGE' };
  if (code === 131n) return { kind: 'AUTHENTICATE' };
  if (code === 132n) return { kind: 'AUTHORIZE' };
  return null;
}

// ----------------------------------------------------------------------------
// Length-class predicate.
//
// Mirrors the runtime predicate at messaging.ts:82 — the parser uses this
// to decide whether to read a 2-byte length prefix or treat the rest as a
// fixed 514-byte payload.
// ----------------------------------------------------------------------------

/** @total */
function isVariableLengthCell(t: MessageCellType): boolean {
  switch (t.kind) {
    case 'VERSIONS':
      return true;
    case 'VPADDING':
      return true;
    case 'CERTS':
      return true;
    case 'AUTH_CHALLENGE':
      return true;
    case 'AUTHENTICATE':
      return true;
    case 'AUTHORIZE':
      return true;

    case 'PADDING':
      return false;
    case 'CREATE':
      return false;
    case 'CREATED':
      return false;
    case 'RELAY':
      return false;
    case 'DESTROY':
      return false;
    case 'CREATE_FAST':
      return false;
    case 'CREATED_FAST':
      return false;
    case 'NETINFO':
      return false;
    case 'RELAY_EARLY':
      return false;
    case 'CREATE2':
      return false;
    case 'CREATED2':
      return false;
    case 'PADDING_NEGOTIATE':
      return false;
  }
}
