// SMUX command codes (verified core).
//
// SMUX (skywind3000/smux v2, used by Snowflake's transport stack)
// frames each carry a 1-byte command in the second position of the
// 8-byte header. The five spec-defined commands are:
//
//   0  SYN  — open a new logical stream
//   1  FIN  — close a logical stream
//   2  PSH  — push data into a stream
//   3  NOP  — keep-alive
//   4  UPD  — flow-control window update (carries an 8-byte payload
//             of two uint32s: consumed and window)
//
// Mirrors `SMUX_CMD` from `packages/snowflake/src/smux/protocol.ts`.
// The full SMUX header decoder is a follow-up slice — it needs the
// LE byte-decode primitives (we have them in kcpHeader.ts) plus
// import support to compose them, which Thales 0.5 doesn't yet have
// (Issue 5).

type SmuxCmd =
  | { kind: 'SYN' } // 0
  | { kind: 'FIN' } // 1
  | { kind: 'PSH' } // 2
  | { kind: 'NOP' } // 3
  | { kind: 'UPD' }; // 4

/** SMUX framed header is 8 bytes: ver (1) + cmd (1) + len (2 LE) + sid (4 LE). */
const SMUX_HEADER_SIZE: bigint = 8n;

/** UPD command's payload is 8 bytes: two uint32s LE. */
const SMUX_UPD_PAYLOAD_SIZE: bigint = 8n;

// ----------------------------------------------------------------------------
// Wire-format encoding: numeric code <-> DU.
// ----------------------------------------------------------------------------

/** @total */
function smuxCmdCode(c: SmuxCmd): bigint {
  switch (c.kind) {
    case 'SYN':
      return 0n;
    case 'FIN':
      return 1n;
    case 'PSH':
      return 2n;
    case 'NOP':
      return 3n;
    case 'UPD':
      return 4n;
  }
}

/** @total */
function smuxCmdFromCode(code: bigint): SmuxCmd | null {
  if (code === 0n) return { kind: 'SYN' };
  if (code === 1n) return { kind: 'FIN' };
  if (code === 2n) return { kind: 'PSH' };
  if (code === 3n) return { kind: 'NOP' };
  if (code === 4n) return { kind: 'UPD' };
  return null;
}

// ----------------------------------------------------------------------------
// Classifiers.
// ----------------------------------------------------------------------------

/**
 * Whether the command carries a payload (PSH carries arbitrary data,
 * UPD carries the 8-byte flow-control update). The other commands
 * are header-only.
 */
/** @total */
function smuxCarriesPayload(c: SmuxCmd): boolean {
  switch (c.kind) {
    case 'PSH':
      return true;
    case 'UPD':
      return true;
    case 'SYN':
      return false;
    case 'FIN':
      return false;
    case 'NOP':
      return false;
  }
}

/**
 * Whether the command operates on stream lifecycle (SYN opens, FIN
 * closes). Useful for the seam to dispatch lifecycle events
 * separately from data/control events.
 */
/** @total */
function smuxIsStreamLifecycle(c: SmuxCmd): boolean {
  switch (c.kind) {
    case 'SYN':
      return true;
    case 'FIN':
      return true;
    case 'PSH':
      return false;
    case 'NOP':
      return false;
    case 'UPD':
      return false;
  }
}
