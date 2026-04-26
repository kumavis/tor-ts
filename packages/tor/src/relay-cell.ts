import { bufferFromUint } from './util.ts';
import type { LinkSpecifier } from './messaging.ts';

// The relay commands are:

// 1 -- RELAY_BEGIN     [forward]
// 2 -- RELAY_DATA      [forward or backward]
// 3 -- RELAY_END       [forward or backward]
// 4 -- RELAY_CONNECTED [backward]
// 5 -- RELAY_SENDME    [forward or backward] [sometimes control]
// 6 -- RELAY_EXTEND    [forward]             [control]
// 7 -- RELAY_EXTENDED  [backward]            [control]
// 8 -- RELAY_TRUNCATE  [forward]             [control]
// 9 -- RELAY_TRUNCATED [backward]            [control]
// 10 -- RELAY_DROP      [forward or backward] [control]
// 11 -- RELAY_RESOLVE   [forward]
// 12 -- RELAY_RESOLVED  [backward]
// 13 -- RELAY_BEGIN_DIR [forward]
// 14 -- RELAY_EXTEND2   [forward]             [control]
// 15 -- RELAY_EXTENDED2 [backward]            [control]

// 16..18 -- Reserved for UDP; Not yet in use, see prop339.

// 19..22 -- Reserved for Conflux, see prop329.

// 32..40 -- Used for hidden services; see rend-spec-{v2,v3}.txt.

// 41..42 -- Used for circuit padding; see Section 3 of padding-spec.txt.

// Used for flow control; see Section 4 of prop324.
// 43 -- XON             [forward or backward]
// 44 -- XOFF            [forward or backward]

export const RelayCell = {
  BEGIN: 1,
  DATA: 2,
  END: 3,
  CONNECTED: 4,
  SENDME: 5,
  EXTEND: 6,
  EXTENDED: 7,
  TRUNCATE: 8,
  TRUNCATED: 9,
  DROP: 10,
  RESOLVE: 11,
  RESOLVED: 12,
  BEGIN_DIR: 13,
  EXTEND2: 14,
  EXTENDED2: 15,

  // Hidden service relay commands (rend-spec-v3.txt)
  ESTABLISH_INTRO: 32,
  ESTABLISH_RENDEZVOUS: 33,
  INTRODUCE1: 34,
  INTRODUCE2: 35,
  RENDEZVOUS1: 36,
  RENDEZVOUS2: 37,
  INTRO_ESTABLISHED: 38,
  RENDEZVOUS_ESTABLISHED: 39,
  INTRODUCE_ACK: 40,

  // Circuit padding (padding-spec.txt section 3)
  PADDING_NEGOTIATE: 41,
  PADDING_NEGOTIATED: 42,

  // Stream-level flow control (prop324)
  XON: 43,
  XOFF: 44,
} as const;
// eslint-disable-next-line no-redeclare
export type RelayCell = (typeof RelayCell)[keyof typeof RelayCell];

const relayCellNames: Record<number, string> = {
  [RelayCell.BEGIN]: 'BEGIN',
  [RelayCell.DATA]: 'DATA',
  [RelayCell.END]: 'END',
  [RelayCell.CONNECTED]: 'CONNECTED',
  [RelayCell.SENDME]: 'SENDME',
  [RelayCell.EXTEND]: 'EXTEND',
  [RelayCell.EXTENDED]: 'EXTENDED',
  [RelayCell.TRUNCATE]: 'TRUNCATE',
  [RelayCell.TRUNCATED]: 'TRUNCATED',
  [RelayCell.DROP]: 'DROP',
  [RelayCell.RESOLVE]: 'RESOLVE',
  [RelayCell.RESOLVED]: 'RESOLVED',
  [RelayCell.BEGIN_DIR]: 'BEGIN_DIR',
  [RelayCell.EXTEND2]: 'EXTEND2',
  [RelayCell.EXTENDED2]: 'EXTENDED2',

  [RelayCell.ESTABLISH_INTRO]: 'ESTABLISH_INTRO',
  [RelayCell.ESTABLISH_RENDEZVOUS]: 'ESTABLISH_RENDEZVOUS',
  [RelayCell.INTRODUCE1]: 'INTRODUCE1',
  [RelayCell.INTRODUCE2]: 'INTRODUCE2',
  [RelayCell.RENDEZVOUS1]: 'RENDEZVOUS1',
  [RelayCell.RENDEZVOUS2]: 'RENDEZVOUS2',
  [RelayCell.INTRO_ESTABLISHED]: 'INTRO_ESTABLISHED',
  [RelayCell.RENDEZVOUS_ESTABLISHED]: 'RENDEZVOUS_ESTABLISHED',
  [RelayCell.INTRODUCE_ACK]: 'INTRODUCE_ACK',
  [RelayCell.PADDING_NEGOTIATE]: 'PADDING_NEGOTIATE',
  [RelayCell.PADDING_NEGOTIATED]: 'PADDING_NEGOTIATED',
  [RelayCell.XON]: 'XON',
  [RelayCell.XOFF]: 'XOFF',
};

/**
 * Get the name of a relay cell command by its numeric code.
 */
export function getRelayCellName(code: number): string {
  return relayCellNames[code] ?? `UNKNOWN(${code})`;
}

export function serializeExtend2({
  linkSpecifiers,
  handshake,
}: {
  linkSpecifiers: Array<LinkSpecifier>;
  handshake: { type: number; data: Buffer };
}): Buffer {
  // NSPEC      (Number of link specifiers)     [1 byte]
  //   NSPEC times:
  //     LSTYPE (Link specifier type)           [1 byte]
  //     LSLEN  (Link specifier length)         [1 byte]
  //     LSPEC  (Link specifier)                [LSLEN bytes]
  // HTYPE      (Client Handshake Type)         [2 bytes]
  // HLEN       (Client Handshake Data Len)     [2 bytes]
  // HDATA      (Client Handshake Data)         [HLEN bytes]
  const payloadBytes = Buffer.concat([
    bufferFromUint(1, linkSpecifiers.length),
    Buffer.concat(
      linkSpecifiers.map((linkSpecifier) => {
        return Buffer.concat([
          bufferFromUint(1, linkSpecifier.type),
          bufferFromUint(1, linkSpecifier.data.length),
          linkSpecifier.data,
        ]);
      })
    ),
    bufferFromUint(2, handshake.type),
    bufferFromUint(2, handshake.data.length),
    handshake.data,
  ]);
  return payloadBytes;
}

// RELAY_END Reason

// 1 -- REASON_MISC           (catch-all for unlisted reasons)
// 2 -- REASON_RESOLVEFAILED  (couldn't look up hostname)
// 3 -- REASON_CONNECTREFUSED (remote host refused connection) [*]
// 4 -- REASON_EXITPOLICY     (OR refuses to connect to host or port)
// 5 -- REASON_DESTROY        (Circuit is being destroyed)
// 6 -- REASON_DONE           (Anonymized TCP connection was closed)
// 7 -- REASON_TIMEOUT        (Connection timed out, or OR timed out
//                             while connecting)
// 8 -- REASON_NOROUTE        (Routing error while attempting to
//                             contact destination)
// 9 -- REASON_HIBERNATING    (OR is temporarily hibernating)
// 10 -- REASON_INTERNAL       (Internal error at the OR)
// 11 -- REASON_RESOURCELIMIT  (OR has no resources to fulfill request)
// 12 -- REASON_CONNRESET      (Connection was unexpectedly reset)
// 13 -- REASON_TORPROTOCOL    (Sent when closing connection because of
//                             Tor protocol violations.)
// 14 -- REASON_NOTDIRECTORY   (Client sent RELAY_BEGIN_DIR to a
//                             non-directory relay.)

export const RelayEndReasons = {
  REASON_MISC: 1,
  REASON_RESOLVEFAILED: 2,
  REASON_CONNECTREFUSED: 3,
  REASON_EXITPOLICY: 4,
  REASON_DESTROY: 5,
  REASON_DONE: 6,
  REASON_TIMEOUT: 7,
  REASON_NOROUTE: 8,
  REASON_HIBERNATING: 9,
  REASON_INTERNAL: 10,
  REASON_RESOURCELIMIT: 11,
  REASON_CONNRESET: 12,
  REASON_TORPROTOCOL: 13,
  REASON_NOTDIRECTORY: 14,
} as const;
// eslint-disable-next-line no-redeclare
export type RelayEndReasons = (typeof RelayEndReasons)[keyof typeof RelayEndReasons];

export const RelayEndReasonNames: Record<number, string> = {
  [RelayEndReasons.REASON_MISC]: 'REASON_MISC',
  [RelayEndReasons.REASON_RESOLVEFAILED]: 'REASON_RESOLVEFAILED',
  [RelayEndReasons.REASON_CONNECTREFUSED]: 'REASON_CONNECTREFUSED',
  [RelayEndReasons.REASON_EXITPOLICY]: 'REASON_EXITPOLICY',
  [RelayEndReasons.REASON_DESTROY]: 'REASON_DESTROY',
  [RelayEndReasons.REASON_DONE]: 'REASON_DONE',
  [RelayEndReasons.REASON_TIMEOUT]: 'REASON_TIMEOUT',
  [RelayEndReasons.REASON_NOROUTE]: 'REASON_NOROUTE',
  [RelayEndReasons.REASON_HIBERNATING]: 'REASON_HIBERNATING',
  [RelayEndReasons.REASON_INTERNAL]: 'REASON_INTERNAL',
  [RelayEndReasons.REASON_RESOURCELIMIT]: 'REASON_RESOURCELIMIT',
  [RelayEndReasons.REASON_CONNRESET]: 'REASON_CONNRESET',
  [RelayEndReasons.REASON_TORPROTOCOL]: 'REASON_TORPROTOCOL',
  [RelayEndReasons.REASON_NOTDIRECTORY]: 'REASON_NOTDIRECTORY',
};

/**
 * Stream retry behavior based on RELAY_END reason.
 * Per tor-spec path-spec/attaching-streams-to-circuits.md
 *
 * 'retry_circuit' = try a new circuit (transient relay issue)
 * 'retry_exit' = try a different exit (exit policy or route issue)
 * 'no_retry' = don't retry (permanent error or normal close)
 */
export type StreamRetryBehavior = 'retry_circuit' | 'retry_exit' | 'no_retry';

/**
 * Determine retry behavior for a RELAY_END reason.
 * Based on tor-spec path-spec/handling-failure.md
 */
export function getStreamRetryBehavior(reason: number): StreamRetryBehavior {
  switch (reason) {
    case RelayEndReasons.REASON_RESOLVEFAILED:
    case RelayEndReasons.REASON_EXITPOLICY:
    case RelayEndReasons.REASON_NOROUTE:
    case RelayEndReasons.REASON_HIBERNATING:
      // Exit-specific issues - try a different exit
      return 'retry_exit';

    case RelayEndReasons.REASON_TIMEOUT:
    case RelayEndReasons.REASON_RESOURCELIMIT:
      // Transient issues - try a new circuit
      return 'retry_circuit';

    case RelayEndReasons.REASON_CONNECTREFUSED:
    case RelayEndReasons.REASON_DESTROY:
    case RelayEndReasons.REASON_DONE:
    case RelayEndReasons.REASON_INTERNAL:
    case RelayEndReasons.REASON_TORPROTOCOL:
    case RelayEndReasons.REASON_NOTDIRECTORY:
      // Permanent errors or normal close - don't retry
      return 'no_retry';

    case RelayEndReasons.REASON_MISC:
    case RelayEndReasons.REASON_CONNRESET:
    default:
      // Ambiguous - could be transient, try circuit retry once
      return 'retry_circuit';
  }
}

/**
 * Check if a RELAY_END reason indicates the stream should be retried.
 */
export function isRetryableEndReason(reason: number): boolean {
  return getStreamRetryBehavior(reason) !== 'no_retry';
}

/**
 * Error thrown / surfaced when the exit returns RELAY_END with a non-DONE
 * reason. The numeric `reason` and human-readable `reasonName` are exposed
 * as own properties so callers can map them to a higher-level status (e.g.
 * SOCKS reply codes) without having to pattern-match the message string.
 *
 * The message format is preserved across releases so any
 * existing log/scrape consumers stay working.
 */
export class RelayEndError extends Error {
  readonly reason: number;
  readonly reasonName: string;
  readonly payloadHex: string;

  constructor(reason: number, payloadHex: string) {
    const reasonName = RelayEndReasonNames[reason] ?? `UNKNOWN_REASON_${reason}`;
    super(`stream ended: ${reasonName} (${reason}) payload=0x${payloadHex}`);
    this.name = 'RelayEndError';
    this.reason = reason;
    this.reasonName = reasonName;
    this.payloadHex = payloadHex;
  }
}

// =============================================================================
// RELAY_RESOLVE / RELAY_RESOLVED  (tor-spec 6.4)
// =============================================================================
//
// The exit's response to RELAY_RESOLVE is a sequence of records:
//
//   Type   [1 octet]
//   Length [1 octet]
//   Value  [Length octets]
//   TTL    [4 octets]
//
// Type values: 0x00 hostname, 0x04 IPv4, 0x06 IPv6, 0xF0 transient error,
// 0xF1 permanent error.

/** Type byte values inside a RELAY_RESOLVED record (tor-spec 6.4). */
export const RelayResolvedType = {
  Hostname: 0x00,
  IPv4: 0x04,
  IPv6: 0x06,
  ErrorTransient: 0xf0,
  ErrorPermanent: 0xf1,
} as const;
// eslint-disable-next-line no-redeclare
export type RelayResolvedType = (typeof RelayResolvedType)[keyof typeof RelayResolvedType];

/** A single record from a RELAY_RESOLVED payload. */
export interface RelayResolvedRecord {
  /** Record type byte. May be one of {@link RelayResolvedType}, or unknown. */
  type: number;
  /**
   * Record value. For IPv4: 4 bytes; for IPv6: 16 bytes; for Hostname/Error:
   * the raw bytes (caller decodes as needed).
   */
  value: Buffer;
  /** TTL in seconds (32-bit big-endian on the wire). */
  ttl: number;
}

/**
 * Parse a RELAY_RESOLVED payload into its record list. Records that don't
 * have all of {Type, Length, Value, TTL} bytes are dropped silently; that's
 * what c-tor does too (`connection_edge.c::connection_edge_process_resolved_cell`)
 * since a partial cell is the spec's signal that no more records follow.
 */
export function parseRelayResolvedPayload(data: Buffer): RelayResolvedRecord[] {
  const records: RelayResolvedRecord[] = [];
  let offset = 0;
  while (offset + 2 <= data.length) {
    const type = data.readUInt8(offset);
    const length = data.readUInt8(offset + 1);
    // Need {Type, Length, Value, TTL=4} = length + 6 bytes total.
    if (offset + 2 + length + 4 > data.length) break;
    const value = Buffer.from(data.subarray(offset + 2, offset + 2 + length));
    const ttl = data.readUInt32BE(offset + 2 + length);
    records.push({ type, value, ttl });
    offset += 2 + length + 4;
  }
  return records;
}

/** Convenience: format a hostname for forward DNS over RELAY_RESOLVE. */
export function buildRelayResolvePayload(hostname: string): Buffer {
  // tor-spec: ADDRPORT is a NUL-terminated ASCII string, but RESOLVE has no
  // port — just the NUL-terminated hostname.
  return Buffer.concat([Buffer.from(hostname, 'ascii'), Buffer.from([0x00])]);
}

/**
 * Convert an IPv4 dotted-quad to its `in-addr.arpa` reverse-DNS form, which
 * is what c-tor and Arti also send on RELAY_RESOLVE for PTR queries.
 */
export function ipv4ToInAddrArpa(addr: string): string {
  const parts = addr.split('.').map((p) => parseInt(p, 10));
  if (parts.length !== 4 || parts.some((p) => !Number.isInteger(p) || p < 0 || p > 255)) {
    throw new Error(`Not a dotted-quad IPv4 address: ${addr}`);
  }
  return `${parts[3]}.${parts[2]}.${parts[1]}.${parts[0]}.in-addr.arpa`;
}

/**
 * Parse any RFC 4291 IPv6 string (with optional brackets, `::`
 * zero-compression, or a dotted-quad tail) into its 16-byte network
 * representation. Useful both for building `ip6.arpa` reverse names and
 * for putting an IPv6 bound-address on the SOCKS5 reply wire.
 */
export function ipv6StringToBytes(addr: string): Buffer {
  // Strip optional brackets and a zone-id suffix (`%eth0`); zone-ids
  // don't have routing meaning over Tor.
  const stripped = addr.replace(/^\[/, '').replace(/\]$/, '').split('%')[0] ?? addr;

  let head = stripped;
  let tail4: [number, number, number, number] | undefined;
  if (head.includes('.')) {
    const lastColon = head.lastIndexOf(':');
    const v4 = head.slice(lastColon + 1);
    const parts = v4.split('.').map((p) => parseInt(p, 10));
    if (parts.length !== 4 || parts.some((p) => !Number.isInteger(p) || p < 0 || p > 255)) {
      throw new Error(`Not a valid IPv6 address: ${addr}`);
    }
    tail4 = parts as [number, number, number, number];
    head = head.slice(0, lastColon);
  }
  const sides = head.split('::');
  if (sides.length > 2) throw new Error(`Not a valid IPv6 address: ${addr}`);
  const left = sides[0] ? sides[0].split(':') : [];
  const right = sides.length === 2 && sides[1] ? sides[1].split(':') : [];
  const groupsAvailable = 8 - (tail4 ? 2 : 0);
  const fillCount = groupsAvailable - left.length - right.length;
  if (sides.length === 2) {
    if (fillCount < 0) throw new Error(`Not a valid IPv6 address: ${addr}`);
  } else {
    if (left.length !== groupsAvailable) {
      throw new Error(`Not a valid IPv6 address: ${addr}`);
    }
  }
  // Each non-compressed hextet must be 1-4 hex digits. The `sides[0] ?` /
  // `sides[1] ?` ternaries above already collapse the empty boundary
  // strings produced by `::`-compression to `[]`, so any empty group we
  // see here came from a trailing/double-colon outside `::` (e.g.
  // `1:2:3:4:5:6:7:`) and is invalid per RFC 4291.
  const parseHextet = (g: string): number => {
    if (!/^[0-9A-Fa-f]{1,4}$/.test(g)) {
      throw new Error(`Not a valid IPv6 address: ${addr}`);
    }
    return parseInt(g, 16);
  };
  const groups: number[] = [];
  for (const g of left) groups.push(parseHextet(g));
  for (let i = 0; i < fillCount; i++) groups.push(0);
  for (const g of right) groups.push(parseHextet(g));
  if (tail4) {
    groups.push((tail4[0] << 8) | tail4[1]);
    groups.push((tail4[2] << 8) | tail4[3]);
  }
  if (groups.length !== 8) {
    throw new Error(`Not a valid IPv6 address: ${addr}`);
  }
  const buf = Buffer.alloc(16);
  for (let i = 0; i < 8; i++) {
    buf.writeUInt16BE(groups[i]!, i * 2);
  }
  return buf;
}

/**
 * Convert an IPv6 address (any RFC 4291 form Node accepts) to its
 * `ip6.arpa` reverse-DNS form. Colons/zero-compression/brackets are
 * normalized via the standard parsing rules.
 */
export function ipv6ToIp6Arpa(addr: string): string {
  const bytes = ipv6StringToBytes(addr);
  const nibbles: string[] = [];
  for (let i = 0; i < 16; i++) {
    const b = bytes.readUInt8(i);
    nibbles.push(((b >> 4) & 0xf).toString(16));
    nibbles.push((b & 0xf).toString(16));
  }
  return nibbles.reverse().join('.') + '.ip6.arpa';
}

/**
 * Format the bytes inside a RELAY_RESOLVED `IPv4` record as the customary
 * dotted-quad string. Throws if the value isn't exactly 4 bytes.
 */
export function formatResolvedIPv4(value: Buffer): string {
  if (value.length !== 4) {
    throw new Error(`RELAY_RESOLVED IPv4 record must be 4 bytes, got ${value.length}`);
  }
  return `${value.readUInt8(0)}.${value.readUInt8(1)}.${value.readUInt8(2)}.${value.readUInt8(3)}`;
}

/**
 * Format the bytes inside a RELAY_RESOLVED `IPv6` record as the customary
 * colon-delimited 8-group string. Zero-compression is intentionally NOT
 * applied — keeping the canonical 8-group form lines up with what the
 * SOCKS layer puts on the wire as a bound address.
 */
export function formatResolvedIPv6(value: Buffer): string {
  if (value.length !== 16) {
    throw new Error(`RELAY_RESOLVED IPv6 record must be 16 bytes, got ${value.length}`);
  }
  const parts: string[] = [];
  for (let i = 0; i < 16; i += 2) {
    parts.push(value.readUInt16BE(i).toString(16));
  }
  return parts.join(':');
}
