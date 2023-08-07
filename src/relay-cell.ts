import { bufferFromUint } from './util'

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

export enum RelayCell {
  BEGIN = 1,
  DATA = 2,
  END = 3,
  CONNECTED = 4,
  SENDME = 5,
  EXTEND = 6,
  EXTENDED = 7,
  TRUNCATE = 8,
  TRUNCATED = 9,
  DROP = 10,
  RESOLVE = 11,
  RESOLVED = 12,
  BEGIN_DIR = 13,
  EXTEND2 = 14,
  EXTENDED2 = 15,
}

const relayCellNames = {
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
}

export function serializeExtend2 ({ linkSpecifiers, handshake }): Buffer {
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
    Buffer.concat(linkSpecifiers.map(linkSpecifier => {
      return Buffer.concat([
        bufferFromUint(1, linkSpecifier.type),
        bufferFromUint(1, linkSpecifier.data.length),
        linkSpecifier.data,
      ])
    })),
    bufferFromUint(2, handshake.type),
    bufferFromUint(2, handshake.data.length),
    handshake.data,
  ])
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

export enum RelayEndReasons {
  REASON_MISC = 1,
  REASON_RESOLVEFAILED = 2,
  REASON_CONNECTREFUSED = 3,
  REASON_EXITPOLICY = 4,
  REASON_DESTROY = 5,
  REASON_DONE = 6,
  REASON_TIMEOUT = 7,
  REASON_NOROUTE = 8,
  REASON_HIBERNATING = 9,
  REASON_INTERNAL = 10,
  REASON_RESOURCELIMIT = 11,
  REASON_CONNRESET = 12,
  REASON_TORPROTOCOL = 13,
  REASON_NOTDIRECTORY = 14,
}

export const RelayEndReasonNames = {
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
}