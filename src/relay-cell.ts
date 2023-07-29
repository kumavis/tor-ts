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