/**
 * Tests for relay cell serialization.
 */

import test from 'ava';
import { RelayCell, RelayEndReasons, RelayEndReasonNames, serializeExtend2 } from './relay-cell.ts';
import { LinkSpecifierTypes, HandshakeTypes } from './messaging.ts';
import type { LinkSpecifier } from './messaging.ts';

test('RelayCell: enum values match Tor spec', (t) => {
  t.is(RelayCell.BEGIN, 1);
  t.is(RelayCell.DATA, 2);
  t.is(RelayCell.END, 3);
  t.is(RelayCell.CONNECTED, 4);
  t.is(RelayCell.SENDME, 5);
  t.is(RelayCell.EXTEND, 6);
  t.is(RelayCell.EXTENDED, 7);
  t.is(RelayCell.TRUNCATE, 8);
  t.is(RelayCell.TRUNCATED, 9);
  t.is(RelayCell.DROP, 10);
  t.is(RelayCell.RESOLVE, 11);
  t.is(RelayCell.RESOLVED, 12);
  t.is(RelayCell.BEGIN_DIR, 13);
  t.is(RelayCell.EXTEND2, 14);
  t.is(RelayCell.EXTENDED2, 15);
});

test('RelayCell: hidden service commands match rend-spec-v3', (t) => {
  t.is(RelayCell.ESTABLISH_INTRO, 32);
  t.is(RelayCell.ESTABLISH_RENDEZVOUS, 33);
  t.is(RelayCell.INTRODUCE1, 34);
  t.is(RelayCell.INTRODUCE2, 35);
  t.is(RelayCell.RENDEZVOUS1, 36);
  t.is(RelayCell.RENDEZVOUS2, 37);
  t.is(RelayCell.INTRO_ESTABLISHED, 38);
  t.is(RelayCell.RENDEZVOUS_ESTABLISHED, 39);
  t.is(RelayCell.INTRODUCE_ACK, 40);
});

test('RelayEndReasons: enum values match Tor spec', (t) => {
  t.is(RelayEndReasons.REASON_MISC, 1);
  t.is(RelayEndReasons.REASON_RESOLVEFAILED, 2);
  t.is(RelayEndReasons.REASON_CONNECTREFUSED, 3);
  t.is(RelayEndReasons.REASON_EXITPOLICY, 4);
  t.is(RelayEndReasons.REASON_DESTROY, 5);
  t.is(RelayEndReasons.REASON_DONE, 6);
  t.is(RelayEndReasons.REASON_TIMEOUT, 7);
  t.is(RelayEndReasons.REASON_NOROUTE, 8);
  t.is(RelayEndReasons.REASON_HIBERNATING, 9);
  t.is(RelayEndReasons.REASON_INTERNAL, 10);
  t.is(RelayEndReasons.REASON_RESOURCELIMIT, 11);
  t.is(RelayEndReasons.REASON_CONNRESET, 12);
  t.is(RelayEndReasons.REASON_TORPROTOCOL, 13);
  t.is(RelayEndReasons.REASON_NOTDIRECTORY, 14);
});

test('RelayEndReasonNames: provides human-readable names', (t) => {
  t.is(RelayEndReasonNames[RelayEndReasons.REASON_DONE], 'REASON_DONE');
  t.is(RelayEndReasonNames[RelayEndReasons.REASON_TIMEOUT], 'REASON_TIMEOUT');
  t.is(RelayEndReasonNames[RelayEndReasons.REASON_EXITPOLICY], 'REASON_EXITPOLICY');
});

test('serializeExtend2: creates valid payload with IPv4 link specifier', (t) => {
  const linkSpecifiers: LinkSpecifier[] = [
    {
      type: LinkSpecifierTypes.TlsOverTcpIPv4,
      data: Buffer.from([127, 0, 0, 1, 0x23, 0x29]), // 127.0.0.1:9001
    },
    {
      type: LinkSpecifierTypes.LegacyId,
      data: Buffer.alloc(20).fill(0x42), // 20-byte fingerprint
    },
  ];

  const handshake = {
    type: HandshakeTypes.NTOR,
    data: Buffer.alloc(84).fill(0xab), // ntor handshake data
  };

  const payload = serializeExtend2({ linkSpecifiers, handshake });

  // Parse the payload to verify structure
  let offset = 0;

  // NSPEC
  const nspec = payload[offset++];
  t.is(nspec, 2);

  // First link specifier
  const lstype1 = payload[offset++];
  const lslen1 = payload[offset++];
  t.is(lstype1, LinkSpecifierTypes.TlsOverTcpIPv4);
  t.is(lslen1, 6);
  offset += lslen1!;

  // Second link specifier
  const lstype2 = payload[offset++];
  const lslen2 = payload[offset++];
  t.is(lstype2, LinkSpecifierTypes.LegacyId);
  t.is(lslen2, 20);
  offset += lslen2!;

  // HTYPE (2 bytes)
  const htype = payload.readUInt16BE(offset);
  offset += 2;
  t.is(htype, HandshakeTypes.NTOR);

  // HLEN (2 bytes)
  const hlen = payload.readUInt16BE(offset);
  offset += 2;
  t.is(hlen, 84);

  // HDATA
  const hdata = payload.subarray(offset, offset + hlen);
  t.is(hdata.length, 84);
  t.true(hdata.every((b) => b === 0xab));
});

test('serializeExtend2: handles empty link specifiers', (t) => {
  const handshake = {
    type: HandshakeTypes.NTOR,
    data: Buffer.from('test'),
  };

  const payload = serializeExtend2({ linkSpecifiers: [], handshake });

  // NSPEC should be 0
  t.is(payload[0], 0);

  // HTYPE at offset 1
  const htype = payload.readUInt16BE(1);
  t.is(htype, HandshakeTypes.NTOR);

  // HLEN at offset 3
  const hlen = payload.readUInt16BE(3);
  t.is(hlen, 4);
});

test('serializeExtend2: handles multiple link specifiers of different types', (t) => {
  const linkSpecifiers: LinkSpecifier[] = [
    {
      type: LinkSpecifierTypes.TlsOverTcpIPv4,
      data: Buffer.from([192, 168, 1, 1, 0x00, 0x50]), // 192.168.1.1:80
    },
    {
      type: LinkSpecifierTypes.LegacyId,
      data: Buffer.alloc(20).fill(0x11),
    },
    {
      type: LinkSpecifierTypes.Ed25519Id,
      data: Buffer.alloc(32).fill(0x22),
    },
  ];

  const handshake = {
    type: HandshakeTypes.NTOR,
    data: Buffer.alloc(10),
  };

  const payload = serializeExtend2({ linkSpecifiers, handshake });

  // NSPEC should be 3
  t.is(payload[0], 3);

  // Expected total size:
  // 1 (NSPEC) + (1+1+6) + (1+1+20) + (1+1+32) + 2 (HTYPE) + 2 (HLEN) + 10 (HDATA)
  // = 1 + 8 + 22 + 34 + 2 + 2 + 10 = 79
  t.is(payload.length, 79);
});
