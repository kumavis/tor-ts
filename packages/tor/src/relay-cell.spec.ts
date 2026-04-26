/**
 * Tests for relay cell serialization.
 */

import test from 'ava';
import {
  RelayCell,
  RelayEndError,
  RelayEndReasons,
  RelayEndReasonNames,
  RelayResolvedType,
  buildRelayResolvePayload,
  formatResolvedIPv4,
  formatResolvedIPv6,
  ipv4ToInAddrArpa,
  ipv6StringToBytes,
  ipv6ToIp6Arpa,
  parseRelayResolvedPayload,
  serializeExtend2,
} from './relay-cell.ts';
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

// =============================================================================
// RelayEndError
// =============================================================================

test('RelayEndError: exposes typed reason / reasonName / payloadHex', (t) => {
  const err = new RelayEndError(RelayEndReasons.REASON_EXITPOLICY, 'aabb');
  t.is(err.reason, RelayEndReasons.REASON_EXITPOLICY);
  t.is(err.reasonName, 'REASON_EXITPOLICY');
  t.is(err.payloadHex, 'aabb');
  t.true(err.message.includes('REASON_EXITPOLICY'));
  t.true(err.message.includes('payload=0xaabb'));
  t.is(err.name, 'RelayEndError');
  t.true(err instanceof Error);
});

test('RelayEndError: unknown reason gets UNKNOWN_REASON_<n> name', (t) => {
  const err = new RelayEndError(99, '');
  t.is(err.reason, 99);
  t.is(err.reasonName, 'UNKNOWN_REASON_99');
});

// =============================================================================
// RELAY_RESOLVE / RELAY_RESOLVED
// =============================================================================

test('buildRelayResolvePayload: NUL-terminates the hostname', (t) => {
  const payload = buildRelayResolvePayload('example.com');
  t.is(payload.length, 12);
  t.is(payload.subarray(0, 11).toString('ascii'), 'example.com');
  t.is(payload[11], 0x00);
});

test('parseRelayResolvedPayload: parses a single IPv4 record', (t) => {
  // Type=4, Length=4, Value=93.184.216.34, TTL=300
  const data = Buffer.concat([
    Buffer.from([0x04, 0x04, 93, 184, 216, 34]),
    Buffer.from([0x00, 0x00, 0x01, 0x2c]),
  ]);
  const records = parseRelayResolvedPayload(data);
  t.is(records.length, 1);
  t.is(records[0]!.type, RelayResolvedType.IPv4);
  t.deepEqual(records[0]!.value, Buffer.from([93, 184, 216, 34]));
  t.is(records[0]!.ttl, 300);
});

test('parseRelayResolvedPayload: parses IPv4 + IPv6 records back-to-back', (t) => {
  const data = Buffer.concat([
    // IPv4 record
    Buffer.from([0x04, 0x04, 1, 2, 3, 4, 0, 0, 0, 60]),
    // IPv6 record (::1)
    Buffer.concat([
      Buffer.from([0x06, 0x10]),
      Buffer.alloc(15),
      Buffer.from([0x01]),
      Buffer.from([0, 0, 0, 120]),
    ]),
  ]);
  const records = parseRelayResolvedPayload(data);
  t.is(records.length, 2);
  t.is(records[0]!.type, RelayResolvedType.IPv4);
  t.is(records[0]!.ttl, 60);
  t.is(records[1]!.type, RelayResolvedType.IPv6);
  t.is(records[1]!.value.length, 16);
  t.is(records[1]!.ttl, 120);
});

test('parseRelayResolvedPayload: parses Hostname (PTR) record', (t) => {
  const name = 'host.example.com';
  const data = Buffer.concat([
    Buffer.from([0x00, name.length]),
    Buffer.from(name, 'ascii'),
    Buffer.from([0, 0, 0, 0xff]),
  ]);
  const records = parseRelayResolvedPayload(data);
  t.is(records.length, 1);
  t.is(records[0]!.type, RelayResolvedType.Hostname);
  t.is(records[0]!.value.toString('ascii'), name);
  t.is(records[0]!.ttl, 0xff);
});

test('parseRelayResolvedPayload: parses transient and permanent error records', (t) => {
  const transient = Buffer.from('temp', 'ascii');
  const permanent = Buffer.from('nope', 'ascii');
  const data = Buffer.concat([
    Buffer.from([0xf0, transient.length]),
    transient,
    Buffer.from([0, 0, 0, 0]),
    Buffer.from([0xf1, permanent.length]),
    permanent,
    Buffer.from([0, 0, 0, 0]),
  ]);
  const records = parseRelayResolvedPayload(data);
  t.is(records.length, 2);
  t.is(records[0]!.type, RelayResolvedType.ErrorTransient);
  t.is(records[1]!.type, RelayResolvedType.ErrorPermanent);
});

test('parseRelayResolvedPayload: drops trailing partial record silently', (t) => {
  const data = Buffer.concat([
    Buffer.from([0x04, 0x04, 1, 2, 3, 4, 0, 0, 0, 60]),
    // A second record header but missing TTL
    Buffer.from([0x04, 0x04, 5, 6, 7, 8]),
  ]);
  const records = parseRelayResolvedPayload(data);
  t.is(records.length, 1);
});

test('parseRelayResolvedPayload: returns empty array on empty buffer', (t) => {
  t.deepEqual(parseRelayResolvedPayload(Buffer.alloc(0)), []);
});

// =============================================================================
// IP <-> reverse-DNS / canonical-form helpers
// =============================================================================

test('ipv4ToInAddrArpa: dotted-quad → reverse', (t) => {
  t.is(ipv4ToInAddrArpa('1.2.3.4'), '4.3.2.1.in-addr.arpa');
  t.is(ipv4ToInAddrArpa('192.168.1.1'), '1.1.168.192.in-addr.arpa');
});

test('ipv4ToInAddrArpa: rejects malformed input', (t) => {
  t.throws(() => ipv4ToInAddrArpa('1.2.3'), { message: /dotted-quad/ });
  t.throws(() => ipv4ToInAddrArpa('256.0.0.0'), { message: /dotted-quad/ });
  t.throws(() => ipv4ToInAddrArpa('a.b.c.d'), { message: /dotted-quad/ });
});

test('ipv6ToIp6Arpa: ::1 → standard reverse name', (t) => {
  t.is(
    ipv6ToIp6Arpa('::1'),
    '1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa'
  );
});

test('ipv6ToIp6Arpa: 2001:db8::1 normalizes correctly', (t) => {
  // 2001:0db8:0000:0000:0000:0000:0000:0001 → reversed nibbles:
  // 1 (lo of 0001), then 23 zeros, then 8bd0 (reversed of 0db8),
  // then 1002 (reversed of 2001).
  const arpa = ipv6ToIp6Arpa('2001:db8::1');
  t.true(arpa.endsWith('.ip6.arpa'));
  t.is(arpa.split('.').slice(0, 32).join(''), '1' + '0'.repeat(23) + '8bd0' + '1002');
});

test('ipv6ToIp6Arpa: handles bracketed and zone-id forms', (t) => {
  t.is(ipv6ToIp6Arpa('[::1]'), ipv6ToIp6Arpa('::1'));
  t.is(ipv6ToIp6Arpa('::1%eth0'), ipv6ToIp6Arpa('::1'));
});

test('ipv6ToIp6Arpa: handles dotted-quad tail (IPv4-mapped)', (t) => {
  t.is(ipv6ToIp6Arpa('::ffff:1.2.3.4'), ipv6ToIp6Arpa('::ffff:0102:0304'));
});

test('ipv6StringToBytes: round-trips with formatResolvedIPv6', (t) => {
  const input = '2001:db8:0:0:0:0:0:1';
  const bytes = ipv6StringToBytes(input);
  t.is(bytes.length, 16);
  t.is(formatResolvedIPv6(bytes), '2001:db8:0:0:0:0:0:1');
});

test('ipv6StringToBytes: ::1 → 15 zero bytes + 0x01', (t) => {
  const bytes = ipv6StringToBytes('::1');
  t.is(bytes.length, 16);
  for (let i = 0; i < 15; i++) t.is(bytes[i], 0, `byte ${i} should be 0`);
  t.is(bytes[15], 1);
});

test('ipv6StringToBytes: rejects malformed strings', (t) => {
  t.throws(() => ipv6StringToBytes('not-an-ipv6'), { message: /Not a valid IPv6/ });
  t.throws(() => ipv6StringToBytes('1:2:3:4:5:6:7'), { message: /Not a valid IPv6/ });
  t.throws(() => ipv6StringToBytes('1::2::3'), { message: /Not a valid IPv6/ });
});

test('formatResolvedIPv4: rejects non-4-byte inputs', (t) => {
  t.throws(() => formatResolvedIPv4(Buffer.from([1, 2, 3])), { message: /4 bytes/ });
});

test('formatResolvedIPv6: rejects non-16-byte inputs', (t) => {
  t.throws(() => formatResolvedIPv6(Buffer.alloc(15)), { message: /16 bytes/ });
});
