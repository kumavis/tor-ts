import test from 'ava';
import { decodeKcpSegmentsFromPacket, encodeKcpSegment, KCP_CMD, KCP_HEADER_SIZE } from './snowflake/kcp/segment.ts';

test('kcp segment: encode/decode roundtrip', (t) => {
  const seg = {
    conv: 0x11223344,
    cmd: KCP_CMD.PUSH,
    frg: 0,
    wnd: 0x3456,
    ts: 0x77889900,
    sn: 7,
    una: 3,
    data: Uint8Array.from([1, 2, 3, 4]),
  } as const;
  const pkt = encodeKcpSegment(seg);
  t.is(pkt.byteLength, KCP_HEADER_SIZE + 4);

  const decoded = decodeKcpSegmentsFromPacket(pkt);
  t.is(decoded.length, 1);
  t.is(decoded[0]!.conv, seg.conv);
  t.is(decoded[0]!.cmd, seg.cmd);
  t.is(decoded[0]!.frg, seg.frg);
  t.is(decoded[0]!.wnd, seg.wnd);
  t.is(decoded[0]!.ts, seg.ts);
  t.is(decoded[0]!.sn, seg.sn);
  t.is(decoded[0]!.una, seg.una);
  t.deepEqual(decoded[0]!.data, seg.data);
});

test('kcp segment: decode handles multiple concatenated segments in one packet', (t) => {
  const a = encodeKcpSegment({
    conv: 1,
    cmd: KCP_CMD.ACK,
    frg: 0,
    wnd: 10,
    ts: 1,
    sn: 1,
    una: 1,
    data: new Uint8Array(0),
  });
  const b = encodeKcpSegment({
    conv: 1,
    cmd: KCP_CMD.PUSH,
    frg: 0,
    wnd: 10,
    ts: 2,
    sn: 2,
    una: 1,
    data: Uint8Array.from([9, 9]),
  });

  const pkt = new Uint8Array(a.byteLength + b.byteLength);
  pkt.set(a, 0);
  pkt.set(b, a.byteLength);

  const decoded = decodeKcpSegmentsFromPacket(pkt);
  t.is(decoded.length, 2);
  t.is(decoded[0]!.cmd, KCP_CMD.ACK);
  t.is(decoded[1]!.cmd, KCP_CMD.PUSH);
  t.deepEqual(decoded[1]!.data, Uint8Array.from([9, 9]));
});

test('kcp segment: decode throws on short packet', (t) => {
  t.throws(() => decodeKcpSegmentsFromPacket(new Uint8Array(KCP_HEADER_SIZE - 1)));
});

