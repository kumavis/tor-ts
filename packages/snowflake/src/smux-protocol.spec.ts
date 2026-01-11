/**
 * Tests for SMUX protocol encoding/decoding.
 */

import test from 'ava';
import {
  SMUX_CMD,
  SMUX_HEADER_SIZE,
  SMUX_UPD_SIZE,
  encodeSmuxFrame,
  decodeSmuxHeader,
  encodeUpdPayload,
  decodeUpdPayload,
} from './smux/protocol.ts';
import type { SmuxFrame } from './smux/protocol.ts';

test('SMUX_CMD: constants match smux v2 protocol', (t) => {
  t.is(SMUX_CMD.SYN, 0);
  t.is(SMUX_CMD.FIN, 1);
  t.is(SMUX_CMD.PSH, 2);
  t.is(SMUX_CMD.NOP, 3);
  t.is(SMUX_CMD.UPD, 4);
});

test('SMUX_HEADER_SIZE: is 8 bytes', (t) => {
  t.is(SMUX_HEADER_SIZE, 8);
});

test('SMUX_UPD_SIZE: is 8 bytes', (t) => {
  t.is(SMUX_UPD_SIZE, 8);
});

test('encodeSmuxFrame: creates frame with correct header', (t) => {
  const frame: SmuxFrame = {
    ver: 2,
    cmd: SMUX_CMD.PSH,
    sid: 0x12345678,
    data: Uint8Array.from([0xaa, 0xbb, 0xcc]),
  };

  const encoded = encodeSmuxFrame(frame);

  t.is(encoded.length, SMUX_HEADER_SIZE + 3);

  // Verify header
  const view = new DataView(encoded.buffer, encoded.byteOffset, encoded.byteLength);
  t.is(view.getUint8(0), 2); // ver
  t.is(view.getUint8(1), SMUX_CMD.PSH); // cmd
  t.is(view.getUint16(2, true), 3); // len (little-endian)
  t.is(view.getUint32(4, true), 0x12345678); // sid (little-endian)

  // Verify data
  t.deepEqual(encoded.subarray(8), Uint8Array.from([0xaa, 0xbb, 0xcc]));
});

test('encodeSmuxFrame: handles empty data', (t) => {
  const frame: SmuxFrame = {
    ver: 2,
    cmd: SMUX_CMD.SYN,
    sid: 1,
    data: new Uint8Array(0),
  };

  const encoded = encodeSmuxFrame(frame);
  t.is(encoded.length, SMUX_HEADER_SIZE);

  const view = new DataView(encoded.buffer, encoded.byteOffset, encoded.byteLength);
  t.is(view.getUint16(2, true), 0); // len should be 0
});

test('encodeSmuxFrame: throws on frame too large', (t) => {
  const frame: SmuxFrame = {
    ver: 2,
    cmd: SMUX_CMD.PSH,
    sid: 1,
    data: new Uint8Array(0x10000), // 65536 bytes, exceeds 16-bit limit
  };

  t.throws(() => encodeSmuxFrame(frame), {
    message: /smux frame too large/,
  });
});

test('decodeSmuxHeader: parses header correctly', (t) => {
  const header = new Uint8Array(8);
  const view = new DataView(header.buffer);
  view.setUint8(0, 2); // ver
  view.setUint8(1, SMUX_CMD.FIN); // cmd
  view.setUint16(2, 100, true); // len
  view.setUint32(4, 0x42, true); // sid

  const decoded = decodeSmuxHeader(header);

  t.is(decoded.ver, 2);
  t.is(decoded.cmd, SMUX_CMD.FIN);
  t.is(decoded.len, 100);
  t.is(decoded.sid, 0x42);
});

test('decodeSmuxHeader: throws on wrong size', (t) => {
  const tooShort = new Uint8Array(7);
  t.throws(() => decodeSmuxHeader(tooShort), {
    message: /expected 8 byte header/,
  });

  const tooLong = new Uint8Array(9);
  t.throws(() => decodeSmuxHeader(tooLong), {
    message: /expected 8 byte header/,
  });
});

test('encodeSmuxFrame + decodeSmuxHeader: roundtrip', (t) => {
  const frame: SmuxFrame = {
    ver: 2,
    cmd: SMUX_CMD.UPD,
    sid: 999,
    data: Uint8Array.from([1, 2, 3, 4, 5]),
  };

  const encoded = encodeSmuxFrame(frame);
  const header = encoded.subarray(0, SMUX_HEADER_SIZE);
  const decoded = decodeSmuxHeader(header);

  t.is(decoded.ver, frame.ver);
  t.is(decoded.cmd, frame.cmd);
  t.is(decoded.len, frame.data.length);
  t.is(decoded.sid, frame.sid);
});

test('encodeUpdPayload: creates correct payload', (t) => {
  const payload = encodeUpdPayload(1000, 65535);

  t.is(payload.length, SMUX_UPD_SIZE);

  const view = new DataView(payload.buffer, payload.byteOffset, payload.byteLength);
  t.is(view.getUint32(0, true), 1000); // consumed
  t.is(view.getUint32(4, true), 65535); // window
});

test('decodeUpdPayload: parses payload correctly', (t) => {
  const payload = new Uint8Array(8);
  const view = new DataView(payload.buffer);
  view.setUint32(0, 5000, true); // consumed
  view.setUint32(4, 1048576, true); // window (1MB)

  const decoded = decodeUpdPayload(payload);

  t.is(decoded.consumed, 5000);
  t.is(decoded.window, 1048576);
});

test('decodeUpdPayload: throws on wrong size', (t) => {
  const tooShort = new Uint8Array(7);
  t.throws(() => decodeUpdPayload(tooShort), {
    message: /expected 8 byte UPD payload/,
  });
});

test('encodeUpdPayload + decodeUpdPayload: roundtrip', (t) => {
  const consumed = 123456;
  const window = 987654;

  const encoded = encodeUpdPayload(consumed, window);
  const decoded = decodeUpdPayload(encoded);

  t.is(decoded.consumed, consumed);
  t.is(decoded.window, window);
});

test('encodeUpdPayload: handles large values', (t) => {
  // Test with values near uint32 max
  const consumed = 0xffffffff;
  const window = 0xfffffffe;

  const encoded = encodeUpdPayload(consumed, window);
  const decoded = decodeUpdPayload(encoded);

  t.is(decoded.consumed, consumed >>> 0);
  t.is(decoded.window, window >>> 0);
});
