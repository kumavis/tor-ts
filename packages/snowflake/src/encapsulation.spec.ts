import test from 'ava';
import {
  EncapsulationDecoder,
  EncapsulationTooLongError,
  encodeEncapsulatedData,
} from './encapsulation.ts';

function u8(...bytes: number[]): Uint8Array {
  return Uint8Array.from(bytes);
}

test('encapsulation: encodeEncapsulatedData uses 1-byte prefix for small lengths', (t) => {
  // n=4 => prefix is 0x80|0x04
  const frame = encodeEncapsulatedData(u8(1, 2, 3, 4));
  t.deepEqual(frame, u8(0x84, 1, 2, 3, 4));
});

test('encapsulation: encodeEncapsulatedData uses 2-byte prefix for length >= 64', (t) => {
  // n=64 => binary 1_000000, so first byte carries upper 6 bits = 0, second = 64.
  const data = new Uint8Array(64);
  const frame = encodeEncapsulatedData(data);
  t.is(frame[0], 0xc0); // 0b11000000
  t.is(frame[1], 0x40); // 64
  t.is(frame.byteLength, 2 + 64);
});

test('encapsulation: decoder returns data chunks and skips padding chunks', (t) => {
  const dec = new EncapsulationDecoder();
  // Padding chunk of length 3: 0b00xxxxxx with xxxxxx=3, then 3 padding bytes.
  // Then data chunk length 2: 0x82, payload 0xaa 0xbb
  dec.push(u8(0x03, 0x00, 0x00, 0x00, 0x82, 0xaa, 0xbb));
  t.deepEqual(dec.popData(), u8(0xaa, 0xbb));
  t.is(dec.popData(), undefined);
  dec.finish();
  t.pass();
});

test('encapsulation: decoder handles prefix split across chunks', (t) => {
  const dec = new EncapsulationDecoder();
  // data length 64 prefix is 0xC0 0x40, then 64 zeros.
  dec.push(u8(0xc0));
  t.is(dec.popData(), undefined);
  dec.push(u8(0x40, ...new Uint8Array(64)));
  const out = dec.popData();
  t.truthy(out);
  t.is(out!.byteLength, 64);
  dec.finish();
});

test('encapsulation: decoder throws on >3-byte prefix', (t) => {
  const dec = new EncapsulationDecoder();
  // First byte: data + continuation.
  // Next bytes: continuation + continuation + continuation => too long (>3 bytes total).
  dec.push(u8(0xc0, 0x80, 0x80, 0x00));
  t.throws(() => dec.popData(), { instanceOf: EncapsulationTooLongError });
});
