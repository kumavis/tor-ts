import test from 'ava';
import {
  TURBOTUNNEL_TOKEN,
  buildTurbotunnelPreamble,
  DEFAULT_PADDING_MIN,
  DEFAULT_PADDING_MAX,
} from './turbotunnel.ts';
import { EncapsulationDecoder } from './encapsulation.ts';

const id = Uint8Array.from([1, 2, 3, 4, 5, 6, 7, 8]);

test('turbotunnel padding: default preamble is larger than 16 bytes', (t) => {
  const p = buildTurbotunnelPreamble(id);
  t.true(p.byteLength >= 16 + DEFAULT_PADDING_MIN);
  t.true(p.byteLength <= 16 + DEFAULT_PADDING_MAX + 3 /* prefix overhead */);
  t.deepEqual(p.slice(0, 8), TURBOTUNNEL_TOKEN);
  t.deepEqual(p.slice(8, 16), id);
});

test('turbotunnel padding: opt-out yields exactly 16 bytes', (t) => {
  const p = buildTurbotunnelPreamble(id, { padding: false });
  t.is(p.byteLength, 16);
});

test('turbotunnel padding: padding section parses as padding chunks only', (t) => {
  const p = buildTurbotunnelPreamble(id, { paddingSize: 1500 });
  const padded = p.slice(16);
  // An EncapsulationDecoder fed the padded section and then asked for data
  // should produce no data chunks (padding is silently skipped).
  const dec = new EncapsulationDecoder();
  dec.push(padded);
  // popData returns undefined when no data chunk is present.
  t.is(dec.popData(), undefined);
  // finish() consumes the rest — if any byte is unaccounted for, it throws.
  t.notThrows(() => dec.finish());
});

test('turbotunnel padding: two preambles differ in padding bytes', (t) => {
  // Fix the size (not random) so we only vary the body bytes.
  const a = buildTurbotunnelPreamble(id, { paddingSize: 1000 });
  const b = buildTurbotunnelPreamble(id, { paddingSize: 1000 });
  // Both are the same length but body should differ (with overwhelming probability).
  t.is(a.byteLength, b.byteLength);
  t.notDeepEqual(a, b);
});

test('turbotunnel padding: fixed-size path is deterministic given deterministic randomBytes', (t) => {
  const zeros = (n: number) => new Uint8Array(n);
  const a = buildTurbotunnelPreamble(id, { paddingSize: 500, randomBytes: zeros });
  const b = buildTurbotunnelPreamble(id, { paddingSize: 500, randomBytes: zeros });
  t.deepEqual(a, b);
});
