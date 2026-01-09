import test from 'ava';
import { TURBOTUNNEL_TOKEN, buildTurbotunnelPreamble, newClientId } from './turbotunnel.ts';

test('turbotunnel: token is 8 bytes', (t) => {
  t.is(TURBOTUNNEL_TOKEN.byteLength, 8);
});

test('turbotunnel: newClientId is 8 bytes', (t) => {
  const id = newClientId();
  t.is(id.byteLength, 8);
});

test('turbotunnel: buildTurbotunnelPreamble concatenates token and clientId', (t) => {
  const id = Uint8Array.from([1, 2, 3, 4, 5, 6, 7, 8]);
  const pre = buildTurbotunnelPreamble(id);
  t.is(pre.byteLength, 16);
  t.deepEqual(pre.slice(0, 8), TURBOTUNNEL_TOKEN);
  t.deepEqual(pre.slice(8), id);
});

test('turbotunnel: buildTurbotunnelPreamble rejects wrong clientId length', (t) => {
  t.throws(() => buildTurbotunnelPreamble(new Uint8Array(7)));
});
