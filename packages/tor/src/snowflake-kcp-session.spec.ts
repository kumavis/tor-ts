import test from 'ava';
import { MinimalKcpSession } from './snowflake/kcp/session.ts';

test('minimal kcp session: transfers stream bytes over packet sink/source', async (t) => {
  const now = () => 123;
  const conv = 0x99aabbcc;

  const a = new MinimalKcpSession({ conv, now, mss: 3 });
  const b = new MinimalKcpSession({ conv, now, mss: 3 });

  // Wire them together with a synchronous "carrier".
  a.attachSink((pkt) => {
    b.inputPacket(pkt);
  });
  b.attachSink((pkt) => {
    a.inputPacket(pkt);
  });

  a.write(Uint8Array.from([1, 2, 3, 4, 5, 6, 7]));
  const r1 = await b.readExactly(7);
  t.deepEqual(r1, Uint8Array.from([1, 2, 3, 4, 5, 6, 7]));

  b.write(Uint8Array.from([9, 8, 7, 6]));
  const r2 = await a.readExactly(4);
  t.deepEqual(r2, Uint8Array.from([9, 8, 7, 6]));
});
