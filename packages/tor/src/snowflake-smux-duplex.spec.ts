import test from 'ava';
import { once } from 'node:events';
import { MinimalKcpSession } from './snowflake/kcp/session.ts';
import { SmuxSession } from './snowflake/smux/session.ts';
import { SmuxStreamDuplex } from './snowflake/smux/duplex.ts';

test('smux duplex: adapts SmuxStream to node Duplex', async (t) => {
  const now = () => 123;
  const conv = 0x77778888;

  const aKcp = new MinimalKcpSession({ conv, now, mss: 1200 });
  const bKcp = new MinimalKcpSession({ conv, now, mss: 1200 });
  aKcp.attachSink((pkt) => bKcp.inputPacket(pkt));
  bKcp.attachSink((pkt) => aKcp.inputPacket(pkt));

  const client = new SmuxSession(
    { readExactly: (n) => aKcp.readExactly(n), write: (d) => aKcp.write(d) },
    { isClient: true, ver: 2 }
  );
  const server = new SmuxSession(
    { readExactly: (n) => bKcp.readExactly(n), write: (d) => bKcp.write(d) },
    { isClient: false, ver: 2 }
  );

  const s1 = await client.openStream();
  const s2 = await server.acceptStream();

  const d1 = new SmuxStreamDuplex(s1);
  const d2 = new SmuxStreamDuplex(s2);

  d1.write(Buffer.from([1, 2, 3, 4]));
  const [chunk] = (await once(d2, 'data')) as [Buffer];
  t.deepEqual(new Uint8Array(chunk), new Uint8Array([1, 2, 3, 4]));

  // Start readable side so it can observe FIN/end.
  d1.resume();
  d2.end();
  await once(d1, 'end');
  t.pass();
});

