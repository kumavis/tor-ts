import test from 'ava';
import { MinimalKcpSession } from './snowflake/kcp/session.ts';
import { SmuxSession } from './snowflake/smux/session.ts';

test('smux v2: client opens stream and sends data', async (t) => {
  const now = () => 123;
  const conv = 0x12345678;

  const aKcp = new MinimalKcpSession({ conv, now, mss: 1200 });
  const bKcp = new MinimalKcpSession({ conv, now, mss: 1200 });

  aKcp.attachSink((pkt) => bKcp.inputPacket(pkt));
  bKcp.attachSink((pkt) => aKcp.inputPacket(pkt));

  const client = new SmuxSession(
    {
      readExactly: (n) => aKcp.readExactly(n),
      write: (d) => aKcp.write(d),
    },
    { isClient: true, ver: 2 }
  );
  const server = new SmuxSession(
    {
      readExactly: (n) => bKcp.readExactly(n),
      write: (d) => bKcp.write(d),
    },
    { isClient: false, ver: 2 }
  );

  const s1 = await client.openStream();
  const s2 = await server.acceptStream();

  s1.write(Uint8Array.from([1, 2, 3, 4, 5]));
  const got = await s2.readExactly(5);
  t.deepEqual(got, Uint8Array.from([1, 2, 3, 4, 5]));

  // And reverse direction
  s2.write(Uint8Array.from([9, 8, 7]));
  const got2 = await s1.readExactly(3);
  t.deepEqual(got2, Uint8Array.from([9, 8, 7]));
});
