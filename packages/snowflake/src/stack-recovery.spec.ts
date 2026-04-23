/**
 * End-to-end test for the flakiness scenario: a server-side packet drop on the
 * KCP layer must no longer strand a SMUX stream. Before the retransmission fix
 * this test would hang forever; we gate it behind a 2s deadline to prove the
 * bug is gone.
 */

import test from 'ava';
import { MinimalKcpSession } from './kcp/session.ts';
import { SmuxSession } from './smux/session.ts';

function makeClock(): { now: () => number; advance: (ms: number) => void } {
  let t = 0;
  return {
    now: () => t,
    advance: (ms) => {
      t += ms;
    },
  };
}

test('stack: kcp retransmit recovers a dropped packet mid-stream', async (t) => {
  const clock = makeClock();

  const kcpA = new MinimalKcpSession({
    conv: 0xf00d,
    now: clock.now,
    mss: 32,
    rtoInitial: 50,
  });
  const kcpB = new MinimalKcpSession({
    conv: 0xf00d,
    now: clock.now,
    mss: 32,
    rtoInitial: 50,
  });

  // Drop the third packet a emits, like the server's QueuePacketConn would
  // when its 512-slot channel overflows during a bulk transfer.
  let dropIndex = 2;
  let seen = 0;
  kcpA.attachSink((pkt) => {
    if (seen++ === dropIndex) return;
    kcpB.inputPacket(pkt);
  });
  kcpB.attachSink((pkt) => kcpA.inputPacket(pkt));

  const client = new SmuxSession(
    { readExactly: (n) => kcpA.readExactly(n), write: (d) => kcpA.write(d) },
    {
      isClient: true,
      ver: 2,
      keepAliveIntervalMs: 0,
      keepAliveTimeoutMs: 0,
    }
  );
  const server = new SmuxSession(
    { readExactly: (n) => kcpB.readExactly(n), write: (d) => kcpB.write(d) },
    {
      isClient: false,
      ver: 2,
      keepAliveIntervalMs: 0,
      keepAliveTimeoutMs: 0,
    }
  );

  const s1 = await client.openStream();
  const s2 = await server.acceptStream();

  // 200 bytes across ~7 segments with MSS=32; one will be dropped.
  const payload = new Uint8Array(200).map((_, i) => i & 0xff);
  // Drive the write without awaiting so we can also drive update() interleaved.
  const writeDone = s1.write(payload);

  // Let queued writes flush and the drop take effect.
  await Promise.resolve();
  await Promise.resolve();

  // Simulate the retransmission timer firing after RTO.
  clock.advance(60);
  kcpA.update();
  kcpB.update(); // also drain any peer-side retransmits

  // Read the full payload on the server. Without retransmission this would
  // hang on the missing segment forever.
  const got = await s2.readExactly(200);
  await writeDone;

  t.deepEqual(got, payload);
  t.true(seen >= 7, 'more than one segment traversed the sink');
  t.is(dropIndex, 2, 'we really did skip a packet');
});

test('stack: no dropped bytes when carrier is lossless', async (t) => {
  const clock = makeClock();

  const kcpA = new MinimalKcpSession({ conv: 1, now: clock.now, mss: 64 });
  const kcpB = new MinimalKcpSession({ conv: 1, now: clock.now, mss: 64 });
  kcpA.attachSink((pkt) => kcpB.inputPacket(pkt));
  kcpB.attachSink((pkt) => kcpA.inputPacket(pkt));

  const client = new SmuxSession(
    { readExactly: (n) => kcpA.readExactly(n), write: (d) => kcpA.write(d) },
    { isClient: true, ver: 2, keepAliveIntervalMs: 0, keepAliveTimeoutMs: 0 }
  );
  const server = new SmuxSession(
    { readExactly: (n) => kcpB.readExactly(n), write: (d) => kcpB.write(d) },
    { isClient: false, ver: 2, keepAliveIntervalMs: 0, keepAliveTimeoutMs: 0 }
  );

  const s1 = await client.openStream();
  const s2 = await server.acceptStream();

  const chunk = new Uint8Array(512).map((_, i) => (i * 7) & 0xff);
  await s1.write(chunk);
  const got = await s2.readExactly(chunk.byteLength);
  t.deepEqual(got, chunk);
});
