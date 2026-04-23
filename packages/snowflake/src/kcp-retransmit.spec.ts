import test from 'ava';
import { MinimalKcpSession } from './kcp/session.ts';
import { decodeKcpSegmentsFromPacket, KCP_CMD } from './kcp/segment.ts';

// A clock that advances only when tests explicitly call tick().
function fakeClock(): { now: () => number; tick: (ms: number) => void; set: (ms: number) => void } {
  let t = 0;
  return {
    now: () => t,
    tick: (ms) => {
      t += ms;
    },
    set: (ms) => {
      t = ms;
    },
  };
}

test('kcp: stream-mode writes coalesce up to MSS', async (t) => {
  const clock = fakeClock();
  const conv = 1;
  const emitted: Uint8Array[] = [];

  const a = new MinimalKcpSession({ conv, now: clock.now, mss: 10 });
  a.attachSink((pkt) => emitted.push(pkt));

  // Three small writes totalling 8 bytes must coalesce into ONE PUSH segment
  // (MSS=10, so everything fits in one segment).
  a.write(Uint8Array.from([1, 2, 3]));
  a.write(Uint8Array.from([4, 5, 6]));
  a.write(Uint8Array.from([7, 8]));

  // Flushing is microtask-batched; yield once so coalesced segments emit.
  await Promise.resolve();

  const pushSegs = emitted
    .flatMap(decodeKcpSegmentsFromPacket)
    .filter((s) => s.cmd === KCP_CMD.PUSH);
  t.is(pushSegs.length, 1, 'expected coalesced single PUSH segment');
  t.deepEqual(pushSegs[0]!.data, Uint8Array.from([1, 2, 3, 4, 5, 6, 7, 8]));
});

test('kcp: write > MSS splits into multiple segments', async (t) => {
  const clock = fakeClock();
  const emitted: Uint8Array[] = [];
  const a = new MinimalKcpSession({ conv: 1, now: clock.now, mss: 3 });
  a.attachSink((pkt) => emitted.push(pkt));
  a.write(Uint8Array.from([1, 2, 3, 4, 5, 6, 7]));
  await Promise.resolve();

  const pushSegs = emitted
    .flatMap(decodeKcpSegmentsFromPacket)
    .filter((s) => s.cmd === KCP_CMD.PUSH);
  t.is(pushSegs.length, 3);
  t.deepEqual(pushSegs[0]!.data, Uint8Array.from([1, 2, 3]));
  t.deepEqual(pushSegs[1]!.data, Uint8Array.from([4, 5, 6]));
  t.deepEqual(pushSegs[2]!.data, Uint8Array.from([7]));
});

test('kcp: retransmits a dropped PUSH when RTO expires and update() is called', async (t) => {
  const clock = fakeClock();
  const conv = 0xabc;

  const a = new MinimalKcpSession({ conv, now: clock.now, mss: 100, rtoInitial: 50 });
  const b = new MinimalKcpSession({ conv, now: clock.now, mss: 100 });

  let dropsLeft = 1;
  a.attachSink((pkt) => {
    if (dropsLeft > 0) {
      dropsLeft -= 1;
      return; // simulate server-side queue drop
    }
    b.inputPacket(pkt);
  });
  b.attachSink((pkt) => a.inputPacket(pkt));

  a.write(Uint8Array.from([1, 2, 3, 4, 5]));
  await Promise.resolve(); // drain microtask-batched flush
  t.is(a.inflight, 1, 'segment is pending ACK');

  // Without update(), readExactly hangs forever — race against a short timeout
  // to prove that before update() there is no delivery.
  const readPromise = b.readExactly(5);
  const hangGuard = new Promise<'hang'>((resolve) => setTimeout(() => resolve('hang'), 20));
  const raced = await Promise.race([readPromise.then(() => 'ok' as const), hangGuard]);
  t.is(raced, 'hang', 'data must be undeliverable until retransmit');

  // Advance clock past RTO; update() should retransmit and b should receive it.
  clock.tick(100);
  a.update();
  const got = await readPromise;
  t.deepEqual(got, Uint8Array.from([1, 2, 3, 4, 5]));
  t.is(a.inflight, 0, 'segment ACKed after retransmit');
});

test('kcp: una piggybacked on any segment trims sender buffer', async (t) => {
  const clock = fakeClock();
  const conv = 0xdef;

  const a = new MinimalKcpSession({ conv, now: clock.now, mss: 3 });
  const emitted: Uint8Array[] = [];

  a.attachSink((pkt) => emitted.push(pkt));

  a.write(Uint8Array.from([1, 2, 3, 4, 5, 6])); // 2 segments (sn=0, sn=1)
  await Promise.resolve();
  t.is(a.inflight, 2);

  // Feed back a WINS carrying una=2 (peer claims to have received 0 and 1).
  const winsWithUna = encodeAckLikeSeg(conv, 2);
  a.inputPacket(winsWithUna);
  t.is(a.inflight, 0, 'both segments trimmed by una');
});

test('kcp: dead link raises error after too many retransmits', async (t) => {
  const clock = fakeClock();
  const a = new MinimalKcpSession({
    conv: 1,
    now: clock.now,
    mss: 10,
    rtoInitial: 10,
    deadLink: 3,
  });
  const errors: Error[] = [];
  a.onError((err) => errors.push(err));
  a.attachSink(() => {}); // nothing ever gets through (simulated total carrier loss)

  a.write(Uint8Array.from([1]));
  await Promise.resolve();
  // xmit=1 after initial write. Advance clock through 3 retransmits.
  for (let i = 0; i < 5; i++) {
    clock.tick(10_000);
    a.update();
  }

  t.true(errors.length > 0, 'dead link error was emitted');
  t.regex(errors[0]!.message, /dead link/);
});

test('kcp: update() on closed session is a no-op', (t) => {
  const clock = fakeClock();
  const a = new MinimalKcpSession({ conv: 1, now: clock.now });
  a.attachSink(() => {});
  a.close();
  t.is(a.update(), 0);
});

test('kcp: out-of-order PUSH is buffered and delivered in order after gap fills', async (t) => {
  const clock = fakeClock();
  const conv = 1;
  const a = new MinimalKcpSession({ conv, now: clock.now, mss: 5 });
  const b = new MinimalKcpSession({ conv, now: clock.now, mss: 5 });

  // Intercept a's outbound traffic, reorder the first two segments.
  const pending: Uint8Array[] = [];
  let bypass = false;
  a.attachSink((pkt) => {
    if (bypass) {
      b.inputPacket(pkt);
      return;
    }
    pending.push(pkt);
  });
  b.attachSink((pkt) => a.inputPacket(pkt));

  a.write(Uint8Array.from([1, 2, 3, 4, 5, 6, 7, 8])); // 2 segs (sn0=[1..5], sn1=[6..8])
  await Promise.resolve();
  t.is(pending.length, 2);

  // Deliver sn=1 first, then sn=0. In-order delivery must still produce 1..8.
  bypass = true;
  b.inputPacket(pending[1]!); // sn=1 arrives first — should be buffered
  b.inputPacket(pending[0]!); // sn=0 fills the gap — both get flushed
  const got = await b.readExactly(8);
  t.deepEqual(got, Uint8Array.from([1, 2, 3, 4, 5, 6, 7, 8]));
});

// Build a minimal segment whose only purpose is carrying an `una` value.
function encodeAckLikeSeg(conv: number, una: number): Uint8Array {
  const out = new Uint8Array(24);
  const view = new DataView(out.buffer);
  view.setUint32(0, conv, true);
  view.setUint8(4, KCP_CMD.ACK);
  view.setUint8(5, 0);
  view.setUint16(6, 0, true);
  view.setUint32(8, 0, true);
  view.setUint32(12, 0xffff_ffff, true); // sn that won't match any unacked entry
  view.setUint32(16, una, true);
  view.setUint32(20, 0, true);
  return out;
}
