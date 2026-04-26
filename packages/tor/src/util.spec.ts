/**
 * PromiseLatch tests.
 *
 * The latch is the replacement for `Promise.withResolvers()` in places where
 * `reject()` may run before any caller has called `wait()` (the canonical
 * orphan-rejection case in `Hop` and `CircuitStream`). The big invariant we
 * test here: rejecting a latch nobody is waiting on must NOT surface as a
 * Node `unhandledRejection`.
 */

import test from 'ava';
import { PromiseLatch } from './util.ts';

test('PromiseLatch: wait() before resolve() observes the resolution', async (t) => {
  const latch = new PromiseLatch<number>();
  const p = latch.wait();
  latch.resolve(7);
  t.is(await p, 7);
});

test('PromiseLatch: wait() before reject() observes the rejection', async (t) => {
  const latch = new PromiseLatch<number>();
  const p = latch.wait();
  latch.reject(new Error('boom'));
  await t.throwsAsync(p, { message: 'boom' });
});

test('PromiseLatch: late wait() after resolve() resolves immediately', async (t) => {
  const latch = new PromiseLatch<string>();
  latch.resolve('done');
  t.is(await latch.wait(), 'done');
});

test('PromiseLatch: late wait() after reject() rejects with the same error', async (t) => {
  const latch = new PromiseLatch<void>();
  latch.reject(new Error('observed-late'));
  await t.throwsAsync(latch.wait(), { message: 'observed-late' });
});

test('PromiseLatch: multiple wait()ers each observe the same resolution', async (t) => {
  const latch = new PromiseLatch<number>();
  const a = latch.wait();
  const b = latch.wait();
  latch.resolve(42);
  t.is(await a, 42);
  t.is(await b, 42);
});

test('PromiseLatch: multiple wait()ers each observe the same rejection', async (t) => {
  const latch = new PromiseLatch<void>();
  const a = latch.wait().catch((e) => `a:${(e as Error).message}`);
  const b = latch.wait().catch((e) => `b:${(e as Error).message}`);
  latch.reject(new Error('shared'));
  t.is(await a, 'a:shared');
  t.is(await b, 'b:shared');
});

// Settling twice is a programmer error — the latch is one-shot. Loud failure
// surfaces real bugs (handling a response twice, racing two destroy paths
// against the success path) instead of silently dropping the second call.

test('PromiseLatch: a second resolve() throws', async (t) => {
  const latch = new PromiseLatch<number>();
  latch.resolve(1);
  t.throws(() => latch.resolve(2), {
    message: /already-resolved/,
  });
  // Original value is preserved.
  t.is(await latch.wait(), 1);
});

test('PromiseLatch: reject() after resolve() throws', async (t) => {
  const latch = new PromiseLatch<number>();
  latch.resolve(1);
  t.throws(() => latch.reject(new Error('too late')), {
    message: /already-resolved/,
  });
  t.is(await latch.wait(), 1);
});

test('PromiseLatch: resolve() after reject() throws', async (t) => {
  const latch = new PromiseLatch<number>();
  latch.reject(new Error('first'));
  t.throws(() => latch.resolve(1), {
    message: /already-rejected/,
  });
  await t.throwsAsync(latch.wait(), { message: 'first' });
});

test('PromiseLatch: a second reject() throws', (t) => {
  const latch = new PromiseLatch<void>();
  latch.reject(new Error('first'));
  t.throws(() => latch.reject(new Error('second')), {
    message: /already-rejected/,
  });
});

test('PromiseLatch: callers can guard with isPending() to keep idempotent semantics', (t) => {
  const latch = new PromiseLatch<void>();
  // Pattern used in CircuitStream.destroy: only settle if pending.
  if (latch.isPending()) latch.resolve();
  if (latch.isPending()) latch.reject(new Error('would-have-thrown'));
  t.true(latch.isSettled());
});

test('PromiseLatch: isPending / isSettled track state correctly', (t) => {
  const a = new PromiseLatch<void>();
  t.true(a.isPending());
  t.false(a.isSettled());
  a.resolve();
  t.false(a.isPending());
  t.true(a.isSettled());

  const b = new PromiseLatch<void>();
  b.reject(new Error('x'));
  t.false(b.isPending());
  t.true(b.isSettled());
});

// The whole reason PromiseLatch exists: a bare reject() with no waiter must
// NOT trigger Node's unhandledRejection. Run serial so the global listener
// install/remove can't race with other parallel tests.
test.serial(
  'PromiseLatch: reject() with no waiter does not surface unhandledRejection',
  async (t) => {
    const unhandled: unknown[] = [];
    const listener = (reason: unknown): void => {
      unhandled.push(reason);
    };
    process.on('unhandledRejection', listener);
    try {
      const latch = new PromiseLatch<void>();
      latch.reject(new Error('orphan'));
      // Two macrotask flushes give Node a chance to fire unhandledRejection
      // for any actual orphan.
      await new Promise<void>((r) => setImmediate(r));
      await new Promise<void>((r) => setImmediate(r));
      t.deepEqual(unhandled, [], 'no unhandled rejection leaked');
    } finally {
      process.removeListener('unhandledRejection', listener);
    }
  }
);
