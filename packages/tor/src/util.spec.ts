/**
 * Regression tests for tear-down races: a late DESTROY cell arriving on a
 * circuit the caller has already given up on must not create an unhandled
 * promise rejection, and hop-handshake promises that get rejected without an
 * awaiter must not crash the process either.
 *
 * The symptom we fixed looked like this in CI:
 *
 *   Unhandled rejection in index.spec.ts
 *   Error: circuit destroyed: CHANNEL_CLOSED (8)
 *       at Circuit.receiveMessage (.../circuit.ts:695:21)
 *       ...
 *
 * That was a hop's deferred handshake promise getting reject()ed while
 * nobody held a reference — the retry wrapper had already moved on.
 */

import test from 'ava';
import { deferred } from './util.ts';

// Hook unhandledRejection during the test and assert nothing fired.
async function captureUnhandled<T>(
  fn: () => Promise<T>
): Promise<{ result: T; unhandled: unknown[] }> {
  const unhandled: unknown[] = [];
  const listener = (reason: unknown): void => {
    unhandled.push(reason);
  };
  process.on('unhandledRejection', listener);
  try {
    const result = await fn();
    // Let the microtask queue flush so any pending rejection is observed
    // via the 'unhandledRejection' event (fires on next microtask tick).
    await new Promise<void>((r) => setImmediate(r));
    await new Promise<void>((r) => setImmediate(r));
    return { result, unhandled };
  } finally {
    process.removeListener('unhandledRejection', listener);
  }
}

test('deferred(): reject() without an awaiter does not surface as unhandledRejection', async (t) => {
  const { unhandled } = await captureUnhandled(async () => {
    const d = deferred<void>();
    d.reject(new Error('nobody is listening'));
    return undefined;
  });
  t.deepEqual(unhandled, [], 'no unhandled rejection leaked');
});

test('deferred(): awaiters still observe rejection', async (t) => {
  const d = deferred<number>();
  const observed = d.promise.catch((err) => (err as Error).message);
  d.reject(new Error('observed-by-awaiter'));
  t.is(await observed, 'observed-by-awaiter');
});

test('deferred(): multiple awaiters each observe rejection independently', async (t) => {
  const d = deferred<number>();
  const a = d.promise.catch((err) => `a:${(err as Error).message}`);
  const b = d.promise.catch((err) => `b:${(err as Error).message}`);
  d.reject(new Error('x'));
  t.is(await a, 'a:x');
  t.is(await b, 'b:x');
});
