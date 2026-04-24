/**
 * Unit tests for the retry helpers in build-circuit/mainnet.ts. These tests
 * never touch the live Tor network — they drive retryTransient directly with
 * synthetic attempt functions.
 */

import test from 'ava';
import { isRetryableTorError, retryTransient } from './mainnet.ts';

test('isRetryableTorError: structured DESTROY with retryable reason', (t) => {
  t.true(isRetryableTorError(new Error('circuit destroyed: CHANNEL_CLOSED (8)')));
  t.true(isRetryableTorError(new Error('circuit destroyed: TIMEOUT (10)')));
  t.true(isRetryableTorError(new Error('circuit destroyed: CONNECTFAILED (6)')));
  t.true(isRetryableTorError(new Error('circuit destroyed: HIBERNATING (4)')));
  t.true(isRetryableTorError(new Error('circuit destroyed: RESOURCELIMIT (5)')));
  t.true(isRetryableTorError(new Error('circuit destroyed: OR_IDENTITY (7)')));
  t.true(isRetryableTorError(new Error('circuit destroyed: DESTROYED (11)')));
});

test('isRetryableTorError: non-retryable DESTROY reasons do not retry', (t) => {
  t.false(isRetryableTorError(new Error('circuit destroyed: NONE (0)')));
  t.false(isRetryableTorError(new Error('circuit destroyed: PROTOCOL (1)')));
  t.false(isRetryableTorError(new Error('circuit destroyed: INTERNAL (2)')));
  t.false(isRetryableTorError(new Error('circuit destroyed: REQUESTED (3)')));
  t.false(isRetryableTorError(new Error('circuit destroyed: FINISHED (9)')));
  t.false(isRetryableTorError(new Error('circuit destroyed: NOSUCHSERVICE (12)')));
});

test('isRetryableTorError: UNKNOWN_<N> falls back to numeric-code check', (t) => {
  t.true(isRetryableTorError(new Error('circuit destroyed: UNKNOWN_8 (8)')));
  t.false(isRetryableTorError(new Error('circuit destroyed: UNKNOWN_99 (99)')));
});

test('isRetryableTorError: transport-level hang-ups', (t) => {
  t.true(isRetryableTorError(new Error('connect ECONNREFUSED 205.185.119.222:443')));
  t.true(isRetryableTorError(new Error('connect ECONNRESET')));
  t.true(isRetryableTorError(new Error('connect ECONNABORTED 1.2.3.4:443')));
  t.true(isRetryableTorError(new Error('read ETIMEDOUT')));
  t.true(isRetryableTorError(new Error('write EPIPE')));
  t.true(isRetryableTorError(new Error('ENETUNREACH 203.0.113.1')));
  t.true(isRetryableTorError(new Error('EHOSTUNREACH')));
  t.true(isRetryableTorError(new Error('ENETDOWN')));
  t.true(isRetryableTorError(new Error('ENETRESET')));
  t.true(isRetryableTorError(new Error('ENOTCONN on socket')));
  t.true(isRetryableTorError(new Error('EPROTO negotiation failed')));
  t.true(isRetryableTorError(new Error('socket hang up')));
  t.true(isRetryableTorError(new Error('Request timed out after 60000ms')));
});

test('isRetryableTorError: unrelated errors do not retry', (t) => {
  t.false(isRetryableTorError(new Error('invalid consensus signature')));
  t.false(isRetryableTorError(new Error('caller forgot to call foo()')));
  t.false(isRetryableTorError('string, not Error'));
  t.false(isRetryableTorError(undefined));
});

test('retryTransient: returns attempt() result on first success', async (t) => {
  let calls = 0;
  const got = await retryTransient(async () => {
    calls += 1;
    return 42;
  });
  t.is(got, 42);
  t.is(calls, 1);
});

test('retryTransient: retries on retryable errors, surfaces last result', async (t) => {
  const retried: Array<{ attempt: number; message: string }> = [];
  let n = 0;
  const got = await retryTransient(
    async () => {
      n += 1;
      if (n === 1) throw new Error('circuit destroyed: CHANNEL_CLOSED (8)');
      if (n === 2) throw new Error('connect ECONNREFUSED 1.2.3.4:443');
      return 'ok';
    },
    { onRetry: (attempt, err) => retried.push({ attempt, message: err.message }) }
  );
  t.is(got, 'ok');
  t.is(n, 3);
  t.deepEqual(retried, [
    { attempt: 1, message: 'circuit destroyed: CHANNEL_CLOSED (8)' },
    { attempt: 2, message: 'connect ECONNREFUSED 1.2.3.4:443' },
  ]);
});

test('retryTransient: non-retryable errors propagate on first attempt', async (t) => {
  let retryCalls = 0;
  let calls = 0;
  await t.throwsAsync(
    retryTransient(
      async () => {
        calls += 1;
        throw new Error('caller bug: no such module');
      },
      { onRetry: () => (retryCalls += 1) }
    ),
    { message: /caller bug/ }
  );
  t.is(calls, 1);
  t.is(retryCalls, 0);
});

test('retryTransient: surfaces the last retryable error after exhausting attempts', async (t) => {
  let n = 0;
  await t.throwsAsync(
    retryTransient(
      async () => {
        n += 1;
        throw new Error(`circuit destroyed: TIMEOUT (10) [try ${n}]`);
      },
      { maxAttempts: 3 }
    ),
    { message: /try 3\]/ }
  );
  t.is(n, 3);
});

test('retryTransient: maxAttempts=1 does not retry', async (t) => {
  let n = 0;
  await t.throwsAsync(
    retryTransient(
      async () => {
        n += 1;
        throw new Error('circuit destroyed: CHANNEL_CLOSED (8)');
      },
      { maxAttempts: 1 }
    ),
    { message: /CHANNEL_CLOSED/ }
  );
  t.is(n, 1);
});

test('retryTransient: rejects maxAttempts < 1', async (t) => {
  await t.throwsAsync(
    retryTransient(async () => 1, { maxAttempts: 0 }),
    {
      message: /maxAttempts/,
    }
  );
});

test('retryTransient: custom shouldRetry overrides the default predicate', async (t) => {
  let n = 0;
  const got = await retryTransient(
    async () => {
      n += 1;
      if (n === 1) throw new Error('weird non-standard error');
      return 'ok';
    },
    { shouldRetry: (err) => err instanceof Error && err.message.includes('weird') }
  );
  t.is(got, 'ok');
  t.is(n, 2);
});

test('retryTransient: backoffMs delays between retries', async (t) => {
  const delaysObserved: number[] = [];
  let lastTick = Date.now();
  let n = 0;
  await retryTransient(
    async () => {
      const now = Date.now();
      if (n > 0) delaysObserved.push(now - lastTick);
      lastTick = now;
      n += 1;
      if (n < 3) throw new Error('circuit destroyed: TIMEOUT (10)');
      return 'ok';
    },
    { maxAttempts: 3, backoffMs: 30 }
  );
  t.is(n, 3);
  t.is(delaysObserved.length, 2);
  for (const d of delaysObserved) t.true(d >= 25, `delay ${d} < 25ms`);
});

test('retryTransient: backoffMs as a function gets the failed-attempt number', async (t) => {
  const calls: number[] = [];
  let n = 0;
  await retryTransient(
    async () => {
      n += 1;
      if (n < 4) throw new Error('circuit destroyed: TIMEOUT (10)');
      return 'ok';
    },
    {
      maxAttempts: 4,
      backoffMs: (failedAttempt) => {
        calls.push(failedAttempt);
        return 0; // don't actually sleep in the test
      },
    }
  );
  t.deepEqual(calls, [1, 2, 3]);
});

test('retryTransient: retry budgets compose as expected', async (t) => {
  // Model the expected layered behavior: an "outer" loop (operation-level)
  // calls an "inner" loop (bootstrap-level). Each has its own budget; the
  // combined worst case is outer * inner attempts.
  let bootstrapCalls = 0;
  let opCalls = 0;

  const got = await retryTransient(
    async () => {
      opCalls += 1;
      // Inner retry simulates buildCircuitWithRetry: 2 attempts max.
      const fakeCircuit = await retryTransient(
        async () => {
          bootstrapCalls += 1;
          if (bootstrapCalls === 1) {
            throw new Error('connect ECONNREFUSED 1.2.3.4:443');
          }
          return { id: bootstrapCalls };
        },
        { maxAttempts: 2 }
      );
      // On op attempt 1 the circuit "dies" after successful build.
      if (opCalls === 1) {
        throw new Error('circuit destroyed: CHANNEL_CLOSED (8)');
      }
      return fakeCircuit;
    },
    { maxAttempts: 2 }
  );

  t.is(opCalls, 2);
  // Inner budget exhausted by first bootstrap ECONNREFUSED, so on the second
  // opCall the inner bootstrap succeeds on its first try (counter keeps
  // incrementing across the outer retry).
  t.is(bootstrapCalls, 3);
  t.deepEqual(got, { id: 3 });
});
