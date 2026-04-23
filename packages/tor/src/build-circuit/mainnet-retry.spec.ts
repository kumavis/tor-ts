/**
 * Unit tests for the retry helper in build-circuit/mainnet.ts. These tests
 * never touch the live Tor network — they call retryWithCircuit with an
 * injected connect() to drive each attempt's outcome deterministically.
 */

import test from 'ava';
import { isRetryableTorError, retryWithCircuit } from './mainnet.ts';
import type { Circuit } from '../circuit.ts';

type FakeCircuit = Circuit & { destroyCount: number };

function fakeCircuit(): FakeCircuit {
  let destroyCount = 0;
  const c = {
    get destroyCount() {
      return destroyCount;
    },
    destroy() {
      destroyCount += 1;
    },
  };
  return c as unknown as FakeCircuit;
}

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
  // Node-style system errors. The "connect ECONNREFUSED 1.2.3.4:443" form
  // specifically is what we see when a fallback directory is down.
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

test('retryWithCircuit: returns fn result and destroys the circuit on success', async (t) => {
  const c = fakeCircuit();
  const got = await retryWithCircuit(
    async (circuit) => {
      t.is(circuit, c);
      return 42;
    },
    { connect: async () => c }
  );
  t.is(got, 42);
  t.is(c.destroyCount, 1);
});

test('retryWithCircuit: retries on a retryable DESTROY then succeeds', async (t) => {
  const circuits = [fakeCircuit(), fakeCircuit(), fakeCircuit()];
  const retried: Array<{ attempt: number; message: string }> = [];
  let n = 0;

  const got = await retryWithCircuit(
    async () => {
      n += 1;
      if (n === 1) throw new Error('circuit destroyed: CHANNEL_CLOSED (8)');
      if (n === 2) throw new Error('connect ECONNRESET');
      return 'ok';
    },
    {
      connect: async () => circuits[n]!,
      onRetry: (attempt, err) => retried.push({ attempt, message: err.message }),
    }
  );

  t.is(got, 'ok');
  t.is(n, 3);
  t.deepEqual(retried, [
    { attempt: 1, message: 'circuit destroyed: CHANNEL_CLOSED (8)' },
    { attempt: 2, message: 'connect ECONNRESET' },
  ]);
  // All three circuits (including the failed ones) must be cleaned up.
  for (const c of circuits) t.is(c.destroyCount, 1);
});

test('retryWithCircuit: propagates non-retryable errors on the first attempt', async (t) => {
  const c = fakeCircuit();
  let retryCalls = 0;
  await t.throwsAsync(
    retryWithCircuit(
      async () => {
        throw new Error('caller bug: no such module');
      },
      {
        connect: async () => c,
        onRetry: () => {
          retryCalls += 1;
        },
      }
    ),
    { message: /caller bug/ }
  );
  t.is(retryCalls, 0, 'retry hook must not fire for non-retryable errors');
  t.is(c.destroyCount, 1, 'circuit must still be cleaned up');
});

test('retryWithCircuit: surfaces the last error after exhausting attempts', async (t) => {
  const circuits = [fakeCircuit(), fakeCircuit(), fakeCircuit()];
  let n = 0;
  await t.throwsAsync(
    retryWithCircuit(
      async () => {
        n += 1;
        throw new Error(`circuit destroyed: TIMEOUT (10) [try ${n}]`);
      },
      {
        connect: async () => circuits[n]!,
        maxAttempts: 3,
      }
    ),
    { message: /try 3\]/ }
  );
  t.is(n, 3);
  for (const c of circuits) t.is(c.destroyCount, 1);
});

test('retryWithCircuit: maxAttempts=1 does not retry', async (t) => {
  const c = fakeCircuit();
  let n = 0;
  await t.throwsAsync(
    retryWithCircuit(
      async () => {
        n += 1;
        throw new Error('circuit destroyed: CHANNEL_CLOSED (8)');
      },
      { connect: async () => c, maxAttempts: 1 }
    ),
    { message: /CHANNEL_CLOSED/ }
  );
  t.is(n, 1);
  t.is(c.destroyCount, 1);
});

test('retryWithCircuit: rejects maxAttempts < 1', async (t) => {
  await t.throwsAsync(
    retryWithCircuit(async () => 1, { connect: async () => fakeCircuit(), maxAttempts: 0 }),
    { message: /maxAttempts/ }
  );
});

test('retryWithCircuit: custom shouldRetry overrides the default predicate', async (t) => {
  const c = fakeCircuit();
  let n = 0;
  const got = await retryWithCircuit(
    async () => {
      n += 1;
      if (n === 1) throw new Error('weird non-standard error');
      return 'ok';
    },
    {
      connect: async () => c,
      shouldRetry: (err) => err instanceof Error && err.message.includes('weird'),
    }
  );
  t.is(got, 'ok');
  t.is(n, 2);
});

test('retryWithCircuit: bootstrap failure (connect() throws) is also retried', async (t) => {
  let connectCalls = 0;
  const c = fakeCircuit();
  const got = await retryWithCircuit(async () => 'done', {
    connect: async () => {
      connectCalls += 1;
      if (connectCalls === 1) throw new Error('circuit destroyed: CHANNEL_CLOSED (8)');
      return c;
    },
  });
  t.is(got, 'done');
  t.is(connectCalls, 2);
  t.is(c.destroyCount, 1);
});

test('retryWithCircuit: survives a destroy() that throws during cleanup', async (t) => {
  const c = {
    destroy() {
      throw new Error('internal: already destroyed');
    },
  } as unknown as Circuit;
  const got = await retryWithCircuit(async () => 'ok', { connect: async () => c });
  t.is(got, 'ok');
});
