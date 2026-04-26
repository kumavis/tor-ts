/**
 * Tests for circuit operations.
 */

import test from 'ava';
import { circuitIdLengthForProtocolVersion, CircuitStream } from './circuit.ts';

test('circuitIdLengthForProtocolVersion: returns 2 for version undefined', (t) => {
  const length = circuitIdLengthForProtocolVersion(undefined);
  t.is(length, 2);
});

test('circuitIdLengthForProtocolVersion: returns 2 for version 1', (t) => {
  const length = circuitIdLengthForProtocolVersion(1);
  t.is(length, 2);
});

test('circuitIdLengthForProtocolVersion: returns 2 for version 2', (t) => {
  const length = circuitIdLengthForProtocolVersion(2);
  t.is(length, 2);
});

test('circuitIdLengthForProtocolVersion: returns 2 for version 3', (t) => {
  const length = circuitIdLengthForProtocolVersion(3);
  t.is(length, 2);
});

test('circuitIdLengthForProtocolVersion: returns 4 for version 4', (t) => {
  const length = circuitIdLengthForProtocolVersion(4);
  t.is(length, 4);
});

test('circuitIdLengthForProtocolVersion: returns 4 for version 5', (t) => {
  const length = circuitIdLengthForProtocolVersion(5);
  t.is(length, 4);
});

// CircuitStream error handling tests
//
// PromiseLatch on connectionLatch means orphan rejections (destroy() with no
// awaiter) are inert by construction; these tests no longer need a manual
// `connectionLatch.wait().catch(() => {})` around each call.

test('CircuitStream: destroy with error emits error event', async (t) => {
  const stream = new CircuitStream();
  const testError = new Error('test error');

  const errorPromise = new Promise<Error>((resolve) => {
    stream.on('error', (err) => resolve(err));
  });

  stream.destroy(testError);

  const emittedError = await errorPromise;
  t.is(emittedError.message, 'test error');
});

test('CircuitStream: destroy with error emits end event separately', async (t) => {
  const stream = new CircuitStream();
  const testError = new Error('test error');
  const events: string[] = [];

  stream.on('error', () => events.push('error'));
  stream.on('end', () => events.push('end'));

  stream.destroy(testError);

  // Give a tick for events to be processed
  await new Promise((resolve) => setImmediate(resolve));

  t.deepEqual(events, ['error', 'end']);
});

test('CircuitStream: destroy without error emits only end event', async (t) => {
  const stream = new CircuitStream();
  const events: string[] = [];

  stream.on('error', () => events.push('error'));
  stream.on('end', () => events.push('end'));

  stream.destroy();

  // Give a tick for events to be processed
  await new Promise((resolve) => setImmediate(resolve));

  t.deepEqual(events, ['end']);
});

test('CircuitStream: destroy with error rejects connectionLatch', async (t) => {
  const stream = new CircuitStream();
  const testError = new Error('connection failed');

  stream.destroy(testError);

  await t.throwsAsync(stream.connectionLatch.wait(), {
    message: 'connection failed',
  });
});

test('CircuitStream: destroy without error does not reject connectionLatch', async (t) => {
  const stream = new CircuitStream();

  // Resolve the latch first (simulating successful connection)
  stream.connectionLatch.resolve();

  // Then destroy without error
  stream.destroy();

  // Should not throw
  await stream.connectionLatch.wait();
  t.pass();
});

test('CircuitStream: source ReadableStream errors when stream destroyed with error', async (t) => {
  const stream = new CircuitStream();
  const testError = new Error('stream error');
  const reader = stream.source.getReader();

  // Destroy the stream with an error
  stream.destroy(testError);

  // Reading should throw the error
  await t.throwsAsync(reader.read(), {
    message: 'stream error',
  });
});

test('CircuitStream: multiple destroy calls are idempotent', async (t) => {
  const stream = new CircuitStream();
  const testError = new Error('test error');
  let errorCount = 0;

  stream.on('error', () => errorCount++);

  stream.destroy(testError);
  stream.destroy(testError);
  stream.destroy(new Error('different error'));

  // Give a tick for events to be processed
  await new Promise((resolve) => setImmediate(resolve));

  // Should only emit error once
  t.is(errorCount, 1);
  t.true(stream.destroyed);
});

// Orphan-rejection regression tests: PromiseLatch must NOT surface an
// unhandledRejection when reject() runs before any wait() has been called.
// Before PromiseLatch we needed a centrally-installed no-op .catch(); these
// tests assert the new pattern is inherently safe.

test.serial(
  'CircuitStream: destroy(err) before any connectionLatch awaiter does not surface unhandledRejection',
  async (t) => {
    const unhandled: unknown[] = [];
    const listener = (reason: unknown): void => {
      unhandled.push(reason);
    };
    process.on('unhandledRejection', listener);
    try {
      const stream = new CircuitStream();
      stream.destroy(new Error('orphan reject'));
      // Two macrotask flushes — Node fires unhandledRejection on the next
      // microtask tick after the rejection settles.
      await new Promise<void>((r) => setImmediate(r));
      await new Promise<void>((r) => setImmediate(r));
      t.deepEqual(unhandled, [], 'no unhandled rejection leaked');
    } finally {
      process.removeListener('unhandledRejection', listener);
    }
  }
);

test('CircuitStream: late wait() after destroy(err) still observes the rejection', async (t) => {
  const stream = new CircuitStream();
  stream.destroy(new Error('observed-late'));
  await t.throwsAsync(stream.connectionLatch.wait(), { message: 'observed-late' });
});

test('CircuitStream: destroy(err) after connection succeeded does not throw', async (t) => {
  const stream = new CircuitStream();
  stream.connectionLatch.resolve();

  // PromiseLatch.reject() on an already-resolved latch would throw; destroy()
  // must guard the call so a late RELAY_END after a successful RELAY_CONNECTED
  // doesn't crash the destroy path.
  t.notThrows(() => stream.destroy(new Error('late RELAY_END')));

  // Original resolution is preserved — the connection was successful.
  await stream.connectionLatch.wait();
  t.true(stream.destroyed);
});
