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

test('CircuitStream: destroy with error emits error event', async (t) => {
  const stream = new CircuitStream();
  const testError = new Error('test error');

  // Catch the connectionPromiseKit rejection to prevent unhandled rejection
  stream.connectionPromiseKit.promise.catch(() => {});

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

  // Catch the connectionPromiseKit rejection to prevent unhandled rejection
  stream.connectionPromiseKit.promise.catch(() => {});

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

test('CircuitStream: destroy with error rejects connectionPromiseKit', async (t) => {
  const stream = new CircuitStream();
  const testError = new Error('connection failed');

  stream.destroy(testError);

  await t.throwsAsync(stream.connectionPromiseKit.promise, {
    message: 'connection failed',
  });
});

test('CircuitStream: destroy without error does not reject connectionPromiseKit', async (t) => {
  const stream = new CircuitStream();

  // Resolve the promise first (simulating successful connection)
  stream.connectionPromiseKit.resolve();

  // Then destroy without error
  stream.destroy();

  // Should not throw
  await stream.connectionPromiseKit.promise;
  t.pass();
});

test('CircuitStream: source ReadableStream errors when stream destroyed with error', async (t) => {
  const stream = new CircuitStream();
  const testError = new Error('stream error');
  const reader = stream.source.getReader();

  // Catch the connectionPromiseKit rejection to prevent unhandled rejection
  stream.connectionPromiseKit.promise.catch(() => {});

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

  // Catch the connectionPromiseKit rejection to prevent unhandled rejection
  stream.connectionPromiseKit.promise.catch(() => {});

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
