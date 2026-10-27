/**
 * Tests for circuit operations.
 */

import test from 'ava';
import { circuitIdLengthForProtocolVersion, Circuit, CircuitStream } from './circuit.ts';
import type { ChannelConnection } from './channel.ts';
import { MessageCells, serializeRelayCellPayload, type MessageCell } from './messaging.ts';
import { RelayCell } from './relay-cell.ts';

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

function circuitLifecycleHarness() {
  const sent: Array<{ command: number; circuitId?: Buffer; payload?: Buffer }> = [];
  let unsubscribed = 0;
  const channel = {
    destroyed: false,
    getProtocolVersion: () => 4,
    subscribeCircuit: () => () => {
      unsubscribed++;
    },
    sendMessage(command: number) {
      sent.push({ command });
    },
    sendMessageWithPayload(circuitId: Buffer, command: number, payload: Buffer) {
      sent.push({ circuitId, command, payload });
    },
    destroy() {
      this.destroyed = true;
    },
  };
  const circuit = new Circuit({
    path: [{ onionKey: Buffer.alloc(0), rsaIdDigest: Buffer.alloc(20), linkSpecifiers: [] }],
    channel: channel as unknown as ChannelConnection,
  });
  return {
    circuit,
    channel,
    sent,
    get unsubscribed() {
      return unsubscribed;
    },
  };
}

test('Circuit.connect timeout releases its subscription and remote circuit without closing the channel', async (t) => {
  const h = circuitLifecycleHarness();
  await t.throwsAsync(h.circuit.connect({ timeoutMs: 10 }), { message: /handshake timeout/ });
  t.true(h.circuit.isDestroyed);
  t.false(h.channel.destroyed);
  t.is(h.unsubscribed, 1);
  t.deepEqual(
    h.sent.map((cell) => cell.command),
    [MessageCells.CREATE_FAST, MessageCells.DESTROY]
  );
  t.deepEqual(h.sent[1]!.circuitId, h.circuit.circuitId);
  t.deepEqual(h.sent[1]!.payload, Buffer.from([3]));
  h.circuit.destroy({ preserveChannel: true });
  t.is(h.sent.length, 2, 'idempotent cleanup sends only one DESTROY');
});

test('Circuit.destroy wakes a pending build while preserving its channel', async (t) => {
  const h = circuitLifecycleHarness();
  const building = h.circuit.connect({ timeoutMs: 1000 });
  h.circuit.destroy({ preserveChannel: true });
  await t.throwsAsync(building, { message: 'Circuit destroyed' });
  t.is(h.unsubscribed, 1);
  t.false(h.channel.destroyed);
});

test('Circuit.destroy before CREATE does not send a spurious DESTROY', (t) => {
  const h = circuitLifecycleHarness();
  h.circuit.destroy({ preserveChannel: true });
  t.deepEqual(h.sent, []);
  t.is(h.unsubscribed, 1);
  t.false(h.channel.destroyed);
});

test('Remote DESTROY closes the local circuit without echoing DESTROY or closing the shared channel', async (t) => {
  const h = circuitLifecycleHarness();
  const building = h.circuit.connect({ timeoutMs: 1000 });
  h.circuit.receiveMessage({
    command: MessageCells.DESTROY,
    message: { reason: 3 },
  } as MessageCell);
  await t.throwsAsync(building, { message: /circuit destroyed: REQUESTED/ });
  t.true(h.circuit.isDestroyed);
  t.false(h.channel.destroyed);
  t.is(h.unsubscribed, 1);
  t.deepEqual(
    h.sent.map((cell) => cell.command),
    [MessageCells.CREATE_FAST]
  );
});

test('Circuit cleanup finishes if its channel cannot send DESTROY', async (t) => {
  const h = circuitLifecycleHarness();
  const building = h.circuit.connect({ timeoutMs: 1000 });
  h.channel.sendMessageWithPayload = () => {
    throw new Error('channel closed');
  };
  t.notThrows(() => h.circuit.destroy({ preserveChannel: true }));
  await t.throwsAsync(building, { message: 'Circuit destroyed' });
  t.is(h.unsubscribed, 1);
  t.true(h.circuit.isDestroyed);
});

test('A relay reply still decrypting when the circuit closes is discarded', async (t) => {
  const h = circuitLifecycleHarness();
  const hop = h.circuit.hops[0]!;
  hop.isConnected = true;
  hop.handshakeLatch.resolve();
  let release!: (payload: Buffer<ArrayBuffer>) => void;
  let witnessed = false;
  hop.decryptBackward = () =>
    new Promise<Buffer<ArrayBuffer>>((resolve) => {
      release = resolve;
    });
  hop.witnessBackwardPayload = () => {
    witnessed = true;
  };
  const payload = serializeRelayCellPayload({
    streamId: 0,
    relayCommand: RelayCell.EXTENDED2,
    data: Buffer.concat([Buffer.from([0, 64]), Buffer.alloc(64)]),
  });
  const receiving = h.circuit.receiveRelayMessage({ payload });
  h.circuit.destroy({ preserveChannel: true });
  release(Buffer.from(payload));
  await t.notThrowsAsync(receiving);
  t.false(witnessed, 'the abandoned reply never reaches protocol dispatch');
  t.is(h.unsubscribed, 1);
});

test('An asynchronous CREATED2 failure rejects the build and cleans up its circuit', async (t) => {
  const h = circuitLifecycleHarness();
  const failure = new Error('handshake processing failed');
  h.circuit.firstHop.receiveCreated2Handshake = async () => {
    throw failure;
  };
  const building = h.circuit.connect({ timeoutMs: 1000 });
  const rejected = t.throwsAsync(building, { is: failure });
  h.circuit.receiveMessage({
    command: MessageCells.CREATED2,
    message: { handshake: { data: Buffer.alloc(64) } },
  } as MessageCell);
  await rejected;
  t.true(h.circuit.isDestroyed);
  t.false(h.channel.destroyed);
  t.is(h.unsubscribed, 1);
});
