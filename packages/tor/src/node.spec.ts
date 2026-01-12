/**
 * Tests for node.ts stream adapters - error forwarding.
 */

import test from 'ava';
import { Readable, Writable } from 'node:stream';
import { CircuitStream } from './circuit.ts';
import { circuitStreamToNodeDuplex, proxyCircuitStream, webRSToNodeRS } from './node.ts';

// circuitStreamToNodeDuplex tests

test('circuitStreamToNodeDuplex: forwards error event from CircuitStream', async (t) => {
  const circuitStream = new CircuitStream();
  const duplex = circuitStreamToNodeDuplex(circuitStream);

  // Catch the connectionPromiseKit rejection to prevent unhandled rejection
  circuitStream.connectionPromiseKit.promise.catch(() => {});

  const errorPromise = new Promise<Error>((resolve) => {
    duplex.on('error', (err) => resolve(err));
  });

  const testError = new Error('circuit error');
  circuitStream.destroy(testError);

  const receivedError = await errorPromise;
  t.is(receivedError.message, 'circuit error');
});

test('circuitStreamToNodeDuplex: destroys duplex when CircuitStream ends', async (t) => {
  const circuitStream = new CircuitStream();
  const duplex = circuitStreamToNodeDuplex(circuitStream);

  const closePromise = new Promise<void>((resolve) => {
    duplex.on('close', () => resolve());
  });

  circuitStream.destroy();

  await closePromise;
  t.true(duplex.destroyed);
});

test('circuitStreamToNodeDuplex: propagates read errors from source', async (t) => {
  const circuitStream = new CircuitStream();
  const duplex = circuitStreamToNodeDuplex(circuitStream);

  // Catch the connectionPromiseKit rejection to prevent unhandled rejection
  circuitStream.connectionPromiseKit.promise.catch(() => {});

  const errorPromise = new Promise<Error>((resolve) => {
    duplex.on('error', (err) => resolve(err));
  });

  // Destroy the circuit stream with an error - this should cause the reader to fail
  const testError = new Error('read error');
  circuitStream.destroy(testError);

  const receivedError = await errorPromise;
  t.is(receivedError.message, 'read error');
});

// proxyCircuitStream tests

test('proxyCircuitStream: forwards data from CircuitStream to outStream', async (t) => {
  const circuitStream = new CircuitStream();
  const inStream = new Readable({ read() {} });
  const chunks: Buffer[] = [];
  const outStream = new Writable({
    write(chunk, _encoding, callback) {
      chunks.push(chunk);
      callback();
    },
  });

  proxyCircuitStream(circuitStream, inStream, outStream);

  // Emit data from circuit stream
  const testData = Buffer.from('hello world');
  circuitStream.emit('data', testData);

  t.is(chunks.length, 1);
  t.deepEqual(chunks[0], testData);
});

test('proxyCircuitStream: ends outStream when CircuitStream errors', async (t) => {
  const circuitStream = new CircuitStream();
  const inStream = new Readable({ read() {} });
  const outStream = new Writable({
    write(_chunk, _encoding, callback) {
      callback();
    },
  });

  // Catch the connectionPromiseKit rejection to prevent unhandled rejection
  circuitStream.connectionPromiseKit.promise.catch(() => {});

  proxyCircuitStream(circuitStream, inStream, outStream);

  const endPromise = new Promise<void>((resolve) => {
    outStream.on('finish', () => resolve());
  });

  // Destroy circuit stream with error
  circuitStream.destroy(new Error('test error'));

  await endPromise;
  t.pass();
});

test('proxyCircuitStream: ends outStream when CircuitStream ends normally', async (t) => {
  const circuitStream = new CircuitStream();
  const inStream = new Readable({ read() {} });
  const outStream = new Writable({
    write(_chunk, _encoding, callback) {
      callback();
    },
  });

  proxyCircuitStream(circuitStream, inStream, outStream);

  const endPromise = new Promise<void>((resolve) => {
    outStream.on('finish', () => resolve());
  });

  // End circuit stream normally
  circuitStream.destroy();

  await endPromise;
  t.pass();
});

test('proxyCircuitStream: destroys CircuitStream when inStream errors', async (t) => {
  const circuitStream = new CircuitStream();
  const inStream = new Readable({ read() {} });
  const outStream = new Writable({
    write(_chunk, _encoding, callback) {
      callback();
    },
  });

  proxyCircuitStream(circuitStream, inStream, outStream);

  // Emit error from inStream
  inStream.emit('error', new Error('input error'));

  t.true(circuitStream.destroyed);
});

// webRSToNodeRS tests

test('webRSToNodeRS: forwards data from ReadableStream to Readable', async (t) => {
  const chunks = [Buffer.from('hello'), Buffer.from('world')];
  let index = 0;

  const webStream = new ReadableStream<Uint8Array>({
    pull(controller) {
      if (index < chunks.length) {
        controller.enqueue(chunks[index]!);
        index++;
      } else {
        controller.close();
      }
    },
  });

  const nodeStream = webRSToNodeRS(webStream);
  const received: Buffer[] = [];

  await new Promise<void>((resolve) => {
    nodeStream.on('data', (chunk) => received.push(chunk));
    nodeStream.on('end', () => resolve());
  });

  t.is(received.length, 2);
  t.deepEqual(received[0], chunks[0]);
  t.deepEqual(received[1], chunks[1]);
});

test('webRSToNodeRS: destroys Readable when ReadableStream errors', async (t) => {
  const testError = new Error('web stream error');

  const webStream = new ReadableStream<Uint8Array>({
    start(controller) {
      // Immediately error the stream
      controller.error(testError);
    },
  });

  const nodeStream = webRSToNodeRS(webStream);

  const errorPromise = new Promise<Error>((resolve) => {
    nodeStream.on('error', (err) => resolve(err));
  });

  const receivedError = await errorPromise;
  t.is(receivedError.message, 'web stream error');
});

test('webRSToNodeRS: handles empty ReadableStream', async (t) => {
  const webStream = new ReadableStream<Uint8Array>({
    start(controller) {
      controller.close();
    },
  });

  const nodeStream = webRSToNodeRS(webStream);

  const endPromise = new Promise<void>((resolve) => {
    nodeStream.on('end', () => resolve());
  });

  // Need to consume the stream for 'end' to fire
  nodeStream.resume();

  await endPromise;
  t.pass();
});
