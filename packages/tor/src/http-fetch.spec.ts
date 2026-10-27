import test from 'ava';
import { EventEmitter } from 'node:events';
import { createRequire, syncBuiltinESMExports } from 'node:module';
import { Circuit, CircuitStream } from './circuit.ts';
import { TorClient } from './client.ts';
import { fetchViaTorCircuit } from './http-fetch.ts';

const response = Buffer.from('HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello');
const onion = 'http://test.onion/';

function fixture(write: (stream: CircuitStream) => Promise<void>) {
  const channel = { getProtocolVersion: () => 4, subscribeCircuit: () => () => {} };
  const circuit = new Circuit({ path: [], channel: channel as unknown as Circuit['channel'] });
  const stream = new CircuitStream();
  stream.connectionLatch.resolve();
  stream.write = () => write(stream);
  circuit.openStream = () => stream;
  circuit.streams.push(stream);
  const client = new TorClient({ fetchOverCircuit: fetchViaTorCircuit } as ConstructorParameters<
    typeof TorClient
  >[0]);
  client.connectToHiddenService = async () => ({
    circuit,
    introPoints: [],
    destroy: () => circuit.destroy({ preserveChannel: true }),
  });
  return { client, circuit, stream };
}

test('HTTP content-length success survives TorClient circuit cleanup', async (t) => {
  const { client, stream } = fixture(async (s) => {
    s.emit('data', response);
  });
  const ownedBefore = stream.listeners('error');
  let externalEnd = 0;
  const onEnd = () => {
    externalEnd++;
  };
  stream.on('end', onEnd);
  const result = await client.fetch(onion);
  t.is(result.status, 200);
  t.is(Buffer.from(result.body).toString(), 'hello');
  t.true(stream.destroyed);
  t.deepEqual(stream.listeners('error'), ownedBefore);
  t.true(stream.listeners('end').includes(onEnd));
  t.is(externalEnd, 1);
});

test('HTTP errors before completion still reject with the original error', async (t) => {
  const failure = new Error('response transport failed');
  const { client } = fixture(async (s) => {
    s.emit('data', Buffer.from('HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nshort'));
    s.destroy(failure);
  });
  t.is(await t.throwsAsync(client.fetch(onion)), failure);
});

test('HTTP request write failure rejects instead of becoming an unhandled promise', async (t) => {
  const failure = new Error('request write failed');
  const { client } = fixture(async () => {
    throw failure;
  });
  t.is(await t.throwsAsync(client.fetch(onion)), failure);
});

test('HTTP timeout remains the reported error after circuit cleanup', async (t) => {
  const { client, stream } = fixture(async () => {});
  const ownErrorListeners = stream.listeners('error');
  await t.throwsAsync(client.fetch(onion, { timeout: 5 }), { message: /HTTP response timeout/ });
  t.deepEqual(stream.listeners('error'), ownErrorListeners);
});

test('HTTP redirects clean only the completed response listeners', async (t) => {
  let request = 0;
  const { circuit, stream } = fixture(async (s) => {
    s.emit(
      'data',
      request++ === 0
        ? Buffer.from('HTTP/1.1 302 Found\r\nLocation: /next\r\nContent-Length: 0\r\n\r\n')
        : response
    );
  });
  const first = stream;
  const second = new CircuitStream();
  second.connectionLatch.resolve();
  second.write = async () => {
    second.emit('data', response);
  };
  circuit.openStream = () => (request === 0 ? first : second);
  const listeners = first.listeners('error');
  const result = await fetchViaTorCircuit(circuit, onion);
  t.is(result.status, 200);
  t.true(first.destroyed);
  t.deepEqual(first.listeners('error'), listeners);
  second.destroy();
});

// Stub only Node's TLS handshake/socket; retain the real CircuitStream,
// HTTP reader and public TorClient cleanup path.
const nodeTls = createRequire(import.meta.url)('node:tls') as typeof import('node:tls');
async function withTlsSocket(
  run: (socket: EventEmitter & { reply?: () => void }) => Promise<void>
) {
  const original = nodeTls.connect;
  const socket = new EventEmitter() as EventEmitter & {
    reply?: () => void;
    write: () => boolean;
    destroy: (err?: Error) => void;
  };
  socket.write = () => {
    socket.reply?.();
    return true;
  };
  let destroyed = false;
  socket.destroy = (err) => {
    if (destroyed) return;
    destroyed = true;
    queueMicrotask(() => {
      if (err) socket.emit('error', err);
      socket.emit('close');
    });
  };
  nodeTls.connect = (() => {
    queueMicrotask(() => socket.emit('secureConnect'));
    return socket;
  }) as unknown as typeof nodeTls.connect;
  syncBuiltinESMExports();
  try {
    await run(socket);
  } finally {
    nodeTls.connect = original;
    syncBuiltinESMExports();
  }
}

test.serial(
  'HTTPS content-length success preserves TLS and stream lifecycle handlers',
  async (t) => {
    await withTlsSocket(async (socket) => {
      const { client, stream } = fixture(async () => {});
      const streamErrors = stream.listeners('error');
      const externalSocketEnd = () => {};
      socket.on('end', externalSocketEnd);
      socket.reply = () => {
        socket.emit('data', response);
      };
      const result = await client.fetch('https://test.onion/');
      t.is(result.status, 200);
      t.is(Buffer.from(result.body).toString(), 'hello');
      await new Promise((resolve) => setImmediate(resolve));
      t.deepEqual(stream.listeners('error'), streamErrors);
      t.true(socket.listeners('end').includes(externalSocketEnd));
    });
  }
);

test.serial('HTTPS underlying circuit failure reaches the pending HTTP reader', async (t) => {
  await withTlsSocket(async (socket) => {
    const { client, stream } = fixture(async () => {});
    const failure = new Error('TLS circuit failed');
    socket.reply = () => {
      stream.destroy(failure);
    };
    t.is(await t.throwsAsync(client.fetch('https://test.onion/')), failure);
  });
});

test('HTTP synchronous write failure rejects without leaving a pending response timer', async (t) => {
  const failure = new Error('synchronous write failed');
  const { client } = fixture(() => {
    throw failure;
  });
  t.is(await t.throwsAsync(client.fetch(onion)), failure);
});

test.serial('HTTPS synchronous write failure remains visible to the HTTP reader', async (t) => {
  await withTlsSocket(async (socket) => {
    const { client } = fixture(async () => {});
    const failure = new Error('synchronous TLS write failed');
    socket.reply = () => {
      throw failure;
    };
    t.is(await t.throwsAsync(client.fetch('https://test.onion/')), failure);
  });
});

test.serial(
  'HTTPS handshake write failure propagates through the real Node TLS adapter',
  async (t) => {
    const failure = new Error('TLS handshake write failed');
    const { client, stream } = fixture(async () => {
      throw failure;
    });
    const errors = stream.listeners('error');
    t.is(await t.throwsAsync(client.fetch('https://test.onion/')), failure);
    await new Promise((resolve) => setImmediate(resolve));
    t.deepEqual(stream.listeners('error'), errors);
  }
);
