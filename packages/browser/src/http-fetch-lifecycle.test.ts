import { describe, expect, it, vi } from 'vitest';
import { Circuit, CircuitStream } from 'tor/circuit';
import { TorClient } from 'tor';
import { fetchViaTorCircuit } from './http-fetch.ts';

const tlsMock = vi.hoisted(() => ({
  onWrite: undefined as
    | undefined
    | ((callbacks: {
        onApplicationData(data: Uint8Array): void;
        onTlsEnd(error?: Error): void;
      }) => void),
}));
vi.mock('@reclaimprotocol/tls', () => ({
  setCryptoImplementation: () => {},
  makeTLSClient: (callbacks: {
    onHandshake(): void;
    onApplicationData(data: Uint8Array): void;
    onTlsEnd(error?: Error): void;
  }) => ({
    startHandshake: async () => {
      callbacks.onHandshake();
    },
    write: async () => {
      tlsMock.onWrite?.(callbacks);
    },
    handleReceivedBytes: async () => {},
    end: async () => {},
  }),
}));

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

describe('HTTP transport listener ownership', () => {
  it('returns a complete response through real TorClient cleanup and preserves unrelated listeners', async () => {
    const { client, stream } = fixture(async (s) => {
      s.emit('data', response);
    });
    const errors = stream.listeners('error');
    let ended = 0;
    const onEnd = () => {
      ended++;
    };
    stream.on('end', onEnd);
    const result = await client.fetch(onion);
    expect(result.status).toBe(200);
    expect(Buffer.from(result.body).toString()).toBe('hello');
    expect(stream.destroyed).toBe(true);
    expect(stream.listeners('error')).toEqual(errors);
    expect(stream.listeners('end')).toContain(onEnd);
    expect(ended).toBe(1);
  });
  it('still rejects incomplete responses on genuine stream errors', async () => {
    const failure = new Error('response transport failed');
    const { client } = fixture(async (s) => {
      s.emit('data', Buffer.from('HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nshort'));
      s.destroy(failure);
    });
    await expect(client.fetch(onion)).rejects.toBe(failure);
  });
  it('reports write failures and preserves lifecycle listeners', async () => {
    const failure = new Error('request write failed');
    const { client, stream } = fixture(async () => {
      throw failure;
    });
    const errors = stream.listeners('error');
    await expect(client.fetch(onion)).rejects.toBe(failure);
    expect(stream.listeners('error')).toEqual(errors);
  });
  it('reports timeout rather than a cleanup error', async () => {
    const { client, stream } = fixture(async () => {});
    const errors = stream.listeners('error');
    await expect(client.fetch(onion, { timeout: 5 })).rejects.toThrow('Response timeout');
    expect(stream.listeners('error')).toEqual(errors);
  });
  it('follows redirects without deleting the previous stream lifecycle handlers', async () => {
    let request = 0;
    const { circuit, stream } = fixture(async (s) => {
      request++;
      s.emit(
        'data',
        Buffer.from('HTTP/1.1 302 Found\r\nLocation: /next\r\nContent-Length: 0\r\n\r\n')
      );
    });
    const second = new CircuitStream();
    second.connectionLatch.resolve();
    second.write = async () => {
      second.emit('data', response);
    };
    circuit.openStream = () => (request === 0 ? stream : second);
    const errors = stream.listeners('error');
    const result = await fetchViaTorCircuit(circuit, onion);
    expect(result.status).toBe(200);
    expect(stream.destroyed).toBe(true);
    expect(stream.listeners('error')).toEqual(errors);
    second.destroy();
  });
});

describe('TLS transport listener ownership', () => {
  it('returns completed HTTPS data despite subsequent circuit cleanup', async () => {
    const { client, stream } = fixture(async () => {});
    const errors = stream.listeners('error');
    const onEnd = vi.fn();
    stream.on('end', onEnd);
    tlsMock.onWrite = (callbacks) => {
      callbacks.onApplicationData(response);
    };
    const result = await client.fetch('https://test.onion/');
    expect(result.status).toBe(200);
    expect(Buffer.from(result.body).toString()).toBe('hello');
    for (const errorListener of errors) expect(stream.listeners('error')).toContain(errorListener);
    expect(stream.listeners('end')).toContain(onEnd);
    expect(onEnd).toHaveBeenCalledTimes(1);
  });
  it('forwards underlying circuit errors while the response is pending', async () => {
    const { client, stream } = fixture(async () => {});
    const failure = new Error('TLS circuit failed');
    tlsMock.onWrite = () => {
      stream.destroy(failure);
    };
    await expect(client.fetch('https://test.onion/')).rejects.toBe(failure);
  });
  it('forwards TLS errors while the response is pending', async () => {
    const { client } = fixture(async () => {});
    const failure = new Error('TLS record failed');
    tlsMock.onWrite = (callbacks) => {
      callbacks.onTlsEnd(failure);
    };
    await expect(client.fetch('https://test.onion/')).rejects.toBe(failure);
  });
});

it('reports synchronous raw writes without leaving a pending response timer', async () => {
  const failure = new Error('synchronous write failed');
  const { client } = fixture(() => {
    throw failure;
  });
  await expect(client.fetch(onion)).rejects.toBe(failure);
});

it('reports rejected TLS writes to the response reader', async () => {
  const failure = new Error('TLS write failed');
  const { client } = fixture(async () => {});
  tlsMock.onWrite = () => {
    throw failure;
  };
  await expect(client.fetch('https://test.onion/')).rejects.toBe(failure);
});
