import http from 'node:http';
import type { ClientRequestArgs } from 'node:http';
import https from 'node:https';
import tls from 'node:tls';
import net from 'node:net';
import url from 'node:url';
import { Circuit, CircuitStream } from './circuit.ts';
import { Readable, Writable, Duplex } from 'node:stream';

// Node HTTP Agent https://nodejs.org/docs/latest-v20.x/api/http.html#class-httpagent
export const getTorAgentForUrl = (
  circuit: Circuit,
  target: string
): CircuitHttpsAgent | CircuitHttpAgent => {
  const urlDetails = url.parse(target, false, true);
  const isHttps = urlDetails.protocol === 'https:';
  if (isHttps) {
    return new CircuitHttpsAgent(circuit);
  } else {
    return new CircuitHttpAgent(circuit);
  }
};

// Node HTTPS Agent https://nodejs.org/docs/latest-v20.x/api/https.html#class-httpsagent
export class CircuitHttpsAgent extends https.Agent {
  circuit: Circuit;
  constructor(circuit: Circuit, opts?: http.AgentOptions) {
    super(opts);
    this.circuit = circuit;
  }
  createConnection(req: ClientRequestArgs): Duplex {
    const duplexStream = makeNodeDuplexStreamForCircuit(this.circuit, req);
    const hostname = req.hostname ?? undefined;
    // re-apply TLS as per https://github.com/TooTallNate/proxy-agents/blob/d5cdaa1b774c699c75b543eb4b112290d261e321/packages/https-proxy-agent/src/index.ts#L144
    // TODO: need to pass all options in here?
    return tls.connect({
      socket: duplexStream,
      servername: hostname && net.isIP(hostname) ? undefined : hostname,
    });
  }
}

// http - can be given to http.get({ agent, ... })
export class CircuitHttpAgent extends http.Agent {
  circuit: Circuit;
  constructor(circuit: Circuit, opts?: http.AgentOptions) {
    super(opts);
    this.circuit = circuit;
  }
  createConnection(req: ClientRequestArgs): Duplex {
    return makeNodeDuplexStreamForCircuit(this.circuit, req);
  }
}

export function makeNodeDuplexStreamForCircuit(circuit: Circuit, req: ClientRequestArgs): Duplex {
  const hostname = req.hostname ?? undefined;
  if (!hostname) {
    throw new Error('request hostname is missing');
  }
  const urlDetails = url.parse(`//${hostname}:${req.port}`, false, true);
  const port = urlDetails.port ? Number.parseInt(urlDetails.port, 10) : 443;
  const target = `${urlDetails.hostname}:${port}`;
  const circuitStream = circuit.openStream(target);
  const duplexStream = circuitStreamToNodeDuplex(circuitStream);

  // The HTTP client stack expects a Socket-like interface here and will call
  // setTimeout() to implement request timeouts. Provide a minimal implementation
  // that emits 'timeout' after the requested delay.
  let timeoutTimer: NodeJS.Timeout | undefined;
  (duplexStream as any).setTimeout = (msecs?: number, callback?: () => void) => {
    if (timeoutTimer) clearTimeout(timeoutTimer);
    const ms = typeof msecs === 'number' ? msecs : 0;
    if (ms > 0) {
      timeoutTimer = setTimeout(() => {
        duplexStream.emit('timeout');
        if (callback) callback();
      }, ms);
      // Best-effort: don't keep the event loop open.
      timeoutTimer.unref?.();
    }
    return duplexStream;
  };

  return duplexStream;
}

// TODO: this should be replaced by "circuitStreamToNodeDuplex" when the issue can be resolved
export function proxyCircuitStreamDuplex(circuitStream: CircuitStream, remoteStream: Duplex) {
  proxyCircuitStream(circuitStream, remoteStream, remoteStream);
}

export function proxyCircuitStream(
  circuitStream: CircuitStream,
  inStream: Readable,
  outStream: Writable
) {
  circuitStream.on('data', (data) => {
    // console.log(`Received data from end: ${data.length}`)
    outStream.write(data);
  });
  circuitStream.on('error', (err) => {
    console.log('circuitstream disconnected with error:', err.message);
    outStream.end();
  });
  circuitStream.on('end', () => {
    console.log('circuitstream disconnected');
    outStream.end();
  });
  inStream.on('data', (data) => {
    console.log(`Received data from start: ${data.length}`);
    circuitStream.write(data);
  });
  inStream.on('error', (err) => {
    console.log('Client errored', err);
    circuitStream.destroy();
  });
  inStream.on('end', () => {
    console.log('Request ended');
  });
}

export const circuitStreamToNodeDuplex = (circuitStream: CircuitStream): Duplex => {
  // write into circuitStream
  const writer = circuitStream.sink.getWriter();
  const nodeDuplexStream = new Duplex({
    read(_size) {
      // no means of triggering read
    },
    write(chunk, encoding, callback) {
      console.log('writing to circuitStream');

      writer
        .write(chunk)
        .then(() => {
          callback();
        })
        .catch((err) => {
          callback(err);
        });
    },
  });
  // read from circuitStream
  const reader = circuitStream.source.getReader();
  reader
    .read()
    .then(async (result) => {
      let { value, done } = result as ReadableStreamReadResult<Uint8Array>;
      while (!done) {
        nodeDuplexStream.push(value);
        console.log('reading value from circuitStream');
        ({ done, value } = (await reader.read()) as ReadableStreamReadResult<Uint8Array>);
      }
      console.log('done reading from circuitStream');

      nodeDuplexStream.push(null);
      reader.releaseLock();
    })
    .catch((err) => {
      // Handle errors from reader.read() - e.g., stream was destroyed with an error
      console.log('circuit stream reader error:', err.message);
      nodeDuplexStream.destroy(err);
    });
  // Handle errors emitted by the circuit stream
  circuitStream.on('error', (err) => {
    console.log('circuit stream error:', err.message);
    nodeDuplexStream.destroy(err);
  });
  circuitStream.on('end', () => {
    console.log('circuit stream disconnected');
    nodeDuplexStream.destroy();
  });
  return nodeDuplexStream;
};

// utilities for working with Node.js streams

// window.ReadableStream to Node.js Readable
export const webRSToNodeRS = (rs: ReadableStream<Uint8Array>) => {
  const reader = rs.getReader();
  const out = new Readable({
    read() {
      // no means of triggering read - data is pushed as it arrives
    },
  });
  reader
    .read()
    .then(async (result) => {
      let { value, done } = result as ReadableStreamReadResult<Uint8Array>;
      while (!done) {
        out.push(value);
        ({ done, value } = (await reader.read()) as ReadableStreamReadResult<Uint8Array>);
      }
      out.push(null);
    })
    .catch((err) => {
      // Handle errors from reader.read()
      out.destroy(err);
    });
  return out;
};

// window.WritableStream to Node.js Writable
export const webWSToNodeWS = (ws: WritableStream<Uint8Array>) => {
  const writer = ws.getWriter();
  const out = new Writable();
  out._write = (chunk, encoding, callback) => {
    writer.write(chunk as Uint8Array);
    callback();
  };
  out._final = (callback) => {
    writer.close();
    callback();
  };
  return out;
};
