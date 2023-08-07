import { Duplex, Readable, Writable } from 'stream';
import { CircuitStream } from './circuit';

// utilities for working with Node.js streams

// window.ReadableStream to Node.js Readable
export const webRSToNodeRS = rs => {
  const reader = rs.getReader();
  const out = new Readable();
  reader.read().then(async ({ value, done }) => {
    while (!done) {
      out.push(value);
      ({ done, value } = await reader.read());
    }
    out.push(null);
  });
  return out;
}

// window.WritableStream to Node.js Writable
export const webWSToNodeWS = ws => {
  const writer = ws.getWriter();
  const out = new Writable();
  out._write = (chunk, encoding, callback) => {
    writer.write(chunk);
    callback();
  };
  out._final = callback => {
    writer.close();
    callback();
  };
  return out;
}

export const circuitStreamToNodeDuplex = (circuitStream: CircuitStream): Duplex => {
  // write into circuitStream
  const nodeDuplexStream = new Duplex({
    read(size) {
      // no means of triggering read
    },
    write(chunk, encoding, callback) {
      circuitStream.sink.getWriter().write(chunk)
      .then(() => {
        callback()
      })
      .catch((err) => {
        callback(err)
      })
    },
  })
  // read from circuitStream
  const reader = circuitStream.source.getReader()
  reader.read().then(async ({ value, done }) => {
    while (!done) {
      nodeDuplexStream.push(value);
      ({ done, value } = await reader.read());
    }
    nodeDuplexStream.push(null);
    reader.releaseLock()
  });
  return nodeDuplexStream
}