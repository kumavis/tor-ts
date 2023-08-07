import http, { ClientRequest } from 'http'
import https from 'https'
import url from 'url'
import { Circuit, CircuitStream } from './circuit'
import { Readable, Writable, Duplex } from 'stream'


// https - can be given to https.get({ agent, ... })
export class CircuitHttpsAgent extends https.Agent {
  circuit: Circuit
  constructor (circuit: Circuit, opts?: http.AgentOptions) {
    super(opts)
    this.circuit = circuit
  }
  createConnection(req): ClientRequest {
    const urlDetails = url.parse(`//${req.hostname}:${req.port}`, false, true)
    const port = urlDetails.port ? Number.parseInt(urlDetails.port, 10) : 443
    const target = `${urlDetails.hostname}:${port}`
    const circuitStream = this.circuit.openStream(target)
    const duplexNodeStream = circuitStreamToNodeDuplex(circuitStream) as ClientRequest
    // Nodejs docs suggest this returns a Socket but in reality it returns a ClientRequest (?)
    // called by 'node:_http_client' via 'node-fetch' so I'm adding it here
    duplexNodeStream.setTimeout = () => {}
    // very sorry about this
    return (duplexNodeStream as unknown as ClientRequest)
  }
}

// http - can be given to http.get({ agent, ... })
export class CircuitHttpAgent extends http.Agent {
  circuit: Circuit
  constructor (circuit: Circuit, opts?: http.AgentOptions) {
    super(opts)
    this.circuit = circuit
    this.createConnection = makeHttpCreateConnectionFnForCircuit(circuit)
  }
}

export function makeHttpCreateConnectionFnForCircuit (circuit: Circuit) {
  return (req) => {
    const urlDetails = url.parse(`//${req.hostname}:${req.port}`, false, true)
    const port = urlDetails.port ? Number.parseInt(urlDetails.port, 10) : 443
    const target = `${urlDetails.hostname}:${port}`
    const circuitStream = circuit.openStream(target)
    const duplexNodeStream = circuitStreamToNodeDuplex(circuitStream)
    return duplexNodeStream
  }
}

// TODO: this should be replaced by "circuitStreamToNodeDuplex" when the issue can be resolved
export function proxyCircuitStreamDuplex (circuitStream: CircuitStream, remoteStream: Duplex) {
  proxyCircuitStream (circuitStream, remoteStream, remoteStream)
}

export function proxyCircuitStream (circuitStream: CircuitStream, inStream: Readable, outStream: Writable) {
  circuitStream.on('data', (data) => {
    // console.log(`Received data from end: ${data.length}`)
    outStream.write(data)
  })
  circuitStream.on('end', (err) => {
    if (err) {
      console.log('circuit disconnected with error')
      console.error(err)
      outStream.end()
      return
    }
    console.log('circuit disconnected')
    outStream.end()
  })
  inStream.on('data', (data) => {
    console.log(`Received data from start: ${data.length}`)
    circuitStream.write(data)
  })
  inStream.on('error', (err) => {
    console.log('Client errored', err)
    circuitStream.destroy()
  })
  inStream.on('end', () => {
    console.log('Request ended')
  })
}

export const circuitStreamToNodeDuplex = (circuitStream: CircuitStream): Duplex => {
  console.log('circuitStreamToNodeDuplex')
  // write into circuitStream
  const nodeDuplexStream = new Duplex({
    read(size) {
      // no means of triggering read
    },
    write(chunk, encoding, callback) {
      console.log('writing to circuitStream')

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
      nodeDuplexStream.push(value)
      console.log('reading value from circuitStream')

      ;({ done, value } = await reader.read())
    }
    console.log('done reading from circuitStream')

    nodeDuplexStream.push(null)
    reader.releaseLock()
  })
  circuitStream.on('end', (err) => {
    nodeDuplexStream.end(err)
  })
  return nodeDuplexStream
}

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
