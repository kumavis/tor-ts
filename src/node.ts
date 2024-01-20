import http, { ClientRequestArgs } from 'http'
import https from 'https'
import tls from 'tls'
import net from 'net'
import url from 'url'
import { Circuit, CircuitStream } from './circuit'
import { Readable, Writable, Duplex } from 'stream'

// Node HTTP Agent https://nodejs.org/docs/latest-v20.x/api/http.html#class-httpagent
export const getTorAgentForUrl = (circuit: Circuit, target: string): CircuitHttpsAgent | CircuitHttpAgent => {
  const urlDetails = url.parse(target, false, true);
  const isHttps = urlDetails.protocol === 'https:';
  if (isHttps) {
    return new CircuitHttpsAgent(circuit);
  } else {
    return new CircuitHttpAgent(circuit);
  }
}

// Node HTTPS Agent https://nodejs.org/docs/latest-v20.x/api/https.html#class-httpsagent
export class CircuitHttpsAgent extends https.Agent {
  circuit: Circuit
  constructor (circuit: Circuit, opts?: http.AgentOptions) {
    super(opts)
    this.circuit = circuit
  }
  createConnection (req: ClientRequestArgs): Duplex {
    const duplexStream = makeNodeDuplexStreamForCircuit(this.circuit, req)
    // re-apply TLS as per https://github.com/TooTallNate/proxy-agents/blob/d5cdaa1b774c699c75b543eb4b112290d261e321/packages/https-proxy-agent/src/index.ts#L144
    // TODO: need to pass all options in here?
    return tls.connect({
      socket: duplexStream,
      servername: net.isIP(req.hostname) ? undefined : req.hostname,
    });
  }
}

// http - can be given to http.get({ agent, ... })
export class CircuitHttpAgent extends http.Agent {
  circuit: Circuit
  constructor (circuit: Circuit, opts?: http.AgentOptions) {
    super(opts)
    this.circuit = circuit
  }
  createConnection (req: ClientRequestArgs): Duplex {
    return makeNodeDuplexStreamForCircuit(this.circuit, req)
  }
}

export function makeNodeDuplexStreamForCircuit(circuit: Circuit, req: ClientRequestArgs): Duplex {
  const urlDetails = url.parse(`//${req.hostname}:${req.port}`, false, true)
  const port = urlDetails.port ? Number.parseInt(urlDetails.port, 10) : 443
  const target = `${urlDetails.hostname}:${port}`
  const circuitStream = circuit.openStream(target)
  const duplexStream = circuitStreamToNodeDuplex(circuitStream)

  // Nodejs docs suggest this can return a Duplex but it frequently returns a Socket
  // and `node-fetch` seems to expect it to return a ClientRequest (?)
  // "setTimeout" is called by 'node:_http_client' via 'node-fetch'
  // adding a stub here to prevent errors
  ;(duplexStream as any).setTimeout = () => { console.warn('CircuitHttpAgent - setTimeout stub called') }

  return duplexStream
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
      console.log('circuitstream  disconnected with error')
      console.error(err)
      outStream.end()
      return
    }
    console.log('circuitstream  disconnected')
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
  // write into circuitStream
  const writer = circuitStream.sink.getWriter()
  const nodeDuplexStream = new Duplex({
    read(size) {
      // no means of triggering read
    },
    write(chunk, encoding, callback) {
      console.log('writing to circuitStream')

      writer.write(chunk)
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
    if (err) {
      console.log('circuit stream disconnected with error')
      console.error(err)
      nodeDuplexStream.destroy(err)
      return
    }
    console.log('circuit stream disconnected')
    nodeDuplexStream.destroy()
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
