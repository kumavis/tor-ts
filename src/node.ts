import http from 'http'
import { Circuit, CircuitStream } from './circuit'
import { circuitStreamToNodeDuplex } from './node-streams'
import { Readable, Writable, Duplex } from 'stream'


export class CircuitAgent extends http.Agent {
  circuit: Circuit
  constructor (circuit: Circuit, opts?: http.AgentOptions) {
    super(opts)
    this.circuit = circuit
  }
  createConnection(req) {
    const urlDetails = url.parse(`//${req.hostname}:${req.port}`, false, true)
    const port = urlDetails.port ? Number.parseInt(urlDetails.port, 10) : 443
    const target = `${urlDetails.hostname}:${port}`
    const circuitStream = this.circuit.openStream(target)
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
