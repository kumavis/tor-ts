import { Circuit, TlsChannelConnection, chutney } from '../../src/index'
import { makeHttpCreateConnectionFnForCircuit } from '../../src/node'

import fetch from 'node-fetch'


main()

async function main () {
  const target = 'https://kumavis.me'

  const circuit = await setupTor()
  await makeWebRequest(circuit, target)
}

async function setupTor () {
  // choose relays
  const circuitPeerInfos = await chutney.getStandardChutneyCircuitPath()
  const gatewayPeerInfo = circuitPeerInfos[0]
  const channel = new TlsChannelConnection()
  await channel.connectPeerInfo(gatewayPeerInfo)
  const circuit = new Circuit({
    path: circuitPeerInfos,
    channel,
  })
  await circuit.connect()
  console.log('circuit established')
  return circuit
}

async function makeWebRequest (circuit, target) {
  // "createConnection" is a non-standard fetch option supported by http.get
  const response = await fetch(target, {
    createConnection: makeHttpCreateConnectionFnForCircuit(circuit),
  })
  console.log('got response:', response.status)
  if (response.status !== 200) {
    throw new Error('bad response')
  }
}
