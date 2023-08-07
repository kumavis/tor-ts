import { getRandomCircuitPath } from '../../src/build-circuit/mainnet'
import { Circuit, TlsChannelConnection, chutney } from '../../src/index'
import { getCircuitAgentForUrl } from '../../src/node'

import fetch from 'node-fetch'


main()

async function main () {
  // const target = 'http://api.ipify.org'
  // TODO: this is broken for some reason
  // Error: bad response
  // 400 The plain HTTP request was sent to HTTPS port
  const target = 'https://api.ipify.org'

  const circuit = await setupTor()
  const ipAddresResult = await makeWebRequest(circuit, target)

  console.log('my ip address is:', ipAddresResult)
}

async function setupTor () {
  // choose relays
  const circuitPeerInfos = await getRandomCircuitPath()
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
  // "agent" is a non-standard fetch option supported by node-fetch and http.get
  const agent = getCircuitAgentForUrl(circuit, target)
  const response = await fetch(target, {
    agent,
  })
  console.log('got response:', response.status)
  if (response.status !== 200) {
    const body = await response.text()
    throw new Error(`bad response (${response.status}): ${body}`)
  }
  return response.text()
}
