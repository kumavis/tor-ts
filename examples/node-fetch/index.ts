import { connectRandomCircuit } from '../../src/build-circuit/mainnet'
import { getTorAgentForUrl } from '../../src/node'

import fetch from 'node-fetch'


main()

async function main () {
  const target = 'https://api.ipify.org'

  const circuit = await setupTor()
  const ipAddresResult = await makeWebRequest(circuit, target)
  circuit.destroy()

  console.log('my ip address is:', ipAddresResult)
}

async function setupTor () {
  const circuit = await connectRandomCircuit()
  console.log('circuit established')
  return circuit
}

async function makeWebRequest (circuit, target) {
  // "agent" is a non-standard fetch option supported by node-fetch and http.get/https.get
  const agent = getTorAgentForUrl(circuit, target)
  const response = await fetch(target, { agent })
  console.log('got response:', response.status)
  if (response.status !== 200) {
    const body = await response.text()
    throw new Error(`bad response (${response.status}): ${body}`)
  }
  return response.text()
}
