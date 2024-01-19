import { getRandomCircuitPath } from './build-circuit/mainnet'
import { Circuit, TlsChannelConnection } from './index'
import { SnowflakeChannelConnection } from './snowflake'

main()

async function main () {
  // const target = 'http://api.ipify.org'
  // TODO: this is broken for some reason
  // Error: bad response
  // 400 The plain HTTP request was sent to HTTPS port
  const target = 'https://api.ipify.org'

  const circuit = await setupTor()
  // const ipAddresResult = await makeWebRequest(circuit, target)
  // circuit.destroy()

  // console.log('my ip address is:', ipAddresResult)
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