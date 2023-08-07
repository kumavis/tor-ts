import net from 'node:net'
import { Circuit } from './circuit'
import type { PeerInfo } from './circuit'
import { TlsChannelConnection } from './channel';
import {
  linkSpecifierToAddressAndPort,
} from './messaging'
import {
  downloadMicrodescFromDirectory,
  parseRelaysFromMicroDesc,
  MicroDescNodeInfo,
  dangerouslyLookupPeerInfo,
} from './build-circuit/directory'



async function getStandardChutneyCircuitPath () {
  const loopback = '127.0.0.1'
  const directoryServer = `${loopback}:7000`
  const microDescContent = await downloadMicrodescFromDirectory(directoryServer)
  const microDescNodeInfos = parseRelaysFromMicroDesc(microDescContent)

  const circuitPlan: Array<MicroDescNodeInfo> = []
  circuitPlan.push(microDescNodeInfos.find(nodeInfo => nodeInfo.onion_router_port === 5004))
  circuitPlan.push(microDescNodeInfos.find(nodeInfo => nodeInfo.onion_router_port === 5001))
  circuitPlan.push(microDescNodeInfos.find(nodeInfo => nodeInfo.onion_router_port === 5000))
  
  const circuitPeerInfos: Array<PeerInfo> = await Promise.all(circuitPlan.map(async (relayInfo) => {
    return await dangerouslyLookupPeerInfo(directoryServer, relayInfo)
  }))
  // reverse so that gateway is first and exit is last
  circuitPeerInfos.reverse()

  return circuitPeerInfos
}

// choose relays
const circuitPeerInfos = await getStandardChutneyCircuitPath()

const gatewayPeerInfo = circuitPeerInfos[0]
const gatewayAddress = linkSpecifierToAddressAndPort(gatewayPeerInfo.linkSpecifiers[0])

// console.log(circuitPeerInfos.map(info => {
//   const addressAndPort = linkSpecifierToAddressAndPort(info.linkSpecifiers[0])
//   return `${addressAndPort.ip}:${addressAndPort.port}`
// }).join('\n'))
// console.log(gatewayPeerInfo, gatewayAddress)

const channel = new TlsChannelConnection()
await channel.connect(gatewayAddress)
const circuit = new Circuit({
  path: circuitPeerInfos,
  channel,
})
await circuit.connect()
console.log('circuit established')
// await circuit.open('localhost:5000')
// console.log('connection established')

const port = 1234
const server = net.createServer()
server.listen(port, () => {
  console.log(`Server started and listening on port ${port}`)
})
server.on('connection', async (socket) => {
  console.log('New client connected')
  const circuitStream = await circuit.open('kumavis.me:80')
  // const circuitStream = await circuit.open('kumavis.me:443')
  console.log('connection established')
  
  circuitStream.on('data', (data) => {
    console.log(`Received data from end: ${data.length}`)
    socket.write(data)
  })
  circuitStream.on('end', (err) => {
    if (err) {
      console.log('circuit disconnected with error')
      console.error(err)
      socket.end()
      return
    }
    console.log('circuit disconnected')
    socket.end()
  })
  socket.on('data', (data) => {
    console.log(`Received data from start: ${data.length}`)
    circuitStream.write(data)
  })
  socket.on('error', (err) => {
    console.log('Client errored', err)
    circuitStream.destroy()
  })
  socket.on('end', () => {
    console.log('Client disconnected')
  })
})


// circuit.sendRequest()