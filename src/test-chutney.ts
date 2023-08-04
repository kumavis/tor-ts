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
} from './directory'

/* chutney testing instructions:

start
```sh
./chutney configure networks/basic-min
./chutney start networks/basic-min
./chutney status networks/basic-min
./chutney wait_for_bootstrap networks/basic-min
./chutney verify networks/basic-min
```

stop
```sh
./chutney hup networks/basic-min
./chutney stop networks/basic-min
```

restart
```sh
./chutney stop networks/basic-min
./chutney start networks/basic-min
./chutney status networks/basic-min
./chutney wait_for_bootstrap networks/basic-min
./chutney verify networks/basic-min
```
*/

function filterRelaysByFlags (relays: MicroDescNodeInfo[], flags: string[], ignoreList: MicroDescNodeInfo[] = []): MicroDescNodeInfo[] {
  const matchingRelays = relays.filter(relayInfo => {
    const flagMatches = flags.every(flag => relayInfo.flags.includes(flag))
    if (!flagMatches) return false
    const isIgnored = ignoreList.find(ignoredNodeInfo => {
      return ignoredNodeInfo === relayInfo || ignoredNodeInfo.rsaIdDigest.equals(relayInfo.rsaIdDigest)
    })
    if (isIgnored) return false
    return true
  })
  return matchingRelays
}

function pickRelayWithFlags (relays: MicroDescNodeInfo[], flags: string[], ignoreList: MicroDescNodeInfo[] = []) {
  const matchingRelays = filterRelaysByFlags(relays, flags, ignoreList)
  if (matchingRelays.length === 0) {
    throw new Error(`Failed to find any matching relays for [${flags}] from ${relays.length} relays`)
  }
  // console.log(`matching`, flags, matchingRelays)
  const randomIndex = Math.floor(Math.random() * matchingRelays.length)
  return matchingRelays[randomIndex]
}

async function getRandomChutneyCircuitPath () {
  const loopback = '127.0.0.1'
  const directoryServer = `${loopback}:7000`
  const microDescContent = await downloadMicrodescFromDirectory(directoryServer)
  const microDescNodeInfos = parseRelaysFromMicroDesc(microDescContent)

  const circuitPlan: Array<MicroDescNodeInfo> = []
  circuitPlan.push(pickRelayWithFlags(microDescNodeInfos, ['Exit'], circuitPlan))
  circuitPlan.push(pickRelayWithFlags(microDescNodeInfos, [], circuitPlan))
  circuitPlan.push(pickRelayWithFlags(microDescNodeInfos, ['Guard'], circuitPlan))
  
  const circuitPeerInfos: Array<PeerInfo> = await Promise.all(circuitPlan.map(async (relayInfo) => {
    return await dangerouslyLookupPeerInfo(directoryServer, relayInfo)
  }))
  // reverse so that gateway is first and exit is last
  circuitPeerInfos.reverse()

  return circuitPeerInfos
}

async function getStandardChutneyCircuitPath () {
  const loopback = '127.0.0.1'
  const directoryServer = `${loopback}:7000`
  const microDescContent = await downloadMicrodescFromDirectory(directoryServer)
  const microDescNodeInfos = parseRelaysFromMicroDesc(microDescContent)

  const circuitPlan: Array<MicroDescNodeInfo> = []
  circuitPlan.push(microDescNodeInfos.find(nodeInfo => nodeInfo.onion_router_port === 5002))
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

// circuit.sendRequest()