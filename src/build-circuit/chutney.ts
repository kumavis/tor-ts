import { PeerInfo } from '../circuit'
import {
  downloadMicrodescFromDirectory,
  parseRelaysFromMicroDesc,
  MicroDescNodeInfo,
  dangerouslyLookupPeerInfo,
} from './directory'
import { pickRelayWithFlags } from './util'

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


export async function getStandardChutneyCircuitPath () {
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

export async function getRandomChutneyCircuitPath () {
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
