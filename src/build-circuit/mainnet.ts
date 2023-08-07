import { PeerInfo } from "../circuit"
import { MicroDescNodeInfo, dangerouslyLookupPeerInfo, downloadMicrodescFromDirectory, parseRelaysFromMicroDesc } from "./directory"
import { pickRelayWithFlags } from "./util"
import mainnetDirectoryAuthorities from '../directory-authorities.json'

const getRandomDirectoryAuthority = () => {
  const randomIndex = Math.floor(Math.random() * mainnetDirectoryAuthorities.length)
  return mainnetDirectoryAuthorities[randomIndex]
}

export async function getRandomCircuitPath () {
  const directoryServerInfo = getRandomDirectoryAuthority()
  const directoryServer = directoryServerInfo.dir_address
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
