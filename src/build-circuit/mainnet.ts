import { Circuit, PeerInfo } from "../circuit"
import { TlsChannelConnection } from "../channel"
import { MicroDescNodeInfo, dangerouslyLookupPeerInfo, downloadMicrodescFromDirectory, parseRelaysFromMicroDesc } from "./directory"
import { pickRelayWithFlags } from "./util"
import mainnetDirectoryAuthorities from '../directory-authorities.json'

const getRandomDirectoryAuthority = () => {
  const randomIndex = Math.floor(Math.random() * mainnetDirectoryAuthorities.length);
  return mainnetDirectoryAuthorities[randomIndex];
}

export async function getRandomCircuitPath () {
  const directoryServerInfo = getRandomDirectoryAuthority();
  const directoryServer = directoryServerInfo.dir_address;
  const microDescContent = await downloadMicrodescFromDirectory(directoryServer);
  const microDescNodeInfos = parseRelaysFromMicroDesc(microDescContent);
  if (microDescNodeInfos.length === 0) {
    console.warn('microdesc content:', microDescContent)
    throw new Error(`Failed to download relays from directory server (${directoryServer}). No relays parsed from microdesc.`)
  }

  const circuitPlan: Array<MicroDescNodeInfo> = [];
  circuitPlan.push(pickRelayWithFlags(microDescNodeInfos, ['Exit'], circuitPlan));
  circuitPlan.push(pickRelayWithFlags(microDescNodeInfos, [], circuitPlan));
  circuitPlan.push(pickRelayWithFlags(microDescNodeInfos, ['Guard'], circuitPlan));
  
  const circuitPeerInfos: Array<PeerInfo> = await Promise.all(circuitPlan.map(async (relayInfo) => {
    return await dangerouslyLookupPeerInfo(directoryServer, relayInfo);
  }));
  // reverse so that gateway is first and exit is last
  circuitPeerInfos.reverse();

  return circuitPeerInfos;
}

export async function connectRandomCircuit () {
  const circuitPeerInfos = await getRandomCircuitPath();
  const gatewayPeerInfo = circuitPeerInfos[0];
  const channel = new TlsChannelConnection();
  await channel.connectPeerInfo(gatewayPeerInfo)
  const circuit = new Circuit({
    path: circuitPeerInfos,
    channel,
  });
  await circuit.connect();
  return circuit;
}
