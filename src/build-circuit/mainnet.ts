import { Circuit, PeerInfo } from "../circuit"
import { TlsChannelConnection } from "../channel"
import { MicroDescNodeInfo, dangerouslyLookupPeerInfo, downloadMicrodescFromDirectory, parseRelaysFromMicroDesc } from "./directory"
import { pickRelayWithFlags, pickRelayWithFlagsAndVerify } from "./util"
import mainnetDirectoryAuthorities from '../directory-authorities.json'

const getRandomDirectoryAuthority = () => {
  const randomIndex = Math.floor(Math.random() * mainnetDirectoryAuthorities.length);
  return mainnetDirectoryAuthorities[randomIndex];
}

export async function getRandomCircuitPath () {
  // try directory services until successful
  let directoryServer: string;
  let microDescContent: string;
  while (microDescContent === undefined) {
    const directoryServerInfo = getRandomDirectoryAuthority();
    directoryServer = directoryServerInfo.dir_address;
    try {
      microDescContent = await downloadMicrodescFromDirectory(directoryServer);
    } catch (_err) {
      // ignore error and attempt again
    }
  }
  // console.log('microdesc nodeinfos downloaded from', directoryServer)

  const microDescNodeInfos = parseRelaysFromMicroDesc(microDescContent);
  if (microDescNodeInfos.length === 0) {
    console.warn('microdesc content:', microDescContent)
    throw new Error(`Failed to parwse relays from directory server (${directoryServer}). No relays parsed from microdesc.`)
  }

  // console.log('constructing circuit plan')
  const circuitPlan: Array<MicroDescNodeInfo> = [];
  circuitPlan.push(pickRelayWithFlags(microDescNodeInfos, ['Exit'], circuitPlan));
  circuitPlan.push(pickRelayWithFlags(microDescNodeInfos, [], circuitPlan));
  circuitPlan.push(pickRelayWithFlags(microDescNodeInfos, ['Guard'], circuitPlan));
  // look up PeerInfo for each node
  const circuitPeerInfos: Array<PeerInfo> = await Promise.all(circuitPlan.map(async (relayInfo) => {
    return await dangerouslyLookupPeerInfo(directoryServer, relayInfo);
  }));
  // console.log('constructing circuit plan complete')

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
