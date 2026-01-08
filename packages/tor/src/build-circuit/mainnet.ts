import { Circuit } from '../circuit.ts';
import type { PeerInfo } from '../circuit.ts';
import { TlsChannelConnection } from '../channel.ts';
import {
  getRandomDirectoryAuthority,
  dangerouslyLookupPeerInfo,
  dangerouslyDownloadMicrodescFromDirectory,
  parseRelaysFromMicroDesc,
} from './directory.ts';
import type { MicroDescNodeInfo } from './directory.ts';
import { pickRelayWithFlags } from './util.ts';

export async function getRandomCircuitPath() {
  // try directory services until successful
  let directoryServer: string | undefined;
  let microDescContent: string | undefined;
  while (!microDescContent) {
    const directoryServerInfo = await getRandomDirectoryAuthority();
    directoryServer = directoryServerInfo.dir_address;
    if (!directoryServer) continue;
    try {
      microDescContent = await dangerouslyDownloadMicrodescFromDirectory(directoryServer);
    } catch {
      // ignore error and attempt again
    }
  }
  if (!directoryServer) {
    throw new Error('Failed to select a directory authority');
  }
  // console.log('microdesc nodeinfos downloaded from', directoryServer)
  // console.log('microdesc content:', microDescContent)

  const microDescNodeInfos = parseRelaysFromMicroDesc(microDescContent);
  if (microDescNodeInfos.length === 0) {
    console.warn('microdesc content:', microDescContent);
    throw new Error(
      `Failed to parwse relays from directory server (${directoryServer}). No relays parsed from microdesc.`
    );
  }
  // console.log('microdesc nodeinfos parsed', microDescNodeInfos)

  // console.log('constructing circuit plan')
  const circuitPlan: Array<MicroDescNodeInfo> = [];
  circuitPlan.push(pickRelayWithFlags(microDescNodeInfos, ['Exit'], circuitPlan));
  circuitPlan.push(pickRelayWithFlags(microDescNodeInfos, [], circuitPlan));
  circuitPlan.push(pickRelayWithFlags(microDescNodeInfos, ['Guard'], circuitPlan));
  // look up PeerInfo for each node
  const circuitPeerInfos: Array<PeerInfo> = await Promise.all(
    circuitPlan.map(async (relayInfo) => {
      return await dangerouslyLookupPeerInfo(directoryServer, relayInfo);
    })
  );
  // console.log('constructing circuit plan complete')

  // reverse so that gateway is first and exit is last
  circuitPeerInfos.reverse();

  return circuitPeerInfos;
}

export async function connectRandomCircuit() {
  const circuitPeerInfos = await getRandomCircuitPath();
  const gatewayPeerInfo = circuitPeerInfos[0];
  if (!gatewayPeerInfo) {
    throw new Error('Failed to build circuit path (no gateway peer)');
  }
  const channel = new TlsChannelConnection();
  await channel.connectPeerInfo(gatewayPeerInfo);
  const circuit = new Circuit({
    path: circuitPeerInfos,
    channel,
  });
  await circuit.connect();
  return circuit;
}
