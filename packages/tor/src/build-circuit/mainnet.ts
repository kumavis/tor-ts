import { Circuit } from '../circuit.ts';
import type { PeerInfo } from '../circuit.ts';
import { TlsChannelConnection } from '../channel.ts';
import { SnowflakeTlsChannelConnection } from '../snowflake/channel.ts';
import {
  dangerouslyLookupOnionKey,
  dangerouslyLookupPeerInfo,
  downloadMicrodescFromDirectory,
  parseRelaysFromMicroDesc,
} from './directory.ts';
import type { MicroDescNodeInfo } from './directory.ts';
import { pickRelayWithFlags } from './util.ts';
import { createRequire } from 'node:module';
import { LinkSpecifierTypes } from '../messaging.ts';

const require = createRequire(import.meta.url);
const mainnetDirectoryAuthorities = require('../directory-authorities.json') as Array<{
  dir_address?: string;
}>;

const getRandomDirectoryAuthority = () => {
  const randomIndex = Math.floor(Math.random() * mainnetDirectoryAuthorities.length);
  const selected = mainnetDirectoryAuthorities[randomIndex];
  if (!selected) {
    throw new Error('Failed to pick a directory authority');
  }
  return selected;
};

export async function getRandomCircuitPath() {
  // try directory services until successful
  let directoryServer: string | undefined;
  let microDescContent: string | undefined;
  while (!microDescContent) {
    const directoryServerInfo = getRandomDirectoryAuthority();
    if (!directoryServerInfo.dir_address) {
      continue;
    }
    directoryServer = directoryServerInfo.dir_address;
    try {
      microDescContent = await downloadMicrodescFromDirectory(directoryServer);
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

async function getDirectoryMicrodesc() {
  let directoryServer: string | undefined;
  let microDescContent: string | undefined;
  while (!microDescContent) {
    const directoryServerInfo = getRandomDirectoryAuthority();
    if (!directoryServerInfo.dir_address) continue;
    directoryServer = directoryServerInfo.dir_address;
    try {
      microDescContent = await downloadMicrodescFromDirectory(directoryServer);
    } catch {
      // ignore and retry
    }
  }
  if (!directoryServer) throw new Error('Failed to select a directory authority');
  const microDescNodeInfos = parseRelaysFromMicroDesc(microDescContent);
  if (microDescNodeInfos.length === 0) {
    throw new Error(`No relays parsed from microdesc at ${directoryServer}`);
  }
  return { directoryServer, microDescNodeInfos };
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

export async function connectSnowflakeCircuit(opts: {
  relayUrl?: string;
} = {}) {
  const { directoryServer, microDescNodeInfos } = await getDirectoryMicrodesc();

  const channel = new SnowflakeTlsChannelConnection();
  await channel.connect(opts.relayUrl ? { relayUrl: opts.relayUrl } : {});

  const entryRsaIdDigest = channel.peerIdentity?.rsaIdDigest;
  if (!entryRsaIdDigest) {
    throw new Error('Snowflake channel has no peer identity (handshake incomplete?)');
  }
  const entryOnionKey = await dangerouslyLookupOnionKey(directoryServer, entryRsaIdDigest);
  const entryPeerInfo: PeerInfo = {
    onionKey: entryOnionKey,
    rsaIdDigest: entryRsaIdDigest,
    linkSpecifiers: [
      {
        type: LinkSpecifierTypes.LegacyId,
        data: entryRsaIdDigest,
      },
    ],
  };

  // Pick middle+exit, excluding entry fingerprint.
  const ignoreEntry = [{ rsaIdDigest: entryRsaIdDigest } as MicroDescNodeInfo];
  const exitNode = pickRelayWithFlags(microDescNodeInfos, ['Exit'], ignoreEntry);
  const middleNode = pickRelayWithFlags(microDescNodeInfos, [], [exitNode, ...ignoreEntry]);
  const middlePeerInfo = await dangerouslyLookupPeerInfo(directoryServer, middleNode);
  const exitPeerInfo = await dangerouslyLookupPeerInfo(directoryServer, exitNode);

  const circuitPeerInfos: PeerInfo[] = [entryPeerInfo, middlePeerInfo, exitPeerInfo];
  const circuit = new Circuit({ path: circuitPeerInfos, channel });
  await circuit.connect();
  return circuit;
}
