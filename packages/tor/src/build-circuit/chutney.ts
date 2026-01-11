import { Circuit, type PeerInfo } from '../circuit.ts';
import { TlsChannelConnection } from '../channel.ts';
import fs from 'node:fs/promises';
import path from 'node:path';
import {
  dangerouslyDownloadMicrodescFromDirectory,
  parseMicroDescConsensus,
  dangerouslyLookupPeerInfo,
} from './directory.ts';
import type { MicroDescConsensus, MicroDescNodeInfo } from './directory.ts';
import { pickRelayWithFlags } from './util.ts';
import { DirectoryClient, lookupPeerInfo } from '../directory-client.ts';

function mustFindMicroDescNodeInfo(
  nodes: MicroDescNodeInfo[],
  predicate: (node: MicroDescNodeInfo) => boolean,
  description: string
): MicroDescNodeInfo {
  const found = nodes.find(predicate);
  if (!found) {
    throw new Error(`Failed to find chutney relay: ${description}`);
  }
  return found;
}

async function discoverDirectoryServerIpPort(): Promise<string> {
  if (process.env.CHUTNEY_DIRECTORY_SERVER) {
    return process.env.CHUTNEY_DIRECTORY_SERVER;
  }

  const dataDir = process.env.CHUTNEY_DATA_DIR;
  if (dataDir) {
    // Chutney writes generated torrc files under: $CHUTNEY_DATA_DIR/nodes/<node>/torrc
    // (nodes is usually a symlink to nodes.<timestamp>)
    const nodesDir = path.join(dataDir, 'nodes');
    try {
      const entries = await fs.readdir(nodesDir, { withFileTypes: true });
      for (const entry of entries) {
        if (!entry.isDirectory()) continue;
        const torrcPath = path.join(nodesDir, entry.name, 'torrc');
        let torrc: string;
        try {
          torrc = await fs.readFile(torrcPath, 'utf8');
        } catch {
          continue;
        }
        const match = torrc.match(/^DirPort\s+(\d+)\b/m);
        if (!match) continue;
        const dirPortText = match[1];
        if (!dirPortText) continue;
        const dirPort = Number.parseInt(dirPortText, 10);
        if (!Number.isFinite(dirPort) || dirPort <= 0) continue;
        return `127.0.0.1:${dirPort}`;
      }
    } catch {
      // fall through to default
    }
  }

  // Historical default for this repo's chutney scripts
  return '127.0.0.1:7000';
}

export async function discoverChutneyDirectoryServer(): Promise<string> {
  return await discoverDirectoryServerIpPort();
}

export async function getChutneyMicrodescConsensus(): Promise<{
  directoryServer: string;
  consensus: MicroDescConsensus;
}> {
  const directoryServer = await discoverDirectoryServerIpPort();
  const microDescContent = await dangerouslyDownloadMicrodescFromDirectory(directoryServer);
  // Disable signature verification for Chutney - test networks use local
  // directory authorities that don't match the hardcoded mainnet authorities
  const consensus = parseMicroDescConsensus(microDescContent, { verifySignatures: false });
  return { directoryServer, consensus };
}

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

export async function getStandardChutneyCircuitPath() {
  const { directoryServer, consensus } = await getChutneyMicrodescConsensus();
  const microDescNodeInfos = consensus.relays;

  const circuitPlan: Array<MicroDescNodeInfo> = [];
  circuitPlan.push(
    mustFindMicroDescNodeInfo(
      microDescNodeInfos,
      (n) => n.onion_router_port === 5004,
      'orport 5004'
    )
  );
  circuitPlan.push(
    mustFindMicroDescNodeInfo(
      microDescNodeInfos,
      (n) => n.onion_router_port === 5001,
      'orport 5001'
    )
  );
  circuitPlan.push(
    mustFindMicroDescNodeInfo(
      microDescNodeInfos,
      (n) => n.onion_router_port === 5000,
      'orport 5000'
    )
  );

  const circuitPeerInfos: Array<PeerInfo> = await Promise.all(
    circuitPlan.map(async (relayInfo) => {
      return await dangerouslyLookupPeerInfo(directoryServer, relayInfo);
    })
  );
  // reverse so that gateway is first and exit is last
  circuitPeerInfos.reverse();

  return circuitPeerInfos;
}

export async function getRandomChutneyCircuitPath() {
  const { directoryServer, consensus } = await getChutneyMicrodescConsensus();
  const microDescNodeInfos = consensus.relays;

  const circuitPlan: Array<MicroDescNodeInfo> = [];

  const forcedExitRsaIdDigestHex = process.env.TOR_TS_CHUTNEY_EXIT_RSA_ID_DIGEST_HEX?.toLowerCase();
  if (forcedExitRsaIdDigestHex) {
    const forcedExit = microDescNodeInfos.find((n) => {
      const digestHex = n.rsaIdDigest.toString('hex');
      return digestHex === forcedExitRsaIdDigestHex;
    });
    if (!forcedExit) {
      throw new Error(
        `TOR_TS_CHUTNEY_EXIT_RSA_ID_DIGEST_HEX=${forcedExitRsaIdDigestHex} not found in microdesc`
      );
    }
    circuitPlan.push(forcedExit);
  } else {
    circuitPlan.push(pickRelayWithFlags(microDescNodeInfos, ['Exit'], circuitPlan));
  }

  circuitPlan.push(pickRelayWithFlags(microDescNodeInfos, [], circuitPlan));
  circuitPlan.push(pickRelayWithFlags(microDescNodeInfos, ['Guard'], circuitPlan));

  const circuitPeerInfos: Array<PeerInfo> = await Promise.all(
    circuitPlan.map(async (relayInfo) => {
      return await dangerouslyLookupPeerInfo(directoryServer, relayInfo);
    })
  );
  // reverse so that gateway is first and exit is last
  circuitPeerInfos.reverse();

  return circuitPeerInfos;
}

export async function getRandomChutneyCircuitPathToTarget(
  target: PeerInfo,
  opts: { avoidRsaIdDigests?: Buffer[] } = {}
) {
  const { directoryServer, consensus } = await getChutneyMicrodescConsensus();
  const microDescNodeInfos = consensus.relays;

  const avoid = new Set<string>([
    target.rsaIdDigest.toString('hex'),
    ...(opts.avoidRsaIdDigests ?? []).map((b) => b.toString('hex')),
  ]);

  const ignore: MicroDescNodeInfo[] = microDescNodeInfos.filter((n) =>
    avoid.has(n.rsaIdDigest.toString('hex'))
  );

  const circuitPlan: Array<MicroDescNodeInfo> = [];
  circuitPlan.push(pickRelayWithFlags(microDescNodeInfos, [], ignore));
  circuitPlan.push(pickRelayWithFlags(microDescNodeInfos, ['Guard'], [...ignore, ...circuitPlan]));

  // Build in exit->...->guard order, then reverse at the end.
  const circuitPeerInfos: Array<PeerInfo> = await Promise.all(
    circuitPlan.map(async (relayInfo) => {
      return await dangerouslyLookupPeerInfo(directoryServer, relayInfo);
    })
  );
  circuitPeerInfos.unshift(target);
  circuitPeerInfos.reverse();
  return circuitPeerInfos;
}

// =============================================================================
// Safe versions using DirectoryClient over circuits
// =============================================================================

/**
 * Get Chutney consensus safely over an existing circuit's directory stream.
 *
 * This is the safe alternative to getChutneyMicrodescConsensus().
 */
export async function getChutneyMicrodescConsensusSafe(
  directoryCircuit: Circuit
): Promise<MicroDescConsensus> {
  const client = new DirectoryClient(directoryCircuit);
  const microDescContent = await client.downloadMicrodescConsensus();
  // Disable signature verification for Chutney - test networks use local
  // directory authorities that don't match the hardcoded mainnet authorities
  return parseMicroDescConsensus(microDescContent, { verifySignatures: false });
}

/**
 * Build a random circuit path safely using an existing circuit for directory lookups.
 *
 * This is the safe alternative to getRandomChutneyCircuitPath().
 */
export async function getRandomChutneyCircuitPathSafe(
  directoryCircuit: Circuit
): Promise<PeerInfo[]> {
  const client = new DirectoryClient(directoryCircuit);
  const microDescContent = await client.downloadMicrodescConsensus();
  // Disable signature verification for Chutney - test networks use local
  // directory authorities that don't match the hardcoded mainnet authorities
  const consensus = parseMicroDescConsensus(microDescContent, { verifySignatures: false });
  const microDescNodeInfos = consensus.relays;

  const circuitPlan: Array<MicroDescNodeInfo> = [];

  const forcedExitRsaIdDigestHex = process.env.TOR_TS_CHUTNEY_EXIT_RSA_ID_DIGEST_HEX?.toLowerCase();
  if (forcedExitRsaIdDigestHex) {
    const forcedExit = microDescNodeInfos.find((n) => {
      const digestHex = n.rsaIdDigest.toString('hex');
      return digestHex === forcedExitRsaIdDigestHex;
    });
    if (!forcedExit) {
      throw new Error(
        `TOR_TS_CHUTNEY_EXIT_RSA_ID_DIGEST_HEX=${forcedExitRsaIdDigestHex} not found in microdesc`
      );
    }
    circuitPlan.push(forcedExit);
  } else {
    circuitPlan.push(pickRelayWithFlags(microDescNodeInfos, ['Exit'], circuitPlan));
  }

  circuitPlan.push(pickRelayWithFlags(microDescNodeInfos, [], circuitPlan));
  circuitPlan.push(pickRelayWithFlags(microDescNodeInfos, ['Guard'], circuitPlan));

  // Look up PeerInfo safely through the circuit
  const circuitPeerInfos: Array<PeerInfo> = await Promise.all(
    circuitPlan.map((relayInfo) => lookupPeerInfo(client, relayInfo))
  );

  // reverse so that gateway is first and exit is last
  circuitPeerInfos.reverse();
  return circuitPeerInfos;
}

/**
 * Build a random circuit path to a target safely using an existing circuit.
 *
 * This is the safe alternative to getRandomChutneyCircuitPathToTarget().
 */
export async function getRandomChutneyCircuitPathToTargetSafe(
  directoryCircuit: Circuit,
  target: PeerInfo,
  opts: { avoidRsaIdDigests?: Buffer[] } = {}
): Promise<PeerInfo[]> {
  const client = new DirectoryClient(directoryCircuit);
  const microDescContent = await client.downloadMicrodescConsensus();
  // Disable signature verification for Chutney - test networks use local
  // directory authorities that don't match the hardcoded mainnet authorities
  const consensus = parseMicroDescConsensus(microDescContent, { verifySignatures: false });
  const microDescNodeInfos = consensus.relays;

  const avoid = new Set<string>([
    target.rsaIdDigest.toString('hex'),
    ...(opts.avoidRsaIdDigests ?? []).map((b) => b.toString('hex')),
  ]);

  const ignore: MicroDescNodeInfo[] = microDescNodeInfos.filter((n) =>
    avoid.has(n.rsaIdDigest.toString('hex'))
  );

  const circuitPlan: Array<MicroDescNodeInfo> = [];
  circuitPlan.push(pickRelayWithFlags(microDescNodeInfos, [], ignore));
  circuitPlan.push(pickRelayWithFlags(microDescNodeInfos, ['Guard'], [...ignore, ...circuitPlan]));

  // Look up PeerInfo safely through the circuit
  const circuitPeerInfos: Array<PeerInfo> = await Promise.all(
    circuitPlan.map((relayInfo) => lookupPeerInfo(client, relayInfo))
  );

  circuitPeerInfos.unshift(target);
  circuitPeerInfos.reverse();
  return circuitPeerInfos;
}

/**
 * Connect a random Chutney circuit safely using an existing circuit for directory lookups.
 */
export async function connectRandomChutneyCircuitSafe(directoryCircuit: Circuit): Promise<Circuit> {
  const circuitPeerInfos = await getRandomChutneyCircuitPathSafe(directoryCircuit);
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
