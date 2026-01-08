import type { PeerInfo } from '../circuit.ts';
import fs from 'node:fs/promises';
import path from 'node:path';
import {
  downloadMicrodescFromDirectory,
  parseRelaysFromMicroDesc,
  dangerouslyLookupPeerInfo,
} from './directory.ts';
import type { MicroDescNodeInfo } from './directory.ts';
import { pickRelayWithFlags } from './util.ts';

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
  const directoryServer = await discoverDirectoryServerIpPort();
  const microDescContent = await downloadMicrodescFromDirectory(directoryServer);
  const microDescNodeInfos = parseRelaysFromMicroDesc(microDescContent);

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
  const directoryServer = await discoverDirectoryServerIpPort();
  const microDescContent = await downloadMicrodescFromDirectory(directoryServer);
  const microDescNodeInfos = parseRelaysFromMicroDesc(microDescContent);

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
