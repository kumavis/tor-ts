import fs from 'node:fs/promises';
import path from 'node:path';
import { Circuit, type PeerInfo } from '../circuit.ts';
import { TlsChannelConnection, createTlsChannelManager } from '../channel.ts';
import {
  dangerouslyDownloadMicrodescFromDirectory,
  parseMicroDescConsensus,
  dangerouslyTrustUnverifiedConsensus,
  dangerouslyLookupPeerInfo,
} from './directory.ts';
import type { MicroDescNodeInfo, VerifiedMicroDescConsensus } from './directory.ts';
import { pickRelayWithFlags } from './util.ts';
import { DirectoryClient, lookupPeerInfo } from '../directory-client.ts';
import { type BuildCircuitFn } from '../hidden-service.ts';
import { TorClient, type CircuitResult } from '../client.ts';
import { fetchViaTorCircuit } from '../http-fetch.ts';
import { ConsensusManager } from '../consensus-manager.ts';
import { MicrodescManager, InMemoryMicrodescStorage } from '../microdesc-manager.ts';

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
  consensus: VerifiedMicroDescConsensus;
}> {
  const directoryServer = await discoverDirectoryServerIpPort();
  const microDescContent = await dangerouslyDownloadMicrodescFromDirectory(directoryServer);
  const unverified = parseMicroDescConsensus(microDescContent);

  // SKIP VERIFICATION: Chutney is a test network with local directory authorities
  // that don't match the hardcoded mainnet authorities. Signature verification
  // would always fail because the test authorities' keys aren't known.
  const consensus = dangerouslyTrustUnverifiedConsensus(
    unverified,
    'Chutney test network (local authorities, no mainnet keys)'
  );

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
//
// These mirror the mainnet client path: parse the consensus that came back
// over a Tor circuit, then look up each picked relay's PeerInfo through the
// same DirectoryClient. The single chutney-specific bit is calling
// `dangerouslyTrustUnverifiedConsensus` instead of mainnet's signed
// verification — chutney's directory authorities aren't on the hardcoded
// mainnet keylist, so signatures cannot be checked. Everything else is
// shared with the path the tamanegi browser runs (browser/src/client.ts).

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
  const unverified = parseMicroDescConsensus(microDescContent);

  // SKIP VERIFICATION: Chutney is a test network with local directory authorities
  // that don't match the hardcoded mainnet authorities.
  const consensus = dangerouslyTrustUnverifiedConsensus(
    unverified,
    'Chutney test network (local authorities, no mainnet keys)'
  );
  const microDescNodeInfos = consensus.relays;

  const circuitPlan: Array<MicroDescNodeInfo> = [];

  const forcedExitRsaIdDigestHex = process.env.TOR_TS_CHUTNEY_EXIT_RSA_ID_DIGEST_HEX?.toLowerCase();
  if (forcedExitRsaIdDigestHex) {
    const forcedExit = microDescNodeInfos.find((n: MicroDescNodeInfo) => {
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
  const unverified = parseMicroDescConsensus(microDescContent);

  // SKIP VERIFICATION: Chutney is a test network with local directory authorities
  // that don't match the hardcoded mainnet authorities.
  const consensus = dangerouslyTrustUnverifiedConsensus(
    unverified,
    'Chutney test network (local authorities, no mainnet keys)'
  );
  const microDescNodeInfos = consensus.relays;

  const avoid = new Set<string>([
    target.rsaIdDigest.toString('hex'),
    ...(opts.avoidRsaIdDigests ?? []).map((b) => b.toString('hex')),
  ]);

  const ignore: MicroDescNodeInfo[] = microDescNodeInfos.filter((n: MicroDescNodeInfo) =>
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

// ============================================================================
// Chutney Tor Client
// ============================================================================

export type ChutneyTorClientOptions = {
  /** Callback for status updates */
  onStatus?: (status: string) => void;
};

/**
 * Chutney Tor client - TorClient configured for Chutney test network.
 */
export type ChutneyTorClient = TorClient<TlsChannelConnection>;

/**
 * Create a Tor client for the Chutney test network.
 *
 * This performs bootstrap (consensus fetch, circuit building) and returns
 * a long-lived client that can be used for multiple operations.
 *
 * @example
 * ```typescript
 * const client = await makeChutneyTorClient();
 *
 * // Connect to hidden services
 * const hs = await client.connectToHiddenService('xyz.onion', 80);
 *
 * // Build circuits
 * const circ = await client.buildCircuit();
 *
 * // Cleanup when done
 * client.destroy();
 * ```
 */
export async function makeChutneyTorClient(
  options: ChutneyTorClientOptions = {}
): Promise<ChutneyTorClient> {
  const { onStatus } = options;

  const log = (msg: string) => {
    console.log(`[chutney-client] ${msg}`);
    onStatus?.(msg);
  };

  log('Bootstrapping...');

  // Create channel manager for TLS connection reuse
  const channelManager = createTlsChannelManager();

  // Get consensus
  const { consensus } = await getChutneyMicrodescConsensus();
  log(`Got consensus with ${consensus.relays.length} relays`);

  // Build bootstrap circuit
  const bootstrapPath = await getRandomChutneyCircuitPath();
  const bootstrapFirst = bootstrapPath[0];
  if (!bootstrapFirst) throw new Error('Empty bootstrap circuit path');

  const bootstrapChannel = await channelManager.getOrCreate(bootstrapFirst);
  const bootstrapCircuit = new Circuit({ path: bootstrapPath, channel: bootstrapChannel });
  await bootstrapCircuit.connect();
  log('Bootstrap circuit established');

  const dirClient = new DirectoryClient(bootstrapCircuit);

  // Create microdescriptor manager with in-memory storage
  // Microdescriptors are fetched lazily when needed (e.g., for hidden service connections)
  const microdescManager = new MicrodescManager({
    storage: new InMemoryMicrodescStorage(),
    dirClient,
  });

  // Build circuit to a specific target (for hidden services)
  const buildCircuitToTarget: BuildCircuitFn = async (target, opts) => {
    const avoidRsaIdDigests = opts?.avoid?.map((p) => p.rsaIdDigest);
    const path = await getRandomChutneyCircuitPathToTargetSafe(
      bootstrapCircuit,
      target,
      avoidRsaIdDigests ? { avoidRsaIdDigests } : undefined
    );
    const first = path[0];
    if (!first) throw new Error('Empty circuit path');

    const channel = await channelManager.getOrCreate(first);
    const circuit = new Circuit({ path, channel });
    await circuit.connect();
    return circuit;
  };

  // Build a general circuit
  const buildCircuit = async (_opts?: { targetPorts?: number[] }): Promise<CircuitResult> => {
    const path = await getRandomChutneyCircuitPath();
    const first = path[0];
    if (!first) throw new Error('Empty circuit path');

    const channel = await channelManager.getOrCreate(first);
    const circuit = new Circuit({ path, channel });
    await circuit.connect();

    log(`Built circuit: ${path.map((p) => p.rsaIdDigest.toString('hex').slice(0, 8)).join(' → ')}`);

    return {
      circuit,
      destroy: () => circuit.destroy({ preserveChannel: true }),
    };
  };

  // Reuse the standard ConsensusManager (same code path the tamanegi browser
  // runs); signature verification is opted out via defaultRefreshOptions
  // because chutney's authorities aren't on the hardcoded mainnet keylist.
  const consensusManager = new ConsensusManager(bootstrapCircuit, {
    initialVerifiedConsensus: consensus,
    defaultRefreshOptions: {
      dangerouslySkipSignatureVerification: true,
    },
  });

  log('Client initialized');

  // Create and return the client
  return new TorClient({
    channelManager,
    consensusManager,
    microdescManager,
    dirClient,
    bootstrapCircuit,
    consensus,
    buildCircuitToTarget,
    buildCircuit,
    fetchOverCircuit: fetchViaTorCircuit,
    log,
  });
}
