/**
 * Node.js Tor Client Factory for the main Tor network.
 *
 * This creates a TorClient that connects to the real Tor network,
 * using 3-hop circuits through actual Tor relays.
 */

import { Circuit } from '../circuit.ts';
import {
  TlsChannelConnection,
  createTlsChannelManager,
  type TlsChannelManager,
} from '../channel.ts';
import {
  lookupPeerInfo,
  DirectoryClient,
  type DownloadProgressCallback,
} from '../directory-client.ts';
import { pickRelayWithFlags } from './util.ts';
import { TorClient, type CircuitResult } from '../client.ts';
import { ConsensusManager } from '../consensus-manager.ts';
import { MicrodescManager, InMemoryMicrodescStorage } from '../microdesc-manager.ts';
import type { BuildCircuitFn } from '../hidden-service.ts';
import { fetchViaTorCircuit } from '../http-fetch.ts';
import { getRandomFallbackDirectory, fallbackToPeerInfo } from '../fallback-dirs.ts';

/**
 * Node.js Tor client - TorClient configured for direct TLS connections.
 */
export type NodeTorClient = TorClient<TlsChannelConnection>;

/**
 * Options for creating a Node.js Tor client.
 */
export type NodeTorClientOptions = {
  /** Callback for status updates */
  onStatus?: (status: string) => void;
  /** Callback for consensus download progress */
  onConsensusProgress?: DownloadProgressCallback;
};

/**
 * Create a Node.js Tor client for the main Tor network.
 *
 * This performs bootstrap:
 * 1. Connect to a random fallback directory
 * 2. Build a 1-hop circuit using CREATE_FAST
 * 3. Fetch and verify the network consensus
 * 4. Connect to a guard relay for multi-hop circuits
 * 5. Return a client ready for Tor operations
 *
 * @example
 * ```typescript
 * const client = await makeTorClient({ onStatus: console.log });
 *
 * // Fetch a clearnet page
 * const response = await client.fetch('https://example.com');
 *
 * // Connect to hidden services
 * const { circuit } = await client.connectToHiddenService('xyz.onion', 80);
 *
 * // Cleanup when done
 * client.destroy();
 * ```
 */
export async function makeNodejsTorClient(
  options: NodeTorClientOptions = {}
): Promise<NodeTorClient> {
  const { onStatus, onConsensusProgress } = options;

  const log = (msg: string) => {
    console.log(`[tor-client] ${msg}`);
    onStatus?.(msg);
  };

  // Create channel manager for TLS connections
  const channelManager: TlsChannelManager = createTlsChannelManager();

  // Bootstrap: Connect to a random fallback directory
  log('Connecting to fallback directory...');
  const fallback = getRandomFallbackDirectory();
  const fallbackPeerInfo = fallbackToPeerInfo(fallback);

  const bootstrapChannel = new TlsChannelConnection();
  await bootstrapChannel.connectPeerInfo(fallbackPeerInfo);
  channelManager.add(fallbackPeerInfo.rsaIdDigest, bootstrapChannel);

  // Build 1-hop circuit for directory operations (uses CREATE_FAST)
  const bootstrapCircuit = new Circuit({
    path: [fallbackPeerInfo],
    channel: bootstrapChannel,
  });
  await bootstrapCircuit.connect();
  log('Bootstrap circuit established');

  // Create directory client
  const dirClient = new DirectoryClient(bootstrapCircuit);

  // Create microdescriptor manager with in-memory storage
  // Microdescriptors are fetched lazily when needed (e.g., for hidden service connections)
  const microdescManager = new MicrodescManager({
    storage: new InMemoryMicrodescStorage(),
    dirClient,
  });

  // Create consensus manager and fetch initial consensus
  const consensusManager = new ConsensusManager(bootstrapCircuit);

  log('Fetching consensus...');
  await consensusManager.refresh({
    ...(onConsensusProgress && { onProgress: onConsensusProgress }),
    ...(onStatus && { onStatus }),
  });

  const consensus = await consensusManager.getConsensus();
  log(`Got consensus with ${consensus.relays.length} relays`);

  // Select a guard relay for our circuits
  const guardNode = pickRelayWithFlags(consensus.relays, ['Guard', 'Stable', 'Fast'], []);
  const guardPeerInfo = await lookupPeerInfo(dirClient, guardNode);
  log(`Selected guard: ${guardNode.nickname}`);

  // Connect to guard for multi-hop circuits
  const guardChannel = new TlsChannelConnection();
  await guardChannel.connectPeerInfo(guardPeerInfo);
  channelManager.add(guardPeerInfo.rsaIdDigest, guardChannel);

  // Build circuit to a specific target (for hidden services)
  const buildCircuitToTarget: BuildCircuitFn = async (target) => {
    const candidateRelays = consensus.relays.filter(
      (r) =>
        !r.rsaIdDigest.equals(target.rsaIdDigest) &&
        !r.rsaIdDigest.equals(guardPeerInfo.rsaIdDigest)
    );
    const middleNode = pickRelayWithFlags(candidateRelays, ['Stable'], []);
    const middlePeerInfo = await lookupPeerInfo(dirClient, middleNode);

    const circuit = new Circuit({
      path: [guardPeerInfo, middlePeerInfo, target],
      channel: guardChannel,
    });
    await circuit.connect();
    return circuit;
  };

  // Build a general exit circuit
  const buildCircuit = async (_opts?: { targetPorts?: number[] }): Promise<CircuitResult> => {
    const excludeNodes = [guardNode];
    const candidateRelays = consensus.relays.filter(
      (r) => !r.rsaIdDigest.equals(guardPeerInfo.rsaIdDigest)
    );

    const middleNode = pickRelayWithFlags(candidateRelays, ['Stable'], excludeNodes);
    const exitNode = pickRelayWithFlags(
      candidateRelays,
      ['Exit', 'Stable'],
      [...excludeNodes, middleNode]
    );

    log(
      `Building circuit: guard=${guardNode.nickname}, middle=${middleNode.nickname}, exit=${exitNode.nickname}`
    );

    const middlePeerInfo = await lookupPeerInfo(dirClient, middleNode);
    const exitPeerInfo = await lookupPeerInfo(dirClient, exitNode);

    const circuit = new Circuit({
      path: [guardPeerInfo, middlePeerInfo, exitPeerInfo],
      channel: guardChannel,
    });
    await circuit.connect();

    return {
      circuit,
      destroy: () => circuit.destroy({ preserveChannel: true }),
    };
  };

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
    onDestroy: () => {
      bootstrapCircuit.destroy({ preserveChannel: true });
      channelManager.destroyAll();
    },
  });
}
