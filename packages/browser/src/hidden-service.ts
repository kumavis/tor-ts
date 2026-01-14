/**
 * Browser-compatible hidden service (.onion) connection support.
 * Uses Snowflake as the transport layer.
 *
 * Core HSv3 crypto functions are imported from the tor package.
 * This module provides the browser-specific connection flow using SnowflakeBrowserChannel.
 */

import { Circuit } from 'tor/circuit';
import type { PeerInfo } from 'tor/circuit';
import { RelayCell } from 'tor/relay-cell';
import {
  DirectoryClient,
  lookupPeerInfo,
  lookupPeerInfoWithEd25519IdentityKey,
  parseMicroDescConsensus,
  parseAllKeyCertificates,
} from 'tor/directory-client';
import type { DownloadProgress } from 'tor/directory-client';
import { pickRelayWithFlags } from 'tor/build-circuit/util';
import * as hiddenService from 'tor/hidden-service';
import { SnowflakeBrowserChannel } from './snowflake-channel.ts';
import { getCachedConsensus, cacheConsensus } from './consensus-cache.ts';

// Re-export core functions from tor hidden-service for convenience
export {
  parseOnionV3Address,
  isOnionAddress,
  computeTimePeriod,
  deriveBlindedPublicKey,
  deriveSubcredential,
} from 'tor/hidden-service';
export type { IntroPoint, HiddenServiceDescriptor } from 'tor/hidden-service';

// ============================================================================
// Browser-specific types
// ============================================================================

export type HiddenServiceConnectionOptions = {
  /** Callback for status updates */
  onStatus?: (status: string) => void;
  /** Callback for consensus download progress */
  onConsensusProgress?: (progress: DownloadProgress) => void;
  /** Skip consensus signature verification (DANGEROUS) */
  dangerouslySkipSignatureVerification?: boolean;
  /** Skip using cached consensus */
  skipConsensusCache?: boolean;
  /** Overall timeout in milliseconds */
  overallTimeoutMs?: number;
  /** Snowflake relay URL */
  relayUrl?: string;
};

export type HiddenServiceConnection = {
  circuit: Circuit;
  channel: SnowflakeBrowserChannel;
  introPoints: hiddenService.IntroPoint[];
  destroy: () => void;
};

// ============================================================================
// Helper functions
// ============================================================================

async function waitForRelayCommand(
  circuit: Circuit,
  relayCommand: number,
  timeoutMs: number
): Promise<{ streamId: number; relayCommand: number; data: Buffer }> {
  return await new Promise((resolve, reject) => {
    const onRelay = (evt: { streamId: number; relayCommand: number; data: Buffer }) => {
      if (evt.relayCommand !== relayCommand) return;
      cleanup();
      resolve(evt);
    };
    const t = setTimeout(() => {
      cleanup();
      reject(new Error(`Timed out waiting for relayCommand=${relayCommand}`));
    }, timeoutMs);
    const cleanup = () => {
      clearTimeout(t);
      circuit.off('relay', onRelay);
    };
    circuit.on('relay', onRelay);
  });
}

// ============================================================================
// Main connection flow
// ============================================================================

/**
 * Connect to a .onion hidden service via Snowflake.
 *
 * This establishes a rendezvous circuit to the hidden service and opens a stream
 * to the specified port. The returned connection can be used to fetch content.
 */
export async function connectToHiddenService(
  onionAddress: string,
  port: number,
  options: HiddenServiceConnectionOptions = {}
): Promise<HiddenServiceConnection> {
  const {
    onStatus,
    onConsensusProgress,
    dangerouslySkipSignatureVerification = false,
    skipConsensusCache = false,
    overallTimeoutMs = 300_000, // 5 minutes default for hidden services
    relayUrl = 'wss://snowflake.torproject.net/',
  } = options;

  const log = (msg: string) => {
    console.log(`[tor-hs] ${msg}`);
    onStatus?.(msg);
  };

  const shuffleInPlace = <T>(arr: T[]): T[] => {
    for (let i = arr.length - 1; i > 0; i--) {
      const randBytes = new Uint8Array(4);
      crypto.getRandomValues(randBytes);
      const j = (randBytes[0]! | (randBytes[1]! << 8) | (randBytes[2]! << 16)) % (i + 1);
      const tmp = arr[i]!;
      arr[i] = arr[j]!;
      arr[j] = tmp;
    }
    return arr;
  };

  const perHandshakeTimeoutMs = Math.min(overallTimeoutMs, 120_000);

  // Step 1: Connect to Snowflake
  log('Connecting to Snowflake relay...');
  const channel = new SnowflakeBrowserChannel();
  await channel.connect({ relayUrl });

  const entryRsaIdDigest = channel.peerIdentity?.rsaIdDigest;
  if (!entryRsaIdDigest) {
    channel.destroy();
    throw new Error('Snowflake channel has no peer identity');
  }

  // Step 2: Build bootstrap circuit
  log('Building bootstrap circuit...');
  const entryPeerInfo: PeerInfo = {
    onionKey: Buffer.alloc(0),
    rsaIdDigest: entryRsaIdDigest,
    linkSpecifiers: [],
  };

  const bootstrapCircuit = new Circuit({ path: [entryPeerInfo], channel });
  await bootstrapCircuit.connect();

  const dirClient = new DirectoryClient(bootstrapCircuit, { timeoutMs: 600_000 });

  // Step 3: Get consensus
  let microDescContent: string;
  const cachedConsensus = skipConsensusCache ? undefined : getCachedConsensus();

  if (cachedConsensus) {
    log('Using cached network consensus');
    microDescContent = cachedConsensus.content;
  } else {
    log('Downloading network consensus (via Tor circuit)...');
    microDescContent = await dirClient.downloadMicrodescConsensus(onConsensusProgress);
    cacheConsensus(microDescContent);
  }

  // Step 3.5: Download key certificates for signature verification
  // These contain the signing keys that authorities use to sign the consensus.
  // Without these, verification would incorrectly use identity keys (which will fail).
  let keyCertificates: ReturnType<typeof parseAllKeyCertificates> = [];
  if (!dangerouslySkipSignatureVerification) {
    log('Downloading authority key certificates...');
    const keyCertsText = await dirClient.downloadKeyCertificates();
    keyCertificates = parseAllKeyCertificates(keyCertsText);
    log(`Downloaded ${keyCertificates.length} key certificates`);
  }

  const consensus = await parseMicroDescConsensus(microDescContent, {
    dangerouslySkipSignatureVerification,
    keyCertificates,
  });

  if (!consensus.validAfter) {
    bootstrapCircuit.destroy();
    channel.destroy();
    throw new Error('Consensus missing valid-after');
  }

  // Step 4: Parse onion address
  log('Parsing onion address...');
  const { publicIdentityKey } = hiddenService.parseOnionV3Address(onionAddress);

  // Step 5: Find HSDirs and fetch descriptor
  log('Locating hidden service directory nodes...');
  const hsdirInterval = consensus.params?.['hsdir-interval'] ?? 1440;
  const hsdirNodes = (consensus.relays ?? []).filter((r) => {
    if (!(r.flags ?? []).includes('HSDir')) return false;
    const hsdirProto = r.protocols?.HSDir;
    if (!hsdirProto) return false;
    return hsdirProto.split(',').some((v) => v.includes('2'));
  });

  if (hsdirNodes.length === 0) {
    bootstrapCircuit.destroy();
    channel.destroy();
    throw new Error('No HSDir candidates found in consensus');
  }

  // Build HSDir candidates with Ed25519 identity keys
  log('Looking up HSDir identity keys...');
  const shuffledHsdirNodes = shuffleInPlace([...hsdirNodes]);

  type HsdirCandidate = {
    peerInfo: PeerInfo;
    ed25519IdentityKey: Buffer;
  };
  const hsdirCandidates: HsdirCandidate[] = [];

  // Lookup HSDir peer info in parallel (limited batch)
  const batchSize = Math.min(10, shuffledHsdirNodes.length);
  const results = await Promise.all(
    shuffledHsdirNodes.slice(0, batchSize).map(async (n) => {
      try {
        const { peerInfo, ed25519IdentityKey } = await lookupPeerInfoWithEd25519IdentityKey(
          dirClient,
          n
        );
        return { peerInfo, ed25519IdentityKey } satisfies HsdirCandidate;
      } catch {
        return undefined;
      }
    })
  );
  hsdirCandidates.push(...results.filter((x): x is HsdirCandidate => Boolean(x)));

  if (hsdirCandidates.length === 0) {
    bootstrapCircuit.destroy();
    channel.destroy();
    throw new Error('Failed to build any HSDir candidates');
  }

  // Compute time period and blinded key
  const timeArgs: Parameters<typeof hiddenService.computeTimePeriod>[0] = {
    validAfter: consensus.validAfter,
  };
  if (consensus.freshUntil) timeArgs.freshUntil = consensus.freshUntil;

  const votingIntervalSec = consensus.freshUntil
    ? Math.floor((consensus.freshUntil.getTime() - consensus.validAfter.getTime()) / 1000)
    : 3600;
  const derivedPeriodMinutes = Math.max(1, Math.floor((votingIntervalSec * 24) / 60));
  if (hsdirInterval === derivedPeriodMinutes) {
    timeArgs.hsdirIntervalMinutes = hsdirInterval;
  }

  const { periodNum: basePeriodNum, periodLengthMinutes } =
    hiddenService.computeTimePeriod(timeArgs);
  const periodCandidates = [basePeriodNum, basePeriodNum - 1n, basePeriodNum + 1n].filter(
    (n) => n >= 0n
  );

  const nReplicas = Math.min(16, Math.max(1, consensus.params?.['hsdir_n_replicas'] ?? 2));
  const spreadFetch = Math.min(128, Math.max(1, consensus.params?.['hsdir_spread_fetch'] ?? 3));

  let subcred: Buffer | undefined;
  let blindedPublicKey: Buffer | undefined;
  let descriptor: hiddenService.HiddenServiceDescriptor | undefined;

  log('Fetching hidden service descriptor...');
  const deadline = Date.now() + Math.min(overallTimeoutMs, 180_000);

  for (const periodNum of periodCandidates) {
    if (descriptor) break;
    if (Date.now() > deadline) break;

    blindedPublicKey = hiddenService.deriveBlindedPublicKey({
      publicIdentityKey,
      periodNum,
      periodLengthMinutes,
    });
    subcred = hiddenService.deriveSubcredential({ publicIdentityKey, blindedPublicKey });

    const disasterSrv = hiddenService.computeDisasterSrv({ periodLengthMinutes, periodNum });
    const srvValues: Buffer[] = [
      consensus.sharedRandCurrentValue ?? disasterSrv,
      consensus.sharedRandPreviousValue ?? disasterSrv,
    ];

    for (const srv of srvValues) {
      if (descriptor) break;

      const hsdirPeersThisRound = hiddenService.selectHsdirsForFetch({
        hsdirs: hsdirCandidates,
        sharedRandomValue: srv,
        blindedPublicKey,
        periodLengthMinutes,
        periodNum,
        nReplicas,
        spreadFetch,
        shuffleInPlace,
      });

      for (const hsdirPeer of hsdirPeersThisRound) {
        if (Date.now() > deadline) break;

        try {
          const got = await hiddenService.fetchHsDescriptorOverDirectoryStream(
            bootstrapCircuit,
            hsdirPeer,
            blindedPublicKey,
            subcred,
            perHandshakeTimeoutMs
          );
          if (got) {
            descriptor = got;
            break;
          }
        } catch {
          // Continue to next HSDir
        }
      }
    }
  }

  if (!descriptor || !subcred || !blindedPublicKey) {
    bootstrapCircuit.destroy();
    channel.destroy();
    throw new Error('Failed to download hidden service descriptor');
  }

  const intro = descriptor.introPoints[0];
  if (!intro) {
    bootstrapCircuit.destroy();
    channel.destroy();
    throw new Error('Descriptor contained no introduction points');
  }

  log(`Found ${descriptor.introPoints.length} introduction point(s)`);

  // Step 6: Select rendezvous point
  log('Selecting rendezvous point...');
  const rendCandidates = consensus.relays.filter((r) => {
    const versions = r.protocols?.HSRend;
    if (!versions) return true;
    return versions.split(',').some((v) => v.includes('2'));
  });
  const rendNodeInfo = pickRelayWithFlags(
    rendCandidates.length ? rendCandidates : consensus.relays,
    [],
    []
  );
  const rendezvousPoint = await lookupPeerInfo(dirClient, rendNodeInfo);

  // Step 7: Build 3-hop circuit to rendezvous point
  log('Building rendezvous circuit...');
  const middleNode = pickRelayWithFlags(consensus.relays, [], [rendNodeInfo]);
  const middlePeerInfo = await lookupPeerInfo(dirClient, middleNode);

  const rendCircuit = new Circuit({
    path: [entryPeerInfo, middlePeerInfo, rendezvousPoint],
    channel,
  });
  await rendCircuit.connect();

  // Clean up bootstrap circuit
  bootstrapCircuit.destroy({ preserveChannel: true });

  // Step 8: Establish rendezvous
  log('Establishing rendezvous point...');
  const rendezvousCookie = new Uint8Array(20);
  crypto.getRandomValues(rendezvousCookie);

  await rendCircuit.sendRelayMessage({
    streamId: 0,
    relayCommand: RelayCell.ESTABLISH_RENDEZVOUS,
    data: Buffer.from(rendezvousCookie),
  });
  await waitForRelayCommand(rendCircuit, RelayCell.RENDEZVOUS_ESTABLISHED, perHandshakeTimeoutMs);

  // Step 9: Build introduction circuit
  log('Building introduction circuit...');
  const introPeer = hiddenService.peerInfoFromIntroPoint(intro);
  const introMiddleNode = pickRelayWithFlags(consensus.relays, [], [rendNodeInfo, middleNode]);
  const introMiddlePeerInfo = await lookupPeerInfo(dirClient, introMiddleNode);

  // We need a separate channel for the intro circuit
  const introChannel = new SnowflakeBrowserChannel();
  await introChannel.connect({ relayUrl });

  const introEntryRsaIdDigest = introChannel.peerIdentity?.rsaIdDigest;
  if (!introEntryRsaIdDigest) {
    introChannel.destroy();
    rendCircuit.destroy();
    channel.destroy();
    throw new Error('Intro channel has no peer identity');
  }

  const introEntryPeerInfo: PeerInfo = {
    onionKey: Buffer.alloc(0),
    rsaIdDigest: introEntryRsaIdDigest,
    linkSpecifiers: [],
  };

  const introCircuit = new Circuit({
    path: [introEntryPeerInfo, introMiddlePeerInfo, introPeer],
    channel: introChannel,
  });
  await introCircuit.connect();

  // Step 10: Send INTRODUCE1
  log('Sending introduction...');
  const { payload: introducePayload, state } = await hiddenService.buildIntroduce1Payload({
    introAuthKeyEd25519: intro.authKeyEd25519,
    serviceEncKey: intro.serviceEncKey,
    N_hs_subcred: subcred,
    rendezvousCookie: Buffer.from(rendezvousCookie),
    rendezvousPoint,
  });

  await introCircuit.sendRelayMessage({
    streamId: 0,
    relayCommand: RelayCell.INTRODUCE1,
    data: introducePayload,
  });

  const ack = await waitForRelayCommand(
    introCircuit,
    RelayCell.INTRODUCE_ACK,
    perHandshakeTimeoutMs
  );
  if (ack.data.length < 2) throw new Error('INTRODUCE_ACK too short');
  const status = ack.data.readUInt16BE(0);
  if (status !== 0) {
    introCircuit.destroy();
    introChannel.destroy();
    rendCircuit.destroy();
    channel.destroy();
    throw new Error(`INTRODUCE_ACK status=${status}`);
  }

  // Clean up intro circuit
  introCircuit.destroy();
  introChannel.destroy();

  // Step 11: Wait for RENDEZVOUS2
  log('Waiting for rendezvous completion...');
  const r2 = await waitForRelayCommand(rendCircuit, RelayCell.RENDEZVOUS2, overallTimeoutMs);
  if (r2.data.length < 64) throw new Error('RENDEZVOUS2 too short');

  const Y = r2.data.subarray(0, 32);
  const auth = r2.data.subarray(32, 64);
  const { NTOR_KEY_SEED } = hiddenService.hsNtorComplete({ state, Y, auth });
  const cipherPair = hiddenService.makeHsRendezvousCipherPairFromKeySeed(NTOR_KEY_SEED);
  rendCircuit.addVirtualHop(cipherPair);

  log('Connected to hidden service!');

  return {
    circuit: rendCircuit,
    channel,
    introPoints: descriptor.introPoints,
    destroy: () => {
      rendCircuit.destroy();
    },
  };
}
