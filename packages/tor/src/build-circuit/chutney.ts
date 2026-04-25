import fs from 'node:fs/promises';
import path from 'node:path';
import { Circuit, type PeerInfo } from '../circuit.ts';
import { TlsChannelConnection, createTlsChannelManager } from '../channel.ts';
import { addressAndPortToLinkSpecifier, AddressTypes, LinkSpecifierTypes } from '../messaging.ts';
import type { MicroDescNodeInfo, VerifiedMicroDescConsensus } from './directory.ts';
import { pickRelayWithFlags } from './util.ts';
import { DirectoryClient, lookupPeerInfo } from '../directory-client.ts';
import { type BuildCircuitFn } from '../hidden-service.ts';
import { TorClient, type CircuitResult } from '../client.ts';
import { fetchViaTorCircuit } from '../http-fetch.ts';
import { ConsensusManager } from '../consensus-manager.ts';
import { MicrodescManager, InMemoryMicrodescStorage } from '../microdesc-manager.ts';
import type { DirectoryAuthorityIdentity } from '../consensus-signature.ts';

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

// =============================================================================
// Chutney bootstrap (TLS to a chutney relay, mirroring fallback bootstrap)
// =============================================================================
//
// Chutney runs every relay on 127.0.0.1 and writes their config + identity
// fingerprint to disk under $CHUTNEY_DATA_DIR/nodes/<n>/. We pick any node
// off disk, TLS-connect to its OrPort, and build a single-hop circuit using
// CREATE_FAST. Nothing about consensus or peer info is fetched over plain
// HTTP — every subsequent lookup uses BEGIN_DIR over this circuit, the same
// path mainnet and the tamanegi browser run.

export type ChutneyBootstrapPeer = {
  ip: string;
  orPort: number;
  rsaIdDigest: Buffer;
};

/**
 * Discover any usable chutney relay's `(ip, orPort, rsaIdDigest)` from the
 * filesystem laid out by `chutney start`. Reads `$CHUTNEY_DATA_DIR/nodes/*`
 * (chutney itself sets that env var). The first node with a parseable
 * `OrPort` and a 40-hex `fingerprint` wins; chutney's `127.0.0.1` is
 * implicit.
 */
export async function discoverChutneyBootstrapPeer(): Promise<ChutneyBootstrapPeer> {
  const dataDir = process.env.CHUTNEY_DATA_DIR;
  if (!dataDir) {
    throw new Error('CHUTNEY_DATA_DIR not set; cannot discover a chutney bootstrap peer');
  }
  const nodesDir = path.join(dataDir, 'nodes');
  const entries = await fs.readdir(nodesDir, { withFileTypes: true });
  for (const entry of entries) {
    if (!entry.isDirectory()) continue;
    const torrcPath = path.join(nodesDir, entry.name, 'torrc');
    const fingerprintPath = path.join(nodesDir, entry.name, 'fingerprint');
    let torrc: string;
    let fingerprintLine: string;
    try {
      torrc = await fs.readFile(torrcPath, 'utf8');
      fingerprintLine = await fs.readFile(fingerprintPath, 'utf8');
    } catch {
      continue;
    }
    // Tolerate every chutney OrPort form: bare `OrPort 5004`,
    // `OrPort 127.0.0.1:5004`, `OrPort 0.0.0.0:5004`, `OrPort [::1]:5004`.
    // The optional `\S*:` swallows everything up to the last colon so the
    // capture lands on the actual port number.
    const orPortText = torrc.match(/^OrPort\s+(?:\S*:)?(\d+)\b/m)?.[1];
    if (!orPortText) continue;
    const orPort = Number.parseInt(orPortText, 10);
    if (!Number.isFinite(orPort) || orPort <= 0) continue;
    // fingerprint file: "<nickname> <40-hex (groups of 4)>"
    const fpHex = fingerprintLine.split(/\s+/).slice(1).join('').replace(/\s/g, '');
    if (fpHex.length !== 40) continue;
    const rsaIdDigest = Buffer.from(fpHex, 'hex');
    if (rsaIdDigest.length !== 20) continue;
    return { ip: '127.0.0.1', orPort, rsaIdDigest };
  }
  throw new Error(`No usable chutney nodes found in ${nodesDir}`);
}

/**
 * PeerInfo for a chutney bootstrap peer. `onionKey` is empty so the circuit
 * uses CREATE_FAST — we don't have the ntor onion key on hand and don't need
 * it for a single-hop, identity-verified-by-TLS bootstrap.
 */
export function chutneyBootstrapPeerToPeerInfo(peer: ChutneyBootstrapPeer): PeerInfo {
  return {
    onionKey: Buffer.alloc(0),
    rsaIdDigest: peer.rsaIdDigest,
    linkSpecifiers: [
      addressAndPortToLinkSpecifier({
        type: AddressTypes.IPv4,
        ip: peer.ip,
        port: peer.orPort,
      }),
      { type: LinkSpecifierTypes.LegacyId, data: peer.rsaIdDigest },
    ],
  };
}

/**
 * Bootstrap a chutney session by connecting TLS-direct to a chutney relay
 * and building a 1-hop circuit. Equivalent of mainnet's
 * {@link bootstrapWithFallbackDirectory}; safe to use as the
 * `directoryCircuit` argument for {@link connectRandomCircuitSafe}.
 */
export async function bootstrapWithChutneyDirectory(): Promise<Circuit> {
  const peer = await discoverChutneyBootstrapPeer();
  const peerInfo = chutneyBootstrapPeerToPeerInfo(peer);
  const channel = new TlsChannelConnection();
  await channel.connectPeerInfo(peerInfo);
  const circuit = new Circuit({ path: [peerInfo], channel });
  await circuit.connect();
  return circuit;
}

// =============================================================================
// Safe path-building over an existing chutney directory circuit
// =============================================================================
//
// These look identical to the mainnet pattern in build-circuit/mainnet.ts —
// they are just kept here because chutney has its own forced-exit pin
// (TOR_TS_CHUTNEY_EXIT_RSA_ID_DIGEST_HEX) that pins a specific exit relay
// across CI runs. Everything else routes through the standard
// DirectoryClient/lookupPeerInfo, no plain-HTTP, no `dangerouslyLookup*`.

function pickChutneyExit(microDescNodeInfos: MicroDescNodeInfo[]): MicroDescNodeInfo {
  const forcedExitRsaIdDigestHex = process.env.TOR_TS_CHUTNEY_EXIT_RSA_ID_DIGEST_HEX?.toLowerCase();
  if (forcedExitRsaIdDigestHex) {
    const forcedExit = microDescNodeInfos.find(
      (n) => n.rsaIdDigest.toString('hex') === forcedExitRsaIdDigestHex
    );
    if (!forcedExit) {
      throw new Error(
        `TOR_TS_CHUTNEY_EXIT_RSA_ID_DIGEST_HEX=${forcedExitRsaIdDigestHex} not found in microdesc`
      );
    }
    return forcedExit;
  }
  return pickRelayWithFlags(microDescNodeInfos, ['Exit'], []);
}

/**
 * Build a random 3-hop chutney circuit path using an existing directory
 * circuit. Honors the `TOR_TS_CHUTNEY_EXIT_RSA_ID_DIGEST_HEX` pin if set.
 */
export async function getRandomChutneyCircuitPathSafe(
  directoryCircuit: Circuit,
  consensus: VerifiedMicroDescConsensus
): Promise<PeerInfo[]> {
  const client = new DirectoryClient(directoryCircuit);
  const relays = consensus.relays;

  const circuitPlan: MicroDescNodeInfo[] = [];
  circuitPlan.push(pickChutneyExit(relays));
  circuitPlan.push(pickRelayWithFlags(relays, [], circuitPlan));
  circuitPlan.push(pickRelayWithFlags(relays, ['Guard'], circuitPlan));

  const peerInfos = await Promise.all(circuitPlan.map((r) => lookupPeerInfo(client, r)));
  // exit-first → guard-first
  peerInfos.reverse();
  return peerInfos;
}

/**
 * Build a 3-hop circuit path that ends at `target`, using `directoryCircuit`
 * for safe peer lookups. Used for HS introduction circuits.
 */
export async function getRandomChutneyCircuitPathToTargetSafe(
  directoryCircuit: Circuit,
  consensus: VerifiedMicroDescConsensus,
  target: PeerInfo,
  opts: { avoidRsaIdDigests?: Buffer[] } = {}
): Promise<PeerInfo[]> {
  const client = new DirectoryClient(directoryCircuit);
  const relays = consensus.relays;

  const avoid = new Set<string>([
    target.rsaIdDigest.toString('hex'),
    ...(opts.avoidRsaIdDigests ?? []).map((b) => b.toString('hex')),
  ]);
  const ignore = relays.filter((n) => avoid.has(n.rsaIdDigest.toString('hex')));

  const circuitPlan: MicroDescNodeInfo[] = [];
  circuitPlan.push(pickRelayWithFlags(relays, [], ignore));
  circuitPlan.push(pickRelayWithFlags(relays, ['Guard'], [...ignore, ...circuitPlan]));

  const peerInfos = await Promise.all(circuitPlan.map((r) => lookupPeerInfo(client, r)));
  peerInfos.unshift(target);
  // target-first → guard-first
  peerInfos.reverse();
  return peerInfos;
}

/**
 * Bootstrap chutney + build a full 3-hop circuit. Mirrors mainnet's
 * {@link connectRandomCircuitWithSafeBootstrap} and is the entry point CI
 * scripts should use instead of any `dangerously*` plumbing.
 *
 * Returns the new 3-hop circuit and the PeerInfo path that built it. The
 * bootstrap circuit is destroyed before returning.
 */
export async function connectRandomChutneyCircuitWithSafeBootstrap(): Promise<{
  circuit: Circuit;
  path: PeerInfo[];
}> {
  const bootstrapCircuit = await bootstrapWithChutneyDirectory();
  try {
    const consensus = await fetchChutneyConsensusOverCircuit(bootstrapCircuit);
    const path = await getRandomChutneyCircuitPathSafe(bootstrapCircuit, consensus);
    const first = path[0];
    if (!first) throw new Error('Empty chutney circuit path');

    const channel = new TlsChannelConnection();
    await channel.connectPeerInfo(first);
    const circuit = new Circuit({ path, channel });
    await circuit.connect();
    bootstrapCircuit.destroy();
    return { circuit, path };
  } catch (err) {
    bootstrapCircuit.destroy();
    throw err;
  }
}

/**
 * Discover the chutney directory authorities from the filesystem. Each
 * authority writes its `authority_certificate` to
 * `$CHUTNEY_DATA_DIR/nodes/<n>a/keys/`; the file's `fingerprint` line is
 * the authority's v3ident — the same trust anchor mainnet uses for
 * `DIRECTORY_AUTHORITIES`. Returning these to the verifier replaces the
 * old `dangerouslySkipSignatureVerification` opt-out.
 */
export async function discoverChutneyAuthorities(): Promise<DirectoryAuthorityIdentity[]> {
  const dataDir = process.env.CHUTNEY_DATA_DIR;
  if (!dataDir) {
    throw new Error('CHUTNEY_DATA_DIR not set; cannot discover chutney directory authorities');
  }
  const nodesDir = path.join(dataDir, 'nodes');
  const entries = await fs.readdir(nodesDir, { withFileTypes: true });
  const authorities: DirectoryAuthorityIdentity[] = [];
  for (const entry of entries) {
    if (!entry.isDirectory()) continue;
    const certPath = path.join(nodesDir, entry.name, 'keys', 'authority_certificate');
    let certText: string;
    try {
      certText = await fs.readFile(certPath, 'utf8');
    } catch {
      continue;
    }
    const fpHex = certText.match(/^fingerprint\s+([0-9A-Fa-f]{40})\b/m)?.[1];
    if (!fpHex) continue;
    const identityKeyMatch = certText.match(
      /-----BEGIN RSA PUBLIC KEY-----[\s\S]*?-----END RSA PUBLIC KEY-----/
    );
    authorities.push({
      nickname: entry.name,
      v3ident: fpHex.toUpperCase(),
      identityKeyPem: identityKeyMatch?.[0] ?? '',
    });
  }
  if (authorities.length === 0) {
    throw new Error(`No chutney authority_certificate files found under ${nodesDir}`);
  }
  return authorities;
}

/**
 * Fetch the chutney consensus over an existing directory circuit, verifying
 * signatures against chutney's own discovered authority list.
 */
export async function fetchChutneyConsensusOverCircuit(
  directoryCircuit: Circuit
): Promise<VerifiedMicroDescConsensus> {
  const trustedAuthorities = await discoverChutneyAuthorities();
  const manager = new ConsensusManager(directoryCircuit, {
    defaultRefreshOptions: { trustedAuthorities },
  });
  return manager.getConsensus();
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

  // 1-hop bootstrap circuit via TLS to a chutney relay (same shape as
  // mainnet's fallback-directory bootstrap).
  const bootstrapCircuit = await bootstrapWithChutneyDirectory();
  log('Bootstrap circuit established');

  const dirClient = new DirectoryClient(bootstrapCircuit);

  // Discover chutney's directory authorities from disk and use them as the
  // trust anchor — same verification path mainnet runs, just with a
  // network-specific keylist.
  const trustedAuthorities = await discoverChutneyAuthorities();
  const consensusManager = new ConsensusManager(bootstrapCircuit, {
    defaultRefreshOptions: { trustedAuthorities },
  });
  const consensus = await consensusManager.getConsensus();
  log(`Got consensus with ${consensus.relays.length} relays`);

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
      consensus,
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
    const path = await getRandomChutneyCircuitPathSafe(bootstrapCircuit, consensus);
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
