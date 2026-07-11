/**
 * Browser Tor Client - Long-lived client for Tor operations.
 *
 * Uses TorClient from the tor package with Snowflake transport.
 */

import { Circuit } from 'tor/circuit';
import type { PeerInfo } from 'tor/circuit';
import type { DownloadProgress } from 'tor/directory-client';
import { lookupPeerInfo } from 'tor/directory-client';
import { pickRelayWithFlags } from 'tor/build-circuit/util';
import { ChannelManager } from 'tor/channel';
import type { BuildCircuitFn } from 'tor/hidden-service';
import {
  TorClient,
  type CircuitResult,
  type MicrodescProgressCallback,
  type MicrodescStorage,
} from 'tor';
import { SnowflakeBrowserChannel } from './snowflake-channel.ts';
import { performBootstrap } from './bootstrap.ts';
import { fetchViaTorCircuit } from './http-fetch.ts';

// ============================================================================
// Snowflake Channel Manager
// ============================================================================

/**
 * Create a channel manager for Snowflake browser channels.
 *
 * In browser mode with Snowflake, all circuits share a single channel
 * to the bridge. This factory creates the channel manager that reuses
 * the existing channel for all circuits.
 */
export function createSnowflakeChannelManager(
  channel: SnowflakeBrowserChannel,
  entryPeerInfo: PeerInfo
): ChannelManager<SnowflakeBrowserChannel> {
  const manager = new ChannelManager<SnowflakeBrowserChannel>(
    async (_peerInfo: PeerInfo) => {
      // In Snowflake mode, we always return the same channel
      // since all circuits go through the same bridge
      return channel;
    },
    // Snowflake channels don't have a simple socket.destroyed check
    () => true
  );

  // Pre-add the existing channel
  manager.add(entryPeerInfo.rsaIdDigest, channel);

  return manager;
}

// ============================================================================
// Types
// ============================================================================

export type BrowserTorClientOptions = {
  /** Snowflake relay URL */
  relayUrl?: string;
  /** Callback for status updates */
  onStatus?: (status: string) => void;
  /** Callback for consensus download progress */
  onConsensusProgress?: (progress: DownloadProgress) => void;
  /** Callback for microdescriptor download progress (used during hidden service connections) */
  onMicrodescProgress?: MicrodescProgressCallback;
  /**
   * Trust anchor for consensus signature verification. Defaults to the
   * hardcoded mainnet authorities. Pass an alternate list to verify a
   * non-mainnet consensus (e.g. chutney) without skipping signatures.
   */
  trustedAuthorities?: import('tor').DirectoryAuthorityIdentity[];
  /** Skip using cached consensus from sessionStorage */
  skipConsensusCache?: boolean;
  /** Pre-loaded consensus text (e.g. from IndexedDB). Passed to bootstrap. */
  cachedConsensusText?: string;
  /** Custom microdesc storage. Passed to bootstrap. */
  microdescStorage?: MicrodescStorage;
  /** Callback when consensus is updated. Passed to bootstrap. */
  onConsensusUpdate?: (rawContent: string) => void;
  /**
   * Enable verbose hidden-service diagnostics (SRV / time-period candidates,
   * blinded keys, HSDir ring selection, per-intro-point attempts). These are
   * routed through the same `onStatus` callback as normal status lines, so a
   * host app can capture them for analysis.
   *
   * In Node these logs are gated behind the `TOR_TS_HS_DEBUG` env var; the
   * browser has no `process.env`, so this option sets the equivalent runtime
   * flag (`globalThis.__TOR_TS_HS_DEBUG__`).
   */
  debug?: boolean;
};

/**
 * Browser Tor client - TorClient configured for Snowflake transport.
 */
export type BrowserTorClient = TorClient<SnowflakeBrowserChannel>;

/**
 * Result of creating a browser Tor client.
 */
export type BrowserTorClientResult = {
  /** The Tor client */
  client: BrowserTorClient;
  /** The underlying Snowflake channel (for debugging/advanced use) */
  channel: SnowflakeBrowserChannel;
  /** Entry peer info - the bridge we connected to */
  entryPeerInfo: PeerInfo;
};

// ============================================================================
// Factory
// ============================================================================

/**
 * Create a browser Tor client.
 *
 * This performs bootstrap (Snowflake connection, TLS handshake, consensus fetch)
 * and returns a long-lived client that can be used for multiple operations.
 *
 * @example
 * ```typescript
 * const client = await makeBrowserTorClient({ onStatus: console.log });
 *
 * // Connect to hidden services
 * const hs = await client.connectToHiddenService('xyz.onion', 80);
 *
 * // Fetch clearnet pages
 * const html = await client.fetchHtml('https://example.com');
 *
 * // Cleanup when done
 * client.destroy();
 * ```
 */
export async function makeBrowserTorClient(
  options: BrowserTorClientOptions = {}
): Promise<BrowserTorClientResult> {
  const { onStatus, onMicrodescProgress } = options;

  // Turn on verbose HS diagnostics for the whole process when requested. The
  // core HS code reads this flag at call time via isHsDebugEnabled(), so the
  // extra `dlog` lines then flow through the `log` callback below (and thus
  // out through `onStatus`) without any other wiring.
  if (options.debug) {
    (globalThis as { __TOR_TS_HS_DEBUG__?: boolean }).__TOR_TS_HS_DEBUG__ = true;
  }

  const log = (msg: string) => {
    console.log(`[tor-client] ${msg}`);
    onStatus?.(msg);
  };

  // Bootstrap: connect to Snowflake, get consensus
  // Note: Microdescriptors are fetched lazily when connecting to onion domains
  const {
    channel,
    bootstrapCircuit,
    dirClient,
    consensusManager,
    microdescManager,
    consensus,
    entryPeerInfo,
  } = await performBootstrap({
    ...options,
    logPrefix: 'tor-client',
  });

  // Create channel manager that reuses the single Snowflake channel
  const channelManager = new ChannelManager<SnowflakeBrowserChannel>(
    async () => channel,
    () => true
  );
  channelManager.add(entryPeerInfo.rsaIdDigest, channel);

  // Build circuit to a specific target (for hidden services)
  const buildCircuitToTarget: BuildCircuitFn = async (target, opts) => {
    // Exclude the target, our fixed entry (Snowflake bridge), and any relays
    // the caller asked to avoid. The HS flow passes `{ avoid: [rendezvousPoint] }`
    // when building the introduction circuit so the rendezvous point can't also
    // appear as the middle hop — reusing it makes the service silently drop the
    // introduction, which previously surfaced only as a rendezvous timeout.
    // We also require Fast + Stable so the middle hop is actually usable for
    // relaying (the old empty-flags selection could pick an unsuitable relay
    // and fail the whole HS connection).
    const avoidDigests = (opts?.avoid ?? []).map((p) => p.rsaIdDigest);
    const candidateRelays = consensus.relays.filter(
      (r) =>
        !r.rsaIdDigest.equals(target.rsaIdDigest) &&
        !r.rsaIdDigest.equals(entryPeerInfo.rsaIdDigest) &&
        !avoidDigests.some((d) => d.equals(r.rsaIdDigest))
    );
    const middleNode = pickRelayWithFlags(candidateRelays, ['Fast', 'Stable'], []);
    const middlePeerInfo = await lookupPeerInfo(dirClient, middleNode);

    const circuit = new Circuit({
      path: [entryPeerInfo, middlePeerInfo, target],
      channel,
    });
    await circuit.connect();
    return circuit;
  };

  // Build a general exit circuit
  const buildCircuit = async (_opts?: { targetPorts?: number[] }): Promise<CircuitResult> => {
    const middleNode = pickRelayWithFlags(consensus.relays, [], []);
    const exitNode = pickRelayWithFlags(consensus.relays, ['Exit'], [middleNode]);

    log(`Selected middle: ${middleNode.nickname}, exit: ${exitNode.nickname}`);

    const middlePeerInfo = await lookupPeerInfo(dirClient, middleNode);
    const exitPeerInfo = await lookupPeerInfo(dirClient, exitNode);

    const circuit = new Circuit({
      path: [entryPeerInfo, middlePeerInfo, exitPeerInfo],
      channel,
    });
    await circuit.connect();

    return {
      circuit,
      destroy: () => circuit.destroy({ preserveChannel: true }),
    };
  };

  log('Client initialized');

  // Create the client
  const client = new TorClient<SnowflakeBrowserChannel>({
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
    ...(onMicrodescProgress !== undefined ? { onMicrodescProgress } : {}),
    onDestroy: () => channel.destroy(),
  });

  return { client, channel, entryPeerInfo };
}

// ============================================================================
// Helpers
// ============================================================================

/**
 * Options for fetchHtml.
 */
export type FetchHtmlOptions = {
  /** Request timeout in ms */
  timeout?: number;
};

/**
 * Fetch HTML from a URL using a Tor client.
 * Decodes response body as UTF-8 text.
 *
 * @example
 * ```typescript
 * // Client with microdesc progress reporting
 * const { client } = await makeBrowserTorClient({
 *   onMicrodescProgress: (p) => console.log(`${p.fetched}/${p.total}`)
 * });
 * const html = await fetchHtml(client, 'https://example.com');
 * ```
 */
export async function fetchHtml(
  client: BrowserTorClient,
  url: string,
  options?: FetchHtmlOptions
): Promise<string> {
  const response = await client.fetch(url, {
    headers: {
      Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    },
    ...(options?.timeout !== undefined && { timeout: options.timeout }),
  });

  if (response.status >= 400) {
    throw new Error(`HTTP error ${response.status}: ${response.statusText}`);
  }

  return new TextDecoder().decode(response.body);
}
