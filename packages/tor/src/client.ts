/**
 * Tor Client
 *
 * Configurable Tor client that works across all platforms.
 * Platform-specific factories create instances with appropriate dependencies.
 */

import { Circuit, type PeerInfo } from './circuit.ts';
import type { VerifiedMicroDescConsensus } from './build-circuit/directory.ts';
import type { IntroPoint, BuildCircuitFn } from './hidden-service.ts';
import { connectToHiddenServiceCore } from './hidden-service.ts';
import { DirectoryClient } from './directory-client.ts';
import { ConsensusManager } from './consensus-manager.ts';
import type { MicrodescManager, MicrodescProgressCallback } from './microdesc-manager.ts';
import type { ChannelConnection } from './channel.ts';
import { ChannelManager } from './channel.ts';
import { randomBytes } from 'tor-crypto';

// ============================================================================
// Result Types
// ============================================================================

/**
 * Result of a successful hidden service connection.
 */
export type HsConnectionResult = {
  /** The rendezvous circuit */
  circuit: Circuit;
  /** Introduction points from the descriptor */
  introPoints: IntroPoint[];
  /** Destroy this connection (keeps client alive) */
  destroy: () => void;
};

/**
 * Result of building a circuit.
 */
export type CircuitResult = {
  /** The built circuit */
  circuit: Circuit;
  /** Destroy this circuit (keeps client alive) */
  destroy: () => void;
};

// ============================================================================
// Dependencies
// ============================================================================

/**
 * Function to build a general-purpose circuit (for exit traffic).
 */
export type BuildGeneralCircuitFn = (options?: {
  targetPorts?: number[];
}) => Promise<CircuitResult>;

/**
 * Response from a fetch operation. Body is always raw bytes.
 * Use TextDecoder to decode text responses.
 */
export type FetchResponse = {
  status: number;
  statusText: string;
  headers: Map<string, string>;
  body: Uint8Array;
};

/**
 * Options for fetch operations.
 */
export type FetchOptions = {
  /** HTTP method (default: GET) */
  method?: string;
  /** HTTP headers */
  headers?: Record<string, string>;
  /**
   * Request timeout in ms. For .onion URLs this also bounds the hidden-service
   * connection setup (descriptor fetch, introduction, rendezvous), not just
   * the HTTP response read.
   */
  timeout?: number;
};

/**
 * Function to fetch a URL over a circuit.
 */
export type FetchOverCircuitFn = (
  circuit: Circuit,
  url: string,
  options?: FetchOptions
) => Promise<FetchResponse>;

/**
 * Dependencies needed to create a TorClient.
 * Platform-specific factories provide these.
 */
export type TorClientDeps<TChannel extends ChannelConnection> = {
  /** Channel manager for connection reuse */
  channelManager: ChannelManager<TChannel>;
  /** Consensus manager for caching and refresh */
  consensusManager: ConsensusManager;
  /** Microdescriptor manager for relay info caching */
  microdescManager: MicrodescManager;
  /** Directory client for relay lookups */
  dirClient: DirectoryClient;
  /** Bootstrap circuit for directory operations */
  bootstrapCircuit: Circuit;
  /** Current consensus (from bootstrap) */
  consensus: VerifiedMicroDescConsensus;
  /** Function to build circuits to a specific target (for HS) */
  buildCircuitToTarget: BuildCircuitFn;
  /** Function to build a general circuit (for exit) */
  buildCircuit: BuildGeneralCircuitFn;
  /** Function to fetch a URL over a circuit (platform-specific TLS) */
  fetchOverCircuit: FetchOverCircuitFn;
  /** Logging function */
  log: (msg: string) => void;
  /** Default progress callback for microdescriptor downloads (used in HS connections) */
  onMicrodescProgress?: MicrodescProgressCallback;
  /** Cleanup function called on destroy */
  onDestroy?: () => void;
};

// ============================================================================
// TorClient
// ============================================================================

/**
 * Tor client implementation.
 *
 * All behavior is configured via dependencies. Platform-specific factories
 * create instances with appropriate dependencies.
 */
export class TorClient<TChannel extends ChannelConnection = ChannelConnection> {
  readonly channelManager: ChannelManager<TChannel>;
  readonly consensusManager: ConsensusManager;
  readonly microdescManager: MicrodescManager;
  readonly dirClient: DirectoryClient;

  private readonly bootstrapCircuit: Circuit;
  private readonly buildCircuitToTargetFn: BuildCircuitFn;
  private readonly buildCircuitFn: BuildGeneralCircuitFn;
  private readonly fetchOverCircuitFn: FetchOverCircuitFn;
  private readonly log: (msg: string) => void;
  private readonly defaultOnMicrodescProgress: MicrodescProgressCallback | undefined;
  private readonly onDestroyCallback: (() => void) | undefined;
  private isDestroyed = false;
  private _consensus: VerifiedMicroDescConsensus;

  get consensus(): VerifiedMicroDescConsensus {
    return this._consensus;
  }

  constructor(deps: TorClientDeps<TChannel>) {
    this.channelManager = deps.channelManager;
    this.consensusManager = deps.consensusManager;
    this.microdescManager = deps.microdescManager;
    this.dirClient = deps.dirClient;
    this.bootstrapCircuit = deps.bootstrapCircuit;
    this._consensus = deps.consensus;
    this.buildCircuitToTargetFn = deps.buildCircuitToTarget;
    this.buildCircuitFn = deps.buildCircuit;
    this.fetchOverCircuitFn = deps.fetchOverCircuit;
    this.log = deps.log;
    this.defaultOnMicrodescProgress = deps.onMicrodescProgress;
    this.onDestroyCallback = deps.onDestroy;
  }

  async connectToHiddenService(
    onionAddress: string,
    port: number,
    options: {
      overallTimeoutMs?: number;
      /** Progress callback for microdescriptor downloads */
      onMicrodescProgress?: MicrodescProgressCallback;
    } = {}
  ): Promise<HsConnectionResult> {
    this.checkDestroyed();
    const { overallTimeoutMs = 300_000, onMicrodescProgress } = options;

    // Use provided callback or fall back to default
    const progressCallback = onMicrodescProgress ?? this.defaultOnMicrodescProgress;

    const result = await connectToHiddenServiceCore(
      {
        consensus: this._consensus,
        bootstrapCircuit: this.bootstrapCircuit,
        dirClient: this.dirClient,
        microdescManager: this.microdescManager,
        buildCircuit: this.buildCircuitToTargetFn,
      },
      onionAddress,
      {
        overallTimeoutMs,
        log: this.log,
        ...(progressCallback && { onMicrodescProgress: progressCallback }),
        randomBytes,
      }
    );

    return {
      circuit: result.circuit,
      introPoints: result.descriptor.introPoints,
      destroy: () => {
        result.circuit.destroy({ preserveChannel: true });
      },
    };
  }

  async buildCircuit(options: { targetPorts?: number[] } = {}): Promise<CircuitResult> {
    this.checkDestroyed();
    return this.buildCircuitFn(options);
  }

  /**
   * Build a 3-hop circuit terminating at `target`. Used by the hidden-service
   * host for intro/RP/HSDir circuits, and reachable from anywhere a
   * platform-specific {@link TorClient} has been wired (mainnet, chutney, or
   * Snowflake-backed browser client).
   */
  async buildCircuitToTarget(
    target: PeerInfo,
    options: { avoid?: PeerInfo[] } = {}
  ): Promise<Circuit> {
    this.checkDestroyed();
    return this.buildCircuitToTargetFn(target, options);
  }

  /** Public read-only access for HS-host descriptor publishing. */
  get bootstrapDirCircuit(): Circuit {
    this.checkDestroyed();
    return this.bootstrapCircuit;
  }

  async refreshConsensus(): Promise<VerifiedMicroDescConsensus> {
    this.checkDestroyed();
    const consensus = await this.consensusManager.refresh();
    this._consensus = consensus;
    return consensus;
  }

  /**
   * Fetch a URL through Tor.
   *
   * Automatically detects URL type:
   * - Clearnet URLs: Uses a 3-hop exit circuit
   * - .onion URLs: Establishes a hidden service connection
   *
   * Circuits are created and destroyed automatically per request.
   * Response body is always Uint8Array. Use TextDecoder to decode text responses.
   */
  async fetch(url: string, options?: FetchOptions): Promise<FetchResponse> {
    this.checkDestroyed();

    const parsedUrl = new URL(url);
    const isOnion = parsedUrl.hostname.endsWith('.onion');

    if (isOnion) {
      return this.fetchHiddenService(parsedUrl, options);
    } else {
      return this.fetchClearnet(url, options);
    }
  }

  /**
   * Fetch a clearnet URL through a 3-hop exit circuit.
   */
  private async fetchClearnet(url: string, options?: FetchOptions): Promise<FetchResponse> {
    const { circuit, destroy } = await this.buildCircuitFn();
    try {
      return await this.fetchOverCircuitFn(circuit, url, options);
    } finally {
      destroy();
    }
  }

  /**
   * Fetch from a .onion hidden service.
   * Establishes HS connection, fetches, then cleans up.
   */
  private async fetchHiddenService(parsedUrl: URL, options?: FetchOptions): Promise<FetchResponse> {
    const port = parsedUrl.port
      ? parseInt(parsedUrl.port, 10)
      : parsedUrl.protocol === 'https:'
        ? 443
        : 80;

    // Without this, options.timeout only bounded the HTTP response read and
    // the connection setup ran on its own (much longer) default budget — a
    // caller-side 120s fetch could sit in intro attempts for many minutes.
    const hs = await this.connectToHiddenService(
      parsedUrl.hostname,
      port,
      options?.timeout !== undefined ? { overallTimeoutMs: options.timeout } : {}
    );
    try {
      return await this.fetchOverCircuitFn(hs.circuit, parsedUrl.href, options);
    } finally {
      hs.destroy();
    }
  }

  destroy(): void {
    if (this.isDestroyed) return;
    this.isDestroyed = true;

    this.bootstrapCircuit.destroy({ preserveChannel: true });
    this.channelManager.destroyAll();
    this.onDestroyCallback?.();
  }

  private checkDestroyed(): void {
    if (this.isDestroyed) {
      throw new Error('Client has been destroyed');
    }
  }
}
