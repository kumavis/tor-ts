/**
 * Tor Client
 *
 * Configurable Tor client that works across all platforms.
 * Platform-specific factories create instances with appropriate dependencies.
 */

import { Circuit } from './circuit.ts';
import type { VerifiedMicroDescConsensus } from './build-circuit/directory.ts';
import type { IntroPoint, BuildCircuitFn } from './hidden-service.ts';
import { connectToHiddenServiceCore } from './hidden-service.ts';
import { DirectoryClient } from './directory-client.ts';
import { ConsensusManager } from './consensus-manager.ts';
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
 * Response from a fetch operation.
 */
export type FetchResponse = {
  status: number;
  statusText: string;
  headers: Map<string, string>;
  body: string;
};

/**
 * Options for fetch operations.
 */
export type FetchOptions = {
  /** HTTP method (default: GET) */
  method?: string;
  /** HTTP headers */
  headers?: Record<string, string>;
  /** Request timeout in ms */
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
  readonly dirClient: DirectoryClient;

  private readonly bootstrapCircuit: Circuit;
  private readonly buildCircuitToTargetFn: BuildCircuitFn;
  private readonly buildCircuitFn: BuildGeneralCircuitFn;
  private readonly fetchOverCircuitFn: FetchOverCircuitFn;
  private readonly log: (msg: string) => void;
  private readonly onDestroyCallback: (() => void) | undefined;
  private isDestroyed = false;
  private _consensus: VerifiedMicroDescConsensus;

  get consensus(): VerifiedMicroDescConsensus {
    return this._consensus;
  }

  constructor(deps: TorClientDeps<TChannel>) {
    this.channelManager = deps.channelManager;
    this.consensusManager = deps.consensusManager;
    this.dirClient = deps.dirClient;
    this.bootstrapCircuit = deps.bootstrapCircuit;
    this._consensus = deps.consensus;
    this.buildCircuitToTargetFn = deps.buildCircuitToTarget;
    this.buildCircuitFn = deps.buildCircuit;
    this.fetchOverCircuitFn = deps.fetchOverCircuit;
    this.log = deps.log;
    this.onDestroyCallback = deps.onDestroy;
  }

  async connectToHiddenService(
    onionAddress: string,
    port: number,
    options: { overallTimeoutMs?: number } = {}
  ): Promise<HsConnectionResult> {
    this.checkDestroyed();
    const { overallTimeoutMs = 300_000 } = options;

    const result = await connectToHiddenServiceCore(
      {
        consensus: this._consensus,
        bootstrapCircuit: this.bootstrapCircuit,
        dirClient: this.dirClient,
        buildCircuit: this.buildCircuitToTargetFn,
      },
      onionAddress,
      {
        overallTimeoutMs,
        log: this.log,
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

    const hs = await this.connectToHiddenService(parsedUrl.hostname, port);
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
