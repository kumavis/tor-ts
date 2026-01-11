/**
 * Tor Network Client for Browser
 *
 * Provides real Tor connectivity via Snowflake transport.
 * Allows network exploration and manual circuit construction.
 */

import { Circuit } from 'tor/circuit';
import type { PeerInfo } from 'tor/circuit';
import {
  DirectoryClient,
  parseMicroDescConsensus,
  lookupPeerInfo,
  type MicroDescConsensus,
  type MicroDescNodeInfo,
} from 'tor/directory-client';
import { pickRelayWithFlags, filterRelaysByFlags } from 'tor/build-circuit/util';
import { SnowflakeBrowserChannel } from 'browser';

export type ConnectionState =
  | 'disconnected'
  | 'connecting_snowflake'
  | 'building_bootstrap'
  | 'fetching_consensus'
  | 'connected'
  | 'error';

export type CircuitState = 'building' | 'connected' | 'failed' | 'destroyed';

export interface ManagedCircuit {
  id: number;
  nodes: MicroDescNodeInfo[];
  peerInfos: PeerInfo[];
  circuit: Circuit | null;
  state: CircuitState;
  error?: string;
  createdAt: Date;
}

export interface TorClientEvents {
  onStateChange: (state: ConnectionState, message: string) => void;
  onLog: (message: string, level: 'info' | 'success' | 'error' | 'warning') => void;
  onConsensusLoaded: (consensus: MicroDescConsensus) => void;
  onCircuitUpdate: (circuits: ManagedCircuit[]) => void;
}

/**
 * Browser-based Tor client with manual circuit construction.
 */
export class TorClient {
  private channel: SnowflakeBrowserChannel | null = null;
  private bootstrapCircuit: Circuit | null = null;
  private dirClient: DirectoryClient | null = null;
  private entryPeerInfo: PeerInfo | null = null;

  private _state: ConnectionState = 'disconnected';
  private _consensus: MicroDescConsensus | null = null;
  private _circuits: ManagedCircuit[] = [];
  private _nextCircuitId = 1;

  private events: TorClientEvents;

  constructor(events: TorClientEvents) {
    this.events = events;
  }

  get state(): ConnectionState {
    return this._state;
  }

  get consensus(): MicroDescConsensus | null {
    return this._consensus;
  }

  get circuits(): ManagedCircuit[] {
    return this._circuits;
  }

  get isConnected(): boolean {
    return this._state === 'connected';
  }

  private setState(state: ConnectionState, message: string): void {
    this._state = state;
    this.events.onStateChange(state, message);
  }

  private log(message: string, level: 'info' | 'success' | 'error' | 'warning' = 'info'): void {
    this.events.onLog(message, level);
  }

  /**
   * Connect to the Tor network via Snowflake.
   * Establishes a bootstrap circuit and downloads the network consensus.
   */
  async connect(relayUrl = 'wss://snowflake.torproject.net/'): Promise<void> {
    if (this._state !== 'disconnected' && this._state !== 'error') {
      throw new Error(`Cannot connect: already in state ${this._state}`);
    }

    try {
      // Step 1: Connect to Snowflake
      this.setState('connecting_snowflake', 'Connecting to Snowflake relay...');
      this.log('Initiating Snowflake WebSocket connection...', 'info');

      this.channel = new SnowflakeBrowserChannel();
      await this.channel.connect({ relayUrl });

      const entryRsaIdDigest = this.channel.peerIdentity?.rsaIdDigest;
      if (!entryRsaIdDigest) {
        throw new Error('Snowflake channel has no peer identity');
      }

      this.log(
        `Connected to Snowflake relay (fingerprint: ${entryRsaIdDigest.toString('hex').slice(0, 16)}...)`,
        'success'
      );

      // Step 2: Build bootstrap circuit
      this.setState('building_bootstrap', 'Building bootstrap circuit...');
      this.log('Creating 1-hop bootstrap circuit with CREATE_FAST...', 'info');

      this.entryPeerInfo = {
        onionKey: Buffer.alloc(0), // Empty triggers CREATE_FAST
        rsaIdDigest: entryRsaIdDigest,
        linkSpecifiers: [],
      };

      this.bootstrapCircuit = new Circuit({
        path: [this.entryPeerInfo],
        channel: this.channel,
      });
      await this.bootstrapCircuit.connect();

      this.log('Bootstrap circuit established', 'success');

      // Step 3: Fetch consensus
      this.setState('fetching_consensus', 'Downloading network consensus...');
      this.log('Fetching microdesc consensus via RELAY_BEGIN_DIR...', 'info');

      this.dirClient = new DirectoryClient(this.bootstrapCircuit, { timeoutMs: 60000 });
      const microDescContent = await this.dirClient.downloadMicrodescConsensus();

      // Parse with signature verification disabled for browser (no crypto for RSA verification)
      this._consensus = parseMicroDescConsensus(microDescContent, {
        verifySignatures: false,
      });

      if (this._consensus.relays.length === 0) {
        throw new Error('No relays found in consensus');
      }

      this.log(
        `Consensus loaded: ${this._consensus.relays.length} relays (valid until ${this._consensus.validUntil?.toISOString() || 'unknown'})`,
        'success'
      );

      // Count node types
      const guards = this._consensus.relays.filter((r) => r.flags?.includes('Guard')).length;
      const exits = this._consensus.relays.filter((r) => r.flags?.includes('Exit')).length;
      const authorities = this._consensus.relays.filter((r) =>
        r.flags?.includes('Authority')
      ).length;

      this.log(
        `Network stats: ${guards} guards, ${exits} exits, ${authorities} authorities`,
        'info'
      );

      this.setState('connected', `Connected - ${this._consensus.relays.length} relays`);
      this.events.onConsensusLoaded(this._consensus);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      this.log(`Connection failed: ${message}`, 'error');
      this.setState('error', `Error: ${message}`);
      this.cleanup();
      throw error;
    }
  }

  /**
   * Disconnect from the Tor network.
   */
  disconnect(): void {
    this.log('Disconnecting from Tor network...', 'info');

    // Destroy all circuits
    for (const circuit of this._circuits) {
      if (circuit.circuit && circuit.state === 'connected') {
        circuit.circuit.destroy();
        circuit.state = 'destroyed';
      }
    }
    this._circuits = [];
    this.events.onCircuitUpdate(this._circuits);

    this.cleanup();
    this.setState('disconnected', 'Disconnected');
    this.log('Disconnected from Tor network', 'info');
  }

  private cleanup(): void {
    this.bootstrapCircuit?.destroy();
    this.bootstrapCircuit = null;
    this.channel?.destroy();
    this.channel = null;
    this.dirClient = null;
    this.entryPeerInfo = null;
    this._consensus = null;
  }

  /**
   * Build a circuit with specific nodes.
   * The entry node is always the Snowflake relay we're connected to.
   *
   * @param nodes - Array of relay nodes for the circuit path (middle + exit)
   */
  async buildCircuit(nodes: MicroDescNodeInfo[]): Promise<ManagedCircuit> {
    if (!this.isConnected || !this.channel || !this.entryPeerInfo || !this.dirClient) {
      throw new Error('Not connected to Tor network');
    }

    if (nodes.length === 0) {
      throw new Error('At least one node required for circuit');
    }

    const circuitId = this._nextCircuitId++;
    const managedCircuit: ManagedCircuit = {
      id: circuitId,
      nodes,
      peerInfos: [],
      circuit: null,
      state: 'building',
      createdAt: new Date(),
    };

    this._circuits.push(managedCircuit);
    this.events.onCircuitUpdate([...this._circuits]);

    try {
      this.log(`Building circuit ${circuitId} with ${nodes.length + 1} hops...`, 'info');

      // Look up peer info for each node
      const peerInfos: PeerInfo[] = [this.entryPeerInfo];

      for (const node of nodes) {
        this.log(`Looking up descriptor for ${node.nickname}...`, 'info');
        const peerInfo = await lookupPeerInfo(this.dirClient, node);
        peerInfos.push(peerInfo);
      }

      managedCircuit.peerInfos = peerInfos;

      // Build the circuit
      this.log(`Extending circuit through ${nodes.map((n) => n.nickname).join(' → ')}...`, 'info');

      const circuit = new Circuit({
        path: peerInfos,
        channel: this.channel,
      });

      await circuit.connect();

      managedCircuit.circuit = circuit;
      managedCircuit.state = 'connected';

      this.log(
        `Circuit ${circuitId} established: Snowflake → ${nodes.map((n) => n.nickname).join(' → ')}`,
        'success'
      );

      this.events.onCircuitUpdate([...this._circuits]);
      return managedCircuit;
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      managedCircuit.state = 'failed';
      managedCircuit.error = message;
      this.log(`Circuit ${circuitId} failed: ${message}`, 'error');
      this.events.onCircuitUpdate([...this._circuits]);
      throw error;
    }
  }

  /**
   * Build a random circuit with the specified number of hops.
   * Follows Tor best practices: Guard → Middle(s) → Exit
   */
  async buildRandomCircuit(hopCount = 3): Promise<ManagedCircuit> {
    if (!this._consensus) {
      throw new Error('No consensus loaded');
    }

    const nodes: MicroDescNodeInfo[] = [];
    const relays = this._consensus.relays;

    // We already have entry (Snowflake), so we need hopCount - 1 more nodes
    const additionalHops = hopCount - 1;

    if (additionalHops >= 1) {
      // Pick middle nodes (any stable relay)
      for (let i = 0; i < additionalHops - 1; i++) {
        const middle = pickRelayWithFlags(relays, ['Stable', 'Fast'], nodes);
        nodes.push(middle);
        this.log(`Selected middle node: ${middle.nickname}`, 'info');
      }

      // Pick exit node
      const exit = pickRelayWithFlags(relays, ['Exit', 'Stable'], nodes);
      nodes.push(exit);
      this.log(`Selected exit node: ${exit.nickname}`, 'info');
    }

    return this.buildCircuit(nodes);
  }

  /**
   * Destroy a specific circuit.
   */
  destroyCircuit(circuitId: number): void {
    const circuit = this._circuits.find((c) => c.id === circuitId);
    if (circuit) {
      if (circuit.circuit && circuit.state === 'connected') {
        circuit.circuit.destroy();
      }
      circuit.state = 'destroyed';
      this._circuits = this._circuits.filter((c) => c.id !== circuitId);
      this.log(`Circuit ${circuitId} destroyed`, 'info');
      this.events.onCircuitUpdate([...this._circuits]);
    }
  }

  /**
   * Destroy all circuits.
   */
  destroyAllCircuits(): void {
    for (const circuit of this._circuits) {
      if (circuit.circuit && circuit.state === 'connected') {
        circuit.circuit.destroy();
      }
      circuit.state = 'destroyed';
    }
    this._circuits = [];
    this.log('All circuits destroyed', 'info');
    this.events.onCircuitUpdate([...this._circuits]);
  }

  /**
   * Get relays filtered by flags.
   */
  getRelaysByFlags(flags: string[], exclude: MicroDescNodeInfo[] = []): MicroDescNodeInfo[] {
    if (!this._consensus) return [];
    return filterRelaysByFlags(this._consensus.relays, flags, exclude);
  }

  /**
   * Find a relay by fingerprint.
   */
  findRelayByFingerprint(fingerprint: string): MicroDescNodeInfo | undefined {
    if (!this._consensus) return undefined;
    const normalized = fingerprint.toUpperCase().replace(/\s/g, '');
    return this._consensus.relays.find((r) => {
      const relayFp = r.rsaIdDigest.toString('hex').toUpperCase();
      return relayFp === normalized || relayFp.startsWith(normalized);
    });
  }

  /**
   * Find relays by nickname (partial match).
   */
  findRelaysByNickname(query: string): MicroDescNodeInfo[] {
    if (!this._consensus) return [];
    const lowerQuery = query.toLowerCase();
    return this._consensus.relays.filter((r) => r.nickname.toLowerCase().includes(lowerQuery));
  }

  /**
   * Get a connected circuit by ID.
   */
  getCircuit(circuitId: number): ManagedCircuit | undefined {
    return this._circuits.find((c) => c.id === circuitId);
  }

  /**
   * Get the underlying Circuit object for making requests.
   */
  getCircuitForRequests(circuitId: number): Circuit | null {
    const managed = this.getCircuit(circuitId);
    if (managed?.state === 'connected') {
      return managed.circuit;
    }
    return null;
  }
}

export { type MicroDescNodeInfo, type MicroDescConsensus };
