/**
 * Browser-compatible hidden service (.onion) connection support.
 * Uses Snowflake as the transport layer.
 *
 * Core HSv3 crypto functions are imported from the tor package.
 * This module provides the browser-specific connection flow using SnowflakeBrowserChannel.
 */

import { Circuit } from 'tor/circuit';
import { lookupPeerInfo } from 'tor/directory-client';
import { pickRelayWithFlags } from 'tor/build-circuit/util';
import {
  connectToHiddenServiceCore,
  type BuildCircuitFn,
  type HiddenServiceDescriptor,
  type IntroPoint,
} from 'tor/hidden-service';
import { SnowflakeBrowserChannel } from './snowflake-channel.ts';
import { performBootstrap, type BrowserBootstrapOptions } from './bootstrap.ts';

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

export type HiddenServiceConnectionOptions = BrowserBootstrapOptions & {
  /** Overall timeout in milliseconds */
  overallTimeoutMs?: number;
};

export type HiddenServiceConnection = {
  circuit: Circuit;
  channel: SnowflakeBrowserChannel;
  introPoints: IntroPoint[];
  destroy: () => void;
};

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
  _port: number,
  options: HiddenServiceConnectionOptions = {}
): Promise<HiddenServiceConnection> {
  const { onStatus, overallTimeoutMs = 300_000 } = options;

  const log = (msg: string) => {
    console.log(`[tor-hs] ${msg}`);
    onStatus?.(msg);
  };

  // Perform common bootstrap (connect, build bootstrap circuit, get consensus)
  const { channel, bootstrapCircuit, dirClient, consensus, entryPeerInfo } = await performBootstrap(
    {
      ...options,
      logPrefix: 'tor-hs',
    }
  );

  // Browser circuit builder: reuses single Snowflake channel, picks middle relay
  const buildCircuit: BuildCircuitFn = async (target, _buildOptions) => {
    // Pick a middle relay (simple selection, avoiding exact target match by rsaIdDigest)
    const candidateRelays = consensus.relays.filter(
      (r) => !r.rsaIdDigest.equals(target.rsaIdDigest)
    );
    const middleNode = pickRelayWithFlags(candidateRelays, [], []);
    const middlePeerInfo = await lookupPeerInfo(dirClient, middleNode);

    const circuit = new Circuit({
      path: [entryPeerInfo, middlePeerInfo, target],
      channel,
    });
    await circuit.connect();
    return circuit;
  };

  let descriptor: HiddenServiceDescriptor;
  try {
    const result = await connectToHiddenServiceCore(
      { consensus, bootstrapCircuit, dirClient, buildCircuit },
      onionAddress,
      {
        overallTimeoutMs,
        log,
        randomBytes: (len) => {
          const arr = new Uint8Array(len);
          crypto.getRandomValues(arr);
          return arr;
        },
      }
    );

    // Clean up bootstrap circuit (keep channel for the rend circuit)
    bootstrapCircuit.destroy({ preserveChannel: true });

    descriptor = result.descriptor;

    log('Connected to hidden service!');

    return {
      circuit: result.circuit,
      channel,
      introPoints: descriptor.introPoints,
      destroy: () => {
        result.circuit.destroy();
      },
    };
  } catch (err) {
    bootstrapCircuit.destroy();
    channel.destroy();
    throw err;
  }
}
