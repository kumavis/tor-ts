/**
 * Live browser tests for Snowflake WebRTC connectivity.
 * These tests connect to the real Tor network via Snowflake WebRTC transport.
 *
 * IMPORTANT: These tests require:
 * - Network access
 * - Access to snowflake-broker.torproject.net
 * - WebRTC support (browser environment)
 * - May take 60-180 seconds to complete
 *
 * The circuit is established ONCE at the start and shared across all tests
 * to avoid repeatedly downloading the ~3.35MB consensus.
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { Circuit } from 'tor/circuit';
import type { PeerInfo } from 'tor/circuit';
import {
  DirectoryClient,
  parseMicroDescConsensusAsync,
  lookupPeerInfo,
} from 'tor/directory-client';
import { pickRelayWithFlags } from 'tor/build-circuit/util';
import { SnowflakeWebRtcBrowserChannel } from '../snowflake-webrtc-channel.ts';
import { fetchHtml } from '../http-fetch.ts';

// Shared state - established once, used by all tests
let channel: SnowflakeWebRtcBrowserChannel | null = null;
let circuit: Circuit | null = null;
const statusMessages: string[] = [];

/**
 * Global setup - connect to Tor once before all tests via WebRTC.
 * This downloads the consensus (~3.35MB) which is slow in browser JS TLS.
 */
beforeAll(async () => {
  console.log('[webrtc-test] Establishing Tor circuit via Snowflake WebRTC...');
  console.log('[webrtc-test] This connects via broker + WebRTC to a volunteer proxy');

  statusMessages.push('Connecting to Snowflake broker...');

  // Step 1: Connect via WebRTC channel
  // Note: Domain fronting is disabled because browsers don't allow setting
  // the Host header (it's a forbidden header). Direct broker connection is used.
  channel = new SnowflakeWebRtcBrowserChannel();
  await channel.connect({
    broker: {
      disableDomainFronting: true,
    },
  });
  statusMessages.push('WebRTC connection established');

  const entryRsaIdDigest = channel.peerIdentity?.rsaIdDigest;
  if (!entryRsaIdDigest) {
    throw new Error('Snowflake WebRTC channel has no peer identity');
  }
  statusMessages.push('Peer identity obtained');

  // Step 2: Build 1-hop bootstrap circuit using CREATE_FAST
  const entryPeerInfo: PeerInfo = {
    onionKey: Buffer.alloc(0), // Empty triggers CREATE_FAST
    rsaIdDigest: entryRsaIdDigest,
    linkSpecifiers: [],
  };

  const bootstrapCircuit = new Circuit({ path: [entryPeerInfo], channel });
  await bootstrapCircuit.connect();
  statusMessages.push('Bootstrap circuit connected');

  // Step 3: Fetch consensus
  const dirClient = new DirectoryClient(bootstrapCircuit, { timeoutMs: 600_000 });
  console.log('[webrtc-test] Downloading consensus (~3.35MB)...');
  statusMessages.push('Downloading consensus...');

  const microDescContent = await dirClient.downloadMicrodescConsensus((progress) => {
    if (progress.bytesReceived % 500_000 < 10_000) {
      console.log(
        `[webrtc-test] Consensus: ${(progress.bytesReceived / 1024 / 1024).toFixed(2)} MB`
      );
    }
  });
  statusMessages.push('Consensus downloaded');

  // Parse consensus (skip signature verification for browser - not yet implemented)
  const consensus = await parseMicroDescConsensusAsync(microDescContent, {
    dangerouslySkipSignatureVerification: true,
  });

  if (consensus.relays.length === 0) {
    throw new Error('No relays found in consensus');
  }
  statusMessages.push(`Found ${consensus.relays.length} relays`);

  // Step 4: Select and lookup relay info
  const middleNode = pickRelayWithFlags(consensus.relays, [], []);
  const exitNode = pickRelayWithFlags(consensus.relays, ['Exit'], [middleNode]);
  statusMessages.push(`Selected nodes: ${middleNode.nickname}, ${exitNode.nickname}`);

  const middlePeerInfo = await lookupPeerInfo(dirClient, middleNode);
  const exitPeerInfo = await lookupPeerInfo(dirClient, exitNode);
  statusMessages.push('Relay descriptors fetched');

  // Step 5: Build full 3-hop circuit
  circuit = new Circuit({
    path: [entryPeerInfo, middlePeerInfo, exitPeerInfo],
    channel,
  });
  await circuit.connect();
  bootstrapCircuit.destroy({ preserveChannel: true });

  statusMessages.push('Full circuit established!');
  console.log('[webrtc-test] 3-hop circuit ready via WebRTC!');
}, 600_000); // 10 minute timeout

/**
 * Global teardown - destroy the circuit after all tests.
 */
afterAll(() => {
  if (circuit) {
    console.log('[webrtc-test] Destroying circuit...');
    circuit.destroy();
    circuit = null;
  }
  if (channel) {
    console.log('[webrtc-test] Destroying channel...');
    channel.destroy();
    channel = null;
  }
});

describe('Snowflake WebRTC Live: Connection', () => {
  it('establishes WebRTC channel successfully', () => {
    expect(channel).toBeDefined();
    expect(channel!.peerIdentity).toBeDefined();
  }, 180_000);

  it('builds a valid Tor circuit', () => {
    expect(circuit).toBeDefined();
  }, 180_000);

  it('received status updates during connection', () => {
    expect(statusMessages.length).toBeGreaterThan(0);
    expect(statusMessages.some((s) => s.includes('WebRTC'))).toBe(true);
    expect(statusMessages.some((s) => s.includes('circuit') || s.includes('Circuit'))).toBe(true);
  }, 180_000);
});

describe('Snowflake WebRTC Live: Fetch via Tor', () => {
  it('fetches example.com HTML through Tor via WebRTC', async () => {
    expect(circuit).toBeDefined();

    console.log('[webrtc-test] Fetching https://example.com/...');
    const html = await fetchHtml(circuit!, 'https://example.com/');

    expect(html).toBeDefined();
    expect(typeof html).toBe('string');
    expect(html.length).toBeGreaterThan(100);
    expect(html).toContain('Example Domain');
    console.log('[webrtc-test] Received', html.length, 'bytes');
  }, 180_000);

  it('fetches httpbin.org/ip to verify exit node', async () => {
    expect(circuit).toBeDefined();

    console.log('[webrtc-test] Fetching https://httpbin.org/ip...');
    const response = await fetchHtml(circuit!, 'https://httpbin.org/ip');

    expect(response).toBeDefined();
    expect(typeof response).toBe('string');
    expect(response).toContain('origin');
    console.log('[webrtc-test] Exit IP:', response);
  }, 180_000);
});
