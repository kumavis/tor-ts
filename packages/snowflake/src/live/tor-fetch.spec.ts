/**
 * Live Snowflake integration test.
 *
 * Uses safe bootstrap flow: directory lookups happen over an encrypted Tor circuit.
 * 1. Connect to Snowflake relay (WebSocket)
 * 2. Build 1-hop bootstrap circuit using CREATE_FAST (no onion key needed)
 * 3. Download consensus and key certificates over encrypted circuit
 * 4. Build full 3-hop circuit using relay info from consensus
 *
 * Wraps the whole build-and-fetch sequence in `retryTransient` so a
 * mid-stream `DESTROYED` (reason 11) or other transient Tor-network
 * failure rebuilds a fresh channel + circuit and re-runs rather than
 * failing the suite. Mirrors the retry shape `examples/node-fetch` and
 * `examples/http-proxy` use via `withTorOperation`. The test can't use
 * `withTorOperation` directly because it needs a Snowflake channel
 * (not a fallback-directory bootstrap), so the retry is hand-rolled.
 */

import http from 'node:http';
import https from 'node:https';

import test from 'ava';
import { Circuit } from 'tor/circuit';
import type { PeerInfo } from 'tor/circuit';
import { parseAndVerifyConsensus } from 'tor/build-circuit/directory';
import { DirectoryClient, lookupPeerInfo } from 'tor/directory-client';
import { parseAllKeyCertificates } from 'tor';
import { pickRelayWithFlags } from 'tor/build-circuit/util';
import { retryTransient } from 'tor/build-circuit/mainnet';
import { getTorAgentForUrl } from 'tor/node';

import { SnowflakeTlsChannelConnection } from '../tor-channel.ts';

test.serial('snowflake live: build circuit + fetch example.com (optional)', async (t) => {
  t.timeout(540_000);

  const body = await retryTransient(
    async () => {
      // Step 1: Connect to Snowflake relay
      const channel = new SnowflakeTlsChannelConnection();
      try {
        await channel.connect({ relayUrl: 'wss://snowflake.torproject.net/' });

        const entryRsaIdDigest = channel.peerIdentity?.rsaIdDigest;
        if (!entryRsaIdDigest) throw new Error('snowflake channel has no peer identity');

        // Step 2: Build 1-hop bootstrap circuit using CREATE_FAST.
        // The Snowflake entry may not appear in the public consensus. For the
        // first hop, we use CREATE_FAST (empty onionKey = no descriptor keys
        // required).
        const entryPeerInfo: PeerInfo = {
          onionKey: Buffer.alloc(0),
          rsaIdDigest: entryRsaIdDigest,
          linkSpecifiers: [],
        };

        const bootstrapCircuit = new Circuit({ path: [entryPeerInfo], channel });
        await bootstrapCircuit.connect();

        // Step 3: Download consensus and key certificates over encrypted
        // circuit
        const dirClient = new DirectoryClient(bootstrapCircuit);
        const keyCertsText = await dirClient.downloadKeyCertificates();
        const keyCertificates = parseAllKeyCertificates(keyCertsText);

        const microDescContent = await dirClient.downloadMicrodescConsensus();
        const { consensus } = await parseAndVerifyConsensus(microDescContent, {
          keyCertificates,
        });
        const microDescNodeInfos = consensus.relays;

        // Step 4: Select middle and exit nodes, look up their descriptors
        const middleNode = pickRelayWithFlags(microDescNodeInfos, [], []);
        const exitNode = pickRelayWithFlags(microDescNodeInfos, ['Exit'], [middleNode]);

        const middlePeerInfo = await lookupPeerInfo(dirClient, middleNode);
        const exitPeerInfo = await lookupPeerInfo(dirClient, exitNode);

        // Clean up bootstrap circuit (preserve channel for full circuit)
        bootstrapCircuit.destroy({ preserveChannel: true });

        // Step 5: Build full 3-hop circuit on the same channel
        const circuitPeerInfos: Array<PeerInfo> = [entryPeerInfo, middlePeerInfo, exitPeerInfo];
        const circuit = new Circuit({ path: circuitPeerInfos, channel });
        await circuit.connect();

        const url = new URL('https://example.com/');
        const agent = getTorAgentForUrl(circuit, url.toString());

        try {
          return await new Promise<string>((resolve, reject) => {
            const mod = url.protocol === 'https:' ? https : http;
            const req = mod.request(
              url,
              {
                method: 'GET',
                headers: { accept: 'text/html' },
                agent,
              },
              (res) => {
                let s = '';
                res.setEncoding('utf8');
                res.on('data', (chunk) => (s += chunk));
                res.on('end', () => resolve(s));
              }
            );
            req.setTimeout(30_000, () => {
              req.destroy(new Error('request timeout'));
            });
            req.on('error', reject);
            req.end();
          });
        } finally {
          agent.destroy();
        }
      } finally {
        // Tear down the per-attempt channel (and any remaining circuit on
        // it) so a failed retry doesn't leak the WebSocket / TLS handles.
        channel.destroy();
      }
    },
    {
      maxAttempts: 3,
      backoffMs: (failedAttempt) => 2_000 * failedAttempt,
      onRetry: (attempt, err) =>
        console.warn(`Snowflake live attempt ${attempt} failed: ${err.message}. Retrying...`),
    }
  );

  t.regex(body, /Example Domain/);
});
