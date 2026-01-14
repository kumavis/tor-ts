/**
 * Live Snowflake integration test.
 *
 * Uses safe bootstrap flow: directory lookups happen over an encrypted Tor circuit.
 * 1. Connect to Snowflake relay (WebSocket)
 * 2. Build 1-hop bootstrap circuit using CREATE_FAST (no onion key needed)
 * 3. Download consensus and key certificates over encrypted circuit
 * 4. Build full 3-hop circuit using relay info from consensus
 */

import http from 'node:http';
import https from 'node:https';

import test from 'ava';
import { Circuit } from 'tor/circuit';
import type { PeerInfo } from 'tor/circuit';
import {
  DirectoryClient,
  parseMicroDescConsensus,
  lookupPeerInfo,
  parseAllKeyCertificates,
} from 'tor/directory-client';
import { pickRelayWithFlags } from 'tor/build-circuit/util';
import { getTorAgentForUrl } from 'tor/node';

import { SnowflakeTlsChannelConnection } from '../tor-channel.ts';

test.serial('snowflake live: build circuit + fetch example.com (optional)', async (t) => {
  t.timeout(180_000);

  // Step 1: Connect to Snowflake relay
  const channel = new SnowflakeTlsChannelConnection();
  await channel.connect({ relayUrl: 'wss://snowflake.torproject.net/' });
  t.teardown(() => channel.destroy());

  const entryRsaIdDigest = channel.peerIdentity?.rsaIdDigest;
  if (!entryRsaIdDigest) throw new Error('snowflake channel has no peer identity');

  // Step 2: Build 1-hop bootstrap circuit using CREATE_FAST
  // The Snowflake entry may not appear in the public consensus. For the first hop,
  // we use CREATE_FAST (empty onionKey = no descriptor keys required).
  const entryPeerInfo: PeerInfo = {
    onionKey: Buffer.alloc(0),
    rsaIdDigest: entryRsaIdDigest,
    linkSpecifiers: [],
  };

  const bootstrapCircuit = new Circuit({ path: [entryPeerInfo], channel });
  await bootstrapCircuit.connect();

  // Step 3: Download consensus and key certificates over encrypted circuit
  const dirClient = new DirectoryClient(bootstrapCircuit);

  const keyCertsText = await dirClient.downloadKeyCertificates();
  const keyCertificates = parseAllKeyCertificates(keyCertsText);

  const microDescContent = await dirClient.downloadMicrodescConsensus();
  const consensus = await parseMicroDescConsensus(microDescContent, {
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

  const body = await new Promise<string>((resolve, reject) => {
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

  t.regex(body, /Example Domain/);
});
