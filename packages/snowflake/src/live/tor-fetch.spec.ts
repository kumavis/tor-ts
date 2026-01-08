import http from 'node:http';
import https from 'node:https';

import test from 'ava';
import { Circuit } from 'tor/circuit';
import type { PeerInfo } from 'tor/circuit';
import { getRandomDirectoryAuthority } from 'tor/build-circuit/directory';
import {
  dangerouslyDownloadMicrodescFromDirectory,
  dangerouslyLookupPeerInfo,
  parseRelaysFromMicroDesc,
} from 'tor/build-circuit/directory';
import type { MicroDescNodeInfo } from 'tor/build-circuit/directory';
import { pickRelayWithFlags } from 'tor/build-circuit/util';
import { getTorAgentForUrl } from 'tor/node';

import { SnowflakeTlsChannelConnection } from '../tor-channel.ts';

test.serial('snowflake live: build circuit + fetch ipify (optional)', async (t) => {
  t.timeout(180_000);

  const directoryAuthority = await getRandomDirectoryAuthority();
  const directoryServer = directoryAuthority?.dir_address as string | undefined;
  if (!directoryServer) {
    throw new Error('selected directory authority has no dir_address');
  }

  const microDescContent = await dangerouslyDownloadMicrodescFromDirectory(directoryServer);
  const microDescNodeInfos = parseRelaysFromMicroDesc(microDescContent);

  const channel = new SnowflakeTlsChannelConnection();
  await channel.connect({ relayUrl: 'wss://snowflake.torproject.net/' });
  t.teardown(() => channel.destroy());

  const entryRsaIdDigest = channel.peerIdentity?.rsaIdDigest;
  if (!entryRsaIdDigest) throw new Error('snowflake channel has no peer identity');

  const entryNode = microDescNodeInfos.find((n) => n.rsaIdDigest.equals(entryRsaIdDigest));
  if (!entryNode) {
    throw new Error(
      `snowflake entry rsaIdDigest not found in microdesc consensus from ${directoryServer}`
    );
  }

  const circuitPlan: Array<MicroDescNodeInfo> = [];
  circuitPlan.push(entryNode);
  circuitPlan.push(pickRelayWithFlags(microDescNodeInfos, [], circuitPlan));
  circuitPlan.push(pickRelayWithFlags(microDescNodeInfos, ['Exit'], circuitPlan));

  const circuitPeerInfos: Array<PeerInfo> = await Promise.all(
    circuitPlan.map(async (relayInfo) => {
      return await dangerouslyLookupPeerInfo(directoryServer, relayInfo);
    })
  );

  const circuit = new Circuit({ path: circuitPeerInfos, channel });
  await circuit.connect();
  t.teardown(() => circuit.destroy());

  const url = new URL('https://api.ipify.org?format=json');
  const agent = getTorAgentForUrl(circuit, url.toString());

  const body = await new Promise<string>((resolve, reject) => {
    const mod = url.protocol === 'https:' ? https : http;
    const req = mod.request(
      url,
      {
        method: 'GET',
        headers: { accept: 'application/json' },
        agent,
      },
      (res) => {
        let s = '';
        res.setEncoding('utf8');
        res.on('data', (chunk) => (s += chunk));
        res.on('end', () => resolve(s));
      }
    );
    req.on('error', reject);
    req.end();
  });

  t.regex(body, /"ip"\s*:\s*"/);
});
