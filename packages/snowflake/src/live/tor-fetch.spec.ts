import http from 'node:http';
import https from 'node:https';

import test from 'ava';
import { Circuit } from 'tor/circuit';
import type { PeerInfo } from 'tor/circuit';
import {
  getRandomDirectoryAuthority,
  dangerouslyDownloadMicrodescFromDirectory,
  dangerouslyLookupPeerInfo,
  parseRelaysFromMicroDesc,
} from 'tor/build-circuit/directory';
import { pickRelayWithFlags } from 'tor/build-circuit/util';
import { getTorAgentForUrl } from 'tor/node';

import { SnowflakeTlsChannelConnection } from '../tor-channel.ts';

test.serial('snowflake live: build circuit + fetch example.com (optional)', async (t) => {
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

  // The Snowflake entry may not appear in the public consensus. For the first hop only,
  // we use CREATE_FAST (no descriptor keys required). Subsequent hops are extended with ntor.
  const entryPeerInfo: PeerInfo = {
    onionKey: Buffer.alloc(0),
    rsaIdDigest: entryRsaIdDigest,
    linkSpecifiers: [],
  };

  const middleNode = pickRelayWithFlags(microDescNodeInfos, [], []);
  const exitNode = pickRelayWithFlags(microDescNodeInfos, ['Exit'], [middleNode]);

  const middlePeerInfo = await dangerouslyLookupPeerInfo(directoryServer, middleNode);
  const exitPeerInfo = await dangerouslyLookupPeerInfo(directoryServer, exitNode);

  const circuitPeerInfos: Array<PeerInfo> = [entryPeerInfo, middlePeerInfo, exitPeerInfo];

  const circuit = new Circuit({ path: circuitPeerInfos, channel });
  await circuit.connect();
  t.teardown(() => circuit.destroy());

  const url = new URL('https://example.com/');
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

  t.regex(body, /Example Domain/);
});
